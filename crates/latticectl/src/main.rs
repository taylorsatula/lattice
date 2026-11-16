//! latticectl: operator CLI for a running latticed (admin socket).
//!
//! Usage: latticectl [--socket PATH] <command> [args]
//!
//! Commands:
//!   node                       show node identity, mode, links, custody, drain state
//!   drain [on|off|status]      set or query drain mode (default: status)
//!   link <addr> [--key HEX] [--path STR] [--id ID]
//!                              dial a peer (key = channel key for IK, path = upgrade path for XX)
//!   unlink <id>                drop and demote all links to this peer
//!   rotate --next-key-file P --next-next-commitment HEX
//!                              rotate the signing key: P is the offline, pre-committed
//!                              next key; HEX is the BLAKE3 commitment to the following
//!                              key (generated offline)
//!   abandon --next-key-file P  permanently abandon the identity
//!   rotate-envelope            rotate the envelope (X-Wing) key
//!
//! Identifiers are printed and accepted in the spec text form (§1):
//! lowercase base32, 52 chars. Hex (64 chars) is accepted on input
//! everywhere an identifier is accepted.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lattice_client::Client;
use lattice_client::text::{encode_id, parse_id};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage: latticectl [--socket PATH] <node|drain|link|unlink|rotate|abandon|rotate-envelope> [args]"
        );
        return ExitCode::from(2);
    }
    let mut socket = std::env::var("LATTICE_ADMIN_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/lattice/admin.sock"));
    let mut i = 0;
    let mut rest: Vec<String> = Vec::new();
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                let Some(p) = args.get(i + 1) else {
                    eprintln!("--socket needs a value");
                    return ExitCode::from(2);
                };
                socket = PathBuf::from(p);
                i += 2;
            }
            other => {
                rest.push(other.to_string());
                i += 1;
            }
        }
    }
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(run(&socket, &rest))
}

async fn run(socket: &Path, args: &[String]) -> ExitCode {
    let mut client = match Client::connect_admin(socket).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect {}: {e}", socket.display());
            return ExitCode::from(1);
        }
    };
    match args.first().map(String::as_str) {
        Some("node") => cmd_node(&mut client).await,
        Some("drain") => cmd_drain(&mut client, args).await,
        Some("link") => cmd_link(&mut client, args).await,
        Some("unlink") => cmd_unlink(&mut client, args).await,
        Some("rotate") => cmd_rotate(&mut client, args).await,
        Some("abandon") => cmd_abandon(&mut client, args).await,
        Some("rotate-envelope") => cmd_rotate_envelope(&mut client).await,
        Some(other) => {
            eprintln!(
                "unknown command {other:?}; expected node|drain|link|unlink|rotate|abandon|rotate-envelope"
            );
            ExitCode::from(2)
        }
        None => {
            eprintln!(
                "usage: latticectl [--socket PATH] <node|drain|link|unlink|rotate|abandon|rotate-envelope> [args]"
            );
            ExitCode::from(2)
        }
    }
}

async fn cmd_node(client: &mut Client) -> ExitCode {
    match client.node().await {
        Ok(n) => {
            println!("id:            {}", encode_id(&n.id));
            println!("mode:          {}", n.mode);
            println!("links:         {}", n.links);
            println!("records:       {}", n.records);
            println!("custody_bytes: {}", n.custody_bytes);
            println!("draining:      {}", n.draining);
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

async fn cmd_drain(client: &mut Client, args: &[String]) -> ExitCode {
    let request = match args.get(1).map(String::as_str) {
        None | Some("status") => lattice_client::DrainRequest::Query,
        Some("on") => lattice_client::DrainRequest::Set(lattice_client::DrainState::Draining),
        Some("off") => lattice_client::DrainRequest::Set(lattice_client::DrainState::Serving),
        Some(other) => {
            eprintln!("drain: expected on|off|status, got {other:?}");
            return ExitCode::from(2);
        }
    };
    match client.drain(request).await {
        Ok(state) => {
            println!("draining:      {}", state.draining);
            println!("custody_bytes: {}", state.custody_bytes);
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

async fn cmd_link(client: &mut Client, args: &[String]) -> ExitCode {
    let mut addr: Option<String> = None;
    let mut key: Option<lattice_types::ChannelPublicKey> = None;
    let mut path: Option<String> = None;
    let mut id: Option<lattice_types::Identifier> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--key needs a value");
                    return ExitCode::from(2);
                };
                match decode_hex32(v) {
                    Ok(k) => key = Some(lattice_types::ChannelPublicKey::from_bytes(k)),
                    Err(e) => {
                        eprintln!("--key: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--path" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--path needs a value");
                    return ExitCode::from(2);
                };
                path = Some(v.clone());
                i += 2;
            }
            "--id" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--id needs a value");
                    return ExitCode::from(2);
                };
                match parse_id(v) {
                    Ok(parsed) => id = Some(parsed),
                    Err(e) => {
                        eprintln!("--id: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            other => {
                if addr.replace(other.to_string()).is_some() {
                    eprintln!("unexpected extra argument {other:?}");
                    return ExitCode::from(2);
                }
                i += 1;
            }
        }
    }
    let Some(addr) = addr else {
        eprintln!("usage: latticectl link <addr> [--key HEX | --path STR] [--id ID]");
        return ExitCode::from(2);
    };
    if key.is_none() && path.is_none() {
        eprintln!("link needs --key (IK) or --path (XX upgrade path)");
        return ExitCode::from(2);
    }
    match client.link(&addr, key, path, id).await {
        Ok(()) => {
            println!("dial queued");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

async fn cmd_unlink(client: &mut Client, args: &[String]) -> ExitCode {
    let Some(id_arg) = args.get(1) else {
        eprintln!("usage: latticectl unlink <id>");
        return ExitCode::from(2);
    };
    match parse_id(id_arg) {
        Ok(id) => match client.unlink(&id).await {
            Ok(lattice_client::UnlinkOutcome::Removed) => {
                println!("unlinked");
                ExitCode::SUCCESS
            }
            Ok(lattice_client::UnlinkOutcome::NotFound) => {
                println!("no such link");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e),
        },
        Err(e) => {
            eprintln!("bad peer id: {e}");
            ExitCode::from(2)
        }
    }
}

async fn cmd_rotate(client: &mut Client, args: &[String]) -> ExitCode {
    rotate_or_abandon(client, args, false).await
}

async fn cmd_abandon(client: &mut Client, args: &[String]) -> ExitCode {
    rotate_or_abandon(client, args, true).await
}

async fn rotate_or_abandon(client: &mut Client, args: &[String], abandon: bool) -> ExitCode {
    let mut next_key_file: Option<String> = None;
    let mut next_next_commitment: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--next-key-file" => {
                let Some(p) = args.get(i + 1) else {
                    eprintln!("--next-key-file needs a path");
                    return ExitCode::from(2);
                };
                next_key_file = Some(p.clone());
                i += 2;
            }
            "--next-next-commitment" => {
                if abandon {
                    eprintln!(
                        "--next-next-commitment is only valid for rotate; abandon takes no commitment"
                    );
                    return ExitCode::from(2);
                }
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--next-next-commitment needs a hex value");
                    return ExitCode::from(2);
                };
                next_next_commitment = Some(v.clone());
                i += 2;
            }
            other => {
                eprintln!("unknown flag {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let cmd = if abandon { "abandon" } else { "rotate" };
    let Some(path) = next_key_file else {
        eprintln!("{cmd} requires --next-key-file <path> (the offline, pre-committed next key)");
        return ExitCode::from(2);
    };
    let key_bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let next_key: [u8; 32] = match key_bytes.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => {
            eprintln!("{path}: expected 32 bytes, got {}", key_bytes.len());
            return ExitCode::from(2);
        }
    };
    let result = if abandon {
        client.abandon(&next_key).await
    } else {
        let Some(hex) = next_next_commitment else {
            eprintln!(
                "rotate requires --next-next-commitment <hex> (BLAKE3 commitment to the following key, generated offline)"
            );
            return ExitCode::from(2);
        };
        let commitment = match decode_hex32(&hex) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("--next-next-commitment: {e}");
                return ExitCode::from(2);
            }
        };
        client.rotate(&next_key, &commitment).await
    };
    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

async fn cmd_rotate_envelope(client: &mut Client) -> ExitCode {
    match client.rotate_envelope().await {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn fail(e: &lattice_client::Error) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::from(1)
}

fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes: Result<Vec<u8>, _> = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(s.get(i..i + 2).ok_or("odd length")?, 16).map_err(|e| e.to_string())
        })
        .collect();
    let bytes = bytes?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))
}
