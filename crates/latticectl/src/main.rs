//! latticectl: operator CLI for a running latticed (admin socket).
//!
//! Usage: latticectl [--socket PATH] <command> [args]
//!
//! Commands:
//!   node                       show node identity, mode, links, custody, drain state
//!   drain [on|off|status]      set or query drain mode (default: status)
//!   link <addr> [--key HEX] [--path STR] [--id HEX]
//!                              dial a peer (key = channel key for IK, path = upgrade path for XX)
//!   unlink <id-hex>            drop and demote all links to this peer

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lattice_client::Client;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: latticectl [--socket PATH] <node|drain|link|unlink> [args]");
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
        Some("node") => match client.node().await {
            Ok(n) => {
                println!("id:            {}", hex(&n.id));
                println!("mode:          {}", n.mode);
                println!("links:         {}", n.links);
                println!("records:       {}", n.records);
                println!("custody_bytes: {}", n.custody_bytes);
                println!("draining:      {}", n.draining);
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        Some("drain") => {
            let setting = match args.get(1).map(String::as_str) {
                None | Some("status") => None,
                Some("on") => Some(true),
                Some("off") => Some(false),
                Some(other) => {
                    eprintln!("drain: expected on|off|status, got {other:?}");
                    return ExitCode::from(2);
                }
            };
            match client.drain(setting).await {
                Ok((draining, custody)) => {
                    println!("draining:      {draining}");
                    println!("custody_bytes: {custody}");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }
        Some("link") => {
            let mut addr: Option<String> = None;
            let mut key: Option<[u8; 32]> = None;
            let mut path: Option<String> = None;
            let mut id: Option<[u8; 32]> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--key" | "--path" | "--id" => {
                        let Some(v) = args.get(i + 1) else {
                            eprintln!("{} needs a value", args[i]);
                            return ExitCode::from(2);
                        };
                        match args[i].as_str() {
                            "--key" => match decode_hex32(v) {
                                Ok(k) => key = Some(k),
                                Err(e) => {
                                    eprintln!("--key: {e}");
                                    return ExitCode::from(2);
                                }
                            },
                            "--path" => path = Some(v.clone()),
                            "--id" => match decode_hex32(v) {
                                Ok(k) => id = Some(k),
                                Err(e) => {
                                    eprintln!("--id: {e}");
                                    return ExitCode::from(2);
                                }
                            },
                            _ => unreachable!(),
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
                eprintln!("usage: latticectl link <addr> [--key HEX | --path STR] [--id HEX]");
                return ExitCode::from(2);
            };
            if key.is_none() && path.is_none() {
                eprintln!("link needs --key (IK) or --path (XX upgrade path)");
                return ExitCode::from(2);
            }
            match client.link(&addr, key, path, id).await {
                Ok(true) => {
                    println!("dial queued");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("daemon refused the dial (bad address or missing key/path)");
                    ExitCode::from(1)
                }
                Err(e) => fail(e),
            }
        }
        Some("unlink") => {
            let Some(hex) = args.get(1) else {
                eprintln!("usage: latticectl unlink <id-hex>");
                return ExitCode::from(2);
            };
            match decode_hex32(hex) {
                Ok(id) => match client.unlink(&id).await {
                    Ok(true) => {
                        println!("unlinked");
                        ExitCode::SUCCESS
                    }
                    Ok(false) => {
                        println!("no such link");
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(e),
                },
                Err(e) => {
                    eprintln!("bad peer id: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Some(other) => {
            eprintln!("unknown command {other:?}; expected node|drain|link|unlink");
            ExitCode::from(2)
        }
        None => {
            eprintln!("usage: latticectl [--socket PATH] <node|drain|link|unlink> [args]");
            ExitCode::from(2)
        }
    }
}

fn fail(e: lattice_client::Error) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::from(1)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
