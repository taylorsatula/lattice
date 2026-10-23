"""
Admin CLI for a local Lattice daemon.

    python -m lattice invite [--ttl HOURS]   print a single-use invite token
    python -m lattice accept TOKEN           pair with the server that issued TOKEN
    python -m lattice peers                  list known peers
    python -m lattice block SERVER_ID        block a peer

Carry invite tokens to the other server's admin over a channel you trust
(in person, paper, USB, an end-to-end encrypted messenger). The token is
what defeats a man-in-the-middle; anyone holding it can pair as you.
"""

import argparse
import json
import os
import sys

import httpx

from .client import LatticeClient
from .secrets import load_config


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m lattice", description="Lattice admin CLI")
    parser.add_argument("--url", default=os.getenv("LATTICE_URL", "http://localhost:1113"), help="daemon URL")
    commands = parser.add_subparsers(dest="command", required=True)
    invite = commands.add_parser("invite", help="print a single-use invite token")
    invite.add_argument("--ttl", type=int, default=24, help="hours until the invite expires (1-168)")
    commands.add_parser("accept", help="pair using an invite token").add_argument("token")
    commands.add_parser("peers", help="list known peers")
    commands.add_parser("block", help="block a peer").add_argument("server_id")
    args = parser.parse_args()

    token = os.getenv("LATTICE_ADMIN_TOKEN") or load_config("ADMIN_TOKEN")
    with LatticeClient(base_url=args.url, admin_token=token) as client:
        try:
            if args.command == "invite":
                result = client.create_invite(args.ttl)
                print(result["token"])
                print(f"Expires {result['expires_at']}. Single use.", file=sys.stderr)
            elif args.command == "accept":
                result = client.accept_invite(args.token)
                print(f"Paired with {result['server_id']} ({result['server_uuid']})")
            elif args.command == "peers":
                for peer in client.list_peers():
                    print(f"{peer['trust']:<11} {peer['server_id']:<32} {peer['public_key']}  {peer['endpoint']}")
            elif args.command == "block":
                print(f"Blocked {client.block_peer(args.server_id)['server_id']}")
        except httpx.HTTPStatusError as exc:
            try:
                detail = exc.response.json().get("detail", exc.response.text)
            except json.JSONDecodeError:
                detail = exc.response.text
            print(f"error: {detail}", file=sys.stderr)
            return 1
        except httpx.HTTPError as exc:
            print(f"error: cannot reach daemon at {args.url}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
