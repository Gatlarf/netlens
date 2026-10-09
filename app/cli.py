"""Maintenance commands that run inside the container, for when nobody can sign in any more.

    docker exec -it netlens python -m app.cli list-users
    docker exec -it netlens python -m app.cli reset-password <user>        asks for the new password
    docker exec -it netlens python -m app.cli create-admin <user>          adds an administrator (or promotes and resets an existing user)

They work on the database in the data directory directly, so they need no login and no token.
"""

import argparse
import getpass
import sys
from pathlib import Path

from app import users
from app.config import load_settings
from app.db import connect, init_db


def _db(args):
    path = Path(args.db) if args.db else load_settings().data_dir / "netlens.db"
    if not path.exists():
        sys.exit(f"No database at {path}. Start Netlens once first, or pass --db.")
    conn = connect(path)
    init_db(conn)
    return conn


def _password(args) -> str:
    if args.password:
        return args.password
    first = getpass.getpass("New password: ")
    if getpass.getpass("Repeat it: ") != first:
        sys.exit("The two passwords differ.")
    return first


def run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", help="path of netlens.db (default: the data directory)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list-users")
    for name in ("reset-password", "create-admin"):
        p = sub.add_parser(name)
        p.add_argument("username")
        p.add_argument("--password", help="the new password (otherwise it is asked for, which keeps it out of the shell history)")
    args = parser.parse_args(argv)
    conn = _db(args)
    try:
        if args.command == "list-users":
            for u in users.list_users(conn):
                print(f"{u['username']:<24} {u['role']:<7} {'disabled' if u['disabled'] else 'active':<9} last login: {u['last_login'] or 'never'}")
            return 0
        row = conn.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (args.username,)).fetchone()
        try:
            if args.command == "reset-password":
                if row is None:
                    sys.exit(f"No user named {args.username!r}. Use list-users, or create-admin to add one.")
                users.update_user(conn, row["id"], password=_password(args), disabled=False)
                print(f"Password of {args.username} changed; all its logins ended.")
            else:
                password = _password(args)
                if row is None:
                    users.create_user(conn, args.username, password, "admin")
                    print(f"Administrator {args.username} created.")
                else:
                    users.update_user(conn, row["id"], role="admin", password=password, disabled=False)
                    print(f"{args.username} is now an enabled administrator with the new password.")
        except users.UserError as exc:
            sys.exit(str(exc))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
