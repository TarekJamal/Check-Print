#!/usr/bin/env python3
"""VENDOR TOOL. Do not ship this file or vendor.key to customers.

  python make_license.py init
      One time. Creates vendor.key (your private key) and writes the matching
      public key into licensing.py. Ship licensing.py to customers AFTER this.
      Back up vendor.key: without it you cannot issue keys for copies already sold.

  python make_license.py issue --customer "Nile Traders" --expires 2027-12-31 --users 5
  python make_license.py issue --customer "Nile Traders" --machine 1A2B-3C4D-5E6F
      Writes license.key. Leave out --expires for a perpetual license, --users
      for unlimited users, --machine to allow any computer. The customer's
      computer ID is shown in Users and rights > License.

  python make_license.py issue --customer "Nile Traders" --tenant nile --users 5
      On a multi-company server, --tenant locks the key to that company code so it
      cannot be reused by another company.

  python make_license.py show license.key
"""
import argparse, os, re, sys
from datetime import date
from pathlib import Path

import licensing

HERE = Path(__file__).parent
KEY_FILE = HERE / "vendor.key"


def init():
    if KEY_FILE.exists():
        sys.exit("vendor.key already exists. Refusing to replace it (that would invalidate every license you issued).")
    seed = os.urandom(32)
    KEY_FILE.write_text(seed.hex())
    try:
        KEY_FILE.chmod(0o600)
    except OSError:
        pass
    src = (HERE / "licensing.py").read_text(encoding="utf-8")
    src, n = re.subn(r'^PUBLIC_KEY = ".*?"', f'PUBLIC_KEY = "{licensing.public_key(seed).hex()}"', src, count=1, flags=re.M)
    if n != 1:
        sys.exit("Could not find the PUBLIC_KEY line in licensing.py")
    (HERE / "licensing.py").write_text(src, encoding="utf-8")
    print("Created vendor.key and set the public key in licensing.py.\nKEEP vendor.key SECRET AND BACKED UP.")


def issue(a):
    if not KEY_FILE.exists():
        sys.exit("Run `python make_license.py init` first.")
    if a.expires:
        date.fromisoformat(a.expires)                      # validates YYYY-MM-DD
    payload = {"v": 1, "customer": a.customer, "issued": date.today().isoformat(),
               "expires": a.expires, "max_users": a.users, "machine": a.machine, "tenant": a.tenant}
    token = licensing.make_token(bytes.fromhex(KEY_FILE.read_text().strip()), payload)
    Path(a.out).write_text(token)
    print(f"Wrote {a.out}  ->  {a.customer}, expires {a.expires or 'never'}, "
          f"users {a.users or 'unlimited'}, computer {a.machine or 'any'}, company {a.tenant or 'any'}")


def show(path):
    print(licensing.parse(Path(path).read_text(), licensing.PUBLIC_KEY))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    i = sub.add_parser("issue")
    i.add_argument("--customer", required=True)
    i.add_argument("--expires", help="YYYY-MM-DD (omit for perpetual)")
    i.add_argument("--users", type=int, help="maximum number of users")
    i.add_argument("--machine", help="computer ID to lock the license to")
    i.add_argument("--tenant", help="company code to lock the license to (multi-company server)")
    i.add_argument("--out", default="license.key")
    s = sub.add_parser("show")
    s.add_argument("file")
    a = ap.parse_args()
    init() if a.cmd == "init" else issue(a) if a.cmd == "issue" else show(a.file)
