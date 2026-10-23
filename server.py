#!/usr/bin/env python3
"""Check Printing server, multi-tenant (Python 3.8+, no dependencies).

    python server.py                    # http://127.0.0.1:8080
    python server.py --host 0.0.0.0     # let other PCs on the network connect

Every customer company is a TENANT with its own users, rights, banks, people,
print history, pictures, branding and license. The platform operator manages
tenants at  /admin  (first run prints that password once). The tenant id always
comes from the signed-in session, never from the request, so one company can
never read or change another's data.

Data lives in checks.db and the images/ folder next to this file.
"""
# --- تعديل Turso عشان يشتغل Local وعلى Render ---
try:
    import libsql_experimental as libsql
except ImportError:
    libsql = None
# ------------------------------------------------
import argparse, hashlib, hmac, io, json, os, re, secrets, shutil, sqlite3, tempfile, time, zipfile
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import licensing

ROOT = Path(__file__).parent
DB_PATH = ROOT / "checks.db"
IMAGES = ROOT / "images"                            # images/<tenant id>/<bank id>.jpg
VENDOR_KEY = Path(os.environ.get("CHECKPRINT_VENDOR_KEY") or ROOT / "vendor.key")   # private signing key: operator server only
LICENSE_FILE = ROOT / "license.key"                 # only read once, to migrate an old single-company install
OBJECTS = ("print", "design", "people", "users")    # screens that rights apply to
CODE_RE = re.compile(r"[a-z0-9][a-z0-9_-]{1,29}")   # company code used at sign-in
IMG_ID = re.compile(r"[a-z0-9]{1,20}")
IMG_FILE = re.compile(r"[a-z0-9]{1,20}\.jpg")
MAX_IMAGE = 5 * 1024 * 1024
MAX_BODY = 12 * 1024 * 1024
SESSION_TTL = 8 * 3600
SESSIONS = {}                                       # token -> (kind 'u'|'a', id, tenant id, expires)
FAILS = {}                                          # sign-in failures, for throttling
REASONS = {"invalid": "The license key is not valid.",
           "machine": "This license was issued for a different computer.",
           "tenant": "This license was issued for a different company.",
           "expired": "This license has expired.",
           "trial_over": "The free trial has ended. Enter a license key to continue printing.",
           "clock": "The computer clock was set back. Fix the date and restart."}


def schema(sfx=""):
    return f"""
CREATE TABLE IF NOT EXISTS users{sfx}(
  id INTEGER PRIMARY KEY, tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL COLLATE NOCASE, salt BLOB NOT NULL, hash BLOB NOT NULL, UNIQUE(tenant_id, name));
CREATE TABLE IF NOT EXISTS rights{sfx}(
  user_id INTEGER NOT NULL REFERENCES users{sfx}(id) ON DELETE CASCADE, obj TEXT NOT NULL,
  can_open INT NOT NULL DEFAULT 0, can_edit INT NOT NULL DEFAULT 0, can_delete INT NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id, obj));
CREATE TABLE IF NOT EXISTS kv{sfx}(
  tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, key TEXT NOT NULL, val TEXT NOT NULL,
  PRIMARY KEY(tenant_id, key));
CREATE TABLE IF NOT EXISTS jobs{sfx}(                -- print history (audit trail, never edited)
  id INTEGER PRIMARY KEY, tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  at INT NOT NULL, user TEXT NOT NULL, bank TEXT NOT NULL, payee TEXT NOT NULL,
  check_date TEXT NOT NULL, amount REAL NOT NULL, currency TEXT NOT NULL);
"""


TENANTS = """
CREATE TABLE IF NOT EXISTS tenants(
  id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
  active INT NOT NULL DEFAULT 1, license TEXT NOT NULL DEFAULT '', trial_start TEXT NOT NULL,
  last_seen TEXT NOT NULL DEFAULT '', created INT NOT NULL);
CREATE TABLE IF NOT EXISTS license_log(
  id INTEGER PRIMARY KEY, tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, at INT NOT NULL,
  admin TEXT NOT NULL, customer TEXT NOT NULL, expires TEXT, max_users INT, machine TEXT, applied INT NOT NULL);
CREATE TABLE IF NOT EXISTS admins(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, salt BLOB NOT NULL, hash BLOB NOT NULL);
"""


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


#def db():
#    c = sqlite3.connect(DB_PATH)
#    c.row_factory = sqlite3.Row
#    c.execute("PRAGMA foreign_keys=ON")
#    return c

def db():
    turso_url = os.environ.get("TURSO_DATABASE_URL")
    turso_token = os.environ.get("TURSO_AUTH_TOKEN")
    
    # لو إحنا على Render ومكتبة Turso متسطبة
    if turso_url and turso_token and libsql:
        c = libsql.connect(database=turso_url, auth_token=turso_token)
    else:
        # الاتصال المحلي (للتجربة على جهازك)
        c = sqlite3.connect(DB_PATH)
        
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def hash_pw(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def tdir(tid):
    return IMAGES / str(int(tid))


# ------------------------------------------------------------------ small helpers
def get_rights(c, uid):
    out = {o: [0, 0, 0] for o in OBJECTS}
    for r in c.execute("SELECT * FROM rights WHERE user_id=?", (uid,)):
        if r["obj"] in out:
            out[r["obj"]] = [r["can_open"], r["can_edit"], r["can_delete"]]
    return out


def kv_get(c, tid, key, default):
    r = c.execute("SELECT val FROM kv WHERE tenant_id=? AND key=?", (tid, key)).fetchone()
    return json.loads(r["val"]) if r else default


def kv_set(c, tid, key, val):
    with c:
        c.execute("INSERT OR REPLACE INTO kv VALUES(?,?,?)", (tid, key, json.dumps(val)))


LIMITS = {"ip": 40, "acct": 10, "admin": 10}          # failed sign-ins per 15 minutes. An office shares one IP, so it gets more room.


def throttle(*keys):
    now = time.time()
    for k in keys:
        FAILS[k] = [t for t in FAILS.get(k, []) if now - t < 900]
        if len(FAILS[k]) >= LIMITS[k[0]]:
            raise ApiError(429, "Too many attempts. Try again in a few minutes.")
    if len(FAILS) > 5000:
        for k in [k for k, v in FAILS.items() if not v or now - v[-1] > 900]:
            FAILS.pop(k, None)


def failed(*keys):
    for k in keys:
        FAILS.setdefault(k, []).append(time.time())


def drop_sessions(kind, ident):
    for t in [t for t, s in SESSIONS.items() if s[0] == kind and s[1] == ident]:
        SESSIONS.pop(t, None)


def drop_tenant_sessions(tid):
    for t in [t for t, s in SESSIONS.items() if s[0] == "u" and s[2] == tid]:
        SESSIONS.pop(t, None)


# ------------------------------------------------------------------ licensing (per tenant)
def license_status(c, tid):
    """License state (dev | licensed | trial | locked) of one tenant, plus its user count."""
    t = c.execute("SELECT code, license, trial_start, last_seen FROM tenants WHERE id=?", (tid,)).fetchone()
    today = date.today()
    st = licensing.evaluate(t["license"], date.fromisoformat(t["trial_start"]), today, tenant=t["code"])
    seen = t["last_seen"] or t["trial_start"]
    if st["state"] != "dev" and today < date.fromisoformat(seen) - timedelta(days=1):
        st.update(state="locked", reason="clock")          # clock rolled back to stretch a trial
    elif today.isoformat() > seen:
        with c:
            c.execute("UPDATE tenants SET last_seen=? WHERE id=?", (today.isoformat(), tid))
    st["users"] = c.execute("SELECT COUNT(*) FROM users WHERE tenant_id=?", (tid,)).fetchone()[0]
    return st


def require_license(c, tid):
    if license_status(c, tid)["state"] == "locked":
        raise ApiError(402, "A valid license is required to print. Open Users and rights to activate one.")


def set_license(c, tid, token):
    """Validate a key for this tenant and store it. An empty key clears the license."""
    token = token.strip()
    if token:
        code = c.execute("SELECT code FROM tenants WHERE id=?", (tid,)).fetchone()["code"]
        st = licensing.evaluate(token, date.today(), date.today(), tenant=code)
        if st["state"] == "dev":
            raise ApiError(400, "Licensing is not configured on this server.")
        if st["state"] != "licensed":
            raise ApiError(400, REASONS.get(st["reason"], REASONS["invalid"]))
    with c:
        c.execute("UPDATE tenants SET license=? WHERE id=?", (token, tid))


def vendor_seed():
    """The private signing key, or None if it is missing or does not match the public key in licensing.py."""
    try:
        seed = bytes.fromhex(VENDOR_KEY.read_text().strip())
        return seed if licensing.PUBLIC_KEY and licensing.public_key(seed).hex() == licensing.PUBLIC_KEY else None
    except (OSError, ValueError):
        return None


def licensing_setup(c):
    """Turn licensing on from the console: create vendor.key and put its public half into licensing.py."""
    if licensing.PUBLIC_KEY:
        raise ApiError(400, "Licensing is already on.")
    if VENDOR_KEY.exists():
        raise ApiError(400, "vendor.key already exists. Move it away first, or restore the matching licensing.py.")
    seed = os.urandom(32)
    pub = licensing.public_key(seed).hex()
    path = Path(licensing.__file__)
    try:
        new, n = re.subn(r'^PUBLIC_KEY = ".*?"', f'PUBLIC_KEY = "{pub}"', path.read_text(encoding="utf-8"), count=1, flags=re.M)
        if n != 1:
            raise OSError("PUBLIC_KEY line not found")
        VENDOR_KEY.write_text(seed.hex())
        try:
            VENDOR_KEY.chmod(0o600)
        except OSError:
            pass
        path.write_text(new, encoding="utf-8")
    except OSError as e:
        VENDOR_KEY.unlink(missing_ok=True)
        raise ApiError(500, f"Could not write the key files ({e}). Run  python make_license.py init  instead.")
    licensing.PUBLIC_KEY = pub
    today = date.today().isoformat()
    with c:                                                # companies without a license get a fresh 14-day trial
        c.execute("UPDATE tenants SET trial_start=?, last_seen=? WHERE license=''", (today, today))


def issue_license(c, tid, body, admin):
    """Sign a license for one company; optionally apply it to that company right away."""
    seed = vendor_seed()
    if not seed:
        raise ApiError(400, "License issuing is not available: vendor.key is missing or does not match this server.")
    t = c.execute("SELECT code, name FROM tenants WHERE id=?", (tid,)).fetchone()
    today = date.today()
    expires = str(body.get("expires") or "").strip() or None
    if expires:
        try:
            d = date.fromisoformat(expires)
        except ValueError:
            raise ApiError(400, "Enter a valid expiry date.")
        if d < today:
            raise ApiError(400, "The expiry date is in the past.")
    mu = body.get("max_users")
    if mu in (None, ""):
        mu = None
    else:
        try:
            mu = int(mu)
        except (TypeError, ValueError):
            mu = 0
        if not 1 <= mu <= 100000:
            raise ApiError(400, "The user limit must be a whole number from 1 to 100000.")
    machine = str(body.get("machine") or "").strip().upper() or None
    if machine and not re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}", machine):
        raise ApiError(400, "A computer ID looks like 1A2B-3C4D-5E6F.")
    payload = {"v": 1, "customer": t["name"][:80], "issued": today.isoformat(), "expires": expires,
               "max_users": mu, "machine": machine, "tenant": t["code"]}
    token = licensing.make_token(seed, payload)
    apply = machine is None or machine == licensing.machine_id()      # a key for another computer is only created, not applied here
    if apply:
        set_license(c, tid, token)
    with c:
        c.execute("INSERT INTO license_log(tenant_id,at,admin,customer,expires,max_users,machine,applied) VALUES(?,?,?,?,?,?,?,?)",
                  (tid, int(time.time()), admin, payload["customer"], expires, mu, machine, 1 if apply else 0))
    return {"key": token, "applied": apply, "status": license_status(c, tid)}


def copy_designs(c, src, picks, targets, mode):
    """Copy check designs (layout + picture) from one company to others. Plans everything first, then applies."""
    if mode not in ("both", "replace", "skip"):
        raise ApiError(400, "Invalid option.")
    if not targets:
        raise ApiError(400, "Choose at least one company to copy to.")
    if src in targets:
        raise ApiError(400, "Choose a different company as the target.")
    source = [b for b in kv_get(c, src, "banks", []) if isinstance(b.get("id"), str)]
    chosen = [b for b in source if picks == "all" or b["id"] in picks]
    if not chosen:
        raise ApiError(400, "Select at least one design.")
    plan, failed = [], []
    for tid in targets:
        if not c.execute("SELECT 1 FROM tenants WHERE id=?", (tid,)).fetchone():
            raise ApiError(404, "Company not found.")
        banks = kv_get(c, tid, "banks", [])
        index = {b.get("id"): i for i, b in enumerate(banks)}
        ops, n = [], {"added": 0, "replaced": 0, "skipped": 0}
        for b in chosen:
            nb, old, new = json.loads(json.dumps(b)), b["id"], b["id"]
            if old in index:
                if mode == "skip":
                    n["skipped"] += 1
                    continue
                if mode == "both":
                    while new in index or new == old:
                        new = secrets.token_hex(4)
                    nb["id"], nb["name"] = new, f'{nb.get("name") or old} (copy)'
            had = new in index
            n["replaced" if had else "added"] += 1
            if had:
                banks[index[new]] = nb
            else:
                banks.append(nb)
                index[new] = len(banks) - 1
            ops.append((old, new, nb))
        if len(banks) > 200:                                  # this company cannot take them; the others still can
            failed.append({"tenant": tid, "error": "A company can hold at most 200 designs."})
            continue
        plan.append((tid, banks, ops, n))
    result = []
    for tid, banks, ops, n in plan:
        for old, new, nb in ops:
            pic = tdir(src) / f"{old}.jpg"
            dst = tdir(tid) / f"{new}.jpg"
            if IMG_ID.fullmatch(old) and IMG_ID.fullmatch(new) and pic.is_file():
                tdir(tid).mkdir(parents=True, exist_ok=True)
                shutil.copyfile(pic, dst)                    # its own file: later edits never touch the other company
                nb["img"] = f"/images/{new}.jpg?v={int(time.time())}"
            else:
                if IMG_ID.fullmatch(new):
                    dst.unlink(missing_ok=True)
                if str(nb.get("img", "")).startswith("/images/"):
                    nb["img"] = ""
        kv_set(c, tid, "banks", banks)
        result.append({"tenant": tid, **n})
    return sorted(result + failed, key=lambda r: targets.index(r["tenant"]))


# ------------------------------------------------------------------ users (always inside one tenant)
def ensure_admin_left(c, tid):
    if not c.execute("SELECT 1 FROM rights r JOIN users u ON u.id=r.user_id "
                     "WHERE u.tenant_id=? AND r.obj='users' AND r.can_edit=1", (tid,)).fetchone():
        raise ApiError(400, "At least one user must keep permission to edit users.")


def save_user(c, tid, uid, name, password, rights):
    """Create (uid=0) or update a user of tenant `tid`; raises ApiError on bad input."""
    name = name.strip()
    if not 1 <= len(name) <= 40:
        raise ApiError(400, "User name must be 1 to 40 characters.")
    if (not uid or password) and len(password) < 6:
        raise ApiError(400, "Password must be at least 6 characters.")
    if not uid:
        st = license_status(c, tid)
        if st["max_users"] and st["users"] >= st["max_users"]:
            raise ApiError(400, "Your license user limit has been reached.")
    try:
        with c:
            if uid:
                if not c.execute("SELECT 1 FROM users WHERE id=? AND tenant_id=?", (uid, tid)).fetchone():
                    raise ApiError(404, "User not found.")
                c.execute("UPDATE users SET name=? WHERE id=? AND tenant_id=?", (name, uid, tid))
            else:
                salt = secrets.token_bytes(16)
                uid = c.execute("INSERT INTO users(tenant_id,name,salt,hash) VALUES(?,?,?,?)",
                                (tid, name, salt, hash_pw(password, salt))).lastrowid
                password = ""
            if password:
                salt = secrets.token_bytes(16)
                c.execute("UPDATE users SET salt=?, hash=? WHERE id=?", (salt, hash_pw(password, salt), uid))
            c.execute("DELETE FROM rights WHERE user_id=?", (uid,))
            for obj in OBJECTS:
                o, e, d = [1 if x else 0 for x in (list(rights.get(obj) or []) + [0, 0, 0])[:3]]
                c.execute("INSERT INTO rights VALUES(?,?,?,?,?)", (uid, obj, 1 if (e or d) else o, e, d))
            ensure_admin_left(c, tid)
    except sqlite3.IntegrityError:
        raise ApiError(400, "That user name already exists.")
    drop_sessions("u", uid)
    return uid


def clean_rows(body):
    rows = body.get("rows")
    if not isinstance(rows, list) or not 0 < len(rows) <= 600:
        raise ApiError(400, "1 to 600 checks expected.")
    out = []
    for r in rows:
        try:
            p, d, a = str(r["p"]).strip()[:200], str(r["d"])[:10], round(float(r["a"]), 2)
        except (KeyError, TypeError, ValueError):
            raise ApiError(400, "Invalid check row.")
        if not p or not 0 < a < 1e12 or not re.fullmatch(r"\d{4}-\d\d-\d\d", d):
            raise ApiError(400, "Invalid check row.")
        out.append((p, d, a))
    return out


# ------------------------------------------------------------------ tenants (platform level)
def create_tenant(c, code, name, admin_user, admin_pw):
    code, name, admin_user = code.strip().lower(), name.strip(), (admin_user or "admin").strip()
    if not CODE_RE.fullmatch(code):
        raise ApiError(400, "Company code: 2 to 30 letters, digits, - or _ (start with a letter or digit).")
    if not 1 <= len(name) <= 60:
        raise ApiError(400, "Company name must be 1 to 60 characters.")
    admin_pw = admin_pw or secrets.token_urlsafe(9)
    today = date.today().isoformat()
    try:
        with c:
            tid = c.execute("INSERT INTO tenants(code,name,trial_start,last_seen,created) VALUES(?,?,?,?,?)",
                            (code, name, today, today, int(time.time()))).lastrowid
    except sqlite3.IntegrityError:
        raise ApiError(400, "That company code is already used.")
    try:
        save_user(c, tid, 0, admin_user, admin_pw, {o: [1, 1, 1] for o in OBJECTS})
    except ApiError:
        with c:
            c.execute("DELETE FROM tenants WHERE id=?", (tid,))
        raise
    return tid, admin_user, admin_pw


def tenant_backup(c, tid):
    """One company's data only: data.json (no password hashes) plus its pictures."""
    t = c.execute("SELECT code,name FROM tenants WHERE id=?", (tid,)).fetchone()
    data = {"company": t["name"], "code": t["code"], "exported": time.strftime("%Y-%m-%d %H:%M:%S"),
            "banks": kv_get(c, tid, "banks", []), "people": kv_get(c, tid, "people", []),
            "users": [{"name": r["name"], "rights": get_rights(c, r["id"])}
                      for r in c.execute("SELECT id,name FROM users WHERE tenant_id=? ORDER BY name", (tid,))],
            "jobs": [dict(r) for r in c.execute(
                "SELECT at,user,bank,payee,check_date,amount,currency FROM jobs WHERE tenant_id=? ORDER BY id", (tid,))]}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("data.json", json.dumps(data, ensure_ascii=False, indent=1))
        for f in tdir(tid).glob("*.jpg"):
            z.write(f, f"images/{f.name}")
    return buf.getvalue()


def full_backup():
    """Platform operator: consistent copy of the whole database plus every picture."""
    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "checks.db"
        src, out = db(), sqlite3.connect(dst)
        src.backup(out)
        out.close()
        src.close()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(dst, "checks.db")
            for f in IMAGES.glob("*/*.jpg"):
                z.write(f, f"images/{f.parent.name}/{f.name}")
        return buf.getvalue()


# ------------------------------------------------------------------ database set-up and migration
def migrate_v1(c):
    """Single-company database -> tenant 'default'. Runs once, in one transaction."""
    kv = {r[0]: json.loads(r[1]) for r in c.execute("SELECT key,val FROM kv")}
    today = date.today().isoformat()
    trial = kv.get("trial_start") or today
    lic = LICENSE_FILE.read_text().strip() if LICENSE_FILE.exists() else ""
    c.isolation_level = None
    c.execute("PRAGMA foreign_keys=OFF")
    c.execute("BEGIN")
    try:
        for stmt in (TENANTS + schema("2")).split(";"):
            if stmt.strip():
                c.execute(stmt)
        c.execute("INSERT INTO tenants(id,code,name,license,trial_start,last_seen,created) VALUES(1,'default',?,?,?,?,?)",
                  (kv.get("company") or "Default", lic, trial, kv.get("last_seen") or trial, int(time.time())))
        c.execute("INSERT INTO users2(id,tenant_id,name,salt,hash) SELECT id,1,name,salt,hash FROM users")
        c.execute("INSERT INTO rights2 SELECT * FROM rights")
        c.execute("INSERT INTO kv2(tenant_id,key,val) SELECT 1,key,val FROM kv WHERE key IN ('banks','people')")
        c.execute("INSERT INTO jobs2(id,tenant_id,at,user,bank,payee,check_date,amount,currency) "
                  "SELECT id,1,at,user,bank,payee,check_date,amount,currency FROM jobs")
        for t in ("rights", "users", "kv", "jobs"):
            c.execute(f"DROP TABLE {t}")
        for t in ("users", "rights", "kv", "jobs"):
            c.execute(f"ALTER TABLE {t}2 RENAME TO {t}")
        c.execute("PRAGMA user_version=2")
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    if IMAGES.exists():                                    # pictures move into the tenant's own folder
        (IMAGES / "1").mkdir(exist_ok=True)
        for f in IMAGES.glob("*.jpg"):
            shutil.move(str(f), str(IMAGES / "1" / f.name))
    if LICENSE_FILE.exists():
        LICENSE_FILE.rename(LICENSE_FILE.with_suffix(".key.migrated"))
    print("  Migrated the existing single-company data into company code  default")


def init_db():
#    c = sqlite3.connect(DB_PATH)
    c = db()
    c.row_factory = sqlite3.Row
    old = c.execute("SELECT 1 FROM sqlite_master WHERE name='users'").fetchone()
    if old and c.execute("PRAGMA user_version").fetchone()[0] < 2:
        migrate_v1(c)
        c.close()
        c = db()
    else:
        c.close()
        c = db()
        c.executescript(TENANTS + schema())
        c.execute("PRAGMA user_version=2")
    c.execute("CREATE INDEX IF NOT EXISTS jobs_payee ON jobs(tenant_id, payee)")
    c.commit()
    if not c.execute("SELECT 1 FROM admins").fetchone():
        pw = secrets.token_urlsafe(9)
        salt = secrets.token_bytes(16)
        c.execute("INSERT INTO admins(name,salt,hash) VALUES('platform',?,?)", (salt, hash_pw(pw, salt)))
        c.commit()
        print(f"\n  Platform admin console:  /admin   user  platform   password  {pw}")
    if not c.execute("SELECT 1 FROM tenants").fetchone():
        _, user, pw = create_tenant(c, "default", "My Company", "admin", "")
        print(f"  First company:  code  default   user  {user}   password  {pw}\n  (change passwords after signing in)\n")
    c.close()

    
# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "CheckPrinting"

    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="application/json", headers=(), cache="no-store"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; frame-ancestors 'none'")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ApiError(413, "Request is too large.")
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ApiError(400, "JSON expected.")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError(400, "Invalid JSON.")
        if not isinstance(body, dict):
            raise ApiError(400, "Invalid JSON.")
        return body

    def token(self, kind):
        jar = dict(p.strip().split("=", 1) for p in (self.headers.get("Cookie") or "").split(";") if "=" in p)
        tok = jar.get("sid" if kind == "u" else "asid", "")
        s = SESSIONS.get(tok)
        if not s or s[0] != kind or s[3] < time.time():
            raise ApiError(401, "Please sign in.")
        return tok, s

    def session_user(self, c):
        tok, s = self.token("u")
        row = c.execute("SELECT u.id,u.name,u.tenant_id,t.code,t.name AS company,t.active FROM users u "
                        "JOIN tenants t ON t.id=u.tenant_id WHERE u.id=? AND u.tenant_id=?", (s[1], s[2])).fetchone()
        if not row:
            raise ApiError(401, "Please sign in.")
        if not row["active"]:
            SESSIONS.pop(tok, None)
            raise ApiError(401, "This company account is suspended.")
        return {"id": row["id"], "name": row["name"], "tid": row["tenant_id"], "code": row["code"],
                "company": row["company"], "rights": get_rights(c, row["id"]), "sid": tok}

    def start_session(self, kind, ident, tid):
        now = time.time()
        for t in [t for t, s in SESSIONS.items() if s[3] < now]:
            SESSIONS.pop(t, None)
        tok = secrets.token_urlsafe(32)
        SESSIONS[tok] = (kind, ident, tid, now + SESSION_TTL)
        name = "sid" if kind == "u" else "asid"
        return [("Set-Cookie", f"{name}={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")]

    def serve_image(self, name):
        c = db()
        try:
            u = self.session_user(c)
            R = u["rights"]
            f = tdir(u["tid"]) / name                      # the folder comes from the session, not the URL
            if not (R["print"][0] or R["design"][0]):
                raise ApiError(403, "Not allowed.")
            if not IMG_FILE.fullmatch(name) or not f.is_file():
                raise ApiError(404, "Not found.")
            self.reply(200, f.read_bytes(), "image/jpeg", cache="private, max-age=86400")
        except ApiError as e:
            self.reply(e.code, {"error": e.msg})
        finally:
            c.close()

    # ---------------- login (tenant users)
    def login(self, c, body):
        code = str(body.get("tenant", "")).strip().lower()
        name, pw = str(body.get("name", "")).strip(), str(body.get("password", ""))
        ip = self.client_address[0]
        keys = (("ip", ip), ("acct", code, name.lower()))
        throttle(*keys)
        if code:
            t = c.execute("SELECT * FROM tenants WHERE code=?", (code,)).fetchone()
        else:
            rows = c.execute("SELECT * FROM tenants").fetchall()
            if len(rows) != 1:
                raise ApiError(400, "Enter your company code.")
            t = rows[0]
        row = c.execute("SELECT * FROM users WHERE tenant_id=? AND name=?", (t["id"], name)).fetchone() if t else None
        good = hash_pw(pw, row["salt"] if row else b"\0" * 16)
        if not row or not hmac.compare_digest(good, row["hash"]):
            failed(*keys)
            time.sleep(0.6)                                # slows down password guessing
            raise ApiError(401, "Wrong company code, user name or password." if code else "Wrong user name or password.")
        if not t["active"]:
            raise ApiError(403, "This company account is suspended.")
        FAILS.pop(keys[1], None)
        return self.reply(200, {"ok": 1}, headers=self.start_session("u", row["id"], t["id"]))

    # ---------------- platform admin
    def admin_api(self, c, method, route, body):
        ip = self.client_address[0]
        if route == ["login"] and method == "POST":
            name, pw = str(body.get("name", "")).strip(), str(body.get("password", ""))
            keys = (("ip", ip), ("admin", name.lower()))
            throttle(*keys)
            row = c.execute("SELECT * FROM admins WHERE name=?", (name,)).fetchone()
            good = hash_pw(pw, row["salt"] if row else b"\0" * 16)
            if not row or not hmac.compare_digest(good, row["hash"]):
                failed(*keys)
                time.sleep(0.6)
                raise ApiError(401, "Wrong user name or password.")
            return self.reply(200, {"ok": 1}, headers=self.start_session("a", row["id"], 0))
        tok, s = self.token("a")
        me = c.execute("SELECT id,name FROM admins WHERE id=?", (s[1],)).fetchone()
        if not me:
            raise ApiError(401, "Please sign in.")
        if route == ["logout"]:
            SESSIONS.pop(tok, None)
            return self.reply(200, {"ok": 1})
        if route == ["me"]:
            return self.reply(200, {"name": me["name"]})
        if route == ["backup"] and method == "GET":
            fn = f'attachment; filename="checkprint-full-backup-{time.strftime("%Y%m%d")}.zip"'
            return self.reply(200, full_backup(), "application/zip", headers=[("Content-Disposition", fn)])
        if route == ["password"] and method == "POST":
            row = c.execute("SELECT * FROM admins WHERE id=?", (me["id"],)).fetchone()
            if not hmac.compare_digest(hash_pw(str(body.get("old", "")), row["salt"]), row["hash"]):
                raise ApiError(400, "The current password is wrong.")
            new = str(body.get("new", ""))
            if len(new) < 8:
                raise ApiError(400, "Password must be at least 8 characters.")
            salt = secrets.token_bytes(16)
            with c:
                c.execute("UPDATE admins SET salt=?, hash=? WHERE id=?", (salt, hash_pw(new, salt), me["id"]))
            return self.reply(200, {"ok": 1})
        if route == ["license-info"] and method == "GET":
            return self.reply(200, {"enabled": bool(licensing.PUBLIC_KEY), "can_issue": vendor_seed() is not None,
                                    "server_id": licensing.machine_id()})
        if route == ["copy-designs"] and method == "POST":
            try:
                src = int(body.get("source"))
                targets = [int(x) for x in (body.get("targets") or [])]
            except (TypeError, ValueError):
                raise ApiError(400, "Invalid request.")
            if not c.execute("SELECT 1 FROM tenants WHERE id=?", (src,)).fetchone():
                raise ApiError(404, "Company not found.")
            picks = "all" if body.get("banks") == "all" else [str(x) for x in (body.get("banks") or [])]
            return self.reply(200, {"results": copy_designs(c, src, picks, targets, str(body.get("mode", "both")))})
        if route == ["licensing", "setup"] and method == "POST":
            licensing_setup(c)
            return self.reply(200, {"ok": 1})
        if route == ["tenants"] and method == "GET":
            out = []
            for t in c.execute("SELECT * FROM tenants ORDER BY name COLLATE NOCASE").fetchall():
                st = license_status(c, t["id"])
                out.append({"id": t["id"], "code": t["code"], "name": t["name"], "active": t["active"],
                            "created": t["created"], "users": st["users"],
                            "checks": c.execute("SELECT COUNT(*) FROM jobs WHERE tenant_id=?", (t["id"],)).fetchone()[0],
                            "last_print": c.execute("SELECT MAX(at) FROM jobs WHERE tenant_id=?", (t["id"],)).fetchone()[0],
                            "license": {k: st[k] for k in ("state", "reason", "customer", "expires", "max_users", "days_left")}})
            return self.reply(200, {"tenants": out})
        if route == ["tenants"] and method == "POST":
            tid, user, pw = create_tenant(c, str(body.get("code", "")), str(body.get("name", "")),
                                          str(body.get("admin_user", "")), str(body.get("admin_password", "")))
            return self.reply(200, {"id": tid, "admin_user": user, "admin_password": pw})
        if len(route) >= 2 and route[0] == "tenants" and route[1].isdigit():
            tid = int(route[1])
            t = c.execute("SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()
            if not t:
                raise ApiError(404, "Company not found.")
            if len(route) == 3 and route[2] == "banks" and method == "GET":
                return self.reply(200, {"banks": [
                    {"id": b["id"], "name": b.get("name") or b["id"], "w": b.get("w"), "h": b.get("h"),
                     "picture": (tdir(tid) / f"{b['id']}.jpg").is_file() if IMG_ID.fullmatch(b["id"]) else False}
                    for b in kv_get(c, tid, "banks", []) if isinstance(b.get("id"), str)]})
            if len(route) == 2 and method == "GET":
                log = [dict(r) for r in c.execute("SELECT at,admin,expires,max_users,machine,applied FROM license_log "
                                                  "WHERE tenant_id=? ORDER BY id DESC LIMIT 8", (tid,))]
                return self.reply(200, {"license": license_status(c, tid), "log": log})
            if len(route) == 4 and route[2:] == ["license", "issue"] and method == "POST":
                return self.reply(200, issue_license(c, tid, body, me["name"]))
            if len(route) == 2 and method == "PUT":
                if "name" in body:
                    name = str(body["name"]).strip()
                    if not 1 <= len(name) <= 60:
                        raise ApiError(400, "Company name must be 1 to 60 characters.")
                    with c:
                        c.execute("UPDATE tenants SET name=? WHERE id=?", (name, tid))
                if "active" in body:
                    with c:
                        c.execute("UPDATE tenants SET active=? WHERE id=?", (1 if body["active"] else 0, tid))
                    if not body["active"]:
                        drop_tenant_sessions(tid)
                if "license" in body:
                    set_license(c, tid, str(body["license"]))
                return self.reply(200, {"ok": 1})
            if len(route) == 3 and route[2] == "password" and method == "POST":
                user = str(body.get("user", "")).strip()
                row = c.execute("SELECT id FROM users WHERE tenant_id=? AND name=?", (tid, user)).fetchone() if user else \
                    c.execute("SELECT u.id FROM users u JOIN rights r ON r.user_id=u.id WHERE u.tenant_id=? AND r.obj='users' "
                              "AND r.can_edit=1 ORDER BY u.id LIMIT 1", (tid,)).fetchone()
                if not row:
                    raise ApiError(404, "User not found.")
                pw = str(body.get("password") or "") or secrets.token_urlsafe(9)
                if len(pw) < 6:
                    raise ApiError(400, "Password must be at least 6 characters.")
                salt = secrets.token_bytes(16)
                with c:
                    c.execute("UPDATE users SET salt=?, hash=? WHERE id=?", (salt, hash_pw(pw, salt), row["id"]))
                drop_sessions("u", row["id"])
                name = c.execute("SELECT name FROM users WHERE id=?", (row["id"],)).fetchone()["name"]
                return self.reply(200, {"user": name, "password": pw})
            if len(route) == 2 and method == "DELETE":
                if str(body.get("confirm", "")).strip().lower() != t["code"]:
                    raise ApiError(400, "Type the company code to confirm.")
                drop_tenant_sessions(tid)
                with c:
                    c.execute("DELETE FROM tenants WHERE id=?", (tid,))            # users, rights, data, history cascade
                shutil.rmtree(tdir(tid), ignore_errors=True)
                return self.reply(200, {"ok": 1})
        raise ApiError(404, "Not found.")

    # ---------------- routing
    def dispatch(self, method):
        path = self.path.split("?")[0]
        qs = parse_qs(urlparse(self.path).query)
        if method == "GET" and path.startswith("/images/"):
            return self.serve_image(path[8:])
        if method == "GET" and path in ("/", "/index.html"):
            return self.reply(200, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8")
        if method == "GET" and path in ("/admin", "/admin/"):
            return self.reply(200, (ROOT / "admin.html").read_bytes(), "text/html; charset=utf-8")
        if not path.startswith("/api/"):
            return self.reply(404, {"error": "Not found."})
        route = path[5:].strip("/").split("/")
        c = db()
        try:
            body = self.read_json() if method != "GET" and route[0] != "image" else {}
            if route[0] == "admin":
                return self.admin_api(c, method, route[1:], body)
            if route == ["company"] and method == "GET":      # public: brands the sign-in page, reveals nothing else
                total = c.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
                code = (qs.get("tenant", [""])[0]).strip().lower()
                t = c.execute("SELECT name FROM tenants WHERE code=? AND active=1", (code,)).fetchone() if code else \
                    (c.execute("SELECT name FROM tenants WHERE active=1").fetchone() if total == 1 else None)
                return self.reply(200, {"multi": total != 1, "name": t["name"] if t else ""})
            if route == ["login"] and method == "POST":
                return self.login(c, body)

            u = self.session_user(c)
            R, tid = u["rights"], u["tid"]                      # tid: from the session only
            if route == ["logout"]:
                SESSIONS.pop(u["sid"], None)
                return self.reply(200, {"ok": 1})
            if route == ["me"]:
                return self.reply(200, {"id": u["id"], "name": u["name"], "company": u["company"], "code": u["code"], "rights": R})

            if route == ["company"] and method == "PUT":
                if not R["users"][1]:
                    raise ApiError(403, "You may not edit users.")
                name = str(body.get("name", "")).strip()[:60]
                if not name:
                    raise ApiError(400, "Company name must be 1 to 60 characters.")
                with c:
                    c.execute("UPDATE tenants SET name=? WHERE id=?", (name, tid))
                return self.reply(200, {"name": name})
            if route == ["backup"] and method == "GET":
                if not R["users"][1]:
                    raise ApiError(403, "You may not download backups.")
                fn = f'attachment; filename="checkprint-{u["code"]}-{time.strftime("%Y%m%d")}.zip"'
                return self.reply(200, tenant_backup(c, tid), "application/zip", headers=[("Content-Disposition", fn)])
            if route == ["license"]:
                if method == "GET":
                    return self.reply(200, license_status(c, tid))
                if method == "POST":
                    if not R["users"][1]:
                        raise ApiError(403, "You may not edit users.")
                    tok = str(body.get("key", "")).strip()
                    if not tok:
                        raise ApiError(400, REASONS["invalid"])
                    set_license(c, tid, tok)
                    return self.reply(200, license_status(c, tid))
            if route[0] == "jobs":                            # print history: needs the Print screen
                if not R["print"][0]:
                    raise ApiError(403, "You may not open print history.")
                if method == "POST":
                    require_license(c, tid)                   # printing is what the license pays for
                if route == ["jobs"] and method == "GET":
                    q = (qs.get("q", [""])[0]).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    lim = min(max(int(qs.get("limit", ["100"])[0]), 1), 5000)
                    off = max(int(qs.get("offset", ["0"])[0]), 0)
                    where = "WHERE tenant_id=? AND payee LIKE ? ESCAPE '\\'"
                    total = c.execute(f"SELECT COUNT(*) FROM jobs {where}", (tid, f"%{q}%")).fetchone()[0]
                    rows = c.execute(f"SELECT id,at,user,bank,payee,check_date,amount,currency FROM jobs {where} "
                                     "ORDER BY id DESC LIMIT ? OFFSET ?", (tid, f"%{q}%", lim, off))
                    return self.reply(200, {"total": total, "jobs": [dict(r) for r in rows]})
                if route == ["jobs"] and method == "POST":
                    rows = clean_rows(body)
                    bank, cur = str(body.get("bank", ""))[:80], str(body.get("cur", ""))[:3]
                    with c:
                        c.executemany("INSERT INTO jobs(tenant_id,at,user,bank,payee,check_date,amount,currency) VALUES(?,?,?,?,?,?,?,?)",
                                      [(tid, int(time.time()), u["name"], bank, p, d, a, cur) for p, d, a in rows])
                    return self.reply(200, {"ok": 1, "count": len(rows)})
                if route == ["jobs", "dupes"] and method == "POST":
                    rows = clean_rows(body)
                    return self.reply(200, {"dupes": [i for i, (p, d, a) in enumerate(rows) if c.execute(
                        "SELECT 1 FROM jobs WHERE tenant_id=? AND payee=? AND check_date=? AND amount=? LIMIT 1",
                        (tid, p, d, a)).fetchone()]})
            if route[0] == "image" and len(route) == 2 and IMG_ID.fullmatch(route[1]):
                if not R["design"][1]:
                    raise ApiError(403, "You may not edit check layouts.")
                f = tdir(tid) / f"{route[1]}.jpg"
                if method == "POST":                      # body = the JPEG itself
                    n = int(self.headers.get("Content-Length") or 0)
                    if not 0 < n <= MAX_IMAGE:
                        raise ApiError(413, "Image must be under 5 MB.")
                    raw = self.rfile.read(n)
                    if raw[:2] != b"\xff\xd8":
                        raise ApiError(400, "A JPEG image is expected.")
                    tdir(tid).mkdir(parents=True, exist_ok=True)
                    f.write_bytes(raw)
                    return self.reply(200, {"url": f"/images/{route[1]}.jpg?v={int(time.time())}"})
                if method == "DELETE":
                    f.unlink(missing_ok=True)
                    return self.reply(200, {"ok": 1})

            if route == ["data"]:
                if method == "GET":
                    out = {}
                    if R["print"][0] or R["design"][0]:
                        out["banks"] = kv_get(c, tid, "banks", [])
                    if R["print"][0] or R["people"][0]:
                        out["people"] = kv_get(c, tid, "people", [])
                    return self.reply(200, out)
                if method == "PUT":
                    with c:
                        if "banks" in body:
                            b = body["banks"]
                            if not R["design"][1]:
                                raise ApiError(403, "You may not edit check layouts.")
                            if not (isinstance(b, list) and len(b) <= 200 and all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in b)):
                                raise ApiError(400, "Invalid banks.")
                            gone = {x.get("id") for x in kv_get(c, tid, "banks", [])} - {x["id"] for x in b}
                            c.execute("INSERT OR REPLACE INTO kv VALUES(?,'banks',?)", (tid, json.dumps(b)))
                            for i in gone:                # a deleted bank takes its picture with it
                                if isinstance(i, str) and IMG_ID.fullmatch(i):
                                    (tdir(tid) / f"{i}.jpg").unlink(missing_ok=True)
                        if "people" in body:
                            p = body["people"]
                            if not R["people"][1]:
                                raise ApiError(403, "You may not edit people.")
                            if not (isinstance(p, list) and len(p) <= 20000 and all(isinstance(x, str) and len(x) < 200 for x in p)):
                                raise ApiError(400, "Invalid people.")
                            c.execute("INSERT OR REPLACE INTO kv VALUES(?,'people',?)", (tid, json.dumps(p)))
                    return self.reply(200, {"ok": 1})

            if route[0] == "users":
                if not R["users"][0]:
                    raise ApiError(403, "You may not open users.")
                if route == ["users"] and method == "GET":
                    return self.reply(200, {"users": [
                        {"id": r["id"], "name": r["name"], "rights": get_rights(c, r["id"])}
                        for r in c.execute("SELECT id,name FROM users WHERE tenant_id=? ORDER BY name", (tid,))]})
                if route == ["users"] and method == "POST":
                    if not R["users"][1]:
                        raise ApiError(403, "You may not edit users.")
                    rights = body.get("rights") if isinstance(body.get("rights"), dict) else {}
                    uid = save_user(c, tid, int(body.get("id") or 0), str(body.get("name", "")),
                                    str(body.get("password") or ""), rights)
                    return self.reply(200, {"id": uid})
                if len(route) == 2 and method == "DELETE":
                    if not R["users"][2]:
                        raise ApiError(403, "You may not delete users.")
                    uid = int(route[1])
                    if uid == u["id"]:
                        raise ApiError(400, "You cannot delete your own account.")
                    with c:
                        n = c.execute("DELETE FROM users WHERE id=? AND tenant_id=?", (uid, tid)).rowcount
                        if not n:
                            raise ApiError(404, "User not found.")
                        ensure_admin_left(c, tid)
                    drop_sessions("u", uid)
                    return self.reply(200, {"ok": 1})
            raise ApiError(404, "Not found.")
        except ApiError as e:
            self.reply(e.code, {"error": e.msg})
        except ValueError:
            self.reply(400, {"error": "Invalid request."})
        finally:
            c.close()

    do_GET = lambda self: self.dispatch("GET")
    do_POST = lambda self: self.dispatch("POST")
    do_PUT = lambda self: self.dispatch("PUT")
    do_DELETE = lambda self: self.dispatch("DELETE")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
   # ap.add_argument("--host", default="127.0.0.1")
    # خلي الـ Default بتاع الـ Host يبقى 0.0.0.0 عشان يشتغل على السيرفرات
    ap.add_argument("--host", default="0.0.0.0") 
    #ap.add_argument("--port", type=int, default=8080)
    # خلي الـ Default بتاع البورت يقرأ من متغير البيئة PORT بتاع Render، ولو مش موجود يستخدم 8080
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)))

    a = ap.parse_args()
    init_db()
    if licensing.PUBLIC_KEY and vendor_seed() is None:
        print("  Note: licensing is on but vendor.key is missing here, so the console cannot issue licenses.")
    print(f"Check Printing running at http://{a.host}:{a.port}  (Ctrl+C to stop)")
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()
