#!/usr/bin/env python3
"""Import the old Access database (Checks.mdb) into checks.db.

    python import_mdb.py Checks.mdb
    python import_mdb.py Checks.mdb --images "D:\\OldApp\\Images"
    python import_mdb.py Checks.mdb --tenant nile        # when the server hosts several companies

Imports into ONE company (--tenant). Imports people, bank check layouts (+ their Images\\<BankCode>.jpg pictures),
users and their rights. Safe to run more than once: people are merged, banks
with the same code are replaced, users that already exist are left alone.

Reading .mdb needs ONE of:
  * Windows: pip install pyodbc   (uses the Microsoft Access ODBC driver; its
             bitness, 32/64-bit, must match your Python)
  * Linux/macOS: install mdbtools (provides the mdb-export command)
Run it while the server is stopped.
"""
import argparse, csv, io, shutil, secrets, struct, subprocess, sys
from pathlib import Path

import server

FIELDS = {"date": "CheckDate", "person": "Person", "words": "LabTafkeet", "amount": "Amount",
          "sd": "TxtCheckDate", "sp": "TxtPerson", "sa": "TxtAmount", "cross": "TxtTasteer", "first": "Mostafeed"}
ALIGN = {"date": "right", "person": "left", "words": "left", "amount": "right",
         "sd": "right", "sp": "left", "sa": "right", "cross": "left", "first": "center"}
DEFAULT_W = {"cross": 1.4, "first": 5.0}


def read_table(mdb, name):
    exe = shutil.which("mdb-export")
    if exe:
        out = subprocess.run([exe, str(mdb), name], capture_output=True, check=True).stdout
        return list(csv.DictReader(io.StringIO(out.decode("utf-8", "replace"))))
    try:
        import pyodbc
    except ImportError:
        sys.exit("Cannot read .mdb files. Install mdbtools (Linux/macOS) or run: pip install pyodbc (Windows).")
    cn = pyodbc.connect(rf"Driver={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={mdb}")
    cur = cn.cursor()
    cur.execute(f"SELECT * FROM [{name}]")
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    cn.close()
    return rows


def num(v, default=0.0):
    try:
        return round(float(str(v).replace(",", ".")), 2)
    except ValueError:
        return default


def yes(v):
    return str(v).strip().lower() in ("1", "-1", "true", "yes")


def object_key(name):
    n = str(name).lower()
    if "print" in n:
        return "print"
    if "dsgn" in n or "design" in n or "bankform" in n:
        return "design"
    if "person" in n:
        return "people"
    if "right" in n or "user" in n:
        return "users"
    return None


def jpeg_cm(data, fallback_w=17.5):
    """Physical size (cm) of a JPEG from its DPI; falls back to 17.5 cm wide."""
    i, dpi, px = 2, None, None
    while i + 4 <= len(data) and data[i] == 0xFF:
        m, ln = data[i + 1], struct.unpack(">H", data[i + 2:i + 4])[0]
        seg = data[i + 4:i + 2 + ln]
        if m == 0xE0 and seg[:5] == b"JFIF\0" and len(seg) >= 12:
            unit, x = seg[7], struct.unpack(">H", seg[8:10])[0]
            dpi = x if unit == 1 else x * 2.54 if unit == 2 else None
        if m in (0xC0, 0xC1, 0xC2):
            h, w = struct.unpack(">HH", seg[1:5])
            px = (w, h)
            break
        i += 2 + ln
    if not px:
        return fallback_w, round(fallback_w * 0.43, 1)
    w = px[0] / dpi * 2.54 if dpi else 0
    if not 10 <= w <= 30:
        w = fallback_w
    return round(w, 1), round(w * px[1] / px[0], 1)


def bank_from_row(r, img_dir, tid):
    code = str(int(float(r["BankCode"])))
    f = {}
    for key, pre in FIELDS.items():
        f[key] = {"x": num(r.get(pre + "Left")), "y": num(r.get(pre + "Top")),
                  "w": num(r.get(pre + "Width"), DEFAULT_W.get(key, 3.0)) or DEFAULT_W.get(key, 3.0), "a": ALIGN[key]}
    bank = {"id": code, "name": str(r.get("BankName") or code).strip(), "w": 17.5, "h": 7.5,
            "t": num(r.get("TopMargin")), "l": num(r.get("LeftMargin")), "img": "", "f": f}
    pic = Path(img_dir) / f"{code}.jpg"
    if pic.is_file():
        data = pic.read_bytes()
        server.tdir(tid).mkdir(parents=True, exist_ok=True)
        (server.tdir(tid) / f"{code}.jpg").write_bytes(data)
        bank["img"] = f"/images/{code}.jpg?v=1"
        bank["w"], bank["h"] = jpeg_cm(data)
    return bank


def run(reader, img_dir, tid):
    server.init_db()
    c = server.db()
    report = []
    # people
    names = {str(r.get("PersonName") or "").strip() for r in reader("TblPersons")} - {""}
    people = sorted(set(server.kv_get(c, tid, "people", [])) | names, key=str.casefold)
    # banks
    banks = {b["id"]: b for b in server.kv_get(c, tid, "banks", [])}
    imported = [bank_from_row(r, img_dir, tid) for r in reader("CheckForms")]
    banks.update({b["id"]: b for b in imported})
    # users and rights
    objs = {str(int(float(r["Object_ID"]))): object_key(r["Object_Name"]) for r in reader("TblObjects")}
    rights = {}
    for r in reader("TblUserRights"):
        key = objs.get(str(int(float(r["Object_ID"]))))
        if key:
            cur = rights.setdefault(str(int(float(r["User_ID"]))), {}).setdefault(key, [0, 0, 0])
            for i, col in enumerate(("Can_Open", "Can_Add_Edit", "Can_Delete")):
                cur[i] = cur[i] or int(yes(r.get(col)))
    added = 0
    with c:
        c.execute("INSERT OR REPLACE INTO kv VALUES(?,'people',?)", (tid, server.json.dumps(people)))
        c.execute("INSERT OR REPLACE INTO kv VALUES(?,'banks',?)", (tid, server.json.dumps(list(banks.values()))))
        for r in reader("TblUsers"):
            name, pw = str(r.get("User_Name") or "").strip(), str(r.get("PassWord") or "")
            if not name or c.execute("SELECT 1 FROM users WHERE tenant_id=? AND name=?", (tid, name)).fetchone():
                continue
            if not pw:
                pw = secrets.token_urlsafe(8)
                report.append(f"user '{name}' had no password; new password: {pw}")
            salt = secrets.token_bytes(16)
            uid = c.execute("INSERT INTO users(tenant_id,name,salt,hash) VALUES(?,?,?,?)",
                            (tid, name, salt, server.hash_pw(pw, salt))).lastrowid
            mine = rights.get(str(int(float(r["User_ID"]))), {})
            for obj in server.OBJECTS:
                o, e, d = mine.get(obj, [0, 0, 0])
                c.execute("INSERT INTO rights VALUES(?,?,?,?,?)", (uid, obj, int(o or e or d), e, d))
            added += 1
    c.close()
    unmapped = sorted({str(r["Object_Name"]) for r in reader("TblObjects") if not object_key(r["Object_Name"])})
    print(f"Imported {len(names)} people, {len(imported)} banks "
          f"({sum(1 for b in imported if b['img'])} with pictures), {added} new users.")
    for line in report + [f"screen '{u}' was not recognised and was skipped" for u in unmapped]:
        print("  note:", line)
    print("Old passwords were stored in plain text; they are now hashed. Ask users to change them.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mdb")
    ap.add_argument("--images", help="folder with <BankCode>.jpg files (default: Images next to the .mdb)")
    ap.add_argument("--tenant", help="company code to import into (needed when the server has several companies)")
    a = ap.parse_args()
    mdb = Path(a.mdb).resolve()
    server.init_db()
    c = server.db()
    rows = c.execute("SELECT id, code FROM tenants").fetchall() if not a.tenant else \
        c.execute("SELECT id, code FROM tenants WHERE code=?", (a.tenant.strip().lower(),)).fetchall()
    c.close()
    if len(rows) != 1:
        sys.exit("Several companies exist. Use --tenant <company code>." if not a.tenant else f"No company with code '{a.tenant}'.")
    run(lambda t: read_table(mdb, t), Path(a.images) if a.images else mdb.parent / "Images", rows[0]["id"])
