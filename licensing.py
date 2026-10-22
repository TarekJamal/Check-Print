"""Per-customer licensing: signed license keys, verified offline.

A license key is  CP1.<payload>.<signature>.  The payload (customer, expiry, user
limit, optional computer ID) is signed with the vendor's private key
(vendor.key, kept only by you). This file contains the matching public key, so
a customer can verify a key but never create one.

Ed25519 below is the reference algorithm from RFC 8032 in plain Python, so
nothing needs to be installed. Python source can always be edited by a
determined customer; for sale, ship the program compiled (PyInstaller / Nuitka).
"""
import base64, hashlib, json, platform, subprocess, uuid
from datetime import date
from pathlib import Path

PUBLIC_KEY = "a857490275deda620b1ab49ce88a0961793ae5689c4f44ecd3f9c123c9208edd"      # hex. Filled in by `python make_license.py init`. Empty = licensing off.
TRIAL_DAYS = 14


class LicenseError(Exception):
    pass


# ---------------------------------------------------------------- Ed25519 (RFC 8032)
_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _inv(x):
    return pow(x, _p - 2, _p)


def _add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % _p, (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C, D = 2 * P[3] * Q[3] * _d % _p, 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p:
        x = x * _I % _p
    if (x * x - x2) % _p:
        return None
    return x if (x & 1) == sign else _p - x


_gy = 4 * _inv(5) % _p
_gx = _x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % _p)


def _pack(P):
    z = _inv(P[2])
    x, y = P[0] * z % _p, P[1] * z % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _unpack(s):
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _x(y, sign)
    return None if x is None else (x, y, 1, x * y % _p)


def _h(s):
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % _q


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    return (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254), h[32:]


def public_key(seed):
    return _pack(_mul(_expand(seed)[0], _G))


def sign(seed, msg):
    a, prefix = _expand(seed)
    A = _pack(_mul(a, _G))
    r = _h(prefix + msg)
    Rs = _pack(_mul(r, _G))
    return Rs + int.to_bytes((r + _h(Rs + A + msg) * a) % _q, 32, "little")


def verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A, R = _unpack(public), _unpack(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if A is None or R is None or s >= _q:
        return False
    lhs, rhs = _mul(s, _G), _add(R, _mul(_h(sig[:32] + public + msg), A))
    return (lhs[0] * rhs[2] - rhs[0] * lhs[2]) % _p == 0 and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % _p == 0


# ---------------------------------------------------------------- license keys
def _b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _os_machine_guid():
    """The operating system's own install ID: stable across reboots, network changes and renames."""
    try:
        if platform.system() == "Windows":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                                winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as k:
                return winreg.QueryValueEx(k, "MachineGuid")[0]
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if Path(p).is_file() and Path(p).read_text().strip():
                return Path(p).read_text().strip()
        if platform.system() == "Darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
    except Exception:
        pass
    return None


def machine_id():
    """Short ID of this computer; the customer sends it to you for a locked license.
    Never random: if the OS gives no ID, a one-time ID is saved next to this file (machine.id)."""
    raw = _os_machine_guid()
    if not raw:
        f = Path(__file__).with_name("machine.id")
        if not f.is_file():
            f.write_text(uuid.uuid4().hex)
        raw = f.read_text().strip()
    h = hashlib.sha256(("checkprint|" + raw).encode()).hexdigest().upper()
    return "-".join(h[i:i + 4] for i in (0, 4, 8))


def make_token(seed, payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return f"CP1.{_b64e(body)}.{_b64e(sign(seed, body))}"


def parse(token, public_hex=None):
    try:
        tag, body, sig = token.strip().split(".")
        body, sig = _b64d(body), _b64d(sig)
        ok = tag == "CP1" and verify(bytes.fromhex(public_hex or PUBLIC_KEY), body, sig)
        data = json.loads(body)
    except Exception:
        raise LicenseError("invalid")
    if not ok or not isinstance(data, dict):
        raise LicenseError("invalid")
    return data


def evaluate(token, trial_start, today, public_hex=None, tenant=""):
    """Status dict. state: dev (no key configured) | licensed | trial | locked."""
    pub = public_hex or PUBLIC_KEY
    st = {"state": "locked", "reason": "", "customer": "", "expires": None, "max_users": None,
          "days_left": None, "machine": machine_id()}
    if not pub:
        return {**st, "state": "dev"}
    if token:
        try:
            lic = parse(token, pub)
            st.update(customer=str(lic.get("customer", "")), expires=lic.get("expires"), max_users=lic.get("max_users"))
            if lic.get("tenant") and tenant and str(lic["tenant"]).lower() != str(tenant).lower():
                return {**st, "reason": "tenant"}                  # key was issued for another company
            norm = lambda m: str(m or "").replace("-", "").upper()
            if lic.get("machine") and norm(lic["machine"]) != norm(machine_id()):
                return {**st, "reason": "machine"}
            if st["expires"]:
                left = (date.fromisoformat(st["expires"]) - today).days
                if left < 0:
                    return {**st, "reason": "expired"}
                st["days_left"] = left
            return {**st, "state": "licensed"}
        except (LicenseError, ValueError, TypeError):
            return {**st, "reason": "invalid"}
    left = TRIAL_DAYS - (today - trial_start).days
    if left > 0:
        return {**st, "state": "trial", "days_left": left}
    return {**st, "reason": "trial_over"}
