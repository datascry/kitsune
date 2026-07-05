# evaders/camoufox/patch_webgl_db — correct camoufox's buggy Apple WebGL caps (MAX_TEXTURE_SIZE 8192 -> 16384).
# A real Apple M1/M2/M3 exposes 16384; the bundled DB's 8192 makes an Apple renderer self-incoherent (caps mismatch).

import json
import os
import sqlite3

import camoufox

db = os.path.join(os.path.dirname(camoufox.__file__), "webgl/webgl_data.db")
conn = sqlite3.connect(db)
rows = conn.execute("select rowid, data from webgl_fingerprints where vendor like '%Apple%'").fetchall()
patched = 0
for rowid, data in rows:
    d = json.loads(data)
    params = d.get("webGl:parameters") or {}
    fixed = {k: (16384 if ("3379" in str(k) and v == 8192) else v) for k, v in params.items()}
    if fixed != params:
        d["webGl:parameters"] = fixed
        conn.execute("update webgl_fingerprints set data=? where rowid=?", (json.dumps(d), rowid))
        patched += 1
conn.commit()
print(f"patched {patched} Apple webgl entries: MAX_TEXTURE_SIZE 8192 -> 16384")
