
from __future__ import annotations
import sqlite3, json, time, os
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

DB_PATH = os.getenv("RAVENX_REVIEW_DB", "out/review.db")
app = FastAPI(title="RavenX Review Queue")

def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY AUTOINCREMENT, created_ms INTEGER, fingerprint TEXT, payload TEXT, approved INTEGER DEFAULT 0, rejected INTEGER DEFAULT 0)")
    return c

def enqueue(items: list[dict]):
    c = _conn()
    for it in items:
        fp = it.get("finding",{}).get("fingerprint") or it.get("fingerprint")
        c.execute("INSERT INTO queue (created_ms, fingerprint, payload) VALUES (?,?,?)", (int(time.time()*1000), fp, json.dumps(it)))
    c.commit()
    c.close()

class Decision(BaseModel):
    approve: bool = True

@app.get("/", response_class=HTMLResponse)
def home():
    return "<h1>RavenX Review</h1><p>GET /pending, /approved, /rejected</p>"

@app.get("/pending")
def pending(limit: int = 100):
    c = _conn()
    rows = c.execute("SELECT id, created_ms, fingerprint, payload FROM queue WHERE approved=0 AND rejected=0 ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
    c.close()
    return JSONResponse([{"id": r[0], "created_ms": r[1], "fingerprint": r[2], "payload": json.loads(r[3])} for r in rows])

@app.post("/decide/{item_id}")
def decide(item_id: int, d: Decision):
    c = _conn()
    if d.approve:
        c.execute("UPDATE queue SET approved=1 WHERE id=?", (item_id,))
    else:
        c.execute("UPDATE queue SET rejected=1 WHERE id=?", (item_id,))
    c.commit(); c.close()
    return {"ok": True}

@app.get("/approved")
def approved(limit: int = 100):
    c = _conn()
    rows = c.execute("SELECT id, created_ms, fingerprint, payload FROM queue WHERE approved=1 AND rejected=0 ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
    c.close()
    return JSONResponse([{"id": r[0], "created_ms": r[1], "fingerprint": r[2], "payload": json.loads(r[3])} for r in rows])
