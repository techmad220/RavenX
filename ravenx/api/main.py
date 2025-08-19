
from __future__ import annotations
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import os, json

app = FastAPI(title="RavenX API")

def load_json(path: str):
    if not os.path.exists(path): raise HTTPException(404, "Not found")
    with open(path, "rb") as f:
        return json.load(f)

@app.get("/findings")
def findings():
    return JSONResponse(load_json("out/report.json"))

@app.get("/triaged")
def triaged():
    return JSONResponse(load_json("out/triaged.json"))
