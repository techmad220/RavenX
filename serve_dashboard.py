#!/usr/bin/env python3
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

app = FastAPI(title="RavenX Dashboard")

@app.get("/")
async def dashboard():
    # Serve cyberpunk RavenX
    try:
        with open("templates/cyberpunk_ravenx.html", "r") as f:
            return HTMLResponse(content=f.read())
    except:
        try:
            with open("templates/ravenx_real.html", "r") as f:
                return HTMLResponse(content=f.read())
        except:
            with open("templates/dashboard.html", "r") as f:
                return HTMLResponse(content=f.read())

@app.get("/pending")
async def get_pending():
    # Sample data for demo
    return [
        {
            "id": 1,
            "title": "SQL Injection in User Input",
            "severity": "critical",
            "description": "Unvalidated user input is directly concatenated into SQL queries",
            "target": "https://example.com/api/users",
            "confidence": 0.95
        }
    ]

@app.get("/approved")
async def get_approved():
    return []

@app.get("/rejected") 
async def get_rejected():
    return []

if __name__ == "__main__":
    print("🦅 RavenX Dashboard starting on http://localhost:8091")
    uvicorn.run(app, host="0.0.0.0", port=8091)