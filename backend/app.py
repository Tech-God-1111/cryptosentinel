"""
CRYPTOSENTINEL — FastAPI Server
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from core.config import STATIC_DIR, PORT
from routes.messages import router as messages_router
from routes.threats import router as threats_router

app = FastAPI(title="CRYPTOSENTINEL", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(messages_router)
app.include_router(threats_router)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))

@app.get("/comms")
def comms():
    return FileResponse(str(STATIC_DIR / "comms.html"))

@app.get("/threats")
def threats_page():
    return FileResponse(str(STATIC_DIR / "threats.html"))

@app.get("/health")
def health():
    return {"status": "ok", "port": PORT}