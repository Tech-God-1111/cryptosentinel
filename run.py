"""
CRYPTOSENTINEL — Launcher
"""

import sys
import uvicorn
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

from core.config import PORT, HOST

if __name__ == "__main__":
    print("=" * 60)
    print("  🎖️  CRYPTOSENTINEL — Secure Military Comms")
    print("  🔐 AES-256-GCM + 🤖 AI Anomaly Detection")
    print("=" * 60)
    print(f"  🌐 Open: http://localhost:{PORT}")
    print(f"  📡 Comms: http://localhost:{PORT}/comms")
    print(f"  🚨 Threats: http://localhost:{PORT}/threats")
    print("=" * 60)

    uvicorn.run(
        "app:app",
        host=HOST,
        port=PORT,
        reload=False,
        app_dir=str(ROOT / "backend"),
    )