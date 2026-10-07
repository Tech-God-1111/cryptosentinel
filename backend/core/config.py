"""
CRYPTOSENTINEL — Configuration
Secure Military Comms with AI Anomaly Detection
"""

from pathlib import Path

# ============================================================
# PATHS
# ============================================================
BASE_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = BASE_DIR / "backend"
LOGS_DIR = BASE_DIR / "logs"
STATIC_DIR = BACKEND_DIR / "static"

LOGS_DIR.mkdir(exist_ok=True)
MESSAGES_FILE = LOGS_DIR / "messages.json"
THREATS_FILE = LOGS_DIR / "threats.json"

# ============================================================
# SERVER
# ============================================================
PORT = 8005
HOST = "0.0.0.0"

# ============================================================
# CRYPTOGRAPHY (AES-256-GCM)
# ============================================================
AES_KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16

# ============================================================
# MILITARY UNITS (fictional)
# ============================================================
UNITS = [
    {"id": "alpha",   "callsign": "ALPHA-1",   "emoji": "🦅"},
    {"id": "bravo",   "callsign": "BRAVO-2",   "emoji": "🐺"},
    {"id": "charlie", "callsign": "CHARLIE-3", "emoji": "🦁"},
    {"id": "delta",   "callsign": "DELTA-4",   "emoji": "🐍"},
    {"id": "echo",    "callsign": "ECHO-5",    "emoji": "🦈"},
]

# ============================================================
# AI ANOMALY DETECTION
# ============================================================
IF_N_ESTIMATORS = 100
IF_CONTAMINATION = 0.15
IF_RANDOM_STATE = 42
MIN_TRAINING_SAMPLES = 20
RETRAIN_EVERY_N = 25

SCORE_THREAT_HIGH = -0.05
SCORE_THREAT_MID = 0.02

# ============================================================
# THREAT TYPES
# ============================================================
THREAT_TYPES = {
    "tamper":     {"emoji": "🔴", "label": "Tampering Detected"},
    "replay":     {"emoji": "🔴", "label": "Replay Attack"},
    "burst":      {"emoji": "🟡", "label": "Traffic Burst"},
    "recipient":  {"emoji": "🟡", "label": "Unusual Recipient"},
    "size":       {"emoji": "🟡", "label": "Abnormal Message Size"},
    "unknown":    {"emoji": "⚪", "label": "Unclassified Anomaly"},
}

# ============================================================
# DETECTION THRESHOLDS (heuristic pre-checks)
# ============================================================
BURST_WINDOW_SECONDS = 3.0
BURST_COUNT = 8

REPLAY_WINDOW_SECONDS = 60.0

SIZE_DEVIATION_FACTOR = 3.0