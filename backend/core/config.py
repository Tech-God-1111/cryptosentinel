"""
CRYPTOSENTINEL — Configuration
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend/
BACKEND_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BACKEND_DIR / ".env"
load_dotenv(ENV_PATH)

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOGS_DIR = BASE_DIR / "logs"
STATIC_DIR = BACKEND_DIR / "static"

LOGS_DIR.mkdir(exist_ok=True)
MESSAGES_FILE = LOGS_DIR / "messages.json"
THREATS_FILE = LOGS_DIR / "threats.json"

# Server
PORT = int(os.getenv("PORT", 8005))
HOST = os.getenv("HOST", "0.0.0.0")

# NVIDIA + LLM Analyst
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
THREAT_ANALYST_ENABLED = os.getenv("THREAT_ANALYST_ENABLED", "true").lower() == "true"
THREAT_ANALYST_MODEL = os.getenv("THREAT_ANALYST_MODEL", "nvidia/nemotron-3-super-120b-a12b")

# Content inspection (demo mode)
CONTENT_INSPECTION_ENABLED = os.getenv("CONTENT_INSPECTION_ENABLED", "true").lower() == "true"

# Curated threat keywords (stems catch inflections)
HAZARD_KEYWORDS = [
    # Direct violence
    "kill", "murder", "eliminat", "assassinat", "execut",
    "slay", "end you", "finish you", "take you out",
    "destroy you", "wipe out", "eradicate",
    # Weapons / explosives
    "attack", "assault", "ambush", "raid", "strike",
    "bomb", "explod", "detonat", "blow up", "blowup",
    "shoot", "sniper", "grenade", "missile", "artillery",
    "rifle", "pistol", "ak-47", "ied",
    # Capture / coercion
    "hostage", "kidnap", "abduct", "hijack",
    "extort", "blackmail", "threaten", "ultimatum", "ransom",
    # Cyber
    "hack", "exploit", "breach", "compromise",
    "infiltrat", "exfiltrat", "malware", "ransomware",
    "backdoor", "ddos",
    # Faction / enemy markers
    "red clan", "hostile", "insurgent", "terrorist",
    "militant", "jihadi", "extremist",
    # Sabotage / betrayal
    "sabotage", "betray", "traitor", "defect", "spy",
    "double agent",
    # Abuse (curated, appears in real insults)
    "idiot", "moron", "bastard", "worthless",
    "shut up", "get lost", "piss off",
    # Covert operations
    "cover-up", "conspiracy", "coup", "overthrow",
    "mutiny", "assassination",
]

# Content safety (toxic-bert)
CONTENT_SAFETY_MODEL = os.getenv("CONTENT_SAFETY_MODEL", "unitary/toxic-bert")
CONTENT_SAFETY_THRESHOLD = float(os.getenv("CONTENT_SAFETY_THRESHOLD", "0.7"))

# Crypto
AES_KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16

# Units
UNITS = [
    {"id": "alpha",   "callsign": "ALPHA-1",   "emoji": "🦅"},
    {"id": "bravo",   "callsign": "BRAVO-2",   "emoji": "🐺"},
    {"id": "charlie", "callsign": "CHARLIE-3", "emoji": "🦁"},
    {"id": "delta",   "callsign": "DELTA-4",   "emoji": "🐍"},
    {"id": "echo",    "callsign": "ECHO-5",    "emoji": "🦈"},
]

# Isolation Forest
IF_N_ESTIMATORS = 100
IF_CONTAMINATION = 0.05
IF_RANDOM_STATE = 42
MIN_TRAINING_SAMPLES = 20
RETRAIN_EVERY_N = 25

SCORE_THREAT_HIGH = -0.05
SCORE_THREAT_MID = 0.02

# Threat types
THREAT_TYPES = {
    "tamper":     {"emoji": "🔴", "label": "Tampering Detected"},
    "replay":     {"emoji": "🔴", "label": "Replay Attack"},
    "burst":      {"emoji": "🟡", "label": "Traffic Burst"},
    "recipient":  {"emoji": "🟡", "label": "Unusual Recipient"},
    "size":       {"emoji": "🟡", "label": "Abnormal Message Size"},
    "keyword":    {"emoji": "🔴", "label": "Hazardous Content"},
    "timing":     {"emoji": "🟡", "label": "Unusual Timing"},
    "unknown":    {"emoji": "⚪", "label": "Unclassified Anomaly"},
}

# Detection thresholds
BURST_WINDOW_SECONDS = 3.0
BURST_COUNT = 8
REPLAY_WINDOW_SECONDS = 60.0
SIZE_DEVIATION_FACTOR = 3.0