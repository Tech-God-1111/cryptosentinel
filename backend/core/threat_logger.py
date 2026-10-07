"""
CRYPTOSENTINEL — Threat Logger
Persists detected threats to JSON for the dashboard.
"""

import json
import time
from typing import List, Dict
from collections import deque

from core.config import THREATS_FILE

class ThreatLogger:
    def __init__(self, max_memory: int = 200):
        self.threats: deque = deque(maxlen=max_memory)
        self._load()

    def _load(self):
        if THREATS_FILE.exists():
            try:
                with open(THREATS_FILE, "r", encoding="utf-8") as f:
                    for t in json.load(f)[-200:]:
                        self.threats.append(t)
                print(f"[THREAT] Loaded {len(self.threats)} threats from disk")
            except Exception as e:
                print(f"[THREAT] Load failed: {e}")

    def _save(self):
        try:
            with open(THREATS_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self.threats), f, indent=2)
        except Exception as e:
            print(f"[THREAT] Save failed: {e}")

    def log(self, message_id: int, sender: str, receiver: str,
            detection: Dict) -> Dict:
        entry = {
            "id": len(self.threats) + 1,
            "message_id": message_id,
            "sender": sender,
            "receiver": receiver,
            "level": detection["level"],
            "status": detection["status"],
            "threat_type": detection["threat_type"],
            "label": detection["label"],
            "reasons": detection["reasons"],
            "ai_score": detection["ai_score"],
            "timestamp": time.time(),
        }
        self.threats.append(entry)
        self._save()
        return entry

    def get_all(self) -> List[Dict]:
        return list(self.threats)

    def get_recent(self, n: int = 50) -> List[Dict]:
        return list(self.threats)[-n:]

    def stats(self) -> Dict:
        all_t = list(self.threats)
        return {
            "total": len(all_t),
            "threats": sum(1 for t in all_t if t["level"] == "THREAT"),
            "suspicious": sum(1 for t in all_t if t["level"] == "SUSPICIOUS"),
            "normal": sum(1 for t in all_t if t["level"] == "NORMAL"),
        }

    def clear(self):
        self.threats.clear()
        self._save()

threat_logger = ThreatLogger()