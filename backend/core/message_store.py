"""
CRYPTOSENTINEL — Message Store
In-memory + JSON-persisted log of encrypted messages.
The AI sees only metadata — never plaintext.
"""

import json
import time
from typing import List, Dict, Optional
from collections import deque

from core.config import MESSAGES_FILE

class MessageStore:
    def __init__(self, max_memory: int = 500):
        self.messages: deque = deque(maxlen=max_memory)
        self._load_from_disk()

    def _load_from_disk(self):
        if MESSAGES_FILE.exists():
            try:
                with open(MESSAGES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for m in data[-500:]:
                        self.messages.append(m)
                print(f"[STORE] Loaded {len(self.messages)} messages from disk")
            except Exception as e:
                print(f"[STORE] Could not load messages: {e}")

    def _save_to_disk(self):
        try:
            with open(MESSAGES_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self.messages), f, indent=2)
        except Exception as e:
            print(f"[STORE] Save failed: {e}")

    def add_message(self, sender: str, receiver: str,
                    ciphertext: str, nonce: str, tag: str,
                    msg_hash: str, plaintext_length: int,
                    tampered: bool = False) -> Dict:
        now = time.time()
        last_time = self.messages[-1]["timestamp"] if self.messages else now

        entry = {
            "id": len(self.messages) + 1,
            "sender": sender,
            "receiver": receiver,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "hash": msg_hash,
            "ciphertext_size": len(ciphertext),
            "plaintext_length": plaintext_length,
            "timestamp": now,
            "time_since_last": round(now - last_time, 4),
            "tampered": tampered,
        }

        self.messages.append(entry)
        self._save_to_disk()
        return entry

    def get_all(self) -> List[Dict]:
        return list(self.messages)

    def get_recent(self, n: int = 50) -> List[Dict]:
        return list(self.messages)[-n:]

    def get_last(self) -> Optional[Dict]:
        return self.messages[-1] if self.messages else None

    def find_recent_by_hash(self, msg_hash: str, window_seconds: float) -> Optional[Dict]:
        cutoff = time.time() - window_seconds
        for m in reversed(self.messages):
            if m["timestamp"] < cutoff:
                break
            if m["hash"] == msg_hash:
                return m
        return None

    def count_in_window(self, window_seconds: float) -> int:
        cutoff = time.time() - window_seconds
        return sum(1 for m in self.messages if m["timestamp"] >= cutoff)

    def recipient_pair_counts(self) -> Dict[str, int]:
        counts = {}
        for m in self.messages:
            key = f"{m['sender']}->{m['receiver']}"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def clear(self):
        self.messages.clear()
        self._save_to_disk()

message_store = MessageStore()