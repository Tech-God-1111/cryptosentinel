"""
CRYPTOSENTINEL — AI Threat Detector
Four-layer autonomous detection.
"""

import numpy as np
from sklearn.ensemble import IsolationForest

from core.config import (
    IF_N_ESTIMATORS, IF_CONTAMINATION, IF_RANDOM_STATE,
    MIN_TRAINING_SAMPLES, RETRAIN_EVERY_N,
    SCORE_THREAT_HIGH, SCORE_THREAT_MID,
    BURST_WINDOW_SECONDS, BURST_COUNT,
    REPLAY_WINDOW_SECONDS, SIZE_DEVIATION_FACTOR,
    THREAT_TYPES,
    CONTENT_INSPECTION_ENABLED, HAZARD_KEYWORDS,
)
from core.message_store import message_store
from core.crypto_engine import crypto_engine
from core.threat_analyst import threat_analyst
from core.content_safety import content_safety


class ThreatDetector:
    def __init__(self):
        self.model: IsolationForest | None = None
        self.trained_on = 0
        print("[AI] ✅ Isolation Forest detector initialized")
        print(f"[AI] ✅ LLM analyst: {'ENABLED' if threat_analyst.enabled else 'DISABLED'}")
        print(f"[AI] ✅ Content safety: {'ENABLED' if content_safety.enabled else 'DISABLED'}")
        print(f"[AI] Content inspection: {'ON (demo mode)' if CONTENT_INSPECTION_ENABLED else 'OFF'}")

    def _extract_features(self, msg: dict) -> list:
        return [
            msg["ciphertext_size"],
            msg["plaintext_length"],
            msg["time_since_last"],
            len(msg["sender"]),
            len(msg["receiver"]),
            hash(msg["sender"] + msg["receiver"]) % 1000,
        ]

    def _train(self):
        history = message_store.get_all()
        if len(history) < MIN_TRAINING_SAMPLES:
            return False
        X = np.array([self._extract_features(m) for m in history])
        self.model = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=IF_RANDOM_STATE,
        )
        self.model.fit(X)
        self.trained_on = len(history)
        print(f"[AI] 🧠 Retrained on {len(history)} messages")
        return True

    # --------------------------------------------------------
    # LAYER 0 — CONTENT INSPECTION
    # --------------------------------------------------------
    def _content_inspection(self, msg: dict) -> list:
        if not CONTENT_INSPECTION_ENABLED:
            return []
        if msg.get("tampered"):
            return []

        try:
            plaintext = crypto_engine.decrypt(
                msg["ciphertext"], msg["nonce"], msg["tag"]
            )
            text_lower = plaintext.lower()

            # Check 1: curated keyword scan
            keyword_hits = [kw for kw in HAZARD_KEYWORDS if kw in text_lower]

            # Check 2: toxic-bert
            toxic_hits = content_safety.check(plaintext)

            hits = list(set(keyword_hits))
            if toxic_hits:
                for cat, score in toxic_hits.items():
                    hits.append(f"toxic:{cat}({score})")

            if hits:
                print(f"[CONTENT] ⚠️  msg #{msg['id']} flagged: {hits}")

            del plaintext
            return hits

        except Exception as e:
            print(f"[CONTENT] error on #{msg.get('id')}: {e}")
            return []

    # --------------------------------------------------------
    # LAYER 1 — HEURISTICS
    # --------------------------------------------------------
    def _heuristic_check(self, msg: dict) -> list:
        reasons = []

        keyword_hits = self._content_inspection(msg)
        if keyword_hits:
            reasons.append((
                "keyword",
                f"Hazardous content: {', '.join(keyword_hits)}"
            ))

        if msg.get("tampered"):
            reasons.append(("tamper", "Ciphertext failed integrity check"))

        dup = message_store.find_recent_by_hash(
            msg["hash"], REPLAY_WINDOW_SECONDS
        )
        if dup and dup["id"] != msg["id"]:
            reasons.append(("replay", f"Duplicate hash of msg #{dup['id']}"))

        recent_count = message_store.count_in_window(BURST_WINDOW_SECONDS)
        if recent_count >= BURST_COUNT:
            reasons.append(("burst", f"{recent_count} msgs in {BURST_WINDOW_SECONDS}s"))

        pair = f"{msg['sender']}->{msg['receiver']}"
        pair_counts = message_store.recipient_pair_counts()
        if len(pair_counts) > 1:
            avg = sum(pair_counts.values()) / len(pair_counts)
            this = pair_counts.get(pair, 0)
            if avg >= 5 and this == 0:
                reasons.append(("recipient", f"First-time pair {pair}"))

        history = message_store.get_all()
        if len(history) >= 10:
            sizes = [m["ciphertext_size"] for m in history]
            mean = np.mean(sizes)
            std = np.std(sizes) or 1.0
            if abs(msg["ciphertext_size"] - mean) > SIZE_DEVIATION_FACTOR * std:
                reasons.append(("size", "Size far from baseline"))

        return reasons

    # --------------------------------------------------------
    # MAIN ANALYZE
    # --------------------------------------------------------
    def analyze(self, msg: dict) -> dict:
        if (self.model is None
                or len(message_store.get_all()) - self.trained_on >= RETRAIN_EVERY_N):
            self._train()

        history_len = len(message_store.get_all())
        keyword_hits = self._content_inspection(msg)

        if history_len < 30 and not keyword_hits:
            return {
                "level": "NORMAL",
                "status": "🟢",
                "ai_score": 0.0,
                "threat_type": "unknown",
                "label": f"Warm-up: {history_len}/30 messages collected",
                "reasons": [],
                "features": self._extract_features(msg),
                "analyst": None,
            }

        heuristic_reasons = self._heuristic_check(msg)

        ai_score = 0.0
        ai_flag = False
        if self.model is not None:
            X = np.array([self._extract_features(msg)])
            ai_score = float(self.model.decision_function(X)[0])
            ai_flag = ai_score <= SCORE_THREAT_MID

        if heuristic_reasons or ai_score <= SCORE_THREAT_HIGH:
            level = "THREAT"
            status = "🔴"
        elif ai_flag:
            level = "SUSPICIOUS"
            status = "🟡"
        else:
            level = "NORMAL"
            status = "🟢"

        analyst_result = None
        obvious_normal = (
            level == "NORMAL"
            and not heuristic_reasons
            and not ai_flag
        )

        if not obvious_normal and level != "THREAT" and threat_analyst.enabled:
            print(f"[AI] LLM analyst reviewing msg #{msg['id']}...")
            analyst_result = threat_analyst.analyze(msg)
            if analyst_result:
                llm_level = analyst_result["level"]
                if llm_level == "THREAT":
                    level = "THREAT"
                    status = "🔴"
                elif llm_level == "SUSPICIOUS" and level == "NORMAL":
                    level = "SUSPICIOUS"
                    status = "🟡"

        threat_type = "unknown"
        label = "Normal traffic"

        if heuristic_reasons:
            threat_type = heuristic_reasons[0][0]
            label = heuristic_reasons[0][1]
        elif analyst_result and analyst_result["level"] != "NORMAL":
            threat_type = analyst_result["threat_type"]
            label = analyst_result["reason"]
        elif level != "NORMAL":
            label = "AI anomaly — unusual metadata pattern"

        return {
            "level": level,
            "status": status,
            "ai_score": round(ai_score, 4),
            "threat_type": threat_type,
            "label": label,
            "reasons": [{"type": t, "detail": d} for t, d in heuristic_reasons],
            "features": self._extract_features(msg),
            "analyst": analyst_result,
        }


threat_detector = ThreatDetector()