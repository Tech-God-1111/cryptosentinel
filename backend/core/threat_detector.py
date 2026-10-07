"""
CRYPTOSENTINEL — AI Threat Detector
Isolation Forest on metadata features (never sees plaintext).
Plus heuristic pre-checks for tamper, replay, burst, recipient.
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
)
from core.message_store import message_store

class ThreatDetector:
    def __init__(self):
        self.model: IsolationForest | None = None
        self.trained_on = 0
        print("[AI] ✅ Isolation Forest detector initialized")

    # --------------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------------
    def _extract_features(self, msg: dict) -> list:
        return [
            msg["ciphertext_size"],
            msg["plaintext_length"],
            msg["time_since_last"],
            len(msg["sender"]),
            len(msg["receiver"]),
            hash(msg["sender"] + msg["receiver"]) % 1000,
        ]

    # --------------------------------------------------------
    # TRAIN
    # --------------------------------------------------------
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
        print(f"[AI] 🧠 Trained on {len(history)} messages")
        return True

    # --------------------------------------------------------
    # HEURISTIC PRE-CHECKS
    # --------------------------------------------------------
    def _heuristic_check(self, msg: dict) -> dict:
        reasons = []

        # 1. TAMPER
        if msg.get("tampered"):
            reasons.append(("tamper", "Ciphertext failed integrity check"))

        # 2. REPLAY
        dup = message_store.find_recent_by_hash(
            msg["hash"], REPLAY_WINDOW_SECONDS
        )
        if dup and dup["id"] != msg["id"]:
            reasons.append(("replay", f"Duplicate hash of msg #{dup['id']}"))

        # 3. BURST
        recent_count = message_store.count_in_window(BURST_WINDOW_SECONDS)
        if recent_count >= BURST_COUNT:
            reasons.append(("burst", f"{recent_count} msgs in {BURST_WINDOW_SECONDS}s"))

        # 4. RECIPIENT ANOMALY
        pair = f"{msg['sender']}->{msg['receiver']}"
        pair_counts = message_store.recipient_pair_counts()
        if len(pair_counts) > 1:
            avg = sum(pair_counts.values()) / len(pair_counts)
            this = pair_counts.get(pair, 0)
            if avg >= 3 and this <= 1:
                reasons.append(("recipient", f"Rare pair {pair}"))

        # 5. SIZE ANOMALY
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
        # Retrain if needed
        if (self.model is None
                or len(message_store.get_all()) - self.trained_on >= RETRAIN_EVERY_N):
            self._train()

        # Heuristic reasons
        heuristic_reasons = self._heuristic_check(msg)

        # AI score
        ai_score = 0.0
        ai_flag = False
        if self.model is not None:
            X = np.array([self._extract_features(msg)])
            ai_score = float(self.model.decision_function(X)[0])
            ai_flag = ai_score <= SCORE_THREAT_MID

        # Decide level
        if heuristic_reasons or ai_score <= SCORE_THREAT_HIGH:
            level = "THREAT"
            status = "🔴"
        elif ai_flag:
            level = "SUSPICIOUS"
            status = "🟡"
        else:
            level = "NORMAL"
            status = "🟢"

        # Pick primary threat type
        threat_type = "unknown"
        label = "Normal traffic"
        if heuristic_reasons:
            threat_type = heuristic_reasons[0][0]
            label = heuristic_reasons[0][1]
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
        }

threat_detector = ThreatDetector()