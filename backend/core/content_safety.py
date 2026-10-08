"""
CRYPTOSENTINEL — Content Safety
Uses unitary/toxic-bert to classify decrypted text for abusive content.
Fully offline — no API key, no rate limit.
"""

from transformers import pipeline
from typing import Optional


class ContentSafety:
    def __init__(self):
        print("[SAFETY] Loading unitary/toxic-bert...")
        try:
            self.classifier = pipeline(
                "text-classification",
                model="unitary/toxic-bert",
                top_k=None,
                device=-1,
            )
            print("[SAFETY] ✅ Ready")
            self.enabled = True
        except Exception as e:
            print(f"[SAFETY] ❌ Load failed: {e}")
            self.enabled = False

    def check(self, text: str, threshold: float = 0.7) -> Optional[dict]:
        if not self.enabled or not text.strip():
            return None
        try:
            results = self.classifier(text)[0]
            flagged = {
                r["label"]: round(r["score"], 3)
                for r in results
                if r["score"] >= threshold
            }
            return flagged if flagged else None
        except Exception as e:
            print(f"[SAFETY] Error: {e}")
            return None


content_safety = ContentSafety()