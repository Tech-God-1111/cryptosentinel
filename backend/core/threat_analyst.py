"""
CRYPTOSENTINEL — AI Threat Analyst
Uses NVIDIA Nemotron-3-Super (120B) to reason about message metadata.
Never sees plaintext — only metadata.
"""

import os
import json
from typing import Optional
from openai import OpenAI

from core.config import (
    NVIDIA_BASE_URL,
    THREAT_ANALYST_MODEL,
    THREAT_ANALYST_ENABLED,
    THREAT_TYPES,
)
from core.message_store import message_store


class ThreatAnalyst:
    def __init__(self):
        self.enabled = THREAT_ANALYST_ENABLED
        self.client = None

        if self.enabled:
            api_key = os.getenv("NVIDIA_API_KEY")
            if api_key:
                self.client = OpenAI(
                    base_url=NVIDIA_BASE_URL,
                    api_key=api_key,
                    timeout=30.0,
                )
                print(f"[ANALYST] ✅ LLM threat analyst ready ({THREAT_ANALYST_MODEL})")
            else:
                print("[ANALYST] ⚠️  NVIDIA_API_KEY missing in .env — analyst disabled")
                self.enabled = False
        else:
            print("[ANALYST] ⚪ LLM threat analyst disabled")

    def _build_context(self, msg: dict, recent: list) -> str:
        recent_summary = []
        for m in recent[-15:]:
            recent_summary.append({
                "id": m["id"],
                "sender": m["sender"],
                "receiver": m["receiver"],
                "size": m["ciphertext_size"],
                "time_since_last": m["time_since_last"],
                "tampered": m.get("tampered", False),
            })

        context = {
            "current_message": {
                "id": msg["id"],
                "sender": msg["sender"],
                "receiver": msg["receiver"],
                "ciphertext_size": msg["ciphertext_size"],
                "plaintext_length": msg["plaintext_length"],
                "time_since_last": msg["time_since_last"],
                "tampered": msg.get("tampered", False),
                "hash_prefix": msg["hash"][:16],
            },
            "recent_history": recent_summary,
            "known_units": ["alpha", "bravo", "charlie", "delta", "echo"],
        }
        return json.dumps(context, indent=2)

    def _system_prompt(self) -> str:
        return (
            "You are a military SIGINT threat analyst AI. "
            "You analyze encrypted message METADATA (never plaintext) to detect threats.\n\n"
            "Threat classes:\n"
            "- tamper:    ciphertext integrity failed\n"
            "- replay:    duplicate hash within a short window\n"
            "- burst:     too many messages in a short window\n"
            "- recipient: unusual sender→receiver pair\n"
            "- size:      message size far from baseline\n"
            "- timing:    unusual time gap for this sender\n\n"
            "Rules:\n"
            "1. Return ONLY valid JSON — no markdown, no prose outside JSON.\n"
            "2. If normal, return level='NORMAL' with confidence.\n"
            "3. Be conservative — only flag THREAT with clear evidence.\n"
            "4. Cite the specific reason.\n\n"
            "JSON schema:\n"
            "{\n"
            '  "level": "NORMAL" | "SUSPICIOUS" | "THREAT",\n'
            '  "threat_type": "tamper" | "replay" | "burst" | "recipient" | "size" | "timing" | "unknown",\n'
            '  "reason": "one sentence explaining WHY",\n'
            '  "confidence": 0.0 to 1.0,\n'
            '  "recommended_action": "one sentence for the operator"\n'
            "}"
        )

    def analyze(self, msg: dict) -> Optional[dict]:
        if not self.enabled or not self.client:
            return None

        try:
            recent = message_store.get_recent(20)
            context = self._build_context(msg, recent)

            response = self.client.chat.completions.create(
                model=THREAT_ANALYST_MODEL,
                messages=[
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": f"Analyze this message:\n\n{context}"},
                ],
                temperature=0.1,
                top_p=0.95,
                max_tokens=300,
                stream=False,
            )

            raw = response.choices[0].message.content.strip()

            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            if not raw.startswith("{"):
                start = raw.find("{")
                end = raw.rfind("}")
                if start != -1 and end != -1:
                    raw = raw[start:end + 1]

            parsed = json.loads(raw)

            level = parsed.get("level", "NORMAL").upper()
            if level not in ("NORMAL", "SUSPICIOUS", "THREAT"):
                level = "NORMAL"

            threat_type = parsed.get("threat_type", "unknown").lower()
            if threat_type not in THREAT_TYPES:
                threat_type = "unknown"

            return {
                "level": level,
                "threat_type": threat_type,
                "reason": parsed.get("reason", "No reason provided"),
                "confidence": float(parsed.get("confidence", 0.5)),
                "recommended_action": parsed.get(
                    "recommended_action", "Continue monitoring"
                ),
                "source": "nvidia-nemotron",
            }

        except json.JSONDecodeError as e:
            print(f"[ANALYST] JSON parse error: {e}")
            return None
        except Exception as e:
            print(f"[ANALYST] LLM call failed: {type(e).__name__}: {e}")
            return None


threat_analyst = ThreatAnalyst()