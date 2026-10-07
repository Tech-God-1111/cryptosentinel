# 🎖️ CRYPTOSENTINEL

**Secure Military Comms with AI Anomaly Detection**

End-to-end encrypted military messaging with AI that detects tampering,
replay attacks, traffic bursts, and anomalous communication patterns
in real-time.

## 🧠 Concept

In modern military communications, the **content** is encrypted — but
**metadata isn't**. CRYPTOSENTINEL analyzes metadata patterns (message size,
timing, sender/receiver pairs) to detect four classes of attacks:

| Threat | Signal |
|--------|--------|
| Tampering | AES-GCM auth tag fails |
| Replay Attack | Duplicate SHA-256 hash within window |
| Traffic Burst | Too many messages in a short window |
| Wrong Recipient | Rare sender→receiver pair |

The AI **never sees plaintext** — only metadata. That's how real SIGINT works.

## 🛠️ Stack

- **Crypto:** AES-256-GCM (`cryptography`)
- **AI:** Isolation Forest (`scikit-learn`)
- **Backend:** FastAPI + Uvicorn
- **Frontend:** Vanilla HTML/CSS/JS
- **Storage:** JSON logs

## 🚀 Run

```bash
cd cryptosentinel
pip install -r requirements.txt
python run.py