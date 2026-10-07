"""
CRYPTOSENTINEL — Message Routes
Send, receive, replay, tamper, burst endpoints.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import time
import base64
import os

from core.crypto_engine import crypto_engine
from core.message_store import message_store
from core.threat_detector import threat_detector
from core.threat_logger import threat_logger
from core.config import UNITS

router = APIRouter(prefix="/api/messages", tags=["messages"])

class SendRequest(BaseModel):
    sender: str
    receiver: str
    plaintext: str
    tamper: bool = False

@router.get("/units")
def get_units():
    return {"units": UNITS}

@router.post("/send")
def send_message(req: SendRequest):
    valid_ids = {u["id"] for u in UNITS}
    if req.sender not in valid_ids or req.receiver not in valid_ids:
        raise HTTPException(400, "Invalid sender or receiver")
    if req.sender == req.receiver:
        raise HTTPException(400, "Sender and receiver must differ")

    encrypted = crypto_engine.encrypt(req.plaintext)

    # If tamper flag: flip one byte of ciphertext (breaks GCM auth)
    ct_b64 = encrypted["ciphertext"]
    tampered = False
    if req.tamper:
        raw = bytearray(base64.b64decode(ct_b64))
        if raw:
            raw[0] ^= 0xFF
        ct_b64 = base64.b64encode(bytes(raw)).decode()
        tampered = True

    msg = message_store.add_message(
        sender=req.sender,
        receiver=req.receiver,
        ciphertext=ct_b64,
        nonce=encrypted["nonce"],
        tag=encrypted["tag"],
        msg_hash=encrypted["hash"],
        plaintext_length=len(req.plaintext),
        tampered=tampered,
    )

    detection = threat_detector.analyze(msg)
    threat_entry = None
    if detection["level"] != "NORMAL":
        threat_entry = threat_logger.log(
            msg["id"], req.sender, req.receiver, detection
        )

    return {
        "message": msg,
        "detection": detection,
        "threat": threat_entry,
    }

@router.get("/list")
def list_messages(limit: int = 50):
    return {"messages": message_store.get_recent(limit)}

@router.get("/decrypt/{msg_id}")
def decrypt_message(msg_id: int):
    msg = next((m for m in message_store.get_all() if m["id"] == msg_id), None)
    if not msg:
        raise HTTPException(404, "Message not found")
    try:
        plaintext = crypto_engine.decrypt(
            msg["ciphertext"], msg["nonce"], msg["tag"]
        )
        return {"id": msg_id, "plaintext": plaintext, "tampered": False}
    except Exception as e:
        return {"id": msg_id, "error": str(e), "tampered": True}

@router.post("/replay")
def replay_last():
    last = message_store.get_last()
    if not last:
        raise HTTPException(400, "No messages to replay")
    msg = message_store.add_message(
        sender=last["sender"],
        receiver=last["receiver"],
        ciphertext=last["ciphertext"],
        nonce=last["nonce"],
        tag=last["tag"],
        msg_hash=last["hash"],
        plaintext_length=last["plaintext_length"],
        tampered=False,
    )
    detection = threat_detector.analyze(msg)
    threat = None
    if detection["level"] != "NORMAL":
        threat = threat_logger.log(msg["id"], msg["sender"], msg["receiver"], detection)
    return {"message": msg, "detection": detection, "threat": threat}

@router.post("/burst")
def burst(count: int = 30):
    results = []
    for i in range(count):
        encrypted = crypto_engine.encrypt(f"BURST-{i}")
        msg = message_store.add_message(
            sender="alpha", receiver="bravo",
            ciphertext=encrypted["ciphertext"],
            nonce=encrypted["nonce"],
            tag=encrypted["tag"],
            msg_hash=encrypted["hash"],
            plaintext_length=10,
        )
        detection = threat_detector.analyze(msg)
        if detection["level"] != "NORMAL":
            threat_logger.log(msg["id"], "alpha", "bravo", detection)
        results.append(detection["level"])
    return {"sent": count, "levels": results}

@router.delete("/clear")
def clear_all():
    message_store.clear()
    threat_logger.clear()
    return {"status": "cleared"}