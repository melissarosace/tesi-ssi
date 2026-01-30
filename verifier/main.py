import time
import secrets
import base64
import json
from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Tesi SSI - Railway Verifier Simulation", version="0.2.0")

# Issuer atteso (whitelist)
ISSUER_WHITELIST = {"http://127.0.0.1:8000"}

# Policy del varco (deposito specifico)
REQUIRED_DEPOT = "DEPOT_AURORA_NORD"
ALLOWED_ROLES = {"maintenance_technician", "driver", "conductor", "train_manager"}

# nonce -> {"exp": <timestamp>, "used": bool}
challenge_store: Dict[str, Dict[str, Any]] = {}


def now_ts() -> int:
    return int(time.time())


def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def jwt_decode_no_verify(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    header_json = b64url_decode(parts[0]).decode("utf-8")
    payload_json = b64url_decode(parts[1]).decode("utf-8")
    return {"header": json.loads(header_json), "payload": json.loads(payload_json)}


class ChallengeResponse(BaseModel):
    nonce: str
    expires_in: int


class VerifyRequest(BaseModel):
    nonce: str
    credential: str  # VC JWT


class VerifyResponse(BaseModel):
    verified: bool
    reason: str


@app.post("/challenge", response_model=ChallengeResponse)
def challenge():
    expires_in = 300  # seconds
    nonce = secrets.token_urlsafe(32)
    challenge_store[nonce] = {"exp": now_ts() + expires_in, "used": False}
    return ChallengeResponse(nonce=nonce, expires_in=expires_in)


@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    tnow = now_ts()

    # 1) check nonce/challenge
    entry = challenge_store.get(req.nonce)
    if not entry:
        return VerifyResponse(verified=False, reason="Nonce not found")

    if entry.get("used"):
        return VerifyResponse(verified=False, reason="Nonce already used")

    if tnow >= int(entry["exp"]):
        return VerifyResponse(verified=False, reason="Nonce expired")

    # consume nonce subito (anti-replay)
    entry["used"] = True
    entry["exp"] = tnow - 1

    # 2) decode VC JWT (demo: no signature verify)
    try:
        decoded = jwt_decode_no_verify(req.credential)
    except Exception as e:
        return VerifyResponse(verified=False, reason=f"Invalid VC JWT: {e}")

    payload = decoded["payload"]

    # 3) checks su payload VC
    iss = payload.get("iss")
    exp = payload.get("exp")

    if not iss:
        return VerifyResponse(verified=False, reason="Missing 'iss' in VC JWT payload")

    if iss not in ISSUER_WHITELIST:
        return VerifyResponse(verified=False, reason=f"Issuer not allowed: {iss}")

    if isinstance(exp, (int, float)) and tnow >= int(exp):
        return VerifyResponse(verified=False, reason="VC expired (exp)")

    # 4) controllo subject/holder: sub e vc.credentialSubject.id
    sub = payload.get("sub")
    if not sub:
        return VerifyResponse(verified=False, reason="Missing 'sub' (holder) in VC JWT payload")

    vc = payload.get("vc")
    if not isinstance(vc, dict):
        return VerifyResponse(verified=False, reason="Missing or invalid 'vc' object in JWT payload")

    credential_subject = vc.get("credentialSubject")
    if not isinstance(credential_subject, dict):
        return VerifyResponse(verified=False, reason="Missing or invalid 'vc.credentialSubject' in VC")

    cs_id = credential_subject.get("id")
    if not cs_id:
        return VerifyResponse(verified=False, reason="Missing 'vc.credentialSubject.id' (holder id)")

    if cs_id != sub:
        return VerifyResponse(verified=False, reason="Holder mismatch: 'sub' != 'vc.credentialSubject.id'")

    # 5) check claim (use case deposito ferroviario)
    staff_id = credential_subject.get("staff_id")
    depot_id = credential_subject.get("depot_id")
    role = credential_subject.get("role")
    training_ok = credential_subject.get("safety_training_valid")

    if not staff_id:
        return VerifyResponse(verified=False, reason="Missing claim: staff_id")

    if depot_id != REQUIRED_DEPOT:
        return VerifyResponse(verified=False, reason=f"Wrong depot_id: {depot_id}")

    if role not in ALLOWED_ROLES:
        return VerifyResponse(verified=False, reason=f"Role not allowed: {role}")

    if training_ok is not True:
        return VerifyResponse(verified=False, reason="Safety training not valid")

    return VerifyResponse(verified=True, reason="OK: nonce valid + issuer ok + subject ok + depot policy ok")
