import time
import secrets
from typing import Any, Dict, Optional
from pathlib import Path

import jwt
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Tesi SSI - Railway Verifier Simulation", version="0.3.1")

ISSUER_WHITELIST = {"http://127.0.0.1:8000"}

BASE_DIR = Path(__file__).resolve().parents[1]
ISSUER_PUBLIC_KEY_PATH = BASE_DIR / "keys" / "issuer_public.pem"
ISSUER_PUBLIC_KEY = ISSUER_PUBLIC_KEY_PATH.read_text(encoding="utf-8")

EXPECTED_ISSUER_KID = "issuer-key-1"
EXPECTED_VC_TYP = "jwt_vc_json"
EXPECTED_VC_ALG = "RS256"

REQUIRED_DEPOT = "DEPOT_AURORA_NORD"
ALLOWED_ROLES = {"maintenance_technician", "driver", "conductor", "train_manager"}

challenge_store: Dict[str, Dict[str, Any]] = {}


def now_ts() -> int:
    return int(time.time())


class ChallengeRequest(BaseModel):
    expires_in: int = 300


class ChallengeResponse(BaseModel):
    nonce: str
    expires_in: int


class VerifyRequest(BaseModel):
    nonce: str
    credential: str


class VerifyResponse(BaseModel):
    verified: bool
    reason: str


@app.get("/ping")
def ping():
    return {"ok": True, "ts": now_ts()}


@app.post("/challenge", response_model=ChallengeResponse)
def challenge(body: Optional[ChallengeRequest] = None):
    expires_in = body.expires_in if body is not None else 300
    nonce = secrets.token_urlsafe(32)
    challenge_store[nonce] = {"exp": now_ts() + expires_in, "used": False}
    return ChallengeResponse(nonce=nonce, expires_in=expires_in)


def decode_and_verify_vc_rs256(token: str) -> Dict[str, Any]:
    header = jwt.get_unverified_header(token)

    alg = header.get("alg")
    if alg != EXPECTED_VC_ALG:
        raise ValueError(f"Unexpected alg: {alg}")

    typ = header.get("typ")
    if typ != EXPECTED_VC_TYP:
        raise ValueError(f"Unexpected typ: {typ}")

    kid = header.get("kid")
    if not kid:
        raise ValueError("Missing 'kid' in VC JWT header")
    if kid != EXPECTED_ISSUER_KID:
        raise ValueError(f"Unexpected kid: {kid}")

    payload = jwt.decode(
        token,
        ISSUER_PUBLIC_KEY,
        algorithms=["RS256"],
        options={
            "verify_aud": False,
            "verify_exp": False,
        },
    )
    return payload


@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    tnow = now_ts()

    entry = challenge_store.get(req.nonce)
    if not entry:
        return VerifyResponse(verified=False, reason="Nonce not found")
    if entry.get("used"):
        return VerifyResponse(verified=False, reason="Nonce already used")
    if tnow >= int(entry["exp"]):
        return VerifyResponse(verified=False, reason="Nonce expired")

    entry["used"] = True
    entry["exp"] = tnow - 1

    try:
        payload = decode_and_verify_vc_rs256(req.credential)
    except Exception as e:
        return VerifyResponse(verified=False, reason=f"Invalid VC signature/JWT: {e}")

    iss = payload.get("iss")
    exp = payload.get("exp")

    if not isinstance(iss, str) or not iss:
        return VerifyResponse(verified=False, reason="Missing/invalid 'iss' in VC JWT payload")

    if iss not in ISSUER_WHITELIST:
        return VerifyResponse(verified=False, reason=f"Issuer not allowed: {iss}")

    if not isinstance(exp, (int, float)):
        return VerifyResponse(verified=False, reason="Missing/invalid 'exp' in VC JWT payload")

    if tnow >= int(exp):
        return VerifyResponse(verified=False, reason="VC expired (exp)")

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        return VerifyResponse(verified=False, reason="Missing/invalid 'sub' (holder) in VC JWT payload")

    vc = payload.get("vc")
    if not isinstance(vc, dict):
        return VerifyResponse(verified=False, reason="Missing or invalid 'vc' object in JWT payload")

    credential_subject = vc.get("credentialSubject")
    if not isinstance(credential_subject, dict):
        return VerifyResponse(verified=False, reason="Missing or invalid 'vc.credentialSubject' in VC")

    cs_id = credential_subject.get("id")
    if not isinstance(cs_id, str) or not cs_id:
        return VerifyResponse(verified=False, reason="Missing/invalid 'vc.credentialSubject.id' (holder id)")

    if cs_id != sub:
        return VerifyResponse(verified=False, reason="Holder mismatch: 'sub' != 'vc.credentialSubject.id'")

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

    return VerifyResponse(verified=True, reason="OK: signature ok + header ok + nonce ok + policy ok")
