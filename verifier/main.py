import json
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional

import jwt
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Tesi SSI - Railway Verifier Simulation", version="0.4.1")

BASE_DIR = Path(__file__).resolve().parents[1]
DID_REGISTRY_PATH = BASE_DIR / "did_registry.json"
DID_REGISTRY: Dict[str, Any] = json.loads(DID_REGISTRY_PATH.read_text(encoding="utf-8"))

ISSUER_WHITELIST = {"did:example:issuer"}

EXPECTED_ISSUER_KID = "issuer-key-1"
EXPECTED_VC_TYP = "jwt_vc_json"
EXPECTED_VC_ALG = "RS256"

REQUIRED_DEPOT = "DEPOT_AURORA_NORD"
ALLOWED_ROLES = {"maintenance_technician", "driver", "conductor", "train_manager"}

challenge_store: Dict[str, Dict[str, Any]] = {}


def now_ts() -> int:
    return int(time.time())


def resolve_public_key_pem(did: str, kid: str) -> str:
    did_entry = DID_REGISTRY.get(did)
    if not isinstance(did_entry, dict):
        raise ValueError(f"DID not found: {did}")

    keys = did_entry.get("keys")
    if not isinstance(keys, dict):
        raise ValueError(f"No keys for DID: {did}")

    k = keys.get(kid)
    if not isinstance(k, dict):
        raise ValueError(f"KID not found for DID {did}: {kid}")

    pem = k.get("publicKeyPem")
    if isinstance(pem, str) and pem.strip():
        return pem

    pem_path = k.get("publicKeyPemPath")
    if not isinstance(pem_path, str) or not pem_path:
        raise ValueError(f"Missing publicKeyPem/publicKeyPemPath for DID {did} kid {kid}")

    p = (BASE_DIR / pem_path).resolve()
    if not p.exists():
        raise ValueError(f"Public key file not found: {p}")

    return p.read_text(encoding="utf-8")


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
    if not isinstance(kid, str) or not kid:
        raise ValueError("Missing/invalid 'kid' in VC JWT header")

    if kid != EXPECTED_ISSUER_KID:
        raise ValueError(f"Unexpected kid: {kid}")

    payload_no_verify = jwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
    if not isinstance(payload_no_verify, dict):
        raise ValueError("Invalid VC JWT payload")

    iss = payload_no_verify.get("iss")
    if not isinstance(iss, str) or not iss:
        raise ValueError("Missing/invalid 'iss' in VC JWT payload")

    if iss not in ISSUER_WHITELIST:
        raise ValueError(f"Issuer not allowed: {iss}")

    issuer_public_key = resolve_public_key_pem(iss, kid)

    payload = jwt.decode(
        token,
        issuer_public_key,
        algorithms=["RS256"],
        options={"verify_aud": False, "verify_exp": False},
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
