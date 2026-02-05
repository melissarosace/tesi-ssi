from datetime import datetime, timezone
from uuid import uuid4
import time
import secrets
from typing import Any, Dict, Optional, List
from pathlib import Path

import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Tesi SSI - Railway Issuer Simulation", version="0.5.1")

ISSUER_ID = "http://127.0.0.1:8000"

BASE_DIR = Path(__file__).resolve().parents[1]

ISSUER_PRIVATE_KEY_PATH = BASE_DIR / "keys" / "issuer_private.pem"
ISSUER_PRIVATE_KEY = ISSUER_PRIVATE_KEY_PATH.read_text(encoding="utf-8")
ISSUER_KID = "issuer-key-1"

HOLDER_PUBLIC_KEY_PATH = BASE_DIR / "keys" / "holder_public.pem"
HOLDER_PUBLIC_KEY = HOLDER_PUBLIC_KEY_PATH.read_text(encoding="utf-8")
EXPECTED_HOLDER_KID = "holder-key-1"
EXPECTED_PROOF_TYP = "openid4vci-proof+jwt"
EXPECTED_PROOF_ALG = "RS256"

token_store: Dict[str, Dict[str, Any]] = {}


def now_ts() -> int:
    return int(time.time())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_bearer(auth: Optional[str]) -> Optional[str]:
    if not auth:
        return None
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


def jwt_sign_rs256(payload: Dict[str, Any], *, typ: str) -> str:
    headers = {"typ": typ, "alg": "RS256", "kid": ISSUER_KID}
    token = jwt.encode(payload, ISSUER_PRIVATE_KEY, algorithm="RS256", headers=headers)
    return token if isinstance(token, str) else token.decode("utf-8")


def verify_holder_proof_rs256(proof_jwt: str) -> Dict[str, Any]:
    header = jwt.get_unverified_header(proof_jwt)

    typ = header.get("typ")
    if typ != EXPECTED_PROOF_TYP:
        raise ValueError(f"Unexpected typ: {typ}")

    alg = header.get("alg")
    if alg != EXPECTED_PROOF_ALG:
        raise ValueError(f"Unexpected alg: {alg}")

    kid = header.get("kid")
    if not kid:
        raise ValueError("Missing 'kid' in proof JWT header")
    if kid != EXPECTED_HOLDER_KID:
        raise ValueError(f"Unexpected kid: {kid}")

    payload = jwt.decode(
        proof_jwt,
        HOLDER_PUBLIC_KEY,
        algorithms=["RS256"],
        options={
            "verify_aud": False,
            "verify_exp": False,
        },
    )
    return payload


class TokenRequest(BaseModel):
    client_id: str
    scope: Optional[str] = None
    grant_type: Optional[str] = "client_credentials"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    c_nonce: str
    c_nonce_expires_in: int


class ProofObj(BaseModel):
    proof_type: str = "jwt"
    jwt: str


class CredentialRequest(BaseModel):
    format: str = "jwt_vc_json"
    types: List[str] = Field(default_factory=lambda: ["VerifiableCredential", "RailDepotAccessCredential"])
    proof: ProofObj


class CredentialResponse(BaseModel):
    format: str = "jwt_vc_json"
    credential: str
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[int] = None


@app.get("/ping")
def ping():
    return {"ok": True, "message": "pong", "timestamp": now_iso()}


@app.post("/token", response_model=TokenResponse)
def token(req: TokenRequest):
    access_token = secrets.token_urlsafe(32)
    c_nonce = secrets.token_urlsafe(32)

    expires_in = 600
    c_nonce_expires_in = 600

    tnow = now_ts()
    token_store[access_token] = {
        "client_id": req.client_id,
        "c_nonce": c_nonce,
        "token_exp": tnow + expires_in,
        "c_nonce_exp": tnow + c_nonce_expires_in,
        "scope": req.scope,
    }

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        c_nonce=c_nonce,
        c_nonce_expires_in=c_nonce_expires_in,
    )


@app.post("/credential", response_model=CredentialResponse)
def credential(req: CredentialRequest, authorization: Optional[str] = Header(None, alias="Authorization")):
    tnow = now_ts()

    access_token = parse_bearer(authorization)
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    session = token_store.get(access_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid access_token")

    if tnow >= int(session["token_exp"]):
        raise HTTPException(status_code=401, detail="access_token expired")

    if req.proof.proof_type != "jwt":
        raise HTTPException(status_code=400, detail="Unsupported proof_type (expected 'jwt')")

    try:
        proof_payload = verify_holder_proof_rs256(req.proof.jwt)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid proof signature/JWT: {e}")

    nonce = proof_payload.get("nonce")
    iss = proof_payload.get("iss")
    aud = proof_payload.get("aud")
    exp = proof_payload.get("exp")

    if not isinstance(iss, str) or not iss:
        raise HTTPException(status_code=400, detail="Missing/invalid 'iss' in proof JWT payload")

    if not isinstance(aud, str) or not aud:
        raise HTTPException(status_code=400, detail="Missing/invalid 'aud' in proof JWT payload")
    if aud != ISSUER_ID:
        raise HTTPException(status_code=400, detail="aud mismatch")

    if not isinstance(exp, (int, float)):
        raise HTTPException(status_code=400, detail="Missing/invalid 'exp' in proof JWT payload")
    if tnow >= int(exp):
        raise HTTPException(status_code=400, detail="proof JWT expired")

    if not isinstance(nonce, str) or not nonce:
        raise HTTPException(status_code=400, detail="Missing/invalid 'nonce' in proof JWT payload")

    if tnow >= int(session["c_nonce_exp"]):
        raise HTTPException(status_code=400, detail="c_nonce expired (request a new token)")

    if nonce != session["c_nonce"]:
        raise HTTPException(status_code=400, detail="Nonce mismatch")

    if iss != session["client_id"]:
        raise HTTPException(status_code=400, detail="iss mismatch")

    vc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": req.types,
        "issuer": ISSUER_ID,
        "issuanceDate": now_iso(),
        "credentialSubject": {
            "id": iss,
            "staff_id": "CLC-FL-000742",
            "fullName": "Melissa Rosace",
            "company": "FerroLink S.p.A.",
            "role": "train_manager",
            "depot_id": "DEPOT_AURORA_NORD",
            "safety_training_valid": True,
        },
    }

    vc_jwt_payload = {
        "iss": ISSUER_ID,
        "sub": iss,
        "iat": tnow,
        "exp": tnow + 3600,
        "jti": f"urn:uuid:{uuid4()}",
        "vc": vc,
    }

    vc_jwt = jwt_sign_rs256(vc_jwt_payload, typ="jwt_vc_json")

    new_nonce = secrets.token_urlsafe(32)
    new_nonce_expires_in = 3600
    session["c_nonce"] = new_nonce
    session["c_nonce_exp"] = tnow + new_nonce_expires_in

    return CredentialResponse(
        format="jwt_vc_json",
        credential=vc_jwt,
        c_nonce=new_nonce,
        c_nonce_expires_in=new_nonce_expires_in,
    )
