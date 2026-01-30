from datetime import datetime, timezone
from uuid import uuid4
import time
import secrets
import base64
import json
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Tesi SSI - Railway Issuer Simulation", version="0.4.0")

# Issuer identifier (demo/local)
ISSUER_ID = "http://127.0.0.1:8000"

token_store: Dict[str, Dict[str, Any]] = {}


def now_ts() -> int:
    return int(time.time())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def jwt_encode_none(payload: Dict[str, Any], headers: Optional[Dict[str, Any]] = None) -> str:
    if headers is None:
        headers = {}
    headers = {**headers, "alg": "none"}
    header_b64 = b64url_encode(json.dumps(headers, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return f"{header_b64}.{payload_b64}."


def jwt_decode_no_verify(token: str) -> Dict[str, Dict[str, Any]]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    header_json = b64url_decode(parts[0]).decode("utf-8")
    payload_json = b64url_decode(parts[1]).decode("utf-8")
    return {"header": json.loads(header_json), "payload": json.loads(payload_json)}


def parse_bearer(auth: Optional[str]) -> Optional[str]:
    if not auth:
        return None
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


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
    # Default coerente con use case ferroviario (accesso deposito)
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
    access_token = parse_bearer(authorization)
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    session = token_store.get(access_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid access_token")

    tnow = now_ts()
    if tnow >= session["token_exp"]:
        raise HTTPException(status_code=401, detail="access_token expired")

    # proof check
    try:
        decoded = jwt_decode_no_verify(req.proof.jwt)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid proof JWT: {e}")

    proof_payload = decoded["payload"]
    nonce = proof_payload.get("nonce")
    iss = proof_payload.get("iss")
    aud = proof_payload.get("aud")
    exp = proof_payload.get("exp")

    if tnow >= session["c_nonce_exp"]:
        raise HTTPException(status_code=400, detail="c_nonce expired (request a new token)")

    if nonce != session["c_nonce"]:
        raise HTTPException(status_code=400, detail="Nonce mismatch")

    if iss != session["client_id"]:
        raise HTTPException(status_code=400, detail="iss mismatch")

    if aud is not None and aud != ISSUER_ID:
        raise HTTPException(status_code=400, detail="aud mismatch")

    if isinstance(exp, (int, float)) and tnow >= int(exp):
        raise HTTPException(status_code=400, detail="proof JWT expired")

    # Build VC (as JWT, unsigned) - Use case: Accesso deposito ferroviario (wallet smartphone)
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

    vc_jwt = jwt_encode_none(vc_jwt_payload, headers={"typ": "jwt_vc_json"})

    # new nonce optional
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
