import sys
import time
import json
import base64
from pathlib import Path
from uuid import uuid4

import httpx
import jwt

ISSUER_URL = "http://127.0.0.1:8000"
VERIFIER_URL = "http://127.0.0.1:8001"

ISSUER_DID = "did:example:issuer"
HOLDER_DID = "did:example:holder-melissa"
CLIENT_ID = HOLDER_DID

BASE_DIR = Path(__file__).resolve().parents[1]
HOLDER_PRIVATE_KEY = (BASE_DIR / "keys" / "holder_private.pem").read_text(encoding="utf-8")
HOLDER_KID = "holder-key-1"

ISSUER_PRIVATE_KEY = (BASE_DIR / "keys" / "issuer_private.pem").read_text(encoding="utf-8")
ISSUER_KID = "issuer-key-1"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def jwt_decode_no_verify(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    sig = parts[2] if len(parts) > 2 else ""
    return {"header": header, "payload": payload, "signature": sig, "raw_parts": parts}


def jwt_tamper_payload_keep_signature(token: str, mutate_fn) -> str:
    d = jwt_decode_no_verify(token)
    parts = d["raw_parts"]
    if len(parts) < 3:
        raise ValueError("JWT must have 3 parts (header.payload.signature)")

    header_b64, payload_b64, sig_b64 = parts[0], parts[1], parts[2]
    payload = d["payload"]
    mutate_fn(payload)

    new_payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return f"{header_b64}.{new_payload_b64}.{sig_b64}"


def jwt_tamper_header_keep_signature(token: str, mutate_fn) -> str:
    d = jwt_decode_no_verify(token)
    parts = d["raw_parts"]
    if len(parts) < 3:
        raise ValueError("JWT must have 3 parts (header.payload.signature)")

    header = d["header"]
    mutate_fn(header)

    new_header_b64 = b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return f"{new_header_b64}.{parts[1]}.{parts[2]}"


def sign_proof_rs256(
    payload: dict,
    *,
    key: str = HOLDER_PRIVATE_KEY,
    kid: str = HOLDER_KID,
    typ: str = "openid4vci-proof+jwt",
    include_kid: bool = True,
) -> str:
    headers = {"typ": typ}
    if include_kid:
        headers["kid"] = kid
    return jwt.encode(payload, key, algorithm="RS256", headers=headers)


def build_proof(
    c_nonce: str,
    *,
    iss_override=None,
    aud_override=None,
    nonce_override=None,
    exp_offset=300,
    key_override=None,
    kid_override=None,
    include_kid: bool = True,
):
    now = int(time.time())
    payload = {
        "iss": iss_override or CLIENT_ID,
        "aud": aud_override or ISSUER_URL,
        "nonce": nonce_override or c_nonce,
        "iat": now,
        "exp": now + exp_offset,
    }
    key_to_use = key_override or HOLDER_PRIVATE_KEY
    kid_to_use = kid_override or HOLDER_KID
    return sign_proof_rs256(payload, key=key_to_use, kid=kid_to_use, include_kid=include_kid)


def sign_vc_rs256(vc_payload: dict, *, kid: str = ISSUER_KID, typ: str = "jwt_vc_json") -> str:
    headers = {"typ": typ, "kid": kid}
    return jwt.encode(vc_payload, ISSUER_PRIVATE_KEY, algorithm="RS256", headers=headers)


def build_vc_payload(
    *,
    holder_did: str = HOLDER_DID,
    vc_issuer: str = ISSUER_DID,
    iss_claim: str = ISSUER_DID,
    exp_offset: int = 3600,
    cs_overrides: dict | None = None,
) -> dict:
    tnow = int(time.time())
    credential_subject = {
        "id": holder_did,
        "staff_id": "CLC-FL-000742",
        "fullName": "Melissa Rosace",
        "company": "FerroLink S.p.A.",
        "role": "train_manager",
        "depot_id": "DEPOT_AURORA_NORD",
        "safety_training_valid": True,
    }
    if cs_overrides:
        credential_subject.update(cs_overrides)

    vc_obj = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "RailDepotAccessCredential"],
        "issuer": vc_issuer,
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(tnow)),
        "credentialSubject": credential_subject,
    }

    return {
        "iss": iss_claim,
        "sub": holder_did,
        "iat": tnow,
        "exp": tnow + exp_offset,
        "jti": f"urn:uuid:{uuid4()}",
        "vc": vc_obj,
    }


def post_json(url: str, *, json_body=None, headers=None, timeout=10):
    return httpx.post(url, json=json_body, headers=headers, timeout=timeout)


def show_response(r: httpx.Response):
    try:
        body = r.json()
    except Exception:
        body = r.text
    print(f"HTTP {r.status_code} -> {body}")


def get_token():
    token_req = {"client_id": CLIENT_ID, "scope": "openid vc", "grant_type": "client_credentials"}
    r = post_json(f"{ISSUER_URL}/token", json_body=token_req)
    r.raise_for_status()
    return r.json()


def get_credential(access_token: str, proof_jwt: str):
    cred_req = {
        "format": "jwt_vc_json",
        "types": ["VerifiableCredential", "RailDepotAccessCredential"],
        "proof": {"proof_type": "jwt", "jwt": proof_jwt},
    }
    headers = {"Authorization": f"Bearer {access_token}"}
    return post_json(f"{ISSUER_URL}/credential", json_body=cred_req, headers=headers)


def get_challenge(expires_in: int | None = None):
    if expires_in is None:
        r = post_json(f"{VERIFIER_URL}/challenge")
        r.raise_for_status()
        return r.json()

    r = post_json(f"{VERIFIER_URL}/challenge", json_body={"expires_in": expires_in})
    if r.status_code == 422:
        r = post_json(f"{VERIFIER_URL}/challenge")
    r.raise_for_status()
    return r.json()


def verify_with(verifier_nonce: str, credential_jwt: str):
    req = {"nonce": verifier_nonce, "credential": credential_jwt}
    return post_json(f"{VERIFIER_URL}/verify", json_body=req)


def obtain_valid_credential():
    t = get_token()
    access_token = t["access_token"]
    c_nonce = t["c_nonce"]
    proof = build_proof(c_nonce)
    r = get_credential(access_token, proof)
    if r.status_code != 200:
        show_response(r)
    r.raise_for_status()
    return r.json()["credential"]


def test_happy():
    cred = obtain_valid_credential()
    ch = get_challenge()
    r = verify_with(ch["nonce"], cred)
    show_response(r)


def test_issuer_missing_auth():
    t = get_token()
    proof = build_proof(t["c_nonce"])
    cred_req = {
        "format": "jwt_vc_json",
        "types": ["VerifiableCredential", "RailDepotAccessCredential"],
        "proof": {"proof_type": "jwt", "jwt": proof},
    }
    r = post_json(f"{ISSUER_URL}/credential", json_body=cred_req, headers={})
    show_response(r)


def test_issuer_invalid_token():
    t = get_token()
    proof = build_proof(t["c_nonce"])
    cred_req = {
        "format": "jwt_vc_json",
        "types": ["VerifiableCredential", "RailDepotAccessCredential"],
        "proof": {"proof_type": "jwt", "jwt": proof},
    }
    r = post_json(
        f"{ISSUER_URL}/credential",
        json_body=cred_req,
        headers={"Authorization": "Bearer TOKEN_FALSO"},
    )
    show_response(r)


def test_issuer_nonce_mismatch():
    t = get_token()
    proof = build_proof(t["c_nonce"], nonce_override="NONCE_SBAGLIATO")
    r = get_credential(t["access_token"], proof)
    show_response(r)


def test_issuer_iss_mismatch():
    t = get_token()
    proof = build_proof(t["c_nonce"], iss_override="did:example:holder-falso")
    r = get_credential(t["access_token"], proof)
    show_response(r)


def test_issuer_aud_mismatch():
    t = get_token()
    proof = build_proof(t["c_nonce"], aud_override="http://127.0.0.1:9999")
    r = get_credential(t["access_token"], proof)
    show_response(r)


def test_issuer_proof_expired():
    t = get_token()
    proof = build_proof(t["c_nonce"], exp_offset=-1)
    r = get_credential(t["access_token"], proof)
    show_response(r)


def test_issuer_proof_bad_signature():
    t = get_token()
    proof = build_proof(t["c_nonce"], key_override=ISSUER_PRIVATE_KEY)
    r = get_credential(t["access_token"], proof)
    show_response(r)


def test_issuer_proof_kid_mismatch():
    t = get_token()
    proof = build_proof(t["c_nonce"], kid_override="holder-key-XXX")
    r = get_credential(t["access_token"], proof)
    show_response(r)


def test_issuer_proof_missing_kid():
    t = get_token()
    proof = build_proof(t["c_nonce"], include_kid=False)
    r = get_credential(t["access_token"], proof)
    show_response(r)


def test_verifier_replay():
    cred = obtain_valid_credential()
    ch = get_challenge()
    nonce = ch["nonce"]

    r1 = verify_with(nonce, cred)
    r2 = verify_with(nonce, cred)
    print("VERIFY 1:")
    show_response(r1)
    print("VERIFY 2 (replay):")
    show_response(r2)


def test_verifier_nonce_expired():
    cred = obtain_valid_credential()
    ch = get_challenge(expires_in=1)
    nonce = ch["nonce"]
    time.sleep(2)
    r = verify_with(nonce, cred)
    show_response(r)


def test_verifier_tamper_payload_role():
    cred = obtain_valid_credential()

    def mutate(payload):
        payload["vc"]["credentialSubject"]["role"] = "visitor"

    bad = jwt_tamper_payload_keep_signature(cred, mutate)
    ch = get_challenge()
    r = verify_with(ch["nonce"], bad)
    show_response(r)


def test_verifier_header_kid_mismatch():
    cred = obtain_valid_credential()

    def mutate(h):
        h["kid"] = "issuer-key-XXX"

    bad = jwt_tamper_header_keep_signature(cred, mutate)
    ch = get_challenge()
    r = verify_with(ch["nonce"], bad)
    show_response(r)


def test_verifier_header_typ_mismatch():
    cred = obtain_valid_credential()

    def mutate(h):
        h["typ"] = "wrong_typ"

    bad = jwt_tamper_header_keep_signature(cred, mutate)
    ch = get_challenge()
    r = verify_with(ch["nonce"], bad)
    show_response(r)


def test_verifier_header_alg_mismatch():
    cred = obtain_valid_credential()

    def mutate(h):
        h["alg"] = "HS256"

    bad = jwt_tamper_header_keep_signature(cred, mutate)
    ch = get_challenge()
    r = verify_with(ch["nonce"], bad)
    show_response(r)


def test_verifier_policy_depot_mismatch_signed():
    payload = build_vc_payload(cs_overrides={"depot_id": "DEPOT_ALTRO"})
    signed = sign_vc_rs256(payload)
    ch = get_challenge()
    r = verify_with(ch["nonce"], signed)
    show_response(r)


def test_verifier_policy_role_not_allowed_signed():
    payload = build_vc_payload(cs_overrides={"role": "visitor"})
    signed = sign_vc_rs256(payload)
    ch = get_challenge()
    r = verify_with(ch["nonce"], signed)
    show_response(r)


def test_verifier_policy_training_invalid_signed():
    payload = build_vc_payload(cs_overrides={"safety_training_valid": False})
    signed = sign_vc_rs256(payload)
    ch = get_challenge()
    r = verify_with(ch["nonce"], signed)
    show_response(r)


def test_verifier_vc_expired_signed():
    payload = build_vc_payload(exp_offset=-1)
    signed = sign_vc_rs256(payload)
    ch = get_challenge()
    r = verify_with(ch["nonce"], signed)
    show_response(r)


def main():
    tests = {
        "happy": test_happy,
        "issuer_missing_auth": test_issuer_missing_auth,
        "issuer_invalid_token": test_issuer_invalid_token,
        "issuer_nonce_mismatch": test_issuer_nonce_mismatch,
        "issuer_iss_mismatch": test_issuer_iss_mismatch,
        "issuer_aud_mismatch": test_issuer_aud_mismatch,
        "issuer_proof_expired": test_issuer_proof_expired,
        "issuer_proof_bad_signature": test_issuer_proof_bad_signature,
        "issuer_proof_kid_mismatch": test_issuer_proof_kid_mismatch,
        "issuer_proof_missing_kid": test_issuer_proof_missing_kid,
        "verifier_replay": test_verifier_replay,
        "verifier_nonce_expired": test_verifier_nonce_expired,
        "verifier_tamper_payload_role": test_verifier_tamper_payload_role,
        "verifier_header_kid_mismatch": test_verifier_header_kid_mismatch,
        "verifier_header_typ_mismatch": test_verifier_header_typ_mismatch,
        "verifier_header_alg_mismatch": test_verifier_header_alg_mismatch,
        "verifier_policy_depot_mismatch_signed": test_verifier_policy_depot_mismatch_signed,
        "verifier_policy_role_not_allowed_signed": test_verifier_policy_role_not_allowed_signed,
        "verifier_policy_training_invalid_signed": test_verifier_policy_training_invalid_signed,
        "verifier_vc_expired_signed": test_verifier_vc_expired_signed,
    }

    name = sys.argv[1] if len(sys.argv) > 1 else "happy"
    if name not in tests:
        print("Test disponibili:")
        for k in tests:
            print(" -", k)
        sys.exit(1)

    print(f"=== RUN TEST: {name} ===")
    tests[name]()


if __name__ == "__main__":
    main()
