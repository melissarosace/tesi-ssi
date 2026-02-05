import time
from pathlib import Path

import httpx
import jwt

ISSUER_URL = "http://127.0.0.1:8000"
VERIFIER_URL = "http://127.0.0.1:8001"
CLIENT_ID = "did:key:holder-melissa-rosace"

BASE_DIR = Path(__file__).resolve().parents[1]
HOLDER_PRIVATE_KEY_PATH = BASE_DIR / "keys" / "holder_private.pem"
HOLDER_PRIVATE_KEY = HOLDER_PRIVATE_KEY_PATH.read_text(encoding="utf-8")

HOLDER_KID = "holder-key-1"


def sign_proof_rs256(payload: dict) -> str:
    headers = {
        "typ": "openid4vci-proof+jwt",
        "kid": HOLDER_KID,
    }
    return jwt.encode(payload, HOLDER_PRIVATE_KEY, algorithm="RS256", headers=headers)


def main():
    token_req = {"client_id": CLIENT_ID, "scope": "openid vc", "grant_type": "client_credentials"}
    r = httpx.post(f"{ISSUER_URL}/token", json=token_req, timeout=10)
    r.raise_for_status()
    token_data = r.json()

    access_token = token_data["access_token"]
    c_nonce = token_data["c_nonce"]
    print("TOKEN OK:", access_token[:12] + "...", "nonce:", c_nonce)

    now = int(time.time())
    proof_payload = {
        "iss": CLIENT_ID,
        "aud": ISSUER_URL,
        "nonce": c_nonce,
        "iat": now,
        "exp": now + 300,
    }
    proof_jwt = sign_proof_rs256(proof_payload)

    cred_req = {
        "format": "jwt_vc_json",
        "types": ["VerifiableCredential", "RailDepotAccessCredential"],
        "proof": {"proof_type": "jwt", "jwt": proof_jwt},
    }
    headers = {"Authorization": f"Bearer {access_token}"}
    r2 = httpx.post(f"{ISSUER_URL}/credential", json=cred_req, headers=headers, timeout=10)
    r2.raise_for_status()
    resp = r2.json()

    credential_jwt = resp["credential"]
    print("CREDENTIAL OK, jwt prefix:", credential_jwt[:30] + "...")

    with open("credential.jwt", "w", encoding="utf-8") as f:
        f.write(credential_jwt)
    print("Saved credential.jwt")

    c = httpx.post(f"{VERIFIER_URL}/challenge", timeout=10)
    c.raise_for_status()
    challenge = c.json()
    challenge_nonce = challenge["nonce"]
    print("CHALLENGE OK:", challenge_nonce[:12] + "...")

    verify_req = {"nonce": challenge_nonce, "credential": credential_jwt}
    v = httpx.post(f"{VERIFIER_URL}/verify", json=verify_req, timeout=10)
    v.raise_for_status()
    verify_resp = v.json()
    print("VERIFY RESULT:", verify_resp)


if __name__ == "__main__":
    main()
