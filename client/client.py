import time
import json
import base64
import httpx

BASE_URL = "http://127.0.0.1:8000"
CLIENT_ID = "did:key:holder-melissa"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_encode_none(payload: dict, headers: dict) -> str:
    headers = {**headers, "alg": "none"}
    header_b64 = b64url_encode(json.dumps(headers, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_b64}.{payload_b64}."


def main():
    # 1) /token
    token_req = {"client_id": CLIENT_ID, "scope": "openid", "grant_type": "client_credentials"}
    r = httpx.post(f"{BASE_URL}/token", json=token_req, timeout=10)
    r.raise_for_status()
    token_data = r.json()

    access_token = token_data["access_token"]
    c_nonce = token_data["c_nonce"]

    print("TOKEN OK:", access_token[:12] + "...", "nonce:", c_nonce)

    # 2) proof jwt
    now = int(time.time())
    proof_payload = {
        "iss": CLIENT_ID,
        "aud": BASE_URL,
        "nonce": c_nonce,
        "iat": now,
        "exp": now + 300,
    }
    proof_headers = {"typ": "openid4vci-proof+jwt"}
    proof_jwt = jwt_encode_none(proof_payload, proof_headers)

    # 3) /credential
    cred_req = {
        "format": "jwt_vc_json",
        "types": ["VerifiableCredential", "MyCredential"],
        "proof": {"proof_type": "jwt", "jwt": proof_jwt},
    }
    headers = {"Authorization": f"Bearer {access_token}"}
    r2 = httpx.post(f"{BASE_URL}/credential", json=cred_req, headers=headers, timeout=10)
    r2.raise_for_status()
    resp = r2.json()

    print("CREDENTIAL OK, jwt prefix:", resp["credential"][:30] + "...")
    with open("credential.jwt", "w", encoding="utf-8") as f:
        f.write(resp["credential"])
    print("Saved credential.jwt")


if __name__ == "__main__":
    main()
