import time
import json
import base64
import httpx

ISSUER_URL = "http://127.0.0.1:8000"
VERIFIER_URL = "http://127.0.0.1:8001"
CLIENT_ID = "did:key:holder-melissa-rosace"

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_encode_none(payload: dict, headers: dict) -> str:
    headers = {**headers, "alg": "none"}
    header_b64 = b64url_encode(json.dumps(headers, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_b64}.{payload_b64}."


def main():
    # 1) /token (ISSUER)
    token_req = {"client_id": CLIENT_ID, "scope": "openid vc", "grant_type": "client_credentials"}
    r = httpx.post(f"{ISSUER_URL}/token", json=token_req, timeout=10)
    r.raise_for_status()
    token_data = r.json()

    access_token = token_data["access_token"]
    c_nonce = token_data["c_nonce"]
    print("TOKEN OK:", access_token[:12] + "...", "nonce:", c_nonce)

    # 2) proof jwt (holder -> issuer)
    now = int(time.time())
    proof_payload = {
        "iss": CLIENT_ID,
        "aud": ISSUER_URL,
        "nonce": c_nonce,
        "iat": now,
        "exp": now + 300,  # +5 min
    }
    proof_headers = {"typ": "openid4vci-proof+jwt"}
    proof_jwt = jwt_encode_none(proof_payload, proof_headers)

    # 3) /credential (ISSUER)
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

    # (opzionale) salva la VC
    with open("credential.jwt", "w", encoding="utf-8") as f:
        f.write(credential_jwt)
    print("Saved credential.jwt")

    # 4) /challenge (VERIFIER)
    c = httpx.post(f"{VERIFIER_URL}/challenge", timeout=10)
    c.raise_for_status()
    challenge = c.json()
    challenge_nonce = challenge["nonce"]
    print("CHALLENGE OK:", challenge_nonce[:12] + "...")

    # 5) /verify (VERIFIER)
    verify_req = {"nonce": challenge_nonce, "credential": credential_jwt}
    v = httpx.post(f"{VERIFIER_URL}/verify", json=verify_req, timeout=10)
    v.raise_for_status()
    verify_resp = v.json()
    print("VERIFY RESULT:", verify_resp)


if __name__ == "__main__":
    main()
