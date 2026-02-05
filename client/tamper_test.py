import json, base64, httpx

VERIFIER_URL = "http://127.0.0.1:8001"

def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

with open("credential.jwt","r",encoding="utf-8") as f:
    token = f.read().strip()

h,p,s = token.split(".")
payload = json.loads(b64url_decode(p))

# MANOMISSIONE: cambio depot_id
payload["vc"]["credentialSubject"]["depot_id"] = "DEPOT_ALTRO"

p2 = b64url_encode(json.dumps(payload,separators=(",",":")).encode())
tampered = f"{h}.{p2}.{s}"

ch = httpx.post(f"{VERIFIER_URL}/challenge").json()
r = httpx.post(f"{VERIFIER_URL}/verify", json={"nonce": ch["nonce"], "credential": tampered})
print(r.status_code, r.json())
