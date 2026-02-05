from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
KEYS_DIR.mkdir(exist_ok=True)


def generate_pair(prefix: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # ok
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = KEYS_DIR / f"{prefix}_private.pem"
    pub_path = KEYS_DIR / f"{prefix}_public.pem"

    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)

    print(f"OK: generated {prefix}")
    print(" -", priv_path)
    print(" -", pub_path)


if __name__ == "__main__":
    generate_pair("issuer")
    generate_pair("holder")
