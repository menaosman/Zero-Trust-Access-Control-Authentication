# scripts/attest_client.py
# Usage: python scripts/attest_client.py --email admin@example.com --password Secret123 --dfp demo-device-hash
import argparse, json, os, base64, hashlib
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


API = os.environ.get("API", "http://127.0.0.1:5000")


parser = argparse.ArgumentParser()
parser.add_argument("--email", required=True)
parser.add_argument("--password", required=True)
parser.add_argument("--totp", default=None)
parser.add_argument("--dfp", default="demo-device-hash")
args = parser.parse_args()


# --- 1) login (password + optional TOTP) ---
r = requests.post(f"{API}/auth/login", json={"email": args.email, "password": args.password, "totp": args.totp})
r.raise_for_status()
J = r.json()
if "enroll_totp" in J:
print("TOTP enrollment required. Secret:", J["secret"])
print("Scan with Google Authenticator, then re-run with --totp <code>.")
raise SystemExit(0)
access = J["access"]
print("Logged in. Access token obtained.")


# --- 2) get attestation challenge (nonce) ---
r = requests.post(f"{API}/attest/challenge", json={"access": access})
r.raise_for_status()
nonce = r.json()["nonce"].encode()
print("Nonce:", nonce)


# --- 3) create or load device keypair ---
KEY_FILE = ".device_key.pem"
if not os.path.exists(KEY_FILE):
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open(KEY_FILE, "wb") as f:
f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
format=serialization.PrivateFormat.PKCS8,
encryption_algorithm=serialization.NoEncryption()))
else:
from cryptography.hazmat.primitives import serialization as ser
key = serialization.load_pem_private_key(open(KEY_FILE, "rb").read(), password=None)


pubkey_pem = key.public_key().public_bytes(
serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()


# --- 4) sign (nonce || dfp) ---
message = nonce + args.dfp.encode()
signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())


# We don't send raw signature; server is simplified to accept signature_ok flag. We'll extend server next to verify.
r = requests.post(f"{API}/attest/verify", json={
"access": access,
"dfp_hash": hashlib.sha256(args.dfp.encode()).hexdigest(),
"signature_ok": True,
"pubkey_pem": pubkey_pem
})
print("Verify resp:", r.status_code, r.text)


# --- 5) call /me with X-DFP header ---
headers = {"Authorization": f"Bearer {access}", "X-DFP": hashlib.sha256(args.dfp.encode()).hexdigest()}
r = requests.get(f"{API}/me", headers=headers)
print("/me resp:", r.status_code)
print(r.text)
