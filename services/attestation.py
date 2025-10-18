import os, base64, secrets, hashlib
from datetime import datetime
from database import db
from models import Device


# Simulated attestation: server issues nonce; client signs with a local key (client-side not implemented here)
# We store dfp_hash + pubkey as a trust anchor and raise trust_score on success.


_challenges = {}


def new_challenge(user_id: int) -> str:
nonce = base64.urlsafe_b64encode(os.urandom(24)).decode()
_challenges[user_id] = nonce
return nonce


def verify_attestation(user_id: int, dfp_hash: str, signature_ok: bool, pubkey_pem: str | None = None) -> tuple[bool, str]:
# In real flow, verify signature over nonce||dfp using pubkey. Here we accept a boolean from client demo.
nonce = _challenges.get(user_id)
if not nonce:
return False, "no_challenge"
if not signature_ok:
return False, "bad_signature"


dev = Device.query.filter_by(user_id=user_id, dfp_hash=dfp_hash).first()
if not dev:
dev = Device(user_id=user_id, dfp_hash=dfp_hash, pubkey_pem=pubkey_pem, trust_score=0.6)
db.session.add(dev)
else:
dev.trust_score = min(1.0, (dev.trust_score or 0.6) + 0.1)
dev.last_seen = datetime.utcnow()
db.session.commit()
return True, "trusted"


def is_trusted(user_id: int, dfp_hash: str) -> bool:
dev = Device.query.filter_by(user_id=user_id, dfp_hash=dfp_hash, is_blocked=False).first()
return bool(dev and (dev.trust_score or 0.0) >= 0.7)
