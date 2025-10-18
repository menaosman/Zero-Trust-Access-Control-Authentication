from flask import Blueprint, request, jsonify
from flask import current_app as app
from services.attestation import new_challenge, verify_attestation, is_trusted
from services.policy_engine import audit_log
from utils.jwt_tokens import decode_token


bp = Blueprint("attest", __name__, url_prefix="/attest")


@bp.post("/challenge")
def challenge():
data = request.get_json() or {}
token = data.get("access")
try:
payload = decode_token(token)
except Exception:
return jsonify({"error": "bad_access"}), 401
nonce = new_challenge(payload["sub"])
return jsonify({"nonce": nonce})


@bp.post("/verify")
def verify():
data = request.get_json() or {}
token = data.get("access")
dfp_hash = data.get("dfp_hash")
signature_ok = bool(data.get("signature_ok", False))
try:
payload = decode_token(token)
except Exception:
return jsonify({"error": "bad_access"}), 401
ok, reason = verify_attestation(payload["sub"], dfp_hash, signature_ok, data.get("pubkey_pem"))
audit_log(payload["sub"], request.remote_addr, "attest", "/attest/verify", "allow" if ok else "deny", reason)
return jsonify({"trusted": ok, "reason": reason})
