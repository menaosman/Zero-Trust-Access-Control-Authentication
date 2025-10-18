from flask import Blueprint, request, jsonify
@bp.post("/register_admin_once")
def register_admin_once():
if User.query.filter_by(role="ADMIN").first():
return jsonify({"error": "admin exists"}), 400
data = request.get_json() or {}
email = data.get("email")
pw = data.get("password")
if not email or not pw:
return jsonify({"error": "email/password required"}), 400
u = User(email=email, pass_hash=hash_password(pw), role="ADMIN")
db.session.add(u)
db.session.commit()
return jsonify({"ok": True, "user_id": u.id})


@bp.post("/login")
def login():
data = request.get_json() or {}
email = data.get("email")
pw = data.get("password")
code = data.get("totp")
u = User.query.filter_by(email=email, is_active=True).first()
if not u or not verify_password(u.pass_hash, pw):
return jsonify({"error": "invalid_credentials"}), 401
if not u.totp_secret:
# bootstrap TOTP on first login flow
secret = new_totp_secret()
u.totp_secret = secret
db.session.commit()
return jsonify({"enroll_totp": True, "secret": secret, "otpauth": f"otpauth://totp/ZeroTrust:{u.email}?secret={secret}&issuer=ZeroTrust"}), 200
if not code or not verify_totp(u.totp_secret, str(code)):
return jsonify({"error": "totp_required_or_invalid"}), 401


access, ajti, aexp = issue_access(u.id, u.role)
refresh, rjti, rexp = issue_refresh(u.id)
db.session.add(Token(user_id=u.id, jti=rjti, ttype="refresh", expires_at=rexp))
db.session.commit()
return jsonify({"access": access, "refresh": refresh, "role": u.role})


@bp.post("/refresh")
def refresh():
data = request.get_json() or {}
refresh = data.get("refresh")
try:
payload = decode_token(refresh)
except Exception:
return jsonify({"error": "bad_refresh"}), 401
if payload.get("type") != "refresh":
return jsonify({"error": "not_refresh"}), 401


t = Token.query.filter_by(jti=payload["jti"], revoked=False).first()
if not t:
return jsonify({"error": "revoked_or_missing"}), 401


# rotate refresh
t.revoked = True
access, ajti, aexp = issue_access(payload["sub"], role="USER") # look up role
# fetch user role
from models import User
u = User.query.get(payload["sub"])
access, ajti, aexp = issue_access(u.id, u.role)
new_refresh, rjti, rexp = issue_refresh(u.id)
db.session.add(Token(user_id=u.id, jti=rjti, ttype="refresh", expires_at=rexp))
db.session.commit()
return jsonify({"access": access, "refresh": new_refresh})
