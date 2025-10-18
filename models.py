from datetime import datetime, timedelta
from database import db


class User(db.Model):
__tablename__ = "users"
id = db.Column(db.Integer, primary_key=True)
email = db.Column(db.String(255), unique=True, nullable=False)
pass_hash = db.Column(db.String(255), nullable=False)
role = db.Column(db.String(32), default="USER") # ADMIN | ANALYST | USER
totp_secret = db.Column(db.String(64), nullable=True)
is_active = db.Column(db.Boolean, default=True)
created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Device(db.Model):
__tablename__ = "devices"
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
dfp_hash = db.Column(db.String(128), index=True) # device fingerprint hash
pubkey_pem = db.Column(db.Text, nullable=True)
trust_score = db.Column(db.Float, default=0.5)
is_blocked = db.Column(db.Boolean, default=False)
last_seen = db.Column(db.DateTime, default=datetime.utcnow)


class Token(db.Model):
__tablename__ = "tokens"
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
jti = db.Column(db.String(64), index=True, unique=True)
ttype = db.Column(db.String(16)) # access | refresh
expires_at = db.Column(db.DateTime, nullable=False)
revoked = db.Column(db.Boolean, default=False)


class Audit(db.Model):
__tablename__ = "audit"
id = db.Column(db.Integer, primary_key=True)
ts = db.Column(db.DateTime, default=datetime.utcnow)
user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
ip = db.Column(db.String(64))
action = db.Column(db.String(64)) # login, access, policy_decision, attest
resource = db.Column(db.String(255))
decision = db.Column(db.String(32)) # allow, deny, step_up, require_attestation
reason = db.Column(db.String(255))
meta = db.Column(db.Text) # optional JSON serialized
