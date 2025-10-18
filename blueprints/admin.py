from flask import Blueprint, request, jsonify
from utils.jwt_tokens import decode_token
from services.policy_engine import evaluate_policy, audit_log
from services.audit import summary
from models import User


bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.get("/users")
def users_list():
token = request.headers.get("Authorization", "").replace("Bearer ", "")
try:
payload = decode_token(token)
except Exception:
return ("", 401)
u = User.query.get(payload["sub"])
ctx = {"path": "/admin/users", "role": u.role, "device_trusted": True}
decision, reason = evaluate_policy(ctx)
audit_log(u.id, request.remote_addr, "access", "/admin/users", decision, reason)
if decision != "allow":
return jsonify({"decision": decision, "reason": reason}), 403
users = User.query.all()
return jsonify([{ "id": x.id, "email": x.email, "role": x.role } for x in users])


@bp.get("/audit/summary")
def audit_summary():
token = request.headers.get("Authorization", "").replace("Bearer ", "")
try:
payload = decode_token(token)
except Exception:
return ("", 401)
u = User.query.get(payload["sub"])
ctx = {"path": "/admin/audit/summary", "role": u.role, "device_trusted": True}
d, r = evaluate_policy(ctx)
if d != "allow":
return {"decision": d, "reason": r}, 403
return summary()
