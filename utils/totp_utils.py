
from datetime import datetime
from database import db
from models import Device, Audit


# Simple policy evaluation example


def evaluate_policy(ctx) -> tuple[str, str]:
# ctx: {path, role, device_trusted, hour}
path = ctx.get("path", "/")
role = ctx.get("role", "USER")
device_trusted = ctx.get("device_trusted", False)
hour = ctx.get("hour", datetime.utcnow().hour)


if path.startswith("/admin") and role != "ADMIN":
return ("deny", "role_mismatch")
if not device_trusted and path.startswith("/resources"):
return ("require_attestation", "untrusted_device")
if hour < 7 or hour > 22:
return ("step_up", "out_of_hours")
return ("allow", "ok")


def audit_log(user_id, ip, action, resource, decision, reason, meta=None):
a = Audit(user_id=user_id, ip=ip, action=action, resource=resource, decision=decision, reason=reason, meta=str(meta) if meta else None)
db.session.add(a)
db.session.commit()
