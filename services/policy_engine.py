from models import Policy


def evaluate_policy(ctx) -> tuple[str, str]:
path = ctx.get("path", "/")
role = ctx.get("role", "USER")
device_trusted = ctx.get("device_trusted", False)
hour = ctx.get("hour")


# DB policies take precedence if any matches and enabled
policies = Policy.query.filter(Policy.enabled == True).all()
for p in policies:
if not path.startswith(p.path_prefix):
continue
if p.role_required and role != p.role_required:
return ("deny", "role_mismatch")
if p.require_trusted_device and not device_trusted:
return ("require_attestation", "untrusted_device")
if hour < p.start_hour or hour > p.end_hour:
return ("step_up", "out_of_hours")
# if all constraints pass, allow; keep checking other rules could be added here
# fallback simple defaults
if path.startswith("/admin") and role != "ADMIN":
return ("deny", "role_mismatch")
if not device_trusted and path.startswith("/resources"):
return ("require_attestation", "untrusted_device")
if hour is not None and (hour < 7 or hour > 22):
return ("step_up", "out_of_hours")
return ("allow", "ok")
