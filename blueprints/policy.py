from flask import Blueprint, request, render_template, redirect, url_for
from utils.jwt_tokens import decode_token
from services.policy_engine import evaluate_policy, audit_log
from database import db
from models import User, Policy


bp = Blueprint("policy", __name__, url_prefix="/policy")


@bp.get("/")
def list_policies():
policies = Policy.query.order_by(Policy.id.desc()).all()
return render_template("policy.html", policies=policies)


@bp.post("/add")
def add_policy():
f = request.form
p = Policy(
name=f.get("name"),
path_prefix=f.get("path_prefix","/"),
role_required=f.get("role_required") or None,
require_trusted_device=bool(f.get("require_trusted_device")),
start_hour=int(f.get("start_hour",0)),
end_hour=int(f.get("end_hour",23)),
enabled=True,
)
db.session.add(p)
db.session.commit()
return redirect(url_for("policy.list_policies"))


@bp.post("/toggle/<int:pid>")
def toggle_policy(pid):
p = Policy.query.get(pid)
if p:
p.enabled = not p.enabled
db.session.commit()
return redirect(url_for("policy.list_policies"))


@bp.post("/delete/<int:pid>")
def delete_policy(pid):
p = Policy.query.get(pid)
if p:
db.session.delete(p)
db.session.commit()
return redirect(url_for("policy.list_policies"))
