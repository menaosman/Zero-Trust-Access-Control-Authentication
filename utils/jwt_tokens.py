import os, jwt, uuid
from datetime import datetime, timezone
from config import Config


ALG = "HS256"


def _exp(delta):
return datetime.now(timezone.utc) + delta


def issue_access(user_id: int, role: str):
jti = uuid.uuid4().hex
payload = {"sub": user_id, "role": role, "jti": jti, "type": "access", "exp": _exp(Config.ACCESS_TTL)}
token = jwt.encode(payload, Config.JWT_SECRET, algorithm=ALG)
return token, jti, payload["exp"]


def issue_refresh(user_id: int):
jti = uuid.uuid4().hex
payload = {"sub": user_id, "jti": jti, "type": "refresh", "exp": _exp(Config.REFRESH_TTL)}
token = jwt.encode(payload, Config.JWT_SECRET, algorithm=ALG)
return token, jti, payload["exp"]


def decode_token(token: str):
return jwt.decode(token, Config.JWT_SECRET, algorithms=[ALG])
