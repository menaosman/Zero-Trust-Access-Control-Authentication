# Zero-Trust-Access-Control-Authentication
# Zero-Trust Access Control (Flask)


**Features**: Password hashing (argon2), TOTP MFA, JWT (access/refresh, rotation), RBAC, simulated device attestation, policy engine, audit logs, minimal UI.


## Quickstart
1) Python 3.10+
2) Create venv & install deps:
```bash
python -m venv .venv
source .venv/bin/activate # Windows: .venv\Scripts\activate
pip install -r requirements.txt
