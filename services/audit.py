
from collections import Counter
from models import Audit


def summary():
rows = Audit.query.order_by(Audit.ts.desc()).limit(500).all()
reasons = Counter([r.reason for r in rows])
decisions = Counter([r.decision for r in rows])
actions = Counter([r.action for r in rows])
return {
"counts": {
"reasons": reasons,
"decisions": decisions,
"actions": actions,
"total": len(rows)
}
}
