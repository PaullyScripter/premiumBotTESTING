import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any

# Path: backend/
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

# Our three JSON files
SUB_FILES = {
    "monthly": DATA_DIR / "monthly_user.json",
    "yearly": DATA_DIR / "yearly_user.json",
    "lifetime": DATA_DIR / "lifetime_user.json",
}


def _ensure_file(path: Path) -> dict:
    """Make sure file exists with {'users': []} and return loaded JSON."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        initial = {"users": []}
        path.write_text(json.dumps(initial, indent=2), encoding="utf-8")
        return initial
    return json.loads(path.read_text(encoding="utf-8"))


def _save(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_at_for(tier: str, start_iso: str) -> str | None:
    """Given tier + start time, compute expiry iso string or None for lifetime."""
    start = datetime.fromisoformat(start_iso)
    if tier == "monthly":
        return (start + timedelta(days=30)).isoformat()
    if tier == "yearly":
        return (start + timedelta(days=365)).isoformat()
    if tier == "lifetime":
        return None
    raise ValueError(f"Unknown tier: {tier}")


def add_subscription(user_id: int, tier: str, invoice_id: str):
    """
    Add or renew premium for a user.

    - user_id: Discord user id (int)
    - tier: 'monthly' | 'yearly' | 'lifetime'
    - invoice_id: we store this in 'code' field of JSON
    """
    tier = tier.lower()
    if tier not in SUB_FILES:
        raise ValueError(f"Unknown tier {tier}")

    path = SUB_FILES[tier]
    data = _ensure_file(path)

    now_iso = utcnow_iso()
    exp_iso = _expires_at_for(tier, now_iso)

    # Check if user already exists in this tier file
    found = next((u for u in data["users"] if u.get("user_id") == user_id), None)

    if found:
        found["started_at"] = now_iso
        found["expires_at"] = exp_iso
        found["code"] = invoice_id
    else:
        data["users"].append(
            {
                "user_id": user_id,
                "started_at": now_iso,
                "expires_at": exp_iso,
                "code": invoice_id,
            }
        )

    _save(path, data)


def user_is_active(user_id: int):
    """
    Check if user is premium.

    Returns: (is_active: bool, tier: str | None, expires_at: str | None)
    """
    now = datetime.now(timezone.utc)

    for tier, path in SUB_FILES.items():
        data = _ensure_file(path)
        for u in data["users"]:
            if u.get("user_id") == user_id:
                expires = u.get("expires_at")
                if expires is None:  # lifetime
                    return True, tier, None
                exp_dt = datetime.fromisoformat(expires)
                if now < exp_dt:
                    return True, tier, expires
                else:
                    # was premium but expired
                    return False, tier, expires

    # no entry found
    return False, None, None

def grant_subscription_from_webhook(user_id: int, plan: str, payload: Dict[str, Any]) -> None:
    """
    Called by the webhook once a payment is confirmed.

    plan: "monthly" / "yearly" / "lifetime"
    payload: full Cryptomus webhook JSON (we use it just to store an invoice id).
    """
    tier = (plan or "").lower()
    if tier not in ("monthly", "yearly", "lifetime"):
        raise ValueError(f"Unknown plan type: {plan}")

    # Use Cryptomus identifiers as the "code" field in your JSON
    invoice_id = payload.get("uuid") or payload.get("order_id") or "cryptomus"

    # Reuse your existing subscription logic
    add_subscription(user_id, tier, invoice_id)
