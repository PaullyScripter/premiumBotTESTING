import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

BASE_DIR = Path(__file__).resolve().parent.parent  # premiumBotTESTING/
DATA_DIR = BASE_DIR / "data"  # make sure this exists

SUB_FILES = {
    "monthly": DATA_DIR / "monthly_subs.json",
    "yearly": DATA_DIR / "yearly_subs.json",
    "lifetime": DATA_DIR / "lifetime_subs.json",
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_at_for(tier: str, now_iso: str) -> str | None:
    now = datetime.fromisoformat(now_iso)
    if tier == "monthly":
        return (now + timedelta(days=30)).isoformat()
    elif tier == "yearly":
        return (now + timedelta(days=365)).isoformat()
    elif tier == "lifetime":
        return None  # lifetime
    else:
        raise ValueError(f"Unknown tier: {tier}")


def _ensure_file(path: Path) -> dict:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        initial = {"users": []}
        path.write_text(json.dumps(initial, indent=2), encoding="utf-8")
        return initial
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_subscription(user_id: int, tier: str, ref: str):
    """
    ref = can be code or transaction id.
    """
    file_path = SUB_FILES[tier]
    data = _ensure_file(file_path)

    now_iso = utcnow_iso()
    exp_iso = _expires_at_for(tier, now_iso)

    found = next((u for u in data["users"] if u.get("user_id") == user_id), None)
    if found:
        found["started_at"] = now_iso
        found["expires_at"] = exp_iso
        found["ref"] = ref
    else:
        data["users"].append(
            {
                "user_id": user_id,
                "started_at": now_iso,
                "expires_at": exp_iso,
                "ref": ref,
            }
        )
    save_json(file_path, data)
