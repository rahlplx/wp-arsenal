"""
Feedback store — tracks human review decisions on mined patterns.

Stores accepted/rejected/deferred decisions in a JSON file
for learning which patterns are valuable.
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any


def add_feedback(
    store_path: str,
    pattern_id: str,
    status: str,
    notes: str = "",
) -> None:
    """Add or update feedback for a pattern.

    Args:
        store_path: Path to the JSON feedback file
        pattern_id: Unique pattern identifier
        status: One of "accepted", "rejected", "deferred"
        notes: Optional reviewer notes
    """
    data = load_feedback(store_path)

    data = [entry for entry in data if entry.get("id") != pattern_id]

    data.append({
        "id": pattern_id,
        "status": status,
        "notes": notes,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    })

    os.makedirs(os.path.dirname(store_path) or ".", exist_ok=True)
    with open(store_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_feedback(store_path: str) -> List[Dict[str, Any]]:
    """Load feedback entries from the store file.

    Returns empty list if file doesn't exist.
    """
    if not os.path.exists(store_path):
        return []

    try:
        with open(store_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except (json.JSONDecodeError, OSError):
        return []
