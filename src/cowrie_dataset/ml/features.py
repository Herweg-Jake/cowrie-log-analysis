"""Feature extraction for the ML pipeline.

The 38 engineered features (F1..F38) live under ``session["features"]`` in
labeled_sessions.jsonl. We pull them in a fixed order, plus a handful of
numeric host fields that are obviously useful (root username flag,
duration, download counts). Everything stays in a deterministic order so
that a model trained today still loads tomorrow's predictions correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np


# F1..F38 in order. Hard-coded so a renamed feature in the upstream
# extractor breaks loudly instead of silently scrambling the model input.
KEYWORDS = [
    ("F1", "bash"), ("F2", "shell"), ("F3", "exit"), ("F4", "help"),
    ("F5", "passwd"), ("F6", "chpasswd"), ("F7", "useradd"),
    ("F8", "dot_file"), ("F9", "sh_file"), ("F10", "slash_file"),
    ("F11", "perl"), ("F12", "python"), ("F13", "bin"), ("F14", "chmod"),
    ("F15", "sudo_su"), ("F16", "rm"), ("F17", "history"),
    ("F18", "cat_etc"), ("F19", "uname"), ("F20", "wc"),
    ("F21", "crontab"), ("F22", "w"), ("F23", "ps"), ("F24", "free"),
    ("F25", "lscpu"), ("F26", "nproc"), ("F27", "uptime"),
    ("F28", "wget"), ("F29", "tftp"), ("F30", "scp"), ("F31", "ping"),
    ("F32", "kill"), ("F33", "reboot"),
]
_BASE = [f"{idx}_keyword_{name}" for idx, name in KEYWORDS] + [
    "F34_count_base64",
    "F35_count_hex",
    "F36_count_url",
    "F37_message_length",
    "F38_messages_per_sec",
]

# Extra host features that are numeric and cheap to compute. Named
# conservatively - if any of these show up missing in real data we impute
# with the median over the training fold rather than zero, see train.py.
_HOST = [
    "F40_src_port_high",
    "F42_username_is_root",
    "F42_username_length",
    "F43_password_length",
    "F43_password_is_common",
    "F44_duration",
    "F45_received_size_avg",
    "F46_has_files",
    "F46_download_count",
    "F46_upload_count",
]

FEATURE_ORDER: list[str] = _BASE + _HOST


def extract_features(session: dict) -> np.ndarray:
    """Pull features in canonical order. Missing values become ``np.nan``."""
    feats = session.get("features") or {}
    out = np.empty(len(FEATURE_ORDER), dtype=np.float64)
    for i, key in enumerate(FEATURE_ORDER):
        v = feats.get(key)
        if v is None or isinstance(v, str):
            out[i] = np.nan
        else:
            out[i] = float(v)
    return out


def write_schema(path: str | Path) -> None:
    """Persist the canonical feature ordering alongside saved models."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({
        "version": 1,
        "features": FEATURE_ORDER,
        "n_features": len(FEATURE_ORDER),
    }, indent=2))


def load_schema(path: str | Path) -> list[str]:
    return json.loads(Path(path).read_text())["features"]
