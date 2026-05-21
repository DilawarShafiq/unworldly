"""Real-time danger alerts for Unworldly.

Fires when a DANGER event is detected during a watch session.
Supports: webhook URL (HTTP POST), desktop OS notification.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .types import Session, WatchEvent


def _webhook(url: str, event: WatchEvent, session: Session) -> None:
    """POST event data to a webhook URL."""
    payload = {
        "source": "unworldly",
        "session_id": session.id,
        "agent": session.agent.name if session.agent else None,
        "risk_score": session.summary.risk_score,
        "event": {
            "timestamp": event.timestamp,
            "type": event.type.value,
            "path": event.path,
            "risk": event.risk.value,
            "reason": event.reason,
        },
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "unworldly/0.5.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
    except (urllib.error.URLError, OSError):
        pass  # non-blocking — never crash the watcher


def _desktop(title: str, message: str) -> None:
    """Send an OS desktop notification (best-effort, never raises)."""
    try:
        if sys.platform == "darwin":
            script = f'display notification "{message}" with title "{title}"'
            subprocess.run(["osascript", "-e", script], check=False, timeout=3)
        elif sys.platform == "win32":
            ps = (
                f"Add-Type -AssemblyName System.Windows.Forms; "
                f"$n = New-Object System.Windows.Forms.NotifyIcon; "
                f"$n.Icon = [System.Drawing.SystemIcons]::Warning; "
                f"$n.Visible = $true; "
                f"$n.ShowBalloonTip(5000, '{title}', '{message}', "
                f"[System.Windows.Forms.ToolTipIcon]::Warning)"
            )
            subprocess.run(["powershell", "-Command", ps], check=False, timeout=5)
        else:
            subprocess.run(["notify-send", "-u", "critical", title, message], check=False, timeout=3)
    except Exception:
        pass


def fire_alert(on_danger: str, event: WatchEvent, session: Session) -> None:
    """Dispatch a danger alert to the configured target.

    Args:
        on_danger: Either a webhook URL (http/https) or the string "desktop".
        event:     The WatchEvent that triggered the alert.
        session:   Current recording session (for context).
    """
    reason = event.reason or event.path
    title = "🚨 Unworldly — Danger Detected"
    message = f"{event.type.value.upper()}: {reason[:120]}"

    if on_danger == "desktop":
        _desktop(title, message)
    elif on_danger.startswith("http://") or on_danger.startswith("https://"):
        _webhook(on_danger, event, session)
    # Unknown target → silently ignore (don't crash watcher)
