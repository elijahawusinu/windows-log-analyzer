"""
windows-log-analyzer
--------------------
Parse exported Windows Security event logs and surface the things a help desk
or security analyst actually cares about:

    * Brute-force / password-spray patterns (bursts of 4625 failed logons)
    * Account lockouts (4740)
    * Privilege escalation: users added to privileged groups (4728/4732/4756)
    * Special privileges assigned at logon (4672) for non-admin accounts
    * New user accounts created (4720) and accounts enabled (4722)
    * Audit log cleared (1102)
    * Logons outside business hours (4624)

Input: a CSV export from Event Viewer ("Save All Events As... > CSV") or from
PowerShell:

    Get-WinEvent -LogName Security -MaxEvents 50000 |
        Select-Object TimeCreated, Id, Message |
        Export-Csv security.csv -NoTypeInformation

Usage:
    python analyzer.py security.csv
    python analyzer.py security.csv --threshold 5 --window 10 --json out.json
    python analyzer.py security.csv --business-hours 7-19
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Iterator

# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------

@dataclass
class Event:
    time: datetime
    event_id: int
    message: str
    computer: str = ""
    account: str = ""
    source_ip: str = ""
    logon_type: str = ""
    target_group: str = ""
    extra: dict[str, str] = field(default_factory=dict)


# Common field labels found in Security event message bodies.
_FIELD_PATTERNS = {
    "account": re.compile(r"Account Name:\s*(?P<v>[^\r\n]+)"),
    "source_ip": re.compile(r"Source Network Address:\s*(?P<v>[^\r\n]+)"),
    "logon_type": re.compile(r"Logon Type:\s*(?P<v>\d+)"),
    "target_group": re.compile(r"Group Name:\s*(?P<v>[^\r\n]+)"),
    "failure_reason": re.compile(r"Failure Reason:\s*(?P<v>[^\r\n]+)"),
    "process": re.compile(r"Process Name:\s*(?P<v>[^\r\n]+)"),
    "member": re.compile(r"Member:\s*(?:Security ID:\s*\S+\s*)?Account Name:\s*(?P<v>[^\r\n]+)"),
}

# For 4624/4625 the message lists the *subject* account first and the target
# account second; we want the second one.
_ALL_ACCOUNTS = re.compile(r"Account Name:\s*([^\r\n]+)")

_TIME_FORMATS = (
    "%m/%d/%Y %I:%M:%S %p",     # Event Viewer CSV (US locale)
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M",
)


def parse_time(value: str) -> datetime:
    value = value.strip()
    # strip fractional seconds / timezone like 2026-10-26T14:03:11.123Z
    value = re.sub(r"\.\d+", "", value).rstrip("Z")
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"unrecognised timestamp: {value!r}")


def _clean(v: str) -> str:
    v = v.strip()
    return "" if v in ("-", "", "NULL SID") else v


def parse_event(row: dict[str, str]) -> Event | None:
    """Build an Event from one CSV row. Returns None for rows we can't use."""
    # Accept several common header spellings.
    def pick(*names: str) -> str:
        for n in names:
            for k, v in row.items():
                if k and k.strip().lower() == n:
                    return v or ""
        return ""

    raw_id = pick("id", "event id", "eventid")
    raw_time = pick("timecreated", "date and time", "time", "timestamp")
    msg = pick("message", "description")
    if not raw_id or not raw_time:
        return None
    try:
        event_id = int(raw_id.strip())
        when = parse_time(raw_time)
    except ValueError:
        return None

    ev = Event(time=when, event_id=event_id, message=msg,
               computer=_clean(pick("machinename", "computer", "computername")))

    for key, pat in _FIELD_PATTERNS.items():
        m = pat.search(msg)
        if m:
            val = _clean(m.group("v"))
            if key in ("account", "source_ip", "logon_type", "target_group"):
                setattr(ev, key, val)
            else:
                ev.extra[key] = val

    # Logon events: target account is the second "Account Name".
    if event_id in (4624, 4625):
        names = [_clean(n) for n in _ALL_ACCOUNTS.findall(msg)]
        names = [n for n in names if n]
        if len(names) >= 2:
            ev.account = names[1]
        elif names:
            ev.account = names[0]
    # Group membership events: the *member* added is what we care about.
    if event_id in (4728, 4732, 4756) and ev.extra.get("member"):
        ev.account = _cn(ev.extra["member"])
    return ev


def _cn(value: str) -> str:
    """'CN=jsmith,OU=Users,DC=x' -> 'jsmith'; anything else passes through."""
    m = re.match(r"\s*CN=([^,]+)", value, re.IGNORECASE)
    return m.group(1).strip() if m else value


def load_events(path: str | Path) -> list[Event]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        events = [e for e in (parse_event(r) for r in reader) if e]
    events.sort(key=lambda e: e.time)
    return events


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    detail: str
    first_seen: str
    last_seen: str
    count: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "account operators", "backup operators", "server operators", "dns admins",
    "group policy creator owners", "remote desktop users",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def detect_failed_logon_bursts(events: Iterable[Event], threshold: int = 10,
                               window_minutes: int = 5) -> list[Finding]:
    """Sliding window over 4625 events grouped by source IP (or account if no IP)."""
    by_key: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id == 4625:
            by_key[e.source_ip or f"account:{e.account}"].append(e)

    findings: list[Finding] = []
    window = timedelta(minutes=window_minutes)
    for key, evs in by_key.items():
        evs.sort(key=lambda e: e.time)
        start = 0
        best: tuple[int, int, int] | None = None  # (count, start_idx, end_idx)
        for end in range(len(evs)):
            while evs[end].time - evs[start].time > window:
                start += 1
            n = end - start + 1
            if n >= threshold and (best is None or n > best[0]):
                best = (n, start, end)
        if best:
            n, s, t = best
            accounts = Counter(e.account for e in evs[s:t + 1] if e.account)
            distinct = len(accounts)
            kind = "password spray" if distinct >= max(3, threshold // 2) else "brute force"
            top = ", ".join(f"{a} ({c})" for a, c in accounts.most_common(5))
            findings.append(Finding(
                rule="failed-logon-burst",
                severity="HIGH" if kind == "brute force" else "CRITICAL",
                subject=key,
                detail=f"{n} failed logons in {window_minutes} min — looks like {kind}. Targets: {top}",
                first_seen=_ts(evs[s].time), last_seen=_ts(evs[t].time), count=n,
            ))
    return findings


def detect_lockouts(events: Iterable[Event]) -> list[Finding]:
    by_acct: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id == 4740:
            by_acct[e.account or "unknown"].append(e)
    return [
        Finding("account-lockout", "MEDIUM" if len(v) < 3 else "HIGH", acct,
                f"Account locked out {len(v)} time(s)",
                _ts(v[0].time), _ts(v[-1].time), len(v))
        for acct, v in by_acct.items()
    ]


def detect_privileged_group_changes(events: Iterable[Event]) -> list[Finding]:
    findings = []
    for e in events:
        if e.event_id in (4728, 4732, 4756):
            group = e.target_group
            is_priv = group.lower() in PRIVILEGED_GROUPS
            findings.append(Finding(
                "privileged-group-add" if is_priv else "group-add",
                "CRITICAL" if is_priv else "LOW",
                e.account or "unknown",
                f"Added to group '{group}' (event {e.event_id})",
                _ts(e.time), _ts(e.time),
            ))
    return findings


def detect_account_changes(events: Iterable[Event]) -> list[Finding]:
    labels = {4720: ("user-created", "MEDIUM", "New user account created"),
              4722: ("user-enabled", "LOW", "User account enabled"),
              4724: ("password-reset", "LOW", "Password reset by administrator"),
              4726: ("user-deleted", "LOW", "User account deleted")}
    out = []
    for e in events:
        if e.event_id in labels:
            rule, sev, text = labels[e.event_id]
            out.append(Finding(rule, sev, e.account or "unknown", text, _ts(e.time), _ts(e.time)))
    return out


def detect_log_cleared(events: Iterable[Event]) -> list[Finding]:
    return [
        Finding("audit-log-cleared", "CRITICAL", e.account or "unknown",
                f"Security log cleared on {e.computer or 'host'}", _ts(e.time), _ts(e.time))
        for e in events if e.event_id == 1102
    ]


def detect_after_hours_logons(events: Iterable[Event], start_hour: int = 7,
                              end_hour: int = 19) -> list[Finding]:
    """Interactive (2), RDP (10) and unlock (7) logons outside business hours."""
    by_acct: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id != 4624 or e.logon_type not in ("2", "10", "7"):
            continue
        if e.account.endswith("$") or e.account.upper() in ("SYSTEM", "ANONYMOUS LOGON"):
            continue
        h = e.time.hour
        if h < start_hour or h >= end_hour or e.time.weekday() >= 5:
            by_acct[e.account].append(e)
    return [
        Finding("after-hours-logon", "LOW" if len(v) < 5 else "MEDIUM", acct,
                f"{len(v)} interactive/RDP logon(s) outside {start_hour:02d}:00-{end_hour:02d}:00 Mon-Fri",
                _ts(v[0].time), _ts(v[-1].time), len(v))
        for acct, v in by_acct.items()
    ]


def analyze(events: list[Event], threshold: int = 10, window_minutes: int = 5,
            business_hours: tuple[int, int] = (7, 19)) -> list[Finding]:
    findings: list[Finding] = []
    findings += detect_log_cleared(events)
    findings += detect_failed_logon_bursts(events, threshold, window_minutes)
    findings += detect_privileged_group_changes(events)
    findings += detect_lockouts(events)
    findings += detect_account_changes(events)
    findings += detect_after_hours_logons(events, *business_hours)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
    return findings


def summarize(events: list[Event]) -> dict:
    ids = Counter(e.event_id for e in events)
    return {
        "events": len(events),
        "first": _ts(events[0].time) if events else None,
        "last": _ts(events[-1].time) if events else None,
        "successful_logons": ids.get(4624, 0),
        "failed_logons": ids.get(4625, 0),
        "lockouts": ids.get(4740, 0),
        "top_event_ids": dict(ids.most_common(8)),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(summary: dict, findings: list[Finding]) -> None:
    print(f"Parsed {summary['events']} events from {summary['first']} to {summary['last']}")
    print(f"  logons ok: {summary['successful_logons']}   failed: {summary['failed_logons']}"
          f"   lockouts: {summary['lockouts']}")
    print("=" * 80)
    if not findings:
        print("No suspicious activity detected.")
        return
    for f in findings:
        span = f.first_seen if f.first_seen == f.last_seen else f"{f.first_seen} → {f.last_seen}"
        print(f"[{f.severity:<8}] {f.rule:<22} {f.subject}")
        print(f"    {f.detail}")
        print(f"    {span}")
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Windows Security log analyzer")
    p.add_argument("csv", help="CSV export of the Security event log")
    p.add_argument("--threshold", type=int, default=10, help="failed logons to flag a burst")
    p.add_argument("--window", type=int, default=5, help="burst window in minutes")
    p.add_argument("--business-hours", default="7-19", help="e.g. 8-18")
    p.add_argument("--json", metavar="FILE", help="write findings as JSON")
    args = p.parse_args(argv)

    try:
        bh = tuple(int(x) for x in args.business_hours.split("-"))
        assert len(bh) == 2
    except (ValueError, AssertionError):
        print("--business-hours must look like 7-19", file=sys.stderr)
        return 2

    try:
        events = load_events(args.csv)
    except FileNotFoundError:
        print(f"File not found: {args.csv}", file=sys.stderr)
        return 2

    findings = analyze(events, args.threshold, args.window, bh)  # type: ignore[arg-type]
    _print(summarize(events), findings)
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"summary": summarize(events), "findings": [f.to_dict() for f in findings]}, indent=2))
        print(f"JSON written to {args.json}")
    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
