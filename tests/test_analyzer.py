import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyzer import (  # noqa: E402
    Event,
    analyze,
    detect_account_changes,
    detect_after_hours_logons,
    detect_failed_logon_bursts,
    detect_lockouts,
    detect_log_cleared,
    detect_privileged_group_changes,
    load_events,
    main,
    parse_event,
    parse_time,
)
import generate_sample  # noqa: E402

MON = datetime(2026, 10, 19, 9, 0, 0)  # Monday 09:00


def ev(eid, minutes=0, **kw):
    return Event(time=MON + timedelta(minutes=minutes), event_id=eid, message="", **kw)


# -- parsing ----------------------------------------------------------------

def test_parse_time_formats():
    assert parse_time("10/19/2026 02:14:00 PM").hour == 14
    assert parse_time("2026-10-19 14:14:00").minute == 14
    assert parse_time("2026-10-19T14:14:00.123Z").second == 0


def test_parse_time_rejects_garbage():
    with pytest.raises(ValueError):
        parse_time("yesterday")


def test_parse_event_extracts_target_account_and_ip():
    msg = ("An account failed to log on.\n\nSubject:\n\tAccount Name:\t\t-\n\n"
           "Logon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\tjsmith\n"
           "\nNetwork Information:\n\tSource Network Address:\t10.0.0.5\n")
    e = parse_event({"TimeCreated": "10/19/2026 09:00:00 AM", "Id": "4625", "Message": msg})
    assert e.account == "jsmith"
    assert e.source_ip == "10.0.0.5"
    assert e.logon_type == "3"


def test_parse_event_handles_alternate_headers_and_bad_rows():
    assert parse_event({"Event ID": "4624", "Date and Time": "2026-10-19 09:00:00",
                        "Description": "x"}).event_id == 4624
    assert parse_event({"Id": "abc", "TimeCreated": "2026-10-19 09:00:00", "Message": ""}) is None
    assert parse_event({"Id": "4624", "Message": ""}) is None


def test_group_add_uses_member_cn():
    msg = generate_sample.msg_group_add("svc-x", "Domain Admins", "admin")
    e = parse_event({"TimeCreated": "2026-10-19 09:00:00", "Id": "4728", "Message": msg})
    assert e.account == "svc-x"
    assert e.target_group == "Domain Admins"


# -- detectors ----------------------------------------------------------------

def test_brute_force_detected_above_threshold():
    events = [ev(4625, minutes=i * 0.1, account="admin", source_ip="1.2.3.4") for i in range(12)]
    f = detect_failed_logon_bursts(events, threshold=10, window_minutes=5)
    assert len(f) == 1
    assert f[0].severity == "HIGH" and "brute force" in f[0].detail
    assert f[0].count == 12


def test_no_burst_when_spread_out():
    events = [ev(4625, minutes=i * 10, account="admin", source_ip="1.2.3.4") for i in range(12)]
    assert detect_failed_logon_bursts(events, threshold=10, window_minutes=5) == []


def test_password_spray_is_critical():
    users = [f"user{i}" for i in range(10)]
    events = [ev(4625, minutes=i * 0.2, account=users[i % 10], source_ip="9.9.9.9") for i in range(20)]
    f = detect_failed_logon_bursts(events, threshold=10)
    assert f[0].severity == "CRITICAL" and "spray" in f[0].detail


def test_lockout_severity_scales():
    one = [ev(4740, account="a")]
    three = [ev(4740, minutes=i, account="b") for i in range(3)]
    assert detect_lockouts(one)[0].severity == "MEDIUM"
    assert detect_lockouts(three)[0].severity == "HIGH"


def test_privileged_group_vs_ordinary_group():
    f = detect_privileged_group_changes([
        ev(4728, account="x", target_group="Domain Admins"),
        ev(4732, account="y", target_group="Printer Users"),
    ])
    assert [(x.rule, x.severity) for x in f] == [
        ("privileged-group-add", "CRITICAL"), ("group-add", "LOW")]


def test_account_changes_and_log_cleared():
    assert detect_account_changes([ev(4720, account="new")])[0].rule == "user-created"
    assert detect_log_cleared([ev(1102, account="bad", computer="DC")])[0].severity == "CRITICAL"


def test_after_hours_logons():
    events = [
        ev(4624, minutes=0, account="day", logon_type="2"),                  # Mon 09:00 - fine
        ev(4624, minutes=14 * 60, account="late", logon_type="10"),          # Mon 23:00
        ev(4624, minutes=5 * 24 * 60, account="sat", logon_type="2"),        # Sat 09:00
        ev(4624, minutes=14 * 60, account="SRV01$", logon_type="2"),         # machine acct
        ev(4624, minutes=14 * 60, account="net", logon_type="3"),            # network logon ignored
    ]
    subjects = {f.subject for f in detect_after_hours_logons(events)}
    assert subjects == {"late", "sat"}


# -- end to end -------------------------------------------------------------

def test_sample_log_end_to_end(tmp_path, capsys):
    csv_path = tmp_path / "sample.csv"
    generate_sample.main(str(csv_path))
    events = load_events(csv_path)
    assert len(events) > 200
    findings = analyze(events)
    rules = {f.rule for f in findings}
    assert {"failed-logon-burst", "privileged-group-add", "audit-log-cleared",
            "account-lockout", "user-created"} <= rules
    # highest-severity first
    assert findings[0].severity == "CRITICAL"

    out_json = tmp_path / "out.json"
    code = main([str(csv_path), "--json", str(out_json)])
    assert code == 1  # critical findings present
    assert out_json.exists()
    assert "password spray" in capsys.readouterr().out


def test_main_bad_args(capsys):
    assert main(["nope.csv"]) == 2
    assert main(["nope.csv", "--business-hours", "x"]) == 2
