# windows-log-analyzer

A Python tool that reads an exported Windows Security event log and flags the activity a help desk
technician or SOC analyst needs to act on: brute-force and password-spray attempts, account lockouts,
privileged group changes, new accounts, cleared audit logs, and after-hours logons.

I built this from the Active Directory hardening lab I did for my cybersecurity degree and the
account-support work I do in a HIPAA-regulated environment, where "who tried to log in as the
administrator at 2 a.m.?" is a question that actually comes up. No third-party dependencies —
standard library only.

## What it detects

| Rule | Severity | Event IDs | Logic |
|---|---|---|---|
| `failed-logon-burst` | HIGH / CRITICAL | 4625 | ≥ N failures from one source IP within a sliding window. Many accounts ⇒ **password spray** (CRITICAL); one account ⇒ **brute force** (HIGH) |
| `account-lockout` | MEDIUM / HIGH | 4740 | Any lockout; HIGH if an account locks 3+ times |
| `privileged-group-add` | CRITICAL | 4728 / 4732 / 4756 | Member added to Domain Admins, Administrators, Enterprise Admins, Backup Operators, etc. |
| `group-add` | LOW | 4728 / 4732 / 4756 | Member added to any other group |
| `audit-log-cleared` | CRITICAL | 1102 | Security log cleared — classic anti-forensics step |
| `user-created` / `user-enabled` / `password-reset` / `user-deleted` | MEDIUM / LOW | 4720 / 4722 / 4724 / 4726 | Account lifecycle changes worth a glance |
| `after-hours-logon` | LOW / MEDIUM | 4624 (types 2, 7, 10) | Interactive / unlock / RDP logons outside business hours or on weekends |

Machine accounts (`HOST$`) and SYSTEM are ignored. Group-add events resolve the member's
distinguished name (`CN=jsmith,OU=...`) to the plain username.

## Quick start

```bash
git clone https://github.com/elijahawusinu/windows-log-analyzer.git
cd windows-log-analyzer

# Try it on the bundled sample (218 events with a planted attack chain)
python generate_sample.py
python analyzer.py sample_security.csv
```

Sample output:

```
Parsed 218 events from 2026-10-19 07:46:29 to 2026-10-24 09:00:00
  logons ok: 126   failed: 86   lockouts: 1
================================================================================
[CRITICAL] failed-logon-burst     10.10.1.57
    16 failed logons in 5 min — looks like password spray. Targets: jsmith (2), kbrown (2), ...
    2026-10-22 13:05:00 → 2026-10-22 13:07:45

[CRITICAL] privileged-group-add   svc-backup2
    Added to group 'Domain Admins' (event 4728)
    2026-10-22 22:34:00

[CRITICAL] audit-log-cleared      tnguyen
    Security log cleared on SRV-DC01
    2026-10-22 22:40:00

[HIGH    ] failed-logon-burst     185.220.101.44
    47 failed logons in 5 min — looks like brute force. Targets: administrator (47)
    2026-10-21 02:14:00 → 2026-10-21 02:17:04
...
```

The sample log tells a story: an external brute force against `administrator`, then an internal
password spray from `10.10.1.57`, then that same host logs in as `tnguyen` after hours, creates
`svc-backup2`, adds it to Domain Admins, and clears the audit log. The analyzer surfaces every step.

### Using a real log

Export from Event Viewer (**Security → Save All Events As… → CSV**), or with PowerShell:

```powershell
Get-WinEvent -LogName Security -MaxEvents 50000 |
    Select-Object TimeCreated, Id, MachineName, Message |
    Export-Csv security.csv -NoTypeInformation
```

Then:

```bash
python analyzer.py security.csv
python analyzer.py security.csv --threshold 5 --window 10      # more sensitive burst detection
python analyzer.py security.csv --business-hours 8-18 --json findings.json
```

Exit code is `1` when any CRITICAL or HIGH finding exists, so the script can gate a scheduled job.

## Project layout

```
analyzer.py          # parser, detection rules, CLI
generate_sample.py   # builds sample_security.csv with a realistic attack chain
tests/
  test_analyzer.py   # 14 tests: parsing, each detector, end-to-end on the sample
```

## Running the tests

```bash
pip install -r requirements.txt
pytest
```

## Possible next steps

- Read `.evtx` directly (via `python-evtx`) instead of CSV exports
- Correlate 4625 bursts with a following 4624 from the same IP (successful brute force)
- GeoIP lookup on external source addresses
- Send CRITICAL findings to a ticketing system or Slack

## Author

Elijah Awusinu — IT support technician, A.A.S. Cybersecurity, CompTIA Security+,
B.S. Information Technology (Towson University).
