"""
Generate a realistic sample Security log CSV (sample_security.csv) so the
analyzer can be demoed without exporting a real log.

    python generate_sample.py            # writes sample_security.csv
    python generate_sample.py out.csv    # custom path
"""
from __future__ import annotations

import csv
import random
import sys
from datetime import datetime, timedelta

random.seed(42)

USERS = ["jsmith", "kbrown", "mlee", "tnguyen", "rpatel", "agarcia", "dwilson", "elijah.a"]
HOSTS = ["WS-CLINIC-01", "WS-CLINIC-02", "WS-FRONT-03", "SRV-DC01", "SRV-FILE01"]
START = datetime(2026, 10, 19, 0, 0, 0)  # a Monday


def msg_logon(ok: bool, subject: str, target: str, ltype: int, ip: str, reason: str = "") -> str:
    head = "An account was successfully logged on." if ok else "An account failed to log on."
    body = (
        f"{head}\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\t{subject}\n"
        f"\tAccount Domain:\t\tCLINIC\n\nLogon Type:\t\t\t{ltype}\n\n"
        f"Account For Which Logon Failed:\n" if not ok else
        f"{head}\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\t{subject}\n"
        f"\tAccount Domain:\t\tCLINIC\n\nLogon Type:\t\t\t{ltype}\n\nNew Logon:\n"
    )
    body += f"\tSecurity ID:\t\tS-1-5-21-1\n\tAccount Name:\t\t{target}\n\tAccount Domain:\t\tCLINIC\n"
    if reason:
        body += f"\nFailure Information:\n\tFailure Reason:\t\t{reason}\n"
    body += f"\nNetwork Information:\n\tWorkstation Name:\tWS\n\tSource Network Address:\t{ip}\n\tSource Port:\t\t0\n"
    return body


def msg_group_add(member: str, group: str, by: str) -> str:
    return (f"A member was added to a security-enabled global group.\n\nSubject:\n"
            f"\tAccount Name:\t\t{by}\n\nMember:\n\tSecurity ID:\t\tS-1-5-21-9\n"
            f"\tAccount Name:\t\tCN={member},OU=Users,DC=clinic,DC=local\n\nGroup:\n"
            f"\tSecurity ID:\t\tS-1-5-32-544\n\tGroup Name:\t\t{group}\n\tGroup Domain:\t\tCLINIC\n")


def msg_simple(text: str, account: str) -> str:
    return f"{text}\n\nSubject:\n\tAccount Name:\t\t{account}\n\tAccount Domain:\t\tCLINIC\n"


def main(path: str = "sample_security.csv") -> None:
    rows: list[tuple[datetime, int, str, str]] = []

    # Normal workday logons
    for day in range(5):
        base = START + timedelta(days=day)
        for u in USERS:
            for _ in range(random.randint(2, 5)):
                t = base.replace(hour=random.randint(7, 17), minute=random.randint(0, 59),
                                 second=random.randint(0, 59))
                rows.append((t, 4624, random.choice(HOSTS),
                             msg_logon(True, "-", u, random.choice([2, 2, 2, 10, 3]), "10.10.1.%d" % random.randint(20, 90))))
            # occasional single typo
            if random.random() < 0.4:
                t = base.replace(hour=random.randint(8, 16), minute=random.randint(0, 59))
                rows.append((t, 4625, random.choice(HOSTS),
                             msg_logon(False, "-", u, 2, "10.10.1.%d" % random.randint(20, 90),
                                       "Unknown user name or bad password.")))

    # Brute force against one account from one external IP (day 3, 02:14)
    t0 = START + timedelta(days=2, hours=2, minutes=14)
    for i in range(47):
        rows.append((t0 + timedelta(seconds=i * 4), 4625, "SRV-DC01",
                     msg_logon(False, "-", "administrator", 3, "185.220.101.44",
                               "Unknown user name or bad password.")))
    rows.append((t0 + timedelta(minutes=4), 4740, "SRV-DC01",
                 msg_simple("A user account was locked out.", "administrator")))

    # Password spray: many accounts, few attempts each, from one internal IP (day 4, 13:05)
    t1 = START + timedelta(days=3, hours=13, minutes=5)
    for i, u in enumerate(USERS * 2):
        rows.append((t1 + timedelta(seconds=i * 11), 4625, "SRV-DC01",
                     msg_logon(False, "-", u, 3, "10.10.1.57", "Unknown user name or bad password.")))

    # Privilege escalation + new account + log cleared (day 4, evening)
    t2 = START + timedelta(days=3, hours=22, minutes=31)
    rows.append((t2, 4624, "SRV-DC01", msg_logon(True, "-", "tnguyen", 10, "10.10.1.57")))
    rows.append((t2 + timedelta(minutes=2), 4720, "SRV-DC01",
                 msg_simple("A user account was created.", "svc-backup2")))
    rows.append((t2 + timedelta(minutes=3), 4728, "SRV-DC01",
                 msg_group_add("svc-backup2", "Domain Admins", "tnguyen")))
    rows.append((t2 + timedelta(minutes=4), 4732, "SRV-DC01",
                 msg_group_add("tnguyen", "Remote Desktop Users", "tnguyen")))
    rows.append((t2 + timedelta(minutes=9), 1102, "SRV-DC01",
                 msg_simple("The audit log was cleared.", "tnguyen")))

    # Harmless group add
    rows.append((START + timedelta(days=1, hours=10), 4732, "SRV-DC01",
                 msg_group_add("agarcia", "Printer Users", "elijah.a")))

    # Weekend logon
    rows.append((START + timedelta(days=5, hours=9), 4624, "WS-FRONT-03",
                 msg_logon(True, "-", "rpatel", 2, "10.10.1.33")))

    rows.sort(key=lambda r: r[0])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["TimeCreated", "Id", "MachineName", "Message"])
        for t, eid, host, m in rows:
            w.writerow([t.strftime("%m/%d/%Y %I:%M:%S %p"), eid, host, m])
    print(f"Wrote {len(rows)} events to {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample_security.csv")
