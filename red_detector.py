#!/usr/bin/env python3
import subprocess
import re
import os
from datetime import datetime

BASELINE_TS_FILE = os.path.expanduser("~/control/logs/baseline_timestamp.txt")
RED_LOG          = os.path.expanduser("~/control/logs/red_actions.log")
AUDIT_LOG        = "/var/log/audit/audit.log"

KEY_TO_TYPE = {
    "cron":         "infra_compromise",
    "newbin":       "infra_compromise",
    "sudoers":      "infra_compromise",
    "data_delete":  "data_manipulation",
    "opsim_data":   "data_manipulation",
    "exec":         "control_compromise",
    "staging":      "infra_compromise",
    "queue_manipulation": "queue_manipulation",
}

EXCLUDE_EXES = {
    "/usr/lib/systemd/systemd-executor",
    "/usr/lib/sysstat/sadc",
    "/usr/sbin/nvme",
    "/usr/bin/env",
    "/usr/bin/sponge",
    "/usr/bin/dpkg",
}

def get_baseline_ts():
    if not os.path.exists(BASELINE_TS_FILE):
        print("[ERROR] No baseline timestamp found. Did baseline.sh run?")
        exit(1)
    with open(BASELINE_TS_FILE) as f:
        return float(f.read().strip())

def parse_audit_log(since_ts):
    since_dt = datetime.utcfromtimestamp(since_ts).strftime("%m/%d/%Y %H:%M:%S")
    result = subprocess.run(
        ["ausearch", "--start", since_dt, "-i"],
        capture_output=True, text=True
    )
    if result.returncode != 0 and not result.stdout:
        print(f"[ERROR] ausearch failed: {result.stderr}")
        exit(1)
    return result.stdout

def extract_events(raw):
    events = []
    current = {}
    for line in raw.splitlines():
        if line.startswith("----"):
            if current:
                events.append(current)
            current = {}
            continue
        ts_match = re.search(r'msg=audit\((\d+\.\d+):\d+\)', line)
        if ts_match and "timestamp" not in current:
            current["timestamp"] = float(ts_match.group(1))
        key_match = re.search(r'\bkey="?([^"\s]+)"?', line)
        if key_match:
            current["key"] = key_match.group(1)
        exe_match = re.search(r'\bexe="?([^"\s]+)"?', line)
        if exe_match:
            current["exe"] = exe_match.group(1)
        name_match = re.search(r'\bname="?([^"\s]+)"?', line)
        if name_match:
            current["name"] = name_match.group(1)
    if current:
        events.append(current)
    return events

def build_red_log(events, since_ts):
    red_entries = []
    for e in events:
        key  = e.get("key", "")
        ts   = e.get("timestamp", 0)
        exe  = e.get("exe", "unknown")
        name = e.get("name", "unknown")
        if ts < since_ts:
            continue
        if exe in EXCLUDE_EXES:
            continue
        action_type = KEY_TO_TYPE.get(key)
        if not action_type:
            continue
        red_entries.append((ts, action_type, exe + " -> " + name))
    seen = set()
    deduped = []
    for ts, atype, desc in sorted(red_entries):
        key_id = (atype, desc)
        if key_id not in seen:
            seen.add(key_id)
            deduped.append((ts, atype, desc))
    return deduped

def main():
    since_ts = get_baseline_ts()
    print("[*] Baseline timestamp: " + str(since_ts))
    print("[*] Scanning " + AUDIT_LOG + " for red actions since baseline...")
    raw    = parse_audit_log(since_ts)
    events = extract_events(raw)
    red    = build_red_log(events, since_ts)
    os.makedirs(os.path.dirname(RED_LOG), exist_ok=True)
    with open(RED_LOG, "w") as f:
        for ts, atype, desc in red:
            f.write(str(round(ts, 3)) + " | " + atype + " | " + desc + "\n")
    print("[*] " + str(len(red)) + " red action(s) detected. Written to " + RED_LOG)
    for ts, atype, desc in red:
        print("  " + str(round(ts, 3)) + " | " + atype + " | " + desc)

if __name__ == "__main__":
    main()