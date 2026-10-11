#!/usr/bin/env python3
"""
score_parser.py — Run by organizer at end of round.

alerts.log format:     <epoch_ms> | <blue_type> | <description>
  blue types: queue_anomaly | data_anomaly | control_anomaly | hardening

red_actions.log format: <epoch_ms> | <red_type> | <description>
  red types: queue_manipulation | data_manipulation | control_compromise | infra_compromise
"""

import os

ALERTS_LOG = os.path.expanduser("~/control/logs/alerts.log")
RED_LOG    = os.path.expanduser("~/control/logs/red_actions.log")

# Blue observation type → Red action type(s) it can match
RED_TO_BLUE = {
    "queue_manipulation": "queue_anomaly",
    "data_manipulation":  "data_anomaly",
    "control_compromise": "control_anomaly",
    "infra_compromise":   "control_anomaly",
}

RED_POINTS = {
    "queue_manipulation": 2,
    "data_manipulation":  2,
    "control_compromise": 2,
    "infra_compromise":   3,
}

STEALTH_BONUS    = 1
HARDENING_BONUS  = 1
HARDENING_CAP    = 3
FALSE_POS_PEN    = -1

def parse_log(filepath):
    entries = []
    if not os.path.exists(filepath):
        print(f"[WARN] Log not found: {filepath}")
        return entries
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|", 2)]
            if len(parts) == 3:
                try:
                    entries.append({
                        "timestamp":   float(parts[0]),
                        "type":        parts[1],
                        "description": parts[2],
                        "matched":     False
                    })
                except ValueError:
                    print(f"[WARN] Skipping malformed line: {line}")
    return entries

def score():
    blue_alerts = parse_log(ALERTS_LOG)
    red_actions = parse_log(RED_LOG)

    blue_score    = 0
    red_score     = 0
    report        = []
    hardening_count = 0

    for alert in blue_alerts:
        # Hardening — verified manually by organizer, no red match needed
        if alert["type"] == "hardening":
            if hardening_count < HARDENING_CAP:
                blue_score += HARDENING_BONUS
                hardening_count += 1
                report.append(f"  [+{HARDENING_BONUS}] BLUE hardening: {alert['description']}")
            else:
                report.append(f"  [+0]  BLUE hardening (cap reached): {alert['description']}")
            alert["matched"] = True
            continue

        # Find earliest unmatched red action that maps to this blue alert type
        matched_red = None
        best_lag    = float("inf")

        for red in red_actions:
            if RED_TO_BLUE.get(red["type"]) == alert["type"] and not red["matched"]:
                lag = alert["timestamp"] - red["timestamp"]
                if lag >= 0 and lag < best_lag:
                    best_lag    = lag
                    matched_red = red

        if matched_red:
            alert["matched"]       = True
            matched_red["matched"] = True

            blue_score += 1
            report.append(f"  [+1]  BLUE correct detection [{alert['type']}]: {alert['description']}")

            if best_lag <= 300:
                blue_score += 2
                report.append(f"  [+2]  BLUE time bonus: {best_lag:.1f}s (≤5 min)")
            elif best_lag <= 900:
                blue_score += 1
                report.append(f"  [+1]  BLUE time bonus: {best_lag:.1f}s (5–15 min)")
            else:
                report.append(f"  [+0]  BLUE no time bonus: {best_lag:.1f}s (>15 min)")
        else:
            blue_score += FALSE_POS_PEN
            report.append(f"  [{FALSE_POS_PEN}]  BLUE false positive [{alert['type']}]: {alert['description']}")

    for red in red_actions:
        pts = RED_POINTS.get(red["type"], 0)
        red_score += pts
        report.append(f"  [+{pts}]  RED {red['type']}: {red['description']}")

        if not red["matched"]:
            red_score += STEALTH_BONUS
            report.append(f"  [+{STEALTH_BONUS}]  RED stealth bonus: not detected by blue")

    print("=" * 55)
    print("             ROUND SCORE REPORT")
    print("=" * 55)
    for line in report:
        print(line)
    print("-" * 55)
    print(f"  BLUE TOTAL : {blue_score}")
    print(f"  RED  TOTAL : {red_score}")
    print("=" * 55)

if __name__ == "__main__":
    score()