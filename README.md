# Hawaii-Data-Science-Institute-Hackathon Monitoring and Scoring

A log-driven monitoring and scoring system developed for the University of Hawaiʻi Virtual Telescope Environment (UHVTE) Hackathon, a Spring 2026 capstone project at the Hawaiʻi Data Science Institute.

The hackathon simulates attacks and defenses against an operational control layer built around Rubin OpSim outputs. Rubin itself remains the authoritative simulation ground truth and is not the attack target.

This repository contains the **cybersecurity** component: baseline collection, audit-based action detection, Blue Team alert submission, and automated scoring.

## Repository Files

| File | Purpose |
|---|---|
| `uhvte.rules` | Configures auditd to record commands and changes to watched files and directories. |
| `collect_baseline.sh` | Captures a system snapshot and saves the round's start timestamp. |
| `alert.sh` | Lets Blue Team submit timestamped detections and hardening reports. |
| `red_detector.py` | Extracts and classifies audit events after the baseline into `red_actions.log`. |
| `score_parser.py` | Matches Blue Team alerts to recorded actions and prints the round's score report. |

## Testbed Context

The original project used four FABRIC virtual machines:

| VM | Role |
|---|---|
| `opsim` | Rubin OpSim simulation data and telescope control API. |
| `mgmt` | Audit monitoring, baseline collection, and scoring. |
| `team1` | Red Team attacker environment. |
| `team2` | Blue Team defender environment. |

The telescope control API was a separate contribution by Noah Munz and is not included in this repository.

## Exercise Flow

```text
Organizer takes baseline
          |
          v
Red Team attacks ----> auditd records watched activity
          |                         |
          v                         v
Blue Team detects           red_detector.py
          |                         |
          v                         v
      alert.sh                red_actions.log
          |                         |
          v                         |
      alerts.log -------------------+
                                    |
                                    v
                             score_parser.py
                                    |
                                    v
                             Round score report
```

### 1. Prepare the Exercise

Before the round:

- Install and configure auditd on the monitored host.
- Load the audit rules.
- Ensure the rule keys match `KEY_TO_TYPE` in `red_detector.py`.
- Create the expected log directory.
- Ensure timestamps are synchronized across any hosts involved in detection and alert submission.
- Start with an empty `alerts.log`.

The scripts use paths under `/home/ubuntu/control/logs` or `~/control/logs`. Run them in the intended deployment environment or adjust the paths consistently.

### 2. Organizer Takes a Baseline

Before attacks begin, the organizer runs:

```bash
bash collect_baseline.sh
```

The script creates:

- `baseline_timestamp.txt`: the round's start time in Unix epoch seconds with millisecond precision.
- `baseline_<timestamp>.txt`: a system snapshot containing processes, network interfaces, listening ports, cron jobs, sudoers configuration, binary hashes, loaded audit rules, and recent authentication logs.

The timestamp sets the lower boundary for action detection. The snapshot provides supporting evidence; the final scoring script does not automatically compare baseline snapshots.

### 3. Red Team Attacks

Red Team performs attacks within the authorized exercise scope, such as:

- Placing files in watched directories.
- Modifying cron jobs or privilege-related configuration.
- Tampering with watched data or queue files.
- Executing commands covered by audit rules.

Red Team does not need to invoke a scoring or self-logging script during attacks. Auditd records activity covered by its rules on the monitored host.

### 4. Blue Team Submits Alerts

Blue Team monitors the exercise environment and submits an alert whenever it identifies suspicious activity:

```bash
bash alert.sh control_anomaly "Unexpected binary found in /usr/local/bin"
```

Supported alert types:

| Type | Intended use |
|---|---|
| `queue_anomaly` | Suspicious queue or schedule changes. |
| `data_anomaly` | Suspicious data changes or deletion. |
| `control_anomaly` | Suspicious command execution or infrastructure changes. |
| `hardening` | A reported defensive configuration change. |

Each call appends an entry to `alerts.log`:

```text
<epoch_timestamp> | <alert_type> | <description>
```

The timestamp records when the alert is submitted. Blue Team can submit multiple alerts during a round.

### 5. Organizer Extracts Recorded Actions

After the round ends, the organizer runs:

```bash
python3 red_detector.py
```

The detector:

1. Reads `baseline_timestamp.txt`.
2. Queries audit events using `ausearch`.
3. Excludes events before the baseline.
4. Maps audit-rule keys to action categories.
5. Filters selected system executables.
6. Deduplicates repeated entries.
7. Writes `red_actions.log`.

The script needs permission to query the audit logs. Changing the execution user can also change paths expanded from `~`, so deployment paths and permissions must be configured consistently.

Each action entry uses this format:

```text
<epoch_timestamp> | <action_type> | <description>
```

Action categories:

- `queue_manipulation`
- `data_manipulation`
- `control_compromise`
- `infra_compromise`

### 6. Organizer Calculates Scores

The organizer then runs:

```bash
python3 score_parser.py
```

The scorer reads:

- `red_actions.log`, generated by the detector.
- `alerts.log`, populated by Blue Team.

It matches compatible action and alert types, calculates the delay between the recorded action and the alert submission, and prints a detailed report with both teams' totals.

Each recorded action can be matched only once.

### 7. Prepare the Next Round

Before starting another round:

1. Archive the previous round's logs and score report.
2. Clear the previous Blue Team alerts.
3. Restore the intended starting environment.
4. Take a new baseline.
5. Repeat the exercise.

Taking a new baseline does not clear `alerts.log`. The scorer reads all entries in that file, so stale alerts must be removed between rounds.

`red_detector.py` overwrites `red_actions.log` each time it runs.

## Scoring Rubric

### Blue Team

| Item | Points |
|---|---:|
| Alert matched to a recorded action | +1 |
| Detection within 5 minutes, inclusive | +2 additional |
| Detection after 5 minutes and within 15 minutes, inclusive | +1 additional |
| Unmatched alert | -1 |
| Hardening report | +1, capped at 3 per round |

Hardening reports require organizer verification. The script awards the points without independently checking whether the reported defensive change occurred.

### Red Team

| Item | Points |
|---|---:|
| Queue manipulation | +2 |
| Data manipulation | +2 |
| Control compromise | +2 |
| Infrastructure compromise | +3 |
| Recorded action not matched to a Blue Team alert | +1 additional |

Red Team receives an action's base points even when Blue Team detects it. A matching detection prevents the additional stealth bonus.

## Alert Matching

The scorer uses this mapping:

| Recorded action | Matching Blue Team alert |
|---|---|
| `queue_manipulation` | `queue_anomaly` |
| `data_manipulation` | `data_anomaly` |
| `control_compromise` | `control_anomaly` |
| `infra_compromise` | `control_anomaly` |

For each alert, the scorer selects the unmatched compatible action with the smallest nonnegative time difference.

Matching uses category and timing—not the description or an exact file-path comparison.

## Generated Files

These are runtime artifacts rather than additional source scripts:

| File | Contents |
|---|---|
| `baseline_timestamp.txt` | Start timestamp for the current round. |
| `baseline_<timestamp>.txt` | System snapshot taken at round start. |
| `alerts.log` | Blue Team detection and hardening submissions. |
| `red_actions.log` | Classified audit events used for scoring. |

The attached scoring implementation prints its report to standard output. It does not write `scores.json`.

## Scope and Limitations

- Detection depends on the configured audit rules and activity visible to the monitored host.
- These scripts do not implement cross-node log collection.
- An audit-rule match is a candidate exercise action, not proof of malicious intent. Legitimate activity can require organizer review.
- Executable filtering and deduplication reduce some noise but do not guarantee complete or accurate attack detection.
- Repeated events with the same action type and description are deduplicated, which can collapse separate actions.
- The scorer does not enforce a round-end timestamp; organizers must stop alert submissions and isolate the round's logs.
- The final scorer reads structured action and alert logs. It does not directly parse `auth.log` or compare OpSim plan and execution JSON files.
- Deployment paths are fixed and may need adjustment outside the original environment.

## Project Credits

- Noah deMers — cybersecurity monitoring, alert workflow, and scoring.
- Noah Munz — Rubin OpSim integration and telescope control API.
- Andrew Zilnicki — project management and coordination.
- Dr. Sean Cleveland — project sponsor.

## Authorized Use

This project is intended for controlled, authorized cybersecurity exercises. Conduct attacks only against systems explicitly included in the exercise scope.

