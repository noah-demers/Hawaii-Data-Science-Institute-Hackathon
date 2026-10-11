#!/usr/bin/env bash
set -euo pipefail
TS=$(date -Is)
date +%s.%3N > ~/control/logs/baseline_timestamp.txt
OUT=~/control/logs/baseline_${TS}.txt

{
  echo "ts=$TS"
  echo "host=$(hostname)"
  echo "who=$(whoami)"
  echo "uptime=$(uptime)"

  echo "ip:"
  ip a

  echo "processes:"
  ps aux --sort=-%cpu | head -n 20

  echo "disk:"
  df -h

  echo "listening_ports:"
  ss -tlnp

  echo "cron_root:"
  sudo crontab -l -u root 2>/dev/null || echo "(none)"

  echo "cron_ubuntu:"
  crontab -l 2>/dev/null || echo "(none)"

  echo "cron_d:"
  ls -la /etc/cron.d/ && cat /etc/cron.d/* 2>/dev/null || echo "(empty)"

  echo "sudoers_d:"
  sudo ls /etc/sudoers.d/ && sudo cat /etc/sudoers.d/* 2>/dev/null || echo "(empty)"

  echo "watched_dir_hashes:"
  sha256sum /usr/local/bin/* 2>/dev/null || echo "(empty)"

  echo "auditd_rules:"
  sudo auditctl -l 2>/dev/null || echo "(auditd not running)"

  echo "recent_auth:"
  sudo tail -n 50 /var/log/auth.log 2>/dev/null || true

} > "$OUT"
echo "Wrote $OUT"