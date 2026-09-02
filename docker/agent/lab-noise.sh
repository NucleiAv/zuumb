#!/bin/sh
# Opt-in lab traffic (LAB_NOISE=1): realistic sshd auth failures from rotating
# source IPs, occasional brute->success, occasional FIM change. Gives the zuumb
# pipeline multi-agent data with real source IPs while genuine organic traffic
# accrues. NOT for production — a real deployment monitors real hosts.
set -eu

AUTH=/var/log/auth.log
HOST=$(hostname)
touch "$AUTH"

while :; do
  ip="$(shuf -e 203.0.113 198.51.100 192.0.2 -n1).$(shuf -i 10-240 -n1)"
  usr=$(shuf -e admin root oracle postgres deploy ubuntu svc-backup -n1)
  port=$(shuf -i 1024-60000 -n1)
  ts=$(date '+%b %e %T')

  echo "$ts $HOST sshd[$$]: Failed password for invalid user $usr from $ip port $port ssh2" >> "$AUTH"
  [ "$(shuf -i 1-8 -n1)" = "1" ] && \
    echo "$ts $HOST sshd[$$]: Accepted password for $usr from $ip port $port ssh2" >> "$AUTH"
  [ "$(shuf -i 1-15 -n1)" = "1" ] && \
    echo "# lab-noise $(date +%s)" >> /etc/hosts.allow

  sleep "$(shuf -i 20-70 -n1)"
done
