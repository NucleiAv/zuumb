#!/bin/sh
# Point the agent at the manager, (re)enrol, run, and stream its log.
# The manager's authd (:1515) force-replaces a prior registration with the same
# name, so a restart re-enrols cleanly without any persisted key volume.
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
NAME="${WAZUH_AGENT_NAME:-$(hostname)}"
CONF=/var/ossec/etc/ossec.conf

sed -i "s|<address>[^<]*</address>|<address>${MANAGER}</address>|" "$CONF"
grep -q "<agent_name>" "$CONF" \
  || sed -i "s|</enrollment>|  <agent_name>${NAME}</agent_name>\n  </enrollment>|" "$CONF"
: > /var/ossec/etc/client.keys 2>/dev/null || true

# LAB_NOISE=1: also watch an auth log the noise generator writes to
if [ "${LAB_NOISE:-0}" = "1" ] && ! grep -q "/var/log/auth.log" "$CONF"; then
  touch /var/log/auth.log
  sed -i "s|</ossec_config>|  <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>\n</ossec_config>|" "$CONF"
fi

term() { /var/ossec/bin/wazuh-control stop >/dev/null 2>&1 || true; exit 0; }
trap term TERM INT

/var/ossec/bin/wazuh-control start

# optional lab activity so the pipeline isn't starved while real traffic builds
if [ "${LAB_NOISE:-0}" = "1" ] && [ -x /lab-noise.sh ]; then
  /lab-noise.sh &
fi

exec tail -F /var/ossec/logs/ossec.log
