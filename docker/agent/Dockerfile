# Wazuh 4.9.2 agent, built from the official .deb (there is no wazuh/wazuh-agent
# image for 4.9.x on Docker Hub). One container == one monitored "host".
FROM debian:12-slim

ARG WAZUH_VERSION=4.9.2-1
ARG TARGETARCH=amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl procps lsb-release adduser \
 && curl -fsSL -o /tmp/wazuh-agent.deb \
      "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}_${TARGETARCH}.deb" \
 && (dpkg -i /tmp/wazuh-agent.deb || apt-get install -f -y --no-install-recommends) \
 && rm -f /tmp/wazuh-agent.deb \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY lab-noise.sh /lab-noise.sh
RUN chmod +x /entrypoint.sh /lab-noise.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD /var/ossec/bin/wazuh-control status | grep -q "wazuh-agentd is running" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
