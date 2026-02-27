#!/usr/bin/env bash
set -euo pipefail
iptables -I DOCKER-USER -i br+ ! -o br+ -j DROP
iptables -I DOCKER-USER ! -i br+ -o br+ -j DROP
iptables -I DOCKER-USER -j RETURN
