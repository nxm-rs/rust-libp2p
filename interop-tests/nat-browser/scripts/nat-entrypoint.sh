#!/bin/sh
# Turns this container into a MASQUERADE NAT router between LAN_SUBNET and PUB_SUBNET.
#
# The container is attached to both networks; interface names are not deterministic in
# compose, so the pub interface is discovered by matching its address prefix.
set -eu

: "${PUB_SUBNET:?set PUB_SUBNET, e.g. 172.40.0.0/24}"
: "${LAN_SUBNET:?set LAN_SUBNET, e.g. 172.41.0.0/24}"

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "ERROR: net.ipv4.ip_forward is not 1; start with --sysctl net.ipv4.ip_forward=1" >&2
    exit 1
fi

# 172.40.0.0/24 -> "172.40.0." (assumes /24 lans, which this topology uses).
pub_prefix="${PUB_SUBNET%.*}."

pub_if=""
for path in /sys/class/net/*; do
    ifc="$(basename "$path")"
    [ "$ifc" = "lo" ] && continue
    if ip -o -4 addr show dev "$ifc" | grep -q "inet ${pub_prefix}"; then
        pub_if="$ifc"
    fi
done

if [ -z "$pub_if" ]; then
    echo "ERROR: no interface with an address in ${PUB_SUBNET}" >&2
    ip -o -4 addr show >&2
    exit 1
fi

iptables -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$pub_if" -j MASQUERADE

# Drop unsolicited inbound UDP to this router's own pub address BEFORE conntrack
# confirms it (confirmation only happens after filter INPUT). Without this, the
# remote peer's early STUN connectivity checks pin an unreplied conntrack entry
# whose tuple clashes with the reply tuple of the punch flow the NAT'd peer opens
# moments later, forcing MASQUERADE onto a random source port (symmetric-NAT
# behaviour) and killing the ICE hole-punch. Real consumer NATs silently drop
# such packets, so this also makes the topology more faithful.
iptables -A INPUT -i "$pub_if" -p udp -m conntrack --ctstate NEW -j DROP

# Keep the topology hermetic: without a default route this router (and therefore the
# NAT'd peers behind it) can only reach its directly-connected subnets, never the
# docker host gateway or the real internet.
ip route del default 2>/dev/null || true

echo "NAT_READY lan=${LAN_SUBNET} pub_if=${pub_if}"
touch /tmp/nat-ready

exec sleep 2147483647
