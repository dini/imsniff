#!/bin/bash
# iptables script designed for a gateway. The traffic of clients
# pass through this gateway and the traffic gets analyzed.

# Macro definitions
IPT=/sbin/iptables
IF_WAN=eth0
IF_LAN=eth1
IP_WAN=`ifconfig $IF_WAN | sed -n '/inet /{s/.*addr://;s/ .*//;p}'`
NET_LAN=`ip addr show $IF_LAN | sed -n '3p' | awk '{ print $2 }'`

# Flush and erase existing rules/tables
$IPT -F
$IPT -t nat -F
$IPT -t mangle -F
$IPT -X
$IPT -t nat -X
$IPT -t mangle -X

# Chain for imsniff
$IPT -N imsniff
$IPT -A imsniff -m string --algo bm --from 39 --hex-string '|2A 01|' -j NFQUEUE
$IPT -A imsniff -m string --algo bm --from 39 --hex-string '|2A 02|' -j NFQUEUE
$IPT -A imsniff -m string --algo bm --from 39 --hex-string '|2A 03|' -j NFQUEUE
$IPT -A imsniff -m string --algo bm --from 39 --hex-string '|2A 04|' -j NFQUEUE
$IPT -A imsniff -m string --algo bm --from 39 --hex-string '|2A 05|' -j NFQUEUE

# Firewall ruleset
$IPT -P INPUT   ACCEPT
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT  ACCEPT

$IPT -t nat -A POSTROUTING -o $IF_WAN -s $NET_LAN -j MASQUERADE

$IPT -A FORWARD -p tcp --dport 5190 -j imsniff
$IPT -A FORWARD -p tcp --sport 5190 -j imsniff
$IPT -A FORWARD -m string --algo bm --from 51 --hex-string '|EF BE AD DE|' -j NFQUEUE
