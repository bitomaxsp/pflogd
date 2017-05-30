#!/bin/bash

set -e

# Trapping on TERM signals, according to Apple's launchd docs:
trap 'exit 1' 15

# Wait for all the interfaces to go up:
syslog -s -l 5 pflogd: waiting for interfaces to go up...
ipconfig waitall
sleep 15

# Enable interface forwarding on ipv4 and ipv6
# Needed if for forwarding from one interface to another
sysctl -w net.inet.ip.forwarding=1
sysctl -w net.inet6.ip6.forwarding=1

# create interface for pf logging
syslog -s -l 5 pflogd: creating pflog0 logging interface...
ifconfig pflog0 create

# enable pf using tokens and load rules
syslog -s -l 5 pflogd: starting the pf...
/sbin/pfctl -f /etc/pf.conf
/sbin/pfctl -E

syslog -s -l 5 pflogd: starting pflogd deamon...
/usr/local/sbin/pflogd pflog0

