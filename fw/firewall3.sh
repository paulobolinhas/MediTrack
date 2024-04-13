#!/bin/bash

# ----------------------- NETWORK --------------------------

# VM3 (connected to sw-2):
#   IP address on interface eth0: 192.168.1.1/24

# ----------------------- SETUP --------------------------

# Create directory for iptables rules if it doesn't exist
sudo mkdir -p /etc/iptables

# ----------------------- RULES --------------------------

# Flush existing rules and set default policies
sudo /sbin/iptables -F
sudo /sbin/iptables -P INPUT DROP
sudo /sbin/iptables -P FORWARD DROP
sudo /sbin/iptables -P OUTPUT DROP
# These commands set the default policy for incoming (INPUT) and forwarded (FORWARD) traffic to DROP, meaning that by default, 
# all incoming and forwarded packets will be discarded unless an explicit rule allows them. The default policy for outgoing (OUTPUT) traffic 
# is set to ACCEPT, allowing all outgoing packets.

# Allow loopback interface
sudo /sbin/iptables -A INPUT -i lo -j ACCEPT
sudo /sbin/iptables -A OUTPUT -o lo -j ACCEPT
# Ensure that the loopback interface can be used for local communication between processes on the same machine.

# Allow established and related connections
sudo /sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo /sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Traffic related to an already established connection must also be accepted

# Allow incoming SSL connections from VM2 to VM3
sudo /sbin/iptables -A INPUT -p tcp -s 192.168.1.254 --dport 50000 -j ACCEPT

# Allow outgoing SSL connections from VM3 to VM2
sudo /sbin/iptables -A OUTPUT -p tcp -s 192.168.1.254 --dport 50000 -j ACCEPT

# ----------------------- SAVE --------------------------

# Save the rules using sudo
sudo /sbin/iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null

# Restart the network service to apply the rules
sudo systemctl restart networking

# Delete all existing rules:
# $ sudo /sbin/iptables –F
# $ sudo /sbin/iptables -t nat –F
