#!/bin/bash

# ------------------ Install Dependecies ------------------ 
# Update the package list
sudo apt-get update

# Install Java 17
sudo apt-get install -y openjdk-17-jdk

# Set Java environment variables
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$PATH:$JAVA_HOME/bin

# Install Maven 3.8.1
MAVEN_VERSION=3.8.1
wget https://downloads.apache.org/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz
sudo tar -zxvf apache-maven-${MAVEN_VERSION}-bin.tar.gz -C /opt
sudo ln -s /opt/apache-maven-${MAVEN_VERSION} /opt/maven
sudo ln -s /opt/maven/bin/mvn /usr/local/bin/mvn

# Clean up downloaded archive
rm apache-maven-${MAVEN_VERSION}-bin.tar.gz

# Display Java and Maven versions
java -version
mvn -version

# ------------------ Configure Network Interfaces ------------------

sudo ifconfig eth0 192.168.0.100/24 up
sudo systemctl restart NetworkManager

sudo ip route add default via 192.168.0.10

# ------------------ Configure Firewall ------------------ 

# VM1 (connected to sw-1):
#   IP address on interface eth0: 192.168.0.100/24

# --- SETUP ---

# Create directory for iptables rules if it doesn't exist
sudo mkdir -p /etc/iptables

# --- RULES ---

# Flush existing rules and set default policies
sudo /sbin/iptables -F
sudo /sbin/iptables -P INPUT DROP
sudo /sbin/iptables -P FORWARD DROP
sudo /sbin/iptables -P OUTPUT DROP
# These commands set the default policy for incoming (INPUT), forwarded (FORWARD) and outgoing (OUTPUT) traffic to DROP, meaning that by default, 
# all incoming and forwarded packets will be discarded unless an explicit rule allows them.

# Allow loopback interface
sudo /sbin/iptables -A INPUT -i lo -j ACCEPT
sudo /sbin/iptables -A OUTPUT -o lo -j ACCEPT
# Ensure that the loopback interface can be used for local communication between processes on the same machine.

# Allow established and related connections
sudo /sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo /sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Traffic related to an already established connection must also be accepted

# Allow incoming SSL connections from VM2 to VM1
sudo /sbin/iptables -A INPUT -p tcp -s 192.168.0.10 --dport 12345 -j ACCEPT

# Allow outgoing SSL connections from VM1 to VM2
sudo /sbin/iptables -A OUTPUT -p tcp -s 192.168.0.100 --dport 12345 -j ACCEPT

# Reject ICMP packets
#sudo /sbin/iptables -A INPUT -p icmp -j DROP

# ----------------------- SAVE --------------------------

# Save the rules using sudo
#sudo /sbin/iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null

# Restart the network service to apply the rules
#sudo systemctl restart networking

# Delete all existing rules:
# $ sudo /sbin/iptables –F
# $ sudo /sbin/iptables -t nat –F

