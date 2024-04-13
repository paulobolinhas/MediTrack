#!/bin/bash

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
