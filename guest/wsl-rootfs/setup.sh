#!/bin/sh
# Post-import setup script for the microvm-rs WSL2 distro.
# Run this inside the distro after importing to install required packages.

set -e

echo "Setting up microvm-rs WSL2 distro..."

# Update package index
apk update

# Install required packages
apk add --no-cache \
    openssh-client \
    openvpn \
    socat \
    curl

# Create microvm config directory
mkdir -p /etc/microvm

# Copy the init script
cp /root/init-microvm.sh /etc/microvm/init-microvm.sh
chmod +x /etc/microvm/init-microvm.sh

echo "Setup complete."
