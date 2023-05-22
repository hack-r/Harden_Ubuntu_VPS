#!/bin/bash

# Update system packages
sudo apt update -y
sudo apt upgrade -y

# Add Kali Linux repositories
echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" | sudo tee /etc/apt/sources.list.d/kali.list
wget "https://archive.kali.org/archive-key.asc" -O - | sudo apt-key add -

# Install necessary packages
sudo apt install -y ufw fail2ban unattended-upgrades iptables

# Configure Uncomplicated Firewall (UFW)
sudo ufw --force enable

# Prevent IP Spoofing
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1

# Disable Root Login
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Set up SSH Key-Based Authentication
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Harden the SSH Protocol
sudo sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Set up a Limited User Account
read -p "Enter the username for the non-root user: " username
sudo adduser --disabled-password --gecos "" $username
sudo usermod -aG sudo $username

# Copy SSH key from root user to non-root user
sudo rsync --archive --chown=$username:$username ~/.ssh /home/$username

# Configure SSH Session Timeout
sudo sed -i '$ a\ClientAliveInterval 300' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Install and Configure Fail2Ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Enable Automatic Security Updates
sudo dpkg-reconfigure --frontend noninteractive unattended-upgrades

# Install Additional Tools (e.g., Nmap, Wireshark, and others)
sudo apt install -y nmap wireshark kali-tools-top10 kali-tools-web kali-tools-voip kali-tools-pwtools

# Note on Non-Root User Login
echo "Setup complete!"
echo "You can now log in as the non-root user ($username) using the following command:"
echo "ssh $username@your_server_ip"
