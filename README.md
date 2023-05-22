# Ubuntu VPS Security Setup Script

This script automates the setup of a new Ubuntu VPS with security measures including firewall configuration, SSH hardening, IP spoofing prevention, intrusion detection, and installation of selected security tools.

## Features

- Updates system packages
- Configures Uncomplicated Firewall (UFW) to allow only necessary traffic
- Prevents IP spoofing by enabling Reverse Path Filtering (RPF)
- Disables root login and enforces SSH key-based authentication
- Hardens the SSH protocol with recommended settings
- Creates a limited user account with sudo privileges
- Copies SSH key from the root user to the non-root user
- Configures SSH session timeout
- Installs and configures Fail2Ban for intrusion detection and prevention
- Enables automatic security updates
- Installs selected security tools from Kali Linux repositories

## Prerequisites

- Ubuntu VPS with root access
- Basic knowledge of the Linux command line
- Understanding of the potential risks and security implications

## Usage

1. Log in to your Ubuntu VPS as the root user.

2. Run the setup script:
   ```shell
   wget https://link-to-your-script.sh
   chmod +x auto_config.sh
   ./auto_config.sh
   ```
3. Connect

You can use the same SSH key to connect that you originally used to login as root:
   ```shell
   ssh notroot@your_server_ip -i key
   ```
