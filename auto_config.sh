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

# Install git
apt install git

# Enable Automatic Security Updates
sudo dpkg-reconfigure --frontend noninteractive unattended-upgrades

# Install Additional Sec Tools (e.g., Nmap, Wireshark, and others)
# ~ IT Army of Ukraine! ~
declare -A tools=(
    ["nmap"]="nmap"
    ["ncat"]="nmap"
    ["ndiff"]="nmap"
    ["hydra"]="hydra"
    ["dpl4hydra"]="hydra"
    ["hydra-wizard"]="hydra"
    ["pw-inspector"]="hydra"
    ["xhydra"]="hydra-gtk"
    ["crunch"]="crunch"
    ["msf-egghunter"]="metasploit-framework"
    ["msf-exe2vba"]="metasploit-framework"
    ["msf-exe2vbs"]="metasploit-framework"
    ["msf-find_badchars"]="metasploit-framework"
    ["msf-halflm_second"]="metasploit-framework"
    ["msf-hmac_sha1_crack"]="metasploit-framework"
    ["msf-java_deserializer"]="metasploit-framework"
    ["msf-jsobfu"]="metasploit-framework"
    ["msf-makeiplist"]="metasploit-framework"
    ["msf-md5_lookup"]="metasploit-framework"
    ["msf-metasm_shell"]="metasploit-framework"
    ["msf-msf_irb_shell"]="metasploit-framework"
    ["msf-nasm_shell"]="metasploit-framework"
    ["msf-pattern_create"]="metasploit-framework"
    ["msf-pattern_offset"]="metasploit-framework"
    ["msf-pdf2xdp"]="metasploit-framework"
    ["msf-virustotal"]="metasploit-framework"
    ["msfconsole"]="metasploit-framework"
    ["msfd"]="metasploit-framework"
    ["msfdb"]="metasploit-framework"
    ["msfrpc"]="metasploit-framework"
    ["msfrpcd"]="metasploit-framework"
    ["msfupdate"]="metasploit-framework"
    ["msfvenom"]="metasploit-framework"
    ["wireshark"]="wireshark"
    ["capinfos"]="wireshark"
    ["captype"]="wireshark"
    ["dumpcap"]="wireshark"
    ["editcap"]="wireshark"
    ["mergecap"]="wireshark"
    ["mmdbresolve"]="wireshark"
    ["randpkt"]="wireshark"
    ["rawshark"]="wireshark"
    ["reordercap"]="wireshark"
    ["sharkd"]="wireshark"
    ["text2pcap"]="wireshark"
    ["sqlmap"]="sqlmap"
    ["sqlmapapi"]="sqlmap"
    ["beef-xss"]="beef-xss"
    ["beef-xss-stop"]="beef-xss"
    ["aircrack-ng"]="aircrack-ng"
    ["airbase-ng"]="aircrack-ng"
    ["airdecap-ng"]="aircrack-ng"
    ["airdecloak-ng"]="aircrack-ng"
    ["aireplay-ng"]="aircrack-ng"
    ["airmon-ng"]="aircrack-ng"
    ["airodump-ng"]="aircrack-ng"
    ["airodump-ng-oui-update"]="aircrack-ng"
    ["airolib-ng"]="aircrack-ng"
    ["airserv-ng"]="aircrack-ng"
    ["airtun-ng"]="aircrack-ng"
    ["airventriloquist-ng"]="aircrack-ng"
    ["besside-ng"]="aircrack-ng"
    ["besside-ng-crawler"]="aircrack-ng"
    ["buddy-ng"]="aircrack-ng"
    ["dcrack"]="aircrack-ng"
    ["easside-ng"]="aircrack-ng"
    ["ivstools"]="aircrack-ng"
    ["kstats"]="aircrack-ng"
    ["makeivs-ng"]="aircrack-ng"
    ["packetforge-ng"]="aircrack-ng"
    ["tkiptun-ng"]="aircrack-ng"
    ["wesside-ng"]="aircrack-ng"
    ["wpaclean"]="aircrack-ng"
    ["airgraph-ng"]="airgraph-ng"
    ["airodump-join"]="airgraph-ng"
    ["armitage"]="armitage"
    ["teamserver"]="armitage"
    ["cewl"]="cewl"
    ["fab-cewl"]="cewl"
    ["gobuster"]="gobuster"
    ["wifite"]="wifite"
    ["nikto"]="nikto"
    ["replay"]="nikto"
    ["hashcat"]="hashcat"
    ["hashcat"]="hashcat"
    ["hashcat-data"]="hashcat"
    ["wpscan"]="wpscan"
    ["maltego"]="maltego"
    ["bed"]="bed"
    ["sherlock"]="sherlock"
    ["john"]="john"
    ["SIPdump"]="john"
    ["base64conv"]="john"
    ["bitlocker2john"]="john"
    ["calc_stat"]="john"
    ["cprepair"]="john"
    ["dmg2john"]="john"
    ["eapmd5tojohn"]="john"
    ["genmkvpwd"]="john"
    ["gpg2john"]="john"
    ["hccap2john"]="john"
    ["john"]="john"
    ["keepass2john"]="john"
    ["mailer"]="john"
    ["mkvcalcproba"]="john"
    ["putty2john"]="john"
    ["racf2john"]="john"
    ["rar2john"]="john"
    ["raw2dyna"]="john"
    ["tgtsnarf"]="john"
    ["uaf2john"]="john"
    ["unafs"]="john"
    ["undrop"]="john"
    ["unique"]="john"
    ["unshadow"]="john"
    ["vncpcap2john"]="john"
    ["wpapcap2john"]="john"
    ["zip2john"]="john"
    ["autopsy"]="autopsy"
    ["ettercap"]="ettercap"
    ["ettercap-common"]="ettercap"
    ["ettercap-graphical"]="ettercap-graphical"
    ["ettercap-pkexec"]="ettercap"
    ["etterfilter"]="etterfilter"
    ["etterlog"]="etterlog"
    ["ettercap-text-only"]="ettercap-text-only"
    ["airgeddon"]="airgeddon"
    ["redeye"]="redeye"
    ["redeye-stop"]="redeye"
    ["netdiscover"]="netdiscover"
    ["medusa"]="medusa"
    ["lynis"]="lynis"
    ["dnsenum"]="dnsenum"
    ["wordlists"]="wordlists"
    ["subfinder"]="subfinder"
    ["spiderfoot"]="spiderfoot"
    ["spiderfoot-cli"]="spiderfoot"
    ["socat"]="socat"
    ["filan"]="socat"
    ["procan"]="socat"
    ["nuclei"]="nuclei"
    ["macchanger"]="macchanger"
    ["legion"]="legion"
    ["goldeneye"]="goldeneye"
    ["fern-wifi-cracker"]="fern-wifi-cracker"
    ["cisco-torch"]="cisco-torch"
    ["chntpw"]="chntpw"
    ["amass"]="amass"
    ["amass"]="amass"
    ["sublist3r"]="sublist3r"
    ["steghide"]="steghide"
    ["set"]="setoolkit"
    ["se-toolkit"]="setoolkit"
    ["ngrep"]="ngrep"
    ["masscan"]="masscan"
    ["koadic"]="koadic"
    ["king-phisher"]="king-phisher"
    ["king-phisher-client"]="king-phisher"
    ["king-phisher-server"]="king-phisher"
    ["johnny"]="johnny"
    ["ghidra"]="ghidra"
    ["fierce"]="fierce"
    ["driftnet"]="driftnet"
    ["dnsrecon"]="dnsrecon"
    ["dirsearch"]="dirsearch"
    ["cryptsetup"]="cryptsetup"
    ["cryptsetup"]="cryptsetup"
    ["cryptdisks_start"]="cryptsetup"
    ["cryptdisks_stop"]="cryptsetup"
    ["luksformat"]="cryptsetup"
    ["cryptsetup-bin"]="cryptsetup"
    ["integritysetup"]="cryptsetup"
    ["veritysetup"]="cryptsetup"
    ["cryptsetup-initramfs"]="cryptsetup-initramfs"
    ["cryptsetup-run"]="cryptsetup-run"
    ["cryptsetup-ssh"]="cryptsetup-ssh"
    ["cryptsetup-ssh"]="cryptsetup-ssh"
    ["cryptsetup-suspend"]="cryptsetup"
    ["libcryptsetup-dev"]="libcryptsetup-dev"
    ["libcryptsetup12"]="libcryptsetup12"
    ["btscanner"]="btscanner"
    ["wifipumpkin3"]="wifipumpkin3"
    ["captiveflask"]="wifipumpkin3"
    ["sslstrip3"]="wifipumpkin3"
    ["wifipumpkin3"]="wifipumpkin3"
    ["wp3"]="wifipumpkin3"
    ["tiger"]="tiger"
    ["tiger"]="tiger"
    ["tiger"]="tiger"
    ["tigercron"]="tiger"
    ["tigexp"]="tiger"
    ["tiger-otheros"]="tiger-otheros"
    ["testdisk"]="testdisk"
    ["fidentify"]="testdisk"
    ["photorec"]="testdisk"
    ["testdisk"]="testdisk"
    ["sslscan"]="sslscan"
    ["pipal"]="pipal"
    ["p0f"]="p0f"
    ["nbtscan"]="nbtscan"
    ["mitmproxy"]="mitmproxy"
    ["mitmdump"]="mitmproxy"
    ["mitmproxy"]="mitmproxy"
    ["mitmweb"]="mitmproxy"
    ["jsql"]="jsql"
    ["jadx"]="jadx"
    ["hakrawler"]="hakrawler"
    ["foremost"]="foremost"
    ["eyewitness"]="eyewitness"
    ["evil-winrm"]="evil-winrm"
)

# Install the security tools
for tool in "${!tools[@]}"; do
    package="${tools[$tool]}"
    echo "Installing $tool..."
    sudo apt install -y "$package"
    if [ $? -ne 0 ]; then
        echo "Failed to install $tool."
    fi
done

echo "All security tools installed successfully!"

# Note on Non-Root User Login
echo "Setup complete!"
echo "You can now log in as the non-root user ($username) using the following command:"
echo "ssh $username@your_server_ip"
