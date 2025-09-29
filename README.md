# task1
Scan Your Local Network for Open Ports

I can use tools like Nmap, which is one of the most powerful and widely used port scanning and network reconnaissance tools.
Here’s how I can do it step by step:
1 install nmap 
   * linux(debian/ubuntu) : sudo apt update && sudo apt install nmap -y 
   * Windows: Download from https://nmap.org/download.html
   * MacOs : brew install nmap
2 Check your system’s IP address and gateway
   * Linux/Mac: ifconfig
   * Windows: ipconfig
examples: IP is 192.168.1.25 and subnet mask is 255.255.255.0, then your network range is 192.168.1.0/24.
3 Scan Local Network for Active Hosts
     nmap -sn 192.168.1.0/24
     This shows all live devices on your local network.
4 Scan for Open Ports on a Specific Host
     nmap -p- 192.168.1.25
     -p- scans all 65,535 ports.
     To scan common ports only: nmap 192.168.1.25
5 Scan the Entire Network for Open Ports
     nmap -p 1-1000 192.168.1.0/24
     Scans the first 1000 ports across all devices.
6 Service & Version Detection
     nmap -sV 192.168.1.25
     This tells you which services (e.g., SSH, HTTP, MySQL) are running on open ports.
7 Aggressive Scan
     nmap -A 192.168.1.25
     Performs OS detection, version detection, script scanning, and traceroute
example
       PORT     STATE SERVICE VERSION
       22/tcp   open  ssh     OpenSSH 8.2
       80/tcp   open  http    Apache httpd 2.4.41
       443/tcp  open  ssl/http Apache httpd 2.4.41
     
Useful nmap flags & tips
        -Pn — skip host discovery (treat hosts as up). Useful if ICMP is blocked.
        -sS — TCP SYN scan (fast), requires root on Unix. Standard tool — but remember it's noisier on monitored nets.
        -sC — run default NSE scripts (harmless info-gathering).
        --script vuln — run vulnerability-detection NSE scripts (use carefully; may be intrusive).
        Output formats: -oN (normal), -oX (XML), -oG (grepable) — pick based on downstream parsing needs.
Continuous monitoring & automation
        Save scan output in machine-readable formats:
            nmap -oX scan.xml -oN scan.txt 192.168.1.0/24
        Compare scans over time to spot new open ports. Use simple scripts to diff results and alert.
        Schedule periodic scans using cron (Linux) or Task Scheduler (Windows) — do this only for authorized networks.
Discover live hosts 
        Accurate, LAN-friendly: nmap -sn 192.168.1.0/24 -oN discovery.txt
        -sn = ping/ARP host discovery (no port scan).
        Save output (-oN discovery.txt) for submission.
What nmap -sS 192.168.1.0/24 does
        -sS = TCP SYN scan (aka “half-open” scan). Nmap sends SYN, looks for SYN/ACK (open) or RST (closed), and does not complete the TCP handshake.
        192.168.1.0/24 = scan every IP from 192.168.1.1 to 192.168.1.254 on the local /24.
        Fast and stealthier than a full connect (-sT), but noisy enough to trigger monitoring/IDS on managed networks.
    Note 
        Run as root/administrator on Linux/macOS (raw sockets required): sudo nmap -sS 192.168.1.0/24
        On Windows you must install Npcap and run the terminal as Administrator for SYN scans to work.
        Legal / ethical: Only scan networks/devices you own or have written permission to test.
        IDS/IPS / routers: SYN scans emit packets that can trigger security devices. Consider running -sn discovery first or schedule with permission.
    Safer recommended workflow (two-step)
    Discover live hosts with an ARP/ping sweep: sudo nmap -sn 192.168.1.0/24 -oN 1_discovery.txt
    SYN-scan the live hosts (faster and less noisy than brute /24 SYN on all hosts):
    sudo nmap -sS -T4 -iL <list-of-live-hosts.txt> -oN 2_synscan.txt -oX 2_synscan.xml
    (-T4 speeds up the scan; reduce to -T3 on sensitive networks.)


    
