# task1
Scan Your Local Network for Open Ports

I can use tools like Nmap, which is one of the most powerful and widely used port scanning and network reconnaissance tools.
Here’s how I can do it step by step:
# install nmap 
   * linux(debian/ubuntu) : sudo apt update && sudo apt install nmap -y 
   * Windows: Download from https://nmap.org/download.html
   * MacOs : brew install nmap
# Check your system’s IP address and gateway
   * Linux/Mac: ifconfig
   * Windows: ipconfig
examples: IP is 192.168.1.25 and subnet mask is 255.255.255.0, then your network range is 192.168.1.0/24.
# Scan Local Network for Active Hosts
     nmap -sn 192.168.1.0/24
     This shows all live devices on your local network.
# Scan for Open Ports on a Specific Host
     nmap -p- 192.168.1.25
     -p- scans all 65,535 ports.
     To scan common ports only: nmap 192.168.1.25
# Scan the Entire Network for Open Ports
     nmap -p 1-1000 192.168.1.0/24
     Scans the first 1000 ports across all devices.
# Service & Version Detection
     nmap -sV 192.168.1.25
     This tells you which services (e.g., SSH, HTTP, MySQL) are running on open ports.
# Aggressive Scan
     nmap -A 192.168.1.25
     Performs OS detection, version detection, script scanning, and traceroute
# example
       PORT     STATE SERVICE VERSION
       22/tcp   open  ssh     OpenSSH 8.2
       80/tcp   open  http    Apache httpd 2.4.41
       443/tcp  open  ssl/http Apache httpd 2.4.41
     
# Useful nmap flags & tips
        -Pn — skip host discovery (treat hosts as up). Useful if ICMP is blocked.
        -sS — TCP SYN scan (fast), requires root on Unix. Standard tool — but remember it's noisier on monitored nets.
        -sC — run default NSE scripts (harmless info-gathering).
        --script vuln — run vulnerability-detection NSE scripts (use carefully; may be intrusive).
        Output formats: -oN (normal), -oX (XML), -oG (grepable) — pick based on downstream parsing needs.
# Continuous monitoring & automation
        Save scan output in machine-readable formats:
            nmap -oX scan.xml -oN scan.txt 192.168.1.0/24
        Compare scans over time to spot new open ports. Use simple scripts to diff results and alert.
        Schedule periodic scans using cron (Linux) or Task Scheduler (Windows) — do this only for authorized networks.
# Discover live hosts 
        Accurate, LAN-friendly: nmap -sn 192.168.1.0/24 -oN discovery.txt
        -sn = ping/ARP host discovery (no port scan).
        Save output (-oN discovery.txt) for submission.
# What nmap -sS 192.168.1.0/24 does
        -sS = TCP SYN scan (aka “half-open” scan). Nmap sends SYN, looks for SYN/ACK (open) or RST (closed), and does not complete the TCP handshake.
        192.168.1.0/24 = scan every IP from 192.168.1.1 to 192.168.1.254 on the local /24.
        Fast and stealthier than a full connect (-sT), but noisy enough to trigger monitoring/IDS on managed networks.
    * Note 
        Run as root/administrator on Linux/macOS (raw sockets required): sudo nmap -sS 192.168.1.0/24
        On Windows you must install Npcap and run the terminal as Administrator for SYN scans to work.
        Legal / ethical: Only scan networks/devices you own or have written permission to test.
        IDS/IPS / routers: SYN scans emit packets that can trigger security devices. Consider running -sn discovery first or schedule with permission.
    * Safer recommended workflow (two-step)
    * Discover live hosts with an ARP/ping sweep: sudo nmap -sn 192.168.1.0/24 -oN 1_discovery.txt
    * SYN-scan the live hosts (faster and less noisy than brute /24 SYN on all hosts):
    * sudo nmap -sS -T4 -iL <list-of-live-hosts.txt> -oN 2_synscan.txt -oX 2_synscan.xml
    (-T4 speeds up the scan; reduce to -T3 on sensitive networks.)

# wireshark
* Analyse paket capture with wireshark
       how to capture and analyze scan traffic with Wireshark so you can include solid evidence and interpretation in your internship deliverable. I’ll cover capture (tcpdump/tshark/Wireshark GUI), useful capture & display filters, how to confirm open ports (SYN/SYN-ACK), follow streams (HTTP/SSH), capture TLS considerations, common suspicious patterns, screenshots & exports to include in your report, and quick forensic tips.
  * 1 Capture: how to get the pcap
      Use one of these depending on preference and environment.
    * Linux (tcpdump) — lightweight, reliable
      * capture traffic to/from one host (write file)
          sudo tcpdump -i eth0 host 192.168.1.25 -w scan-192.168.1.25.pcapng
      * capture only TCP (smaller file)
          sudo tcpdump -i eth0 tcp and host 192.168.1.25 -w scan-192.168.1.25.pcapng
      * capture only SYNs (handshakes)
          sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and host 192.168.1.25' -w syns.pcapng
    * Linux (tshark) — CLI + print summaries
      * save pcap and also print a live summary
          sudo tshark -i eth0 -f "host 192.168.1.25" -w scan.pcapng
    * Windows — Wireshark GUI or dumpcap
      * Launch Wireshark as Administrator. Select interface, set capture filter (see next section), click Start.
      * Or use dumpcap to write a pcap:dumpcap -i 3 -w scan.pcapng (run elevated)
   * 2 Helpful capture filters (BPF) to set before you start
        Capture only traffic to/from a host:
          host 192.168.1.25
        Capture only TCP:
          tcp and host 192.168.1.25
        Capture only TCP SYN packets:
          'tcp[tcpflags] & tcp-syn != 0'
        Capture only traffic for a subnet:
           net 192.168.1.0/24
    * 3 Open the pcap in Wireshark & useful display filters
        Open scan-192.168.1.25.pcapng in Wireshark, then use display filters (typed into the top bar):
        Show TCP SYNs:
          tcp.flags.syn == 1 && tcp.flags.ack == 0
          Show SYN+ACK (server response indicating port open):
          tcp.flags.syn == 1 && tcp.flags.ack == 1
          Show completed 3-way handshakes (SYN, SYN/ACK, ACK) — look for pairings by conversation (use Follow TCP Stream for confirmation).
          Show TCP ports for a host:
            ip.addr == 192.168.1.25 && tcp
          Show only HTTP traffic: http
          Show only TLS traffic: ssl || tls (Wireshark recognizes TLS with tls filter for modern versions.)
    * 4 Confirming a port is open (what to look for)
          Find packet from scanner to target with SYN flag set (SYN).
          If target replies with SYN, ACK → port open (server accepted SYN).
          If target replies with RST → port closed.
          If no reply or ICMP unreachable/filtered → port filtered (firewall).
          Workflow:
              Use display filter tcp.flags.syn==1 && ip.addr==192.168.1.25 to find SYNs sent to the host.
              Click a SYN packet → examine the packet bytes and TCP flags in the middle pane.
              Look for immediate corresponding packet from target: SYN, ACK. Use time delta to check responses.
              Right-click on any SYN or SYN/ACK → “Follow” → “TCP Stream” to inspect the stream context.
   * 5 Follow TCP stream & human-readables
          Right-click a packet → Follow → TCP Stream. This opens the full conversation; change “Show data as” to Raw, ASCII, or Hex. Useful to show an HTTP GET/response or to demonstrate SSH banner              exchange (note: SSH encrypted, you’ll see headers only).
          For HTTP, you’ll see full request/response text — great evidence (method, URI, server header).
   * 6 TLS / HTTPS considerations (decryption)
          Most TLS is encrypted; you will not see plaintext unless you have keys.
          To decrypt browser TLS sessions you control, set environment variable for the process:
     SSLKEYLOGFILE=/path/to/sslkeys.log (works with Firefox/Chrome). Then in Wireshark: Preferences → Protocols → TLS → (Pre)-Master-Secret log filename and point to sslkeys.log. Wireshark can then          decrypt those sessions.
      For server-side RSA private-key decryption: only works for older non-ECDHE TLS where RSA key exchange was used — rare for modern servers.
      If you cannot decrypt, still include metadata: Server Hello (cipher suite), certificate subject, SNI (Server Name Indication) in Client Hello (useful for identifying hostnames).
  * 7 Useful columns & coloring in Wireshark to make screenshots clearer
        Add columns: Source, Destination, Protocol, Info, and Time.
        Add a column for TCP Flags (right-click field → “Apply as Column” on tcp.flags).
        Coloring rules: Wireshark colorizes packets by default (TCP SYN usually one color). For consistent report images, you can use built-in colors or set custom coloring rules (View → Coloring Rules).
 * 8 grep/tshark quick evidence exports (if you prefer CLI)  
        List SYN/SYN-ACK pairs (summary):  
        tshark -r scan.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
        Export HTTP objects:
              tshark -r scan.pcapng -Y http -T fields -e http.request.full_uri -e http.user_agent
 * 9 What to screenshot & include in your report  
        For each important finding include:
        Packet list screenshot showing SYN → SYN/ACK pair (highlight the two lines).
        Packet details pane screenshot showing TCP flags and ports (expand Transmission Control Protocol section).
        Follow TCP stream screenshot for HTTP findings (show request + response).
        If TLS: screenshot showing Client Hello with SNI and Server Hello (cipher suite) and certificate subject.
        Attach the .pcapng file itself (named e.g., scan-192.168.1.25.pcapng) in your submission zip.
   * 10 Identifying suspicious or high-risk indicators
        Unexpected open management ports (e.g., 22/3389/80/443 on user laptops). Look for SYN→SYN/ACK on these ports.
        Repeated connection attempts from a single host to many different ports (possible scanning behavior).
        Repeated failed authentication or many RSTs/ICMP unreachable responses (misconfiguration or attempted intrusion).
        Unusual protocols (e.g., SMB/NetBIOS on multiple hosts) that shouldn’t be on guest/user VLANs.
  * 11 Short interpretation examples for your report
        Example (confirmed open port):
            “192.168.1.25:22 — confirmed open. Evidence: tcp SYN from scanner (frame 100) and SYN/ACK from target (frame 101). Follow-TCP-Stream shows SSH banner OpenSSH_7.6p1.”
        Example (filtered):
            “192.168.1.30:3389 — filtered. Evidence: SYNs seen, no SYN/ACK, ICMP unreachable responses observed. Likely host or network-level firewall.”
  * 12 Exporting & metadata for submission
        Save pcap: File → Save As → scan-192.168.1.25.pcapng.  
        Export selected packets: right-click selection → Export Specified Packets → save a small evidence pcap for each finding.  
        Export packet bytes or save as plain text for inclusion: File → Export Packet Dissections → As Plain Text (choose selected packets).
  * 13 Privacy & ethics reminder
        Only capture traffic you are authorized to. Packet captures may contain sensitive data (credentials, personal info). Treat .pcap files as sensitive artifacts — include them in the submission           zip but protect access (e.g., password-protected archive if required).
  * 14 Quick checklist for your internship submission
        scan-192.168.1.0-24_syn.pcapng (full capture)
        Screenshots: syn-synack-pair.png, follow-tcp-stream-http.png, tls-client-hello.png
        Short captions under each screenshot describing what it proves (frame numbers, timestamp, ports).
        One-line evidence statement per finding linking pcap artifacts to the Nmap result.

    
