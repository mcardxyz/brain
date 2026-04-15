---
tags:
  - "#nmap"
  - "#pentesting/networking"
  - "#e"
date: 2026-03-05
---
# Nmap
## Basics
**Limiting the target ports**
*Nmap scans the most common 1,000 ports by default.*
```bash
# Fast mode - scans the 100 most common ports
nmap -F
# Allows to specify a range of ports to scan
nmap -p10-1024
# Scan all ports - equivalent to -p1-65535
nmap -p-

# Tip: The most common services use a port number between 1 and 1024 for either UDP or TCP.
# These ports are also known as **well-known ports**.
# Use `-p1-1023` to scan for the well-known ports.
```


___
## Host Discovery
**Scanning a network for hosts**
```bash
nmap -sn 192.168.66.0/24
```

**Only list the targets to scan without actually scanning them**
```bash
nmap -sL 192.168.0.1/24
```


___
## Port Scanning
### Connect Scan
Tries to complete the TCP three-way handshake with every target TCP port. If the TCP port is open and Nmap connects successfully, Nmap will tear down the established connection.
```bash
nmap -sT 192.168.1.10
```

### SYN Scan (Stealth)
The SYN scan only sends a TCP SYN packet, and never finished the three-way handshake. This advantage is to lead to fewer logs as the connection is never established.
```bash
nmap -sS 192.168.1.10
```

### UDP Ports
```bash
nmap -sU 192.168.1.1
```


___
## Version Detection
**Scan hosts that appear too be down**
```bash
nmap -Pn
```

### OS Detection
```bash
nmap -sS -O 192.168.124.211
```

### Service and Version Detection
```bash
nmap -sS -sV 192.168.124.211
```


___
## Scanning Performance
```bash
# Timing template - paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5)
-T<0-5>

# Minimum and maximum number of parallel probes
--min-parallelism <numprobes>
--max-parallelism <numprobes>

# Minimum and maximum rate (packets/second)
--min-rate <number>
--max-rate <number>

# Maximum amount of time to wait for a target host
--host-timeout
```


___
## Output
- `-oN <filename>` - Normal output
- `-oX <filename>` - XML output
- `-oG <filename>` - `grep`-able output (useful for `grep` and `awk`)
- `-oA <filename>` - Output in all major formats







**Details**
<!-- Main content in body of my note  -->
- 

**Supporting Content**
<!-- Supporting content in tail of my note  -->
-