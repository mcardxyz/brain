---
tags:
  - "#tcpdump"
  - "#PacketAnalysis"
  - "#Networking"
date: 2026-03-05
---
# Tcpdump

## Packet Capture

```bash
# Captures packets on any interface
tcpdump -i any
# Captures packets on a specific interface
tcpdump -i <interface>

# Writes captured packets to a file
tcpdump -w FILE

# Reads captured packets from a file
tcpdump -r FILE

# Captures a specific number of packets
tcpdump -c COUNT

# Don't resolve IP addresses
tcpdump -n

# Don't resolve IP addresses and don't resolve protocol numbers
tcpdump -nn

# Verbosity
tcdump -v
tcpdump -vv
tcpdump -vvv
```



___
## Filtering Expressions

```bash
# Filter by IP address or hostname
tcpdump host IP
tcpdump host HOSTNAME

# Filter by a specific source host
tcpdump src host IP

# Filter by a specific destination host
tcpdump dst host IP

# Filter by port number
tcpdump port PORT_NUMBER

# Filter by the specified source port number
tcpdump src port PORT_NUMBER

# Filter by the specified destination port number
tcpdump dst port PORT_NUMBER

# Filter by protocol
tcpdump PROTOCOL
```

**Logical Operators**
- `and`
- `or`
- `not`

### Advanced Filtering
- `greater LENGTH`
- `less LENGTH`
- 

___
## Displaying Packets

```bash
# Brief packet information
tcpdump -q

# Include MAC addresses
tcpdump -e

# Print packets as ASCII encoding
tcpdump -A

# Display packets in hexadecimal format
tcpdump -xx

# Show packets in both ex and ASCII formats
tcpdump -X
```