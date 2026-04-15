___

source | extend Action = extract(@"act=([^\s]+)", 1, RawData) | extend DestinationCountry = extract(@"dstcountry=([^\s]+)", 1, RawData) | extend DestinationPort = toint(extract(@"dpt=([^\s]+)", 1, RawData)) | where isnotempty(Action) | where RawData !has "app=DNS" and RawData !has "app=NTP" and RawData !has "app=DHCP" and RawData !has "app=Ping" and RawData !has "app=ICMP" and RawData !has "app=SNMP" and RawData !has "app=mDNS" and RawData !has "app=NBNS" and RawData !has "app=Google-DNS" and RawData !has "app=Cloudflare-DNS" and RawData !has "app=Microsoft-Azure" and RawData !has "app=TCP_10051" and RawData !has "app=tcp/10051" and RawData !has "app=TCP_10050" and RawData !has "app=tcp/10050" | where not(RawData has "act=close" and RawData has "appcat=unscanned") and not(RawData has "act=server-rst" and RawData has "appcat=unscanned") and not(RawData has "act=timeout" and RawData has "appcat=unscanned") | where (Action in ("deny", "drop")) or (Action == "accept" and ((isnotempty(DestinationCountry) and DestinationCountry != "Reserved" and DestinationCountry != "private") or (DestinationPort == 21 or DestinationPort == 20 or DestinationPort == 23 or DestinationPort == 69 or DestinationPort == 80 or DestinationPort == 8080 or DestinationPort == 3389 or DestinationPort == 22) or (RawData has "out=" and toint(extract(@"out=([^\s]+)", 1, RawData)) > 10000000))) | extend Message = RawData, LogID = extract(@"logid=([^\s]+)", 1, RawData), PolicyID = toint(extract(@"policyid=([^\s]+)", 1, RawData)), PolicyName = extract(@"policyname=([^\s]+)", 1, RawData), SourceIP = extract(@"src=([^\s]+)", 1, RawData), SourcePort = toint(extract(@"spt=([^\s]+)", 1, RawData)), DestinationIP = extract(@"dst=([^\s]+)", 1, RawData), Protocol = toint(extract(@"proto=([^\s]+)", 1, RawData)), Application = extract(@"app=([^\s]+)", 1, RawData), Duration = toint(extract(@"duration=([^\s]+)", 1, RawData)), BytesSent = toint(extract(@"out=([^\s]+)", 1, RawData)), BytesReceived = toint(extract(@"in=([^\s]+)", 1, RawData)), PacketsSent = toint(extract(@"sentpkt=([^\s]+)", 1, RawData)), PacketsReceived = toint(extract(@"rcvdpkt=([^\s]+)", 1, RawData)), InboundInterface = extract(@"deviceInboundInterface=([^\s]+)", 1, RawData), OutboundInterface = extract(@"deviceOutboundInterface=([^\s]+)", 1, RawData), SourceCountry = extract(@"srccountry=([^\s]+)", 1, RawData), NATSourceIP = extract(@"sourceTranslatedAddress=([^\s]+)", 1, RawData), NATSourcePort = toint(extract(@"sourceTranslatedPort=([^\s]+)", 1, RawData)), Severity = extract(@"deviceSeverity=([^\s]+)", 1, RawData), DeviceName = extract(@"dvchost=([^\s]+)", 1, RawData), VirtualDomain = extract(@"vd=([^\s]+)", 1, RawData) | project TimeGenerated, Message, LogID, PolicyID, PolicyName, SourceIP, SourcePort, DestinationIP, DestinationPort, Action, Protocol, Application, Duration, BytesSent, BytesReceived, PacketsSent, PacketsReceived, InboundInterface, OutboundInterface, SourceCountry, DestinationCountry, NATSourceIP, NATSourcePort, Severity, DeviceName, VirtualDomain


```
source
| extend
    Action           = extract(@"act=([^\s]+)", 1, RawData),
    DestinationCountry = extract(@"dstcountry=([^\s]+)", 1, RawData),
    DestinationPort  = toint(extract(@"dpt=([^\s]+)", 1, RawData))

// Drop rows with no action
| where isnotempty(Action)

// Filter noise services
| where RawData !has "app=DNS"
    and RawData !has "app=NTP"
    and RawData !has "app=DHCP"
    and RawData !has "app=Ping"
    and RawData !has "app=ICMP"
    and RawData !has "app=SNMP"
    and RawData !has "app=mDNS"
    and RawData !has "app=NBNS"
    and RawData !has "app=Google-DNS"
    and RawData !has "app=Cloudflare-DNS"
    and RawData !has "app=Microsoft-Azure"
    and RawData !has "app=TCP_10051"
    and RawData !has "app=tcp/10051"
    and RawData !has "app=TCP_10050"
    and RawData !has "app=tcp/10050"

// Drop unscanned session noise
| where not(RawData has "act=close"      and RawData has "appcat=unscanned")
    and not(RawData has "act=server-rst" and RawData has "appcat=unscanned")
    and not(RawData has "act=timeout"    and RawData has "appcat=unscanned")

// Keep only interesting traffic
//    a) any deny/drop
//    b) accepted traffic that matches at least one signal:
//       • routable destination country
//       • sensitive/insecure destination port
//       • large outbound transfer (>10 MB)
| where
    (Action in ("deny", "drop"))
    or (
        Action == "accept"
        and (
            (
                isnotempty(DestinationCountry)
                and DestinationCountry != "Reserved"
                and DestinationCountry != "private"
            )
            or DestinationPort in (20, 21, 23, 69, 80, 8080, 3389, 22)
            or (
                RawData has "out="
                and toint(extract(@"out=([^\s]+)", 1, RawData)) > 10000000
            )
        )
    )

// ── 6. Parse all remaining fields ────────────────────────────────────────────
| extend
    Message              = RawData,
    LogID                = extract(@"logid=([^\s]+)", 1, RawData),
    PolicyID             = toint(extract(@"policyid=([^\s]+)", 1, RawData)),
    PolicyName           = extract(@"policyname=([^\s]+)", 1, RawData),
    SourceIP             = extract(@"src=([^\s]+)", 1, RawData),
    SourcePort           = toint(extract(@"spt=([^\s]+)", 1, RawData)),
    DestinationIP        = extract(@"dst=([^\s]+)", 1, RawData),
    Protocol             = toint(extract(@"proto=([^\s]+)", 1, RawData)),
    Application          = extract(@"app=([^\s]+)", 1, RawData),
    Duration             = toint(extract(@"duration=([^\s]+)", 1, RawData)),
    BytesSent            = toint(extract(@"out=([^\s]+)", 1, RawData)),
    BytesReceived        = toint(extract(@"in=([^\s]+)", 1, RawData)),
    PacketsSent          = toint(extract(@"sentpkt=([^\s]+)", 1, RawData)),
    PacketsReceived      = toint(extract(@"rcvdpkt=([^\s]+)", 1, RawData)),
    InboundInterface     = extract(@"deviceInboundInterface=([^\s]+)", 1, RawData),
    OutboundInterface    = extract(@"deviceOutboundInterface=([^\s]+)", 1, RawData),
    SourceCountry        = extract(@"srccountry=([^\s]+)", 1, RawData),
    NATSourceIP          = extract(@"sourceTranslatedAddress=([^\s]+)", 1, RawData),
    NATSourcePort        = toint(extract(@"sourceTranslatedPort=([^\s]+)", 1, RawData)),
    Severity             = extract(@"deviceSeverity=([^\s]+)", 1, RawData),
    DeviceName           = extract(@"dvchost=([^\s]+)", 1, RawData),
    VirtualDomain        = extract(@"vd=([^\s]+)", 1, RawData)

// Project final columns
| project
    TimeGenerated,
    Message,
    LogID,
    PolicyID,
    PolicyName,
    SourceIP,
    SourcePort,
    DestinationIP,
    DestinationPort,
    Action,
    Protocol,
    Application,
    Duration,
    BytesSent,
    BytesReceived,
    PacketsSent,
    PacketsReceived,
    InboundInterface,
    OutboundInterface,
    SourceCountry,
    DestinationCountry,
    NATSourceIP,
    NATSourcePort,
    Severity,
    DeviceName,
    VirtualDomain
```


```spl
index="bens_alerts_sentinel_int"  source="prod_incidents_from_sentinel" source!="*metrics*"
| spath properties.title 
| spath properties.incidentNumber 
| spath properties.incidentUrl 
| spath properties.severity
| spath name
| rex field="properties.title" "(\[.*\])?\s*(?<title>.*)"
| eval time=strftime(_time, "%d/%m/%Y %H:%M:%S")
| table time title name "properties.incidentNumber" "properties.incidentUrl" "properties.severity"
| rename name as incidentid "properties.incidentNumber" as incidentnumber, "properties.incidentUrl" as incidenturl, "properties.severity" as sentinelseverity
| lookup bens_sentinel_mapping NAME AS title OUTPUT SEVERITY,WORKHOURS,CLASSIFICATION
| fillnull value="N/A"
| search WORKHOURS!="N/A"
| eval usecase = "[BENS#".CLASSIFICATION."9999] ".title
```

