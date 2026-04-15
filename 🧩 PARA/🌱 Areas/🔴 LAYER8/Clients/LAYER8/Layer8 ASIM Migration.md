___

# ASIM Implementação
- `vimNetworkSessionFortigate` — parser vendor-específico para `Fortinet_CL`
- `vimNetworkSessionFortinetOther` — parser para `FortinetOther_CL`
- `imNetworkSession` — unifying parser, ponto de entrada único


## Parser 1
**Function name:** `vimNetworkSessionFortigate`

```kql
Fortinet_CL
| extend NetworkProtocol = case(
    Protocol == 1,  "ICMP",
    Protocol == 6,  "TCP",
    Protocol == 17, "UDP",
    Protocol == 47, "GRE",
    Protocol == 50, "ESP",
    Protocol == 58, "IPv6-ICMP",
    tostring(Protocol))
| extend
    SrcIpAddr              = SourceIP,
    DstIpAddr              = DestinationIP,
    SrcPort                = SourcePort,
    DstPort                = DestinationPort,
    SrcBytes               = tolong(BytesSent),
    DstBytes               = tolong(BytesReceived),
    SrcPackets             = tolong(PacketsSent),
    DstPackets             = tolong(PacketsReceived),
    NetworkDuration        = Duration,
    DvcAction              = Action,
    EventResult            = iff(Action in ("accept", "Allow"), "Success", "Failure"),
    DvcName                = DeviceName,
    SrcNatIpAddr           = NATSourceIP,
    SrcNatPortNumber       = NATSourcePort,
    NetworkApplicationProtocol = Application,
    RuleName               = PolicyName,
    SrcGeoCountry          = SourceCountry,
    DstGeoCountry          = DestinationCountry,
    EventStartTime         = TimeGenerated,
    EventEndTime           = datetime_add("second", tolong(Duration), TimeGenerated),
    EventVendor            = "Fortinet",
    EventProduct           = "FortiGate",
    EventSchema            = "NetworkSession",
    EventSchemaVersion     = "0.2.6",
    EventOriginalUid       = LogID,
    EventSeverity          = Severity
| project
    TimeGenerated, EventStartTime, EventEndTime,
    SrcIpAddr, SrcPort, SrcNatIpAddr, SrcNatPortNumber,
    SrcBytes, SrcPackets, SrcGeoCountry,
    DstIpAddr, DstPort, DstBytes, DstPackets, DstGeoCountry,
    NetworkProtocol, NetworkDuration, NetworkApplicationProtocol,
    DvcAction, EventResult, DvcName, RuleName,
    EventSeverity, EventOriginalUid,
    EventVendor, EventProduct, EventSchema, EventSchemaVersion
```


## Parser 2
**Parser:** `vimNetworkSessionFortinetOther`

```kql
FortinetOther_CL
| where isnotempty(SourceIP) and isnotempty(DestinationIP)
| extend
    SrcIpAddr          = SourceIP,
    DstIpAddr          = DestinationIP,
    SrcPort            = int(null),
    DstPort            = int(null),
    NetworkProtocol    = "",
    SrcBytes           = tolong(BytesSent),
    DstBytes           = tolong(BytesReceived),
    NetworkDuration    = Duration,
    DvcAction          = Action,
    EventResult        = iff(Action in ("accept","Allow","pass"), "Success", "Failure"),
    DvcName            = DeviceName,
    EventStartTime     = TimeGenerated,
    EventEndTime       = datetime_add("second", tolong(Duration), TimeGenerated),
    EventVendor        = "Fortinet",
    EventProduct       = "FortiGate",
    EventSchema        = "NetworkSession",
    EventSchemaVersion = "0.2.6",
    EventOriginalUid   = LogID,
    EventSeverity      = Severity,
    AdditionalFields   = bag_pack("Category", Category, "Reason", Reason, "User", User)
| project
    TimeGenerated, EventStartTime, EventEndTime,
    SrcIpAddr, SrcPort, DstIpAddr, DstPort,
    SrcBytes, DstBytes, NetworkProtocol, NetworkDuration,
    DvcAction, EventResult, DvcName,
    EventSeverity, EventOriginalUid,
    AdditionalFields,
    EventVendor, EventProduct, EventSchema, EventSchemaVersion
```

# Unifying Parser
`imNetworkSession`

```kql
union isfuzzy=true
    vimNetworkSessionFortigate(),
    vimNetworkSessionFortinetOther()
```