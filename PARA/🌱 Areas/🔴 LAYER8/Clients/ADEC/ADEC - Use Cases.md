___

# UC02 - Possible Port Scan

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where RemoteIPType != "Loopback"
| where DeviceName !startswith "s-dc-"
| summarize
    DistinctPorts = dcount(RemotePort),
    Ports = make_set(RemotePort, 50),
    Connections = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceId, DeviceName, LocalIP, RemoteIP, RemoteIPType
| where DistinctPorts > 15
| extend
    AlertTitle = "Possible Port Scan Detected",
    AlertDescription = strcat(DeviceName, " scanned ", DistinctPorts,
        " distinct ports on ", RemoteIP, " (", RemoteIPType, ")")
| project
    DeviceId, DeviceName, LocalIP, RemoteIP, RemoteIPType,
    DistinctPorts, Ports, Connections,
    FirstSeen, LastSeen,
    AlertTitle, AlertDescription
```



___
# UC03 - Possible Host Scan

- Threshold muito alto, tem de se afinar depois

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where RemoteIPType != "Loopback"
| where DeviceName !startswith "s-dc-"
| summarize
    DistinctHosts = dcount(RemoteIP),
    Hosts = make_set(RemoteIP, 50),
    DistinctPorts = dcount(RemotePort),
    Connections = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceId, DeviceName, LocalIP
| where DistinctHosts > 500
| extend
    AlertTitle = "Possible Host Scan Detected",
    AlertDescription = strcat(DeviceName, " contacted ", DistinctHosts,
        " distinct hosts in 1h from ", LocalIP)
| project
    DeviceId, DeviceName, LocalIP,
    DistinctHosts, Hosts, DistinctPorts, Connections,
    FirstSeen, LastSeen,
    AlertTitle, AlertDescription
```



___
# UC04 - High Number of Network Events

```kql
let Baseline = DeviceNetworkEvents
    | where TimeGenerated between (ago(7d) .. ago(1h))
    | where DeviceName !startswith "s-dc-"
    | summarize HourlyAvg = count() / 168.0 by DeviceName;
let Current = DeviceNetworkEvents
    | where TimeGenerated > ago(1h)
    | where DeviceName !startswith "s-dc-"
    | summarize CurrentCount = count() by DeviceId, DeviceName;
Current
| join kind=inner Baseline on DeviceName
| extend Multiplier = round(CurrentCount / HourlyAvg, 1)
| where CurrentCount > 3000 and Multiplier > 3
| extend
    AlertTitle = "High Number of Network Events",
    AlertDescription = strcat(DeviceName, " generated ", CurrentCount,
        " events in 1h (", Multiplier, "x above baseline of ",
        round(HourlyAvg, 0), ")")
| project
    DeviceId, DeviceName, CurrentCount,
    HourlyAvg = round(HourlyAvg, 0),
    Multiplier, AlertTitle, AlertDescription
| sort by Multiplier desc
```



___
# UC05 - Abnormal Outbound Traffic

```kql
let ExcludedProcesses = dynamic([
    "msedge.exe", "msedgewebview2.exe", "chrome.exe",
    "svchost.exe", "demagentprocess.exe", "outlook.exe",
    "onedrive.exe", "ms-teams.exe", "backgroundtaskhost.exe",
    "excel.exe", "winword.exe", "onedrive.sync.service.exe",
    "lsass.exe", "officeclicktorun.exe", "pangps.exe",
    "powerpnt.exe", "ntoskrnl.exe", "microsoft.management.service.exe"
]);

DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where DeviceName !startswith "s-dc-"
| where isnotempty(InitiatingProcessFileName)
| where InitiatingProcessFileName !in~ (ExcludedProcesses)
| summarize
    ConnectionCount = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    DistinctPorts = dcount(RemotePort),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceId, DeviceName, InitiatingProcessFileName
| where ConnectionCount > 50 or DistinctRemoteIPs > 35
| extend
    AlertTitle = "Abnormal Outbound Traffic",
    AlertDescription = strcat(InitiatingProcessFileName, " on ", DeviceName,
        " made ", ConnectionCount, " external connections to ",
        DistinctRemoteIPs, " distinct IPs")
| project
    DeviceId, DeviceName, InitiatingProcessFileName,
    ConnectionCount, DistinctRemoteIPs, DistinctPorts,
    FirstSeen, LastSeen,
    AlertTitle, AlertDescription
| sort by ConnectionCount desc
```

