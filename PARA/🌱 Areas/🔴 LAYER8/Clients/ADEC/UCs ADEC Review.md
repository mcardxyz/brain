___

# UC 1 - Possible Port Scan
- Ainda temos alguns loopbacks no resultado:
	- Adicionar: `| where RemoteIP !startswith "::ffff:127."` ou filtrar por `RemoteIPType !in ("Loopback", "FourToSixMapping")`

# UC 2 - Possible Host Scan
Query 1
- Demasiados resultados.. Não é viavel em prod
Query 2
- Ao excluirmos o `adcoesao.pt` tamos a perder contexto do que deviamos monitorizar!

Possiveis soluções:
- Focar em scanning externo (`RemoteIPType == "Public"`) e mudar DistinctHosts de 500 para 50. Subit para 75-100 se muito ruido.

# UC 03 - High Number of Events
- Talvez mudar o baseline para ago(7d)
- `RemoteIPType != "Loopback"` em ambos os blocos
- Thresholds de 3000 → 5000 e 3x → 5x?

# UC04 - Abnormal Outbound Traffic
- Uma lista enorme de exclude poderá não ser facil de manter… (mas adicionei mais tho)
	- Subimos thresholds?
- Thresholds subidos: `50 → 100` connections **AND** (não OR) `35 → 50` IPs distintos. o `OR` original fazia com que qualquer processo com 51 connections disparasse mesmo que fosse tudo para o mesmo IPThresholds subidos: `50 → 100` connections **AND** (não OR) `35 → 50` IPs distintos, o `OR` original fazia com que qualquer processo com 51 connections disparasse mesmo que fosse tudo para o mesmo IP

# UC05 - External RDP/SSH Connection
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where RemotePort in (3389, 22)
| where ActionType in ("ConnectionSuccess", "ConnectionFailed", "ConnectionAttemptBlocked")
| where RemoteIPType == "Public"
| where DeviceName !startswith "s-dc-"
| summarize
    Connections = count(),
    DistinctRemoteIPs = dcount(RemoteIP),
    RemoteIPs = make_set(RemoteIP, 20),
    Ports = make_set(RemotePort),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceId, DeviceName, InitiatingProcessFileName, LocalIP
| extend
    AlertTitle = "External RDP/SSH Connection Detected",
    AlertDescription = strcat(InitiatingProcessFileName, " on ", DeviceName,
        " connected to ", DistinctRemoteIPs, " public IP(s) on port(s) ",
        tostring(Ports))
| project
    DeviceId, DeviceName, InitiatingProcessFileName, LocalIP,
    RemoteIPs, Ports, Connections, DistinctRemoteIPs,
    FirstSeen, LastSeen,
    AlertTitle, AlertDescription
| sort by Connections desc
```

- **`RemoteIPType == "Public"`**
- Removida exclude process - Aqui da-nos jeito ter os processos…
- Summarize improved