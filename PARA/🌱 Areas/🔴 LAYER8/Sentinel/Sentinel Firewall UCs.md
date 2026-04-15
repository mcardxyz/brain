---
tags:
  - Azure
  - KQL
  - SIEM
  - "#UseCases"
  - "#Firewall"
  - "#Fortinet"
date: 2026-03-02
---
___
# Sentinel Firewall - TRAFFIC

## UC-01 | Event Disrupt 1 Hour [FW_FORTINET]
**Descrição:** Monitoriza a continuidade de ingestão de logs da tabela Fortinet_CL. Deteta quando não são recebidos logs na última hora, o que pode indicar uma disrupção na recolha de dados.

| -                          | -                                       |
| -------------------------- | --------------------------------------- |
| Severidade                 | Medium                                  |
| Corre a cada               | 15 minutos                              |
| Verifica dados dos últimos | 15 minutos                              |
| MITRE ATT&CK               | Initial Access (T1078 - Valid Accounts) |
**Query:**
```kql
let threshold = 3600; // seconds = 1 hour
Fortinet_CL
| summarize recentTime = max(TimeGenerated)
| extend age = datetime_diff('second', now(), recentTime)
| where age > threshold
| extend
    RecentTimeFormatted = format_datetime(recentTime, 'yyyy-MM-dd HH:mm:ss'),
    AgeMinutes = age / 60,
    AgeHours = age / 3600
| project recentTime, RecentTimeFormatted, age, AgeMinutes, AgeHours
```



___
## UC-02 | Possible Port Scan [FW_FORTINET]
**Descrição:** Deteta port scanning agressivo. Um IP de origem a contactar mais de 50 portos de destino distintos no mesmo IP de destino, dentro de uma janela de 2 minutos.

| Severidade                 | Medium                                             |
| -------------------------- | -------------------------------------------------- |
| Corre a cada               | 5 minutos                                          |
| Verifica dados dos últimos | 30 minutos                                         |
| MITRE ATT&CK               | Reconnaissance (T1046 - Network Service Discovery) |
**Query:**
```kql
let timeWindow = 2m;
let portThreshold = 50;
Fortinet_CL
| summarize
    DistinctPorts = dcount(DestinationPort),   // Quantos portos distintos?
    PortList = make_set(DestinationPort, 100), // Lista dos portos (para contexto)
    EventCount = count()                        // Total de eventos
  by SourceIP, DestinationIP, bin(TimeGenerated, timeWindow)  // Agrupado por par src/dst em janelas de 2min
| where DistinctPorts > portThreshold          // Só alerta se > 50 portos distintos
| project TimeGenerated, SourceIP, DestinationIP, DistinctPorts, PortList, EventCount
| order by DistinctPorts desc
```



___
## UC-03 | Possible Port  Scan - Slow Pace [FW_FORTINET]
**Descrição:**

| Severidade                 | Medium                                             |
| -------------------------- | -------------------------------------------------- |
| Corre a cada               | 30 minutos                                         |
| Verifica dados dos últimos | 1 hora                                             |
| MITRE ATT&CK               | Reconnaissance (T1046 - Network Service Discovery) |
**Query:**
```kql
let timeWindow = 1h;
let portThreshold = 30;
Fortinet_CL
| summarize
    DistinctPorts = dcount(DestinationPort),
    PortList = make_set(DestinationPort, 100),
    EventCount = count()
  by SourceIP, DestinationIP, bin(TimeGenerated, timeWindow)
| where DistinctPorts > portThreshold
| where DistinctPorts <= 50  // Exclui fast scanners já cobertos pelo UC-02
| project TimeGenerated, SourceIP, DestinationIP, DistinctPorts, PortList, EventCount
| order by DistinctPorts desc
```



___
## UC-04 | Possible Host Scan [FW_FORTINET]
**Descrição:** Deteta host scanning agressivo interno. Um IP de origem interno a contactar mais de 50 IPs de destino internos distintos, dentro de uma janela de 2 minutos. Cobre exclusivamente tráfego interno-para-interno, sendo um indicador forte de movimento lateral pós-compromisso.

| Severidade                 | Medium                                             |
| -------------------------- | -------------------------------------------------- |
| Corre a cada               | 5 minutos                                          |
| Verifica dados dos últimos | 30 minutos                                         |
| MITRE ATT&CK               | Reconnaissance (T1046 - Network Service Discovery) |
**Query:**
```kql
let timeWindow = 2m;
let hostThreshold = 50;
Fortinet_CL
| where ipv4_is_private(SourceIP)       // Apenas origem interna
| where ipv4_is_private(DestinationIP)  // Apenas destino interno
| summarize
    DistinctHosts = dcount(DestinationIP),
    HostList = make_set(DestinationIP, 100),
    EventCount = count()
  by SourceIP, bin(TimeGenerated, timeWindow)
| where DistinctHosts > hostThreshold
| project TimeGenerated, SourceIP, DistinctHosts, HostList, EventCount
| order by DistinctHosts desc
```



___
## UC-05 | Possible Host Scan - Slow Pace [FW_FORTINET]
**Descrição:** Deteta host scanning furtivo de baixa cadência. Um IP de origem interno a contactar entre 30 a 50 IPs de destino internos distintos, dentro de uma janela de 1 hora. Complementa o UC-04, cobrindo comportamentos evasivos que espaçam deliberadamente as tentativas para escapar à deteção rápida. Tráfego interno-para-interno exclusivamente.

| Severidade                 | Medium                                             |
| -------------------------- | -------------------------------------------------- |
| Corre a cada               | 30 minutos                                         |
| Verifica dados dos últimos | 1 hora                                             |
| MITRE ATT&CK               | Reconnaissance (T1046 - Network Service Discovery) |
**Query:**
```kql
let timeWindow = 1h;
let hostThreshold = 30;
Fortinet_CL
| where ipv4_is_private(SourceIP)
| where ipv4_is_private(DestinationIP)
| summarize
    DistinctHosts = dcount(DestinationIP),
    HostList = make_set(DestinationIP, 100),
    EventCount = count()
  by SourceIP, bin(TimeGenerated, timeWindow)
| where DistinctHosts > hostThreshold
| where DistinctHosts <= 50 // Exclui fast scanners já cobertos pelo UC-04
| project
    TimeGenerated,
    SourceIP,
    DistinctHosts,
    HostList,
    EventCount
| order by DistinctHosts desc
```



___
## UC-06 | High Number of Events [FW_FORTINET]
**Descrição:** Deteta picos anómalos de volume de eventos de firewall usando uma média móvel. Dispara quando o bucket atual de 20 minutos excede o dobro da média dos 5 buckets anteriores e está acima do mínimo absoluto de 500 eventos. A direção do tráfego (inbound/outbound/internal/external) é derivada dinamicamente a partir dos ranges de IP.

| Severidade                 | Medium                                      |
| -------------------------- | ------------------------------------------- |
| Corre a cada               | 20 minutos                                  |
| Verifica dados dos últimos | 2 horas                                     |
| MITRE ATT&CK               | Impact (T1499 - Endpoint Denial of Service) |
**Query:**
```kql
let bucketSize = 20m;
let thresholdMultiplier = 2.0;
let minBuckets = 6;
let absoluteMin = 500;
Fortinet_CL
| extend Direction = case(
    not(ipv4_is_private(SourceIP)) and ipv4_is_private(DestinationIP), 'inbound',
    ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP)), 'outbound',
    ipv4_is_private(SourceIP) and ipv4_is_private(DestinationIP), 'internal',
    'external'
)
| summarize EventCount = count()
  by bin(TimeGenerated, bucketSize), Direction
| sort by Direction asc, TimeGenerated desc
| serialize rn = row_number(0, prev(Direction) != Direction)
| extend BucketIndex = rn - 1
| summarize
    CurrentValue = minif(EventCount, BucketIndex == 0),
    MA_1 = minif(EventCount, BucketIndex == 1),
    MA_2 = minif(EventCount, BucketIndex == 2),
    MA_3 = minif(EventCount, BucketIndex == 3),
    MA_4 = minif(EventCount, BucketIndex == 4),
    MA_5 = minif(EventCount, BucketIndex == 5),
    BucketCount = count()
  by Direction
| where BucketCount >= minBuckets
| extend MovingAverage = (MA_1 + MA_2 + MA_3 + MA_4 + MA_5) / 5.0
| where CurrentValue > thresholdMultiplier * MovingAverage
| where CurrentValue > absoluteMin
| project
    Direction,
    CurrentValue,
    MovingAverage,
    ThresholdMultiplier = thresholdMultiplier,
    ThresholdValue = thresholdMultiplier * MovingAverage
| order by CurrentValue desc
```



___
## UC-07 | Abnormal Outbound Traffic [FW_FORTINET]
**Descrição:** Deteta potencial exfiltração de dados. IPs internos a enviar mais de 100 MB para o exterior numa janela de 10 minutos, com volume enviado superior ao recebido. Exclui políticas legítimas de alto volume conhecidas.

| Severidade                 | Medium                                                        |
| -------------------------- | ------------------------------------------------------------- |
| Corre a cada               | 10 minutos                                                    |
| Verifica dados dos últimos | 10 minutos                                                    |
| MITRE ATT&CK               | Exfiltration (T1048 - Exfiltration Over Alternative Protocol) |
**Query:**
```kql
let timeWindow = 10m;
let bytesThreshold = 104857600; // 100 MB
let excludedPolicies = dynamic(['DNS8', 'MS', 'Internet', '2001', '1046']);
Fortinet_CL
| where ipv4_is_private(SourceIP)
| where not(ipv4_is_private(DestinationIP))
| where isnotempty(BytesSent) and isnotempty(BytesReceived)
| where BytesSent > BytesReceived
| where TimeGenerated >= ago(timeWindow)
| where PolicyName !in (excludedPolicies)
| summarize
    TotalBytesSent = sum(BytesSent),
    TotalBytesReceived = sum(BytesReceived),
    EventCount = count(),
    Policies = make_set(PolicyName, 10)
  by SourceIP, DestinationIP, DestinationCountry
| where TotalBytesSent > bytesThreshold
| project
    SourceIP,
    DestinationIP,
    DestinationCountry,
    TotalBytesSent,
    TotalBytesReceived,
    Ratio = round(todouble(TotalBytesSent) / todouble(TotalBytesReceived + 1), 2),
    EventCount,
    Policies
| order by TotalBytesSent desc
```



___
## UC-08 | Outbound Traffic to Dangerous Country [FW_FORTINET]
**Descrição:** Deteta ligações outbound aceites de IPs internos para países com score de risco AML (Anti-Money Laundering) superior a 5.0. Utiliza uma tabela de países e scores AML embutida diretamente na query. Os resultados são desduplicados por par src/dst para reduzir ruído.

| Severidade                 | Medium                                                                   |
| -------------------------- | ------------------------------------------------------------------------ |
| Corre a cada               | 10 minutos                                                               |
| Verifica dados dos últimos | 10 minutos                                                               |
| MITRE ATT&CK               | Exfiltration, Command and Control (T1041 - Exfiltration Over C2 Channel) |
**Query:**
```kql
let amlThreshold = 5.0;
let amlCountries = datatable(Country:string, AMLScore:real)[
    'The Democratic Republic Of The Congo', 8.10,
    'Haiti', 8.25,
    'Myanmar', 8.13,
    'Chad', 8.14,
    'Mozambique', 7.88,
    'Republic Of Congo', 7.91,
    'Madagascar', 7.43,
    'GuineaBissau', 7.69,
    'Gabon', 7.73,
    'Venezuela', 7.63,
    'Laos', 7.44,
    'Algeria', 7.22,
    'Liberia', 7.17,
    'Cambodia', 6.78,
    'Suriname', 7.06,
    'Angola', 7.03,
    'Mali', 7.06,
    'Kenya', 6.95,
    'Togo', 6.95,
    'Cote Divoire', 6.87,
    'Turkmenistan', 6.80,
    'Vietnam', 6.96,
    'Sierra Leone', 7.09,
    'Eswatini', 6.97,
    'Mauritania', 6.62,
    'Cameroon', 6.75,
    'Uganda', 6.83,
    'Benin', 6.62,
    'Nigeria', 6.72,
    'Solomon Islands', 6.86,
    'Tonga', 6.43,
    'Nicaragua', 6.42,
    'China', 6.77,
    'Burkina Faso', 6.48,
    'Niger', 6.64,
    'Tanzania', 6.27,
    'Senegal', 6.67,
    'Gambia', 5.66,
    'Zimbabwe', 5.52,
    'Ethiopia', 5.54,
    'Pakistan', 5.44,
    'Bhutan', 5.89,
    'Cape Verde', 6.05,
    'Saint Kitts and Nevis', 6.11,
    'Macao SAR China', 6.05,
    'Sri Lanka', 5.42,
    'Zambia', 5.70,
    'Bahamas', 5.49,
    'Kyrgyzstan', 6.00,
    'Tajikistan', 5.91,
    'Panama', 5.76,
    'South Africa', 5.85,
    'Thailand', 5.82,
    'Bangladesh', 5.80,
    'Palau', 5.68,
    'United Arab Emirates', 5.74,
    'Philippines', 5.64,
    'Cuba', 5.64,
    'Malawi', 5.63,
    'Honduras', 5.60,
    'Turkey', 5.54,
    'Trkiye', 5.53,
    'Vanuatu', 5.45,
    'Guatemala', 5.38,
    'Saudi Arabia', 5.38,
    'Barbados', 5.32,
    'Jamaica', 5.29,
    'Ghana', 5.29,
    'Seychelles', 5.23,
    'Saint Lucia', 5.25,
    'Malaysia', 5.21,
    'Dominican Republic', 5.21,
    'Mexico', 5.21,
    'Belarus', 5.33,
    'Russia', 5.24,
    'Uzbekistan', 5.12,
    'Bulgaria', 5.16,
    'Indonesia', 5.01
];
let dangerousCountries = amlCountries
| where AMLScore > amlThreshold
| project Country;
Fortinet_CL
| where Action =~ 'accept'
| where ipv4_is_private(SourceIP)
| where not(ipv4_is_private(DestinationIP))
| where isnotempty(DestinationCountry)
| where DestinationCountry != 'Reserved'
| join kind=inner dangerousCountries on $left.DestinationCountry == $right.Country
| join kind=inner amlCountries on $left.DestinationCountry == $right.Country
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Ports = make_set(DestinationPort, 10),
    Policies = make_set(PolicyName, 10),
    Applications = make_set(Application, 10),
    AMLScore = max(AMLScore)
  by SourceIP, DestinationIP, DestinationCountry
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    DestinationIP,
    DestinationCountry,
    AMLScore,
    EventCount,
    Ports,
    Policies,
    Applications
| order by AMLScore desc, EventCount desc
```



___
## UC-09 | External RDP/SSH Connections Allowed [FW_FORTINET]
**Descrição:** Deteta ligações RDP (porto 3389) ou SSH (porto 22) aceites provenientes de IPs externos para destinos internos. Qualquer ligação aceite nestas condições é considerada de alta prioridade independentemente do volume. É a única regra de severidade High do bundle.

| Severidade                 | High                                                                |
| -------------------------- | ------------------------------------------------------------------- |
| Corre a cada               | 5 minutos                                                           |
| Verifica dados dos últimos | 5 minutos                                                           |
| MITRE ATT&CK               | Initial Access, Lateral Movement (T1133 - External Remote Services) |
**Query:**
```kql
let rdpPort = 3389;
let sshPort = 22;
Fortinet_CL
| where Action =~ 'accept'
| where DestinationPort in (rdpPort, sshPort)
| where not(ipv4_is_private(SourceIP))
| where ipv4_is_private(DestinationIP)
| extend ServiceType = case(
    DestinationPort == rdpPort, 'RDP',
    DestinationPort == sshPort, 'SSH',
    'Unknown'
)
| summarize
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Policies = make_set(PolicyName, 10),
    SourcePorts = make_set(SourcePort, 10)
  by SourceIP, SourceCountry, DestinationIP, DestinationPort, ServiceType
| project
    FirstSeen,
    LastSeen,
    ServiceType,
    SourceIP,
    SourceCountry,
    DestinationIP,
    DestinationPort,
    EventCount,
    SourcePorts,
    Policies
| order by EventCount desc
```



___


# Sentinel Firewall - AUDIT

## UC-10 | SYSTEM Login Outside Business Hours [FW_FORTINET]
**Descrição:** Deteta logins administrativos bem-sucedidos na firewall fora do horário de expediente (antes das 07:00 ou depois das 19:00) ou ao fim de semana. Consulta a tabela FortinetOther_CL filtrando eventos de auth-logon com LogID 0102043039. Os campos são extraídos do log raw via regex.

| -                          | -                                       |
| -------------------------- | --------------------------------------- |
| Severidade                 | Medium                                  |
| Corre a cada               | 15 minutos                              |
| Verifica dados dos últimos | 15 minutos                              |
| MITRE ATT&CK               | Initial Access (T1078 - Valid Accounts) |
**Query:**
```kql
let utcOffset = 0; // UTC+0 (WET - inverno). Alterar para 1 no verão (WEST)
let businessStart = 7;
let businessEnd = 19;

FortinetOther_CL
| where Message has 'subtype=user'
| where Message has 'act=auth-logon'
| where LogID == '0102043039'
| extend Username = extract(@'duser=([^\s]+)', 1, Message)
| extend SourceIP = extract(@'src=([^\s]+)', 1, Message)
| extend DeviceName = extract(@'dvchost=([^\s]+)', 1, Message)
| extend LocalTime = TimeGenerated + totimespan(strcat(tostring(utcOffset), 'h'))
| extend LocalHour = hourofday(LocalTime)
| extend LocalDayOfWeek = dayofweek(LocalTime) / 1d
| where LocalHour < businessStart
    or LocalHour >= businessEnd
    or LocalDayOfWeek == 0
    or LocalDayOfWeek == 6
| project
    TimeGenerated,
    LocalTime,
    LocalHour,
    LocalDayOfWeek,
    Username,
    SourceIP,
    DeviceName,
    LogID,
    Message
| order by TimeGenerated desc
```


___

## UC-11 | SYSTEM Configuration Outside Business Hours [FW_FORTINET]
**Descrição:** Deteta alterações de configuração na firewall fora do horário de expediente (a partir das 19:00 ou antes das 07:00) ou ao fim de semana.

| Severidade                 | Medium                                                 |
| -------------------------- | ------------------------------------------------------ |
| Corre a cada               | 15 minutos                                             |
| Verifica dados dos últimos | 15 minutos                                             |
| MITRE ATT&CK               | Defense Evasion, Persistence (T1562 - Impair Defenses) |
**Query:**
```kql
let utcOffset = 0; // UTC+0 (WET - inverno). Alterar para 1 no verão (WEST)
let businessStart = 7;
let businessEnd = 19;

FortinetOther_CL
| where Message has_any ('subtype=system', 'subtype=config')
| where Message has_any (
    'act=Edit', 'act=Add', 'act=Delete', 'act=Move', 'act=Rename',
    'act=add-vdom', 'act=reboot', 'act=restore-image', 'act=loaded-image',
    'cfg_attr')
| extend Username = extract(@'duser=([^\s]+)', 1, Message)
| extend DeviceName = extract(@'dvchost=([^\s]+)', 1, Message)
| extend Action = extract(@'act=([^\s]+)', 1, Message)
| extend ConfigObject = extract(@'msg=([^\|]+)', 1, Message)
| where ConfigObject !has 'deleted log file' // Excluir rotação automática de logs
| where Username != 'FGT_ha_admin'           // Excluir conta de serviço HA
| extend LocalTime = TimeGenerated + totimespan(strcat(tostring(utcOffset), 'h'))
| extend LocalHour = hourofday(LocalTime)
| extend LocalDayOfWeek = dayofweek(LocalTime) / 1d
| where LocalHour < businessStart
    or LocalHour >= businessEnd
    or LocalDayOfWeek == 0
    or LocalDayOfWeek == 6
| project
    TimeGenerated,
    LocalTime,
    LocalHour,
    LocalDayOfWeek,
    Username,
    DeviceName,
    Action,
    ConfigObject,
    LogID,
    Message
| order by TimeGenerated desc
```

