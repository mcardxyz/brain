___

# Origem do Incidente
Sentinel gerou alerta de actividade M365 originada de IPs TOR conhecidos, associada ao utilizador `grc_knowbe4@layer8.pt`: [**"Activity from a TOR IP address involving one user"**](https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/IncidentPage.ReactView/incidentArmId/%2Fsubscriptions%2F486b558d-2715-4d65-beec-8b34ed11b776%2FresourceGroups%2Frg-soc-internal-layer8%2Fproviders%2FMicrosoft.OperationalInsights%2Fworkspaces%2Flaw-soc-internal-layer8%2Fproviders%2FMicrosoft.SecurityInsights%2FIncidents%2F5d9a8abf-5b70-4fba-80b9-7bf9057e34a2).


TOR IPs no alerta:
- [`195.47.238.177`](https://www.virustotal.com/gui/ip-address/195.47.238.177) (SE),
- [`185.220.101.3`](https://www.virustotal.com/gui/url/f03191d257c3b480daa04931b6a4a983a7c93b81f384839df2e0c03373ff98c4) (DE),
- [`109.70.100.9`](https://www.virustotal.com/gui/url/256261e8f58796c2af6fd9eeb2ab70805ecf25c139b91f1ccad714dd3a8c89f6) (AT),
- [`178.20.55.16`](https://www.virustotal.com/gui/url/0e44fa846b0ec4c87056b6c738659ffe0e00af665dcbeee94aebd05c5b66d897) (FR)


___
# Investigação

## Fortinet - os TOR IPs passaram pela firewall?
```kql
Fortinet_CL
| where TimeGenerated > ago(7d)
| where DestinationPort in ("9001", "9030", "9050", "9150")
| summarize Connections = count(), BytesSent = sum(tolong(BytesSent))
  by SourceIP, DestinationIP, DestinationPort, Action
| order by Connections desc
```

- Tudo `deny`, `BytesSent = 0`. Tráfego inbound de IPs externos bloqueado pela policy `DROP ALL`.
- Sem relação com o incidente, utilizador acedeu ao M365 fora do perímetro de network.

___

## 2. SigninLogs - Os logins TOR foram bem sucedidos?
```kql
let tor_ips = dynamic(["195.47.238.177","185.220.101.3","109.70.100.9","178.20.55.16"]);
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "grc_knowbe4@layer8.pt"
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResultType
| order by TimeGenerated desc
```

- `ResultType = 0` (sucesso) em todos. Teams, Outlook, OfficeHome acedidos via TOR.

___

## 3. SigninLogs - Qual o padrão histórico de IPs?
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "grc_knowbe4@layer8.pt"
| summarize LoginCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
  by IPAddress, Location
| order by LoginCount desc
```

**Resultado:**

| IP               | País | Logins | Período       |
| ---------------- | ---- | ------ | ------------- |
| `185.220.101.3`  | DE   | 46     | só 18/03      |
| `109.70.100.9`   | AT   | 30     | só 18/03      |
| `178.20.55.16`   | FR   | 28     | só 18/03      |
| `88.157.93.145`  | PT   | 25     | 06/03 → 17/03 |
| `195.47.238.177` | SE   | 18     | só 18/03      |
| `93.108.234.105` | PT   | 1      | 11/03         |
- Durante 12 dias: só IPs PT.
- No dia 18/03: **122 logins em ~12 minutos via 4 exit nodes TOR** - não é comportamento humano, é automatizado.

___
## 4. OfficeActivity - O que foi feito durante a sessão TOR?
```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-03-18T13:30:00Z) .. datetime(2026-03-18T14:00:00Z))
| where UserId == "grc_knowbe4@layer8.pt"
| project TimeGenerated, Operation, OfficeWorkload, ClientIP, ResultStatus
| order by TimeGenerated asc
```

- `MailItemsAccessed` × 2 - Exchange, sem ClientIP → protocolo EWS/MAPI legacy (potencial bypass CAP)
- `TeamsSessionStarted` × 2 - via `109.70.100.9` e `185.220.101.3`

___
## 5. OfficeActivity - Havia actividade suspeita antes da sessão TOR?
```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId == "grc_knowbe4@layer8.pt"
| where Operation in ("SharingInheritanceBroken","SharingSet","FileDownloaded","AttachmentAccess")
| extend params = tostring(Parameters)
| project TimeGenerated, Operation, OfficeWorkload, ClientIP, params
| order by TimeGenerated desc
```







```kql
06/03 – 17/03   Actividade normal de IPs PT. MailItemsAccessed, FileAccessed, Teams.

16/03 17:09     IP legítimo (88.157.93.145)
                AttachmentAccess (Exchange)
                FolderCreated + SharingInheritanceBroken + SharingSet em batch
                → Staging: pasta criada, permissões isoladas, partilha configurada

17/03           MailItemsAccessed frequente ao longo do dia

18/03 13:33     Início da sessão TOR (4 exit nodes: DE/AT/FR/SE)
18/03 13:34     MailItemsAccessed × 2 via EWS/MAPI (sem IP)
18/03 13:35     TeamsSessionStarted × 2
18/03 13:45     Último login TOR registado
```






















## SigninLogs - onde autenticou
**Todos os logins com TOR IPs têm ResultType = 0 (sucesso).** A conta autenticou com sucesso via nós TOR.

|IP|País|Apps|
|---|---|---|
|`185.220.101.3`|DE|Teams, Outlook|
|`178.20.55.16`|FR|Outlook|
|`109.70.100.9`|AT|Teams, My Profile|
|`195.47.238.177`|SE|Teams, Outlook|

- Janela activa: **13:43 → 13:45 UTC**  sessão curta, múltiplas apps
- Todos os IPs são conhecidos exit nodes TOR

---

## OfficeActivity - o que foi feito

**13:35 UTC (via TOR):**
- `TeamsSessionStarted` de `185.220.101.3` e `109.70.100.9`
- `MailItemsAccessed` (Exchange) — sem ClientIP visível = protocolo legacy/MAPI

**Histórico normal (dias anteriores):**
- IPs `93.108.234.105` e `88.157.93.145` - parecem ser os IPs legítimos do utilizador
- `FileAccessed`, `ListViewed`, `SharePoint`, `OneDrive` - actividade típica

**Red flag:**
- `SharingInheritanceBroken` em OneDrive — 17/03 às 17:27 - **quebrou herança de permissões num ficheiro/pasta**. Isto pode ser exfiltração prep ou partilha não autorizada.

---

## Queries de follow-up prioritárias

### 1. O que foi acedido via Exchange durante a sessão TOR

```kql
OfficeActivity
| where TimeGenerated between (
    datetime(2026-03-18T13:30:00Z) .. datetime(2026-03-18T14:00:00Z)
  )
| where UserId == "grc_knowbe4@layer8.pt"
| project TimeGenerated, Operation, OfficeWorkload, 
          ClientIP, Parameters, ResultStatus
| order by TimeGenerated asc
```

### 2. Investigar o SharingInheritanceBroken

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId == "grc_knowbe4@layer8.pt"
| where Operation in (
    "SharingInheritanceBroken", "AddedToSecureLink",
    "SecureLinkCreated", "AnonymousLinkCreated",
    "SharingSet", "FileDownloaded"
  )
| project TimeGenerated, Operation, OfficeWorkload, 
          ClientIP, Parameters
| order by TimeGenerated desc
```

### 3. Confirmar IPs legítimos do utilizador vs TOR

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "grc_knowbe4@layer8.pt"
| summarize 
    LoginCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Apps = make_set(AppDisplayName)
  by IPAddress, Location
| order by LoginCount desc
```









---

## Avaliação actual

|Factor|Detalhe|
|---|---|
|**Severidade real**|Medium-High (não Low como o Sentinel classificou)|
|**Autenticação**|Sucesso via TOR — MFA passou ou não está forçado|
|**Acesso confirmado**|Exchange + Teams durante sessão TOR|
|**Actividade suspeita prévia**|SharingInheritanceBroken 24h antes|
|**Veredicto preliminar**|Conta comprometida OU utilizador a contornar controlos intencionalmente|

A pergunta imediata é: **o `grc_knowbe4@layer8.pt` é uma conta de teste do KnowBe4** (plataforma de phishing simulation)? O nome sugere isso. Se for, pode ser que a própria plataforma KnowBe4 use IPs TOR para simulações — mas mesmo assim o `SharingInheritanceBroken` merece investigação.

Confirmas se é conta real ou conta de simulação?