___
## Tabela de Conteudos

- [[#Considerações]]
- [[#Fase 0 - Qualificação da Fonte]]
- [[#Fase 1 — Onboarding de Cliente Novo]]
- [[#Fase 2 — Integração de Nova Fonte]]
- [[#Fase 3 — Parser e Normalização]]
- [[#Fase 4 — Use Cases de Detecção]]
- [[#Fase 5 — SOAR e Automação]]
- [[#Referência Rápida]]


___
# Considerações
- ELK é sempre o destino universal - tudo chega aqui, sem filtro, para retenção e hunting
- Sentinel recebe apenas o que tem valor de deteção - custo controlado por DCR transforms
- Split de logs no rsyslog por tipo - firewall-traffic, firewall-other, firewall-uncategorized…
- Tabelas custom `_CL` sem CEF nativo; tabelas standard Microsoft para fontes nativas
- ASIM só quando há múltiplas fontes do mesmo tipo - com fonte única, regras apontam directamente à tabela
- RawData não é preservado na `_CL` do Sentinel - o ELK guarda o raw completo
- Acesso ao Sentinel do cliente via Azure Lighthouse


> [!important] CLASSIFICAR SEMPRE A FONTE PRIMEIRO !
> Antes de qualquer implementação, classificar a fonte. A classificação determina o caminho de ingestão, o tipo de tabela, e se ASIM é ou não necessário.



___
# Fase 0 - Qualificação da Fonte
Executar **sempre** antes de qualquer configuração. As respostas a estas perguntas determinam tudo o que se segue.
## 0.1 - Classificação do tipo de fonte

| Condição                                            | Decisão               | Ação                                                                                           |
| --------------------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------- |
| Fonte cloud nativa Microsoft                        | Conector nativo       | Usar conector nativo no Sentinel. Tabelas standard.                                            |
| Fonte on-prem com agent (Servidores Windows/Linux)  | AMA + DCR             | AMA nos servidores, DCR define recolha e destino. Tabelas standard (`SecurityEvent`, `Syslog`) |
| Fonte on-prem sem agent (firewalls, switches, APs…) | Syslog → VM Forwarder | rsyslog na VM Forwarder recebe na porta 514. Split routing decide caminho A ou B               |
| Fonte com formato CEF nativo                        | `CommonSecurityLog`   | Encaminhar para VM Forwarder. Tabela `CommonSecurityLog` no Sentinel                           |
| Fonte raw/proprietária sem CEF                      | Tabela `_CL` custom   | Pipeline rsyslog → ELK + AMA → DCR → tabela `_CL`. Parser manual necessário.                   |

## 0.2 - Decisão ASIM
- Já existe outra fonte do **mesmo tipo** no cliente (ex: segunda firewall de vendor diferente)? → **Implementar ASIM parser.**
- É a **única fonte** deste tipo no cliente? → Não implementar ASIM agora. Regras directas à tabela.
- O cliente pode crescer e adicionar vendors do mesmo tipo? → Considerar semi-normalização via function intermédia (ver [[#3.1 Sem ASIM - KQL Function intermédia]]).

## 0.3 - Decisão de caminho de ingestão (Syslog)
| Condição                                                                         | Caminho | Ação                                                                                     |
| -------------------------------------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------- |
| Fonte menos verbosa, valor directo de deteção (ex. firewall deny, auth failures) | A       | rsyslog → AMA + DCR → Sentinel. Aplicar DCR transform para filtrar.                      |
| Fonte muito verbosa, tráfego de baixo valor (ex. firewall allow, DNS, NTP, DHCP) | B       | rsyslog → Filebeat → Logstash → ELK. Só alertas chegam ao Sentinel via Log Ingestion API |

> [!warning] Filtros DCR obrigatórios
> DNS, NTP, DHCP, ICMP, SNMP, monitoring interno - SEMPRE filtrados antes de ingerir no Sentinel. Sem excepções.



___
# Fase 1 - Onboarding de Cliente Novo
Executar apenas quando é o primeiro cliente. Para novas fontes num cliente existente, saltar para [[#Fase 2 - Integração de Nova Fonte]].

**O que necessitamos da parte do cliente/equipa Microsoft:**
- [ ] Acesso à subscrição Azure via Azure Lighthouse
- [ ] Workspace Sentinel criado
- [ ] Credenciais do Service Principal para uso via Log Ingestion API (ELK)
- [ ] Transformação DCR para a nova fonte já criada (para não enviar TUDO para o Sentinel)

## 1.1 - VM Syslog Forwarder (*se cliente tiver fontes on-prem*)
- Ubuntu 22.04 - 4 vCPU / 8 GB RAM / 50 GB disco
- Porta 514 aberta (UDP + TCP)
- Azure Arc + AMA instalado
### 1.1.1 - Configurar o rsyslog base
```bash
# /etc/rsyslog.d/00-layer8-base.conf

# Receber na porta 514
module(load="imudp")
input(type="imudp" port="514")
module(load="imtcp")
input(type="imtcp" port="514")

# Caminho B — destino ELK (Filebeat)
# Fontes verbosas: definir por hostname ou conteúdo do payload
if $msg contains "TRAFFIC" and $msg contains "action=accept" then {
    action(type="omfwd" target="ELK_IP" port="5044" protocol="tcp")
    stop
}

# Caminho A — AMA lê de ficheiro
*.* /var/log/layer8/caminho-a.log
```



___
# Fase 2 - Integração de Nova Fonte
Executar para cada nova fonte adicionada a um cliente que já tem Sentinel e ELK configurados.

**Primeiro passo:** voltar à [[#Fase 0 - Qualificação da Fonte]] e classificar a fonte.

### 2.1 Conector nativo / CCF _(fontes cloud)_
1. Ir ao Sentinel → Content Hub → pesquisar o conector
2. Instalar e configurar seguindo a documentação do vendor
3. Validar que os dados chegam à tabela esperada (ex: `SigninLogs`, `CrowdStrike_Alerts_CL`)
4. Verificar volume de ingestão nas primeiras 24h - ajustar se necessário

### 2.2 AMA + DCR _(servidores on-prem)_
1. Instalar AMA no servidor (via Azure Arc ou extensão VM)
2. Criar DCR com as tabelas de destino correctas
3. Aplicar DCR Transform em KQL para filtrar eventos de baixo valor
4. Associar o DCR à máquina/AMA
5. Validar: gerar evento de teste, confirmar que aparece no Sentinel na tabela certa

**Exemplo de DCR Transform — DNS Server (só queries externas):**
```kql
// DCR Transform — filtra só queries fora do domínio
source
| where EventID == 3008
| where QueryName !endswith ".nxdomain.local"
| where QueryName !endswith ".internal."
| project TimeGenerated, Computer, QueryName, ClientIP, EventID
```

### 2.3 Fonte via Syslog _(networking, firewalls)_
1. Configurar a fonte para enviar para a VM Syslog Forwarder na porta 514
2. Adicionar regra rsyslog para identificar os logs desta fonte (por hostname ou IP de origem)
3. Decidir caminho A ou B conforme [[#0.3 - Decisão de caminho de ingestão (Syslog)]]
4. Se Caminho A: verificar que AMA recolhe o ficheiro e que o DCR aponta à tabela certa
5. Se Caminho B: verificar que Filebeat está a ler e a enviar para Logstash/ELK
6. Validar em ambos os destinos

### 2.4 Checklist de validação pós-integração

| Verificação                               | Como validar                                   | ✓   |
| ----------------------------------------- | ---------------------------------------------- | --- |
| Logs chegam ao ELK                        | Kibana → Discover → filtrar por fonte          | ☐   |
| Logs chegam ao Sentinel (tabela correcta) | `search * \| take 10` na tabela esperada       | ☐   |
| Filtros DCR activos                       | Confirmar ausência de DNS/NTP/DHCP no Sentinel | ☐   |
| Volume de ingestão dentro do esperado     | Sentinel → Settings → Workspace → Usage        | ☐   |
| Sem duplicados                            | `count()` consistente ao longo do tempo        | ☐   |
| Campos parsados correctamente             | Verificar campos chave na tabela `_CL`         | ☐   |



___
# Fase 3 - Parser e Normalização
Executar quando a fonte chegou à tabela correcta e é necessário normalizar os campos para escrita de regras.

### 3.1 Sem ASIM - KQL Function intermédia
Quando a fonte é a única do seu tipo no cliente. Não é ASIM - é um alias conveniente que facilita a escrita de regras e **reduz o custo de migração futura** se aparecer um segundo vendor.
```kql
// KQL Function: fn_{cliente}_{fonte}
// Guardar em: Sentinel → Logs → Functions → Save as function

{NomeDaTabela}_CL
| extend
    SrcIpAddr  = column_ifexists("{campo_ip_origem}", ""),
    DstIpAddr  = column_ifexists("{campo_ip_destino}", ""),
    DstPort    = toint(column_ifexists("{campo_porto}", "")),
    ActionRaw  = column_ifexists("{campo_acao}", ""),
    // Normalizar valores para consistência
    Action = case(
        ActionRaw =~ "accept", "Allow",
        ActionRaw =~ "deny",   "Deny",
        ActionRaw =~ "drop",   "Deny",
        "Unknown"
    )
| project TimeGenerated, SrcIpAddr, DstIpAddr, DstPort, Action, ActionRaw
```

> [!tip]
> Porquê fazer isto mesmo sem ASIM Se no futuro aparecer um segundo vendor, a migração das regras é trivial - só mudamos o nome da function de origem numa linha. Sem este passo, teriamos de reescrever cada regra campo a campo.

### 3.2 Com ASIM - Parser vim* _(múltiplos vendors)_
Quando existe mais de uma fonte do mesmo tipo. O processo tem sempre dois artefactos: o parser `vim*` por vendor, e o unificador `_Im_*` que agrega todos.

__Parser individual vim_ — um por vendor:_*
```kql
// vim{Schema}{Vendor}  ex: vimNetworkSessionFortiGate
// Schemas: NetworkSession | Authentication | ProcessEvent | FileEvent | Dns | AuditEvent | WebSession

let {Vendor}Data = (
    starttime:   datetime = datetime(null),
    endtime:     datetime = datetime(null),
    dvcaction:   dynamic  = dynamic([]),
    eventresult: string   = '*',
    disabled:    bool     = false
) {
    {NomeDaTabela}_CL
    | where not(disabled)
    | where (isnull(starttime) or TimeGenerated >= starttime)
    | where (isnull(endtime)   or TimeGenerated <= endtime)
    | extend
        EventVendor    = "{Vendor}",
        EventProduct   = "{Produto}",
        EventType      = "{TipoEvento}",
        SrcIpAddr      = column_ifexists("{campo_origem}", ""),
        DstIpAddr      = column_ifexists("{campo_destino}", ""),
        DstPortNumber  = toint(column_ifexists("{campo_porto}", "")),
        DvcAction = case(
            column_ifexists("{campo_acao}", "") =~ "{valor_allow}", "Allow",
            column_ifexists("{campo_acao}", "") =~ "{valor_deny}",  "Deny",
            "Unknown"
        ),
        EventResult = case(
            column_ifexists("{campo_acao}", "") =~ "{valor_allow}", "Success",
            "Failure"
        )
    | where (array_length(dvcaction) == 0 or DvcAction in~ (dvcaction))
    | where (eventresult == "*" or EventResult =~ eventresult)
    | project
        TimeGenerated, EventVendor, EventProduct, EventType,
        SrcIpAddr, DstIpAddr, DstPortNumber, DvcAction, EventResult
};
{Vendor}Data(disabled=false)
```

**Unificador `_Im_*` — um por schema, agrega todos os vim*:**
```kql
// _Im_{Schema}  ex: _Im_NetworkSession
// Este é o que as Analytic Rules chamam

let Vendor1Data = vim{Schema}{Vendor1}(starttime, endtime, dvcaction, eventresult);
let Vendor2Data = vim{Schema}{Vendor2}(starttime, endtime, dvcaction, eventresult);
// Adicionar uma linha por cada novo vendor
union isfuzzy=true Vendor1Data, Vendor2Data
```

### 3.3 Schemas ASIM disponíveis

|Schema|Function|Casos de uso típicos|
|---|---|---|
|NetworkSession|`_Im_NetworkSession`|Firewalls, proxies, IDS/IPS — tráfego de rede|
|Authentication|`_Im_Authentication`|AD, NPS/RADIUS, Entra ID, VPN — autenticação|
|ProcessEvent|`_Im_ProcessEvent`|EDR, Sysmon, auditd — criação de processos|
|FileEvent|`_Im_FileEvent`|EDR, DLP — criação/modificação/eliminação de ficheiros|
|Dns|`_Im_Dns`|DNS servers — queries e respostas|
|AuditEvent|`_Im_AuditEvent`|Mudanças de configuração, eventos de auditoria|
|WebSession|`_Im_WebSession`|Proxies web, WAF — sessões HTTP/HTTPS|



___
# Fase 4 - Use Cases de Deteção
## 4.1 Template base de Analytic Rule
```kql
// 1. FONTE DE DADOS
//    Com ASIM:   _Im_{Schema}(starttime=ago(lookback))
//    Sem ASIM:   {Tabela}_CL  ou  fn_{cliente}_{fonte}

// 2. FILTROS BASE — reduzir volume antes de calcular
| where {condição_de_relevância}

// 3. AGREGAÇÃO — sempre com bin() para performance
| summarize {métrica} by {dimensões}, bin(TimeGenerated, {granularidade})

// 4. THRESHOLD — critério de alerta
| where {métrica} > {threshold}

// 5. ENRIQUECIMENTO — contexto para o analista
| extend
    AlertSeverity = "{High|Medium|Low}",
    AlertTitle    = "{Título do alerta}",
    MitreAttack   = "{Táctica}:{Técnica}"

// 6. PROJECTO FINAL — só o que o analista precisa
| project TimeGenerated, {campos_relevantes}, AlertSeverity, MitreAttack
```

### 4.2 Exemplos por categoria


### 4.3 Configuração da Analytic Rule no Sentinel

|Campo|Orientação|
|---|---|
|Nome|`UC-{NNN} — {Descrição curta} — {Cliente}`|
|Severity|High / Medium / Low / Informational — ser conservador no início|
|Query frequency|5m para High · 1h para Medium/Low|
|Query period|Lookback = 2× a frequency (ex: frequency 5m → period 10m)|
|Suppress alerts|Activar só se o threshold já estiver afinado|
|Entity mapping|Sempre mapear: Account · IP · Host|
|Incident grouping|Agrupar por entidade (IP ou Account) com janela de 24h|
|MITRE ATT&CK|Obrigatório — Táctica + Técnica específica|

## Fase 5 — SOAR e Automação

### 5.1 Playbooks disponíveis

|Playbook|Trigger|Acção|Pré-requisito|
|---|---|---|---|
|`Isolate-Endpoint-CrowdStrike`|Alerta High com entidade Host|Isola o host via CrowdStrike API|CCF connector + API credentials|
|`Disable-User-AD`|Alerta High/Medium com entidade Account|Desactiva conta no AD via LDAP|VM on-prem com acesso ao AD|
|`Disable-User-EntraID`|Alerta High/Medium com entidade Account|Desactiva conta no Entra ID via Graph API|SP com `User.ReadWrite.All`|
|`Notify-Analyst`|Qualquer alerta|Notificação com contexto para canal SOC|Conector Teams/Slack configurado|
### 5.2 Critérios para automação

- Só automatizar acções disruptivas (isolamento, bloqueio) para severidade **High** com alta fidelidade comprovada.
- Confirmar com o cliente antes de activar automação — alguns clientes exigem aprovação manual.
- Sempre incluir um step de notificação antes da acção, mesmo em automação total.
- Testar o playbook com conta de teste antes de activar em produção.
- Documentar no JIRA o playbook activado e os casos em que dispara.