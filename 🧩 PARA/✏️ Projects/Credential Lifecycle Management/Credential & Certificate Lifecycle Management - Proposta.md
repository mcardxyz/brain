___

- De momento não temos qualquer inventário
- Qualquer solução que não resolva isto primeiro, não vale a pena

___

# 1. Tipos de Assets

| Tipo                    | Exemplos                                  | Quem gere |
| ----------------------- | ----------------------------------------- | --------- |
| TLS/SSL Certificates    | Endpoints de clientes, infra SOC8         | Ad hoc    |
| API Keys / Secrets      | Elastic, Splunk, Azure Service Principles | Ad hoc    |
| Azure AD Client Secrets | App Registrations por cliente             | Ad hoc    |
| Domínios DNS            | Domínios de clientes                      | Ad hoc    |


___
# 2. Objectivos da Solução

- [ ] Inventário centralizado no Notion - visível e editável por toda a equipa SOC8
- [ ] Descoberta automática dos assets que têm API (Azure AD, Key Vault, TLS endpoints, WHOIS) com write-back no Confluence
- [ ] Alertas proactiivos antes da expiração (30d / 14d / 7d / 1d)
- [ ] Criação automática de tickets JIRA para renovação
- [ ] Suporte multi-cliente - um  sistema, N clientes isolados
- [ ] Sem segredos em plain text - credenciais geridas via Azure Key Vault Layer8 (?)



___
# 3. Arquitetura da Solução


```
Assets (certs, keys, secrets, domínios)
          │
          ▼
┌─────────────────────────────────────┐
│        Descoberta Automática        │  ← cron diário
│  Azure Graph API / Key Vault /      │
│  TLS scan / WHOIS / entrada manual  │
└──────────────┬──────────────────────┘
               │ write-back (Notion API)
               ▼
┌─────────────────────────────────────┐
│    Notion Database — Inventário     │  ← fonte da verdade
│  Propriedades tipadas por campo     │
│  client_id | type | expiry | owner  │
└──────────────┬──────────────────────┘
               │ leitura (Notion API)
               ▼
┌─────────────────────────────────────┐
│        Motor de Expiração           │  ← cron diário
│  Lê Notion Database                 │
│  Calcula dias restantes             │
│  Trigger: 30d / 14d / 7d / 1d      │
└──────────┬────────────┬─────────────┘
           │            │
           ▼            ▼
   Teams / Email    JIRA Ticket
   (aviso)          (acção)
```


## Isolamento multi-cliente
```yaml
# config/clients/motaengil-lar.yaml
client_id: motaengil-lar
client_name: "MotaEngil / LAR"
azure_tenant_id: "<tenant_id>"
azure_sp_client_id: "<sp_client_id>"
azure_sp_secret_ref: "motaengil-sp-secret"   # referência ao Key Vault Layer8
key_vault_url: "https://kv-lar.vault.azure.net"
tls_endpoints:
  - host: vpn.motaengil.ao
  - host: mail.motaengil.ao
domains:
  - motaengil.ao
  - lar.co.ao
owners:
  default: miguel@layer8.pt
  escalation: pedro@layer8.pt
```

Adicionar um cliente novo = duplicar este ficheiro de configuração


## Gestão de credenciais
**NENHUMA credencial de cliente em ficheiros de configuração ou variáveis de ambiente.**

```
Azure Key Vault — Layer8 (interno)
├── secret/motaengil-sp-secret         ← SP do tenant MotaEngil
├── secret/clienteX-sp-secret          ← SP do tenant Cliente X
├── secret/elastic-api-key-prod        ← API key Elastic Layer8
└── secret/crowdstrike-api-key         ← API key CrowdStrike Layer8
```

A VM onde corre o script autentica via **Managed Identity**.



___
# 4. Modelos de Dados - Notion database
- O inventário vive numa Notion database dedicada
- Cada entrada é um asset.
- O script lê e escreve via Notion API

**Estrutura da tabela**

| Campo            | Tipo     | Descrição                                              |
| ---------------- | -------- | ------------------------------------------------------ |
| `asset_id`       | UUID     | Identificador único (gerado na criação)                |
| `client_id`      | string   | `motaengil-lar` / `internal-layer8`                    |
| `client_name`    | string   | Nome legível do cliente                                |
| `type`           | string   | `tls_cert` / `api_key` / `sp_secret` / `domain`        |
| `name`           | string   | Nome descritivo (e.x. `elastic-layer8-prod`)           |
| `expiry_date`    | date     | Data de expiração (formate: `YYYY-MM-DD`)              |
| `owner_email`    | string   | Responsável pela renovação                             |
| `source`         | string   | Onde vive o asset (`azure_kv`, `manual`,  `splkmst01`) |
| `auto_renew`     | boolean  | Renova automaticamente? (`true`/`false`)               |
| `discovered_via` | string   | `azure-graph`, `tls-scan`, `whois`, `manual`           |
| `jira_ticket_id` | string   | Ticket de renovação activo (preenchido pelo script)    |
| `notes`          | text     | Contexto adicional / instruções de renovação           |
| `last_checked`   | datetime | Último scan (preenchido pelo script)                   |
| `unmanaged`      | boolean  | Descoberto mas não confirmado (`true`/`false`)         |
| `url`            | string   | Link para o bitwarden / secret                         |

**Filtragem possível:**

| Vista               | Filtro / Agrupamento       | Uso                                 |
| ------------------- | -------------------------- | ----------------------------------- |
| Todos os assets     | Sem filtro                 | Visão completa                      |
| A Expirar (30 dias) | `expiry_date` < hoje + 30d | Daily check                         |
| Por cliente         | Agrupado por `client_id`   | Review por cliente                  |
| Não geridos         | `unmanaged = true`         | Triagem de novos assets descobertos |
| Expirados           | `expiry_date` < hoje       | Incidents activos                   |

**Estrutura no Notion**
```
ENG-CORE HUB
└── Credential Lifecycle Management
    ├── Database — Inventário de Assets     ← Notion Database (lida/escrita pelo script)
```




___
# 5. Lógica de Alertas

| Dias restantes | Canal                                          | Acção                  |
| -------------- | ---------------------------------------------- | ---------------------- |
| 30 dias        | Teams (canal #eng-core)                        | Aviso informativo      |
| 14 dias        | Teams + Email à equipa                         | Aviso com urgência     |
| 7 dias         | Teams + Email + JIRA ticket (High)             | Acção requerida        |
| 3 dias         | JIRA escalado para Critical + email escalation | Escalar para o manager |
| 1 dia          | Teams @here + email escalation                 | Alerta crítico         |
| Expirado       | Teams @here + JIRA Critical                    | Incidente activo       |

**Formato do ticket  JIRA**
```
Summary : [EXPIRY][motaengil-lar] vpn.motaengil.ao TLS cert — 7 dias
Type    : Task
Priority: High (→ Critical se ≤ 3 dias)
Labels  : cert-expiry, client:motaengil-lar, type:tls_cert
Assignee: miguel@layer8.pt
Due Date: expiry_date - 2 dias

Description:
  Asset   : vpn.motaengil.ao
  Tipo    : TLS Certificate
  Expira  : 2026-04-01
  Cliente : MotaEngil / LAR
  Owner   : miguel@layer8.pt
  Source  : Manual (renovar via painel do fornecedor)
  Notas   : Certificado emitido pela DigiCert. Renovar com 5 dias
            de antecedência para propagação DNS.
```



___
# 6. Descoberta Automática - Cobertura por Fonte

| Fonte                | O que se descobre                         | Método                | Automático? |
| -------------------- | ----------------------------------------- | --------------------- | ----------- |
| Azure AD (Graph API) | App Registrations + cliente secret expiry | `microsoft-graph` SDK | Siim        |
| Azure Key Vault      | Certs e secrets com expiry definido       | `azure-keyvault` SDK  | Sim         |
| TLS endpoints        | Cert expiry de qualquer host:443          | `ssl` stdlib Python   | Sim         |
| Domínios DNS         | Data de expiração (WHOIS)                 | `python-whois`        | Sim         |
| Elastic API Keys     | Sem endpoint público de expiry            | -                     | Manual      |
| Splunk API Keys      | Sem endpoint publico de expiry            | -                     | Manual      |

- Assets manuais entram no inventário uma vez, com `discovered_via: manual`
- Se o scan encontrar um cert/secret que não existe no inventário, cria o registo com `unmanaged: true` e envia para revisão manual


___

# 7. Roadmap MVP
## Fase 0 - Inventário no Notion
- [ ] Criar Notion Database `Credential Lifecyle Management` com as propriedades definidas na secção 4
- [ ] Configurar vistas: Todos os assets, A Expirar (30d), Por Cliente, Não Geridos, Expirados
- [ ] Catalogar todos os assets SOC8 internos conhecidos
- [ ] Catalogar assets dos clientes activos
- [ ] Criar páginas de runbook por tipo de asset (TLS, SP secrets, API keys, domínios)
- [ ] Confirmar com o Pedro: como está a integração Notion-JIRA existente

## Fase 1 - Script base + alertas Teams
- [ ] Setup do repositório (`credential-lifecycle-mgmt`)
- [ ] Módulo de leitura da Notion Database via API (`notion-client`)
- [ ] Motor de expiração com thresholds configuráveis
- [ ] Notificações Teams via webhook
- [ ] Cron job diário na VM Layer8
- [ ] Teste com assets próximos de expirar

## Fase 2 - Descoberta automática Azure
- [ ] Configurar Managed Identity na VM
- [ ] Setup Key Vault Layer8 com credenciais dos clientes
- [ ] Módulo de descoberta: Azure AD App Registrations (Graph API)
- [ ] Módulo de descoberta: Azure Key Vault por cliente
- [ ] Write-back para Notion Database: novos assets adicionados automaticamente
- [ ] Assets não catalogados → entrada com `unmanaged: true` + alerta Teams para revisão
- [ ] Config YAML por cliente (começar com Layer8)

## Fase 3 - JIRA + TLS + Domínios
- [ ] Integração JIRA (criação automática de tiickets com template definido)
- [ ] Módulo de scan TLS (lista de endpoints por cliente no YAML)
- [ ] Módulo WHOIS para domínios
- [ ] Testes end-to-end
- [ ] Documentação de onboarding de novo cliente

## Fase 4  - Melhorias + expansão
- [ ] Relatório mensal automático por cliente
- [ ] Suporte para mais tipos de assets (Tokens OAuth, Certificados internos PKI, etc)




___

# Utilidades
## A. Estrutura de directórios do projecto
```
credential-lifecycle-mgmt/
├── config/
│   ├── settings.yaml              # config global (thresholds, webhooks, JIRA, Notion DB ID)
│   └── clients/
│       ├── internal-layer8.yaml
│       ├── motaengil-lar.yaml
│       └── cliente-fortinet-poc.yaml
├── src/
│   ├── notion/
│   │   ├── reader.py              # leitura da Notion Database (JSON → objectos Python)
│   │   └── writer.py             # write-back de novos assets e actualizações (last_checked, jira_ticket_id)
│   ├── discovery/
│   │   ├── azure_graph.py         # App Registrations
│   │   ├── azure_keyvault.py      # Key Vault secrets
│   │   ├── tls_scan.py            # TLS endpoint scan
│   │   └── whois_scan.py          # Domain expiry
│   ├── notifications/
│   │   ├── teams.py               # Teams webhook
│   │   ├── email.py               # Email alerts
│   │   └── jira.py                # JIRA ticket creation
│   ├── engine.py                  # Motor de expiração
│   └── main.py                    # Entrypoint
├── tests/
├── requirements.txt
└── README.md
```

## B. Template de entrada Notion
```
name           : elastic-api-key-prod
asset_id       : <gerar UUID v4>
client_id      : internal-layer8        ← select
client_name    : Layer8 Internal
type           : api_key                ← select
expiry_date    : 2026-05-01             ← date picker
owner_email    : miguel@layer8.pt
source         : elastic_portal
auto_renew     : ☐ (false)             ← checkbox
discovered_via : manual                 ← select
unmanaged      : ☐ (false)             ← checkbox
jira_ticket_id : (vazio — preenchido pelo script)
last_checked   : (vazio — preenchido pelo script)
notes          : Renovar via Elastic Cloud console.
                 Gerar nova key antes de revogar a antiga.
```




### C. Referências técnicas
- [Notion API — Databases](https://developers.notion.com/reference/post-database-query)
- [notion-client Python SDK](https://github.com/ramnes/notion-sdk-py)
- [Microsoft Graph API — App Registrations](https://learn.microsoft.com/en-us/graph/api/application-list)
- [Azure Key Vault SDK Python](https://learn.microsoft.com/en-us/python/api/overview/azure/keyvault-secrets-readme)
- [JIRA REST API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/)
- [python-whois](https://pypi.org/project/python-whois/)
- [pymsteams](https://pypi.org/project/pymsteams/)
- [atlassian-python-api](https://atlassian-python-api.readthedocs.io/)