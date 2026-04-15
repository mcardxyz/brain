---
tags:
  - "#BENS"
  - "#UseCases"
  - "#MSSQL"
date: "{{date}}"
---
# MSSQL - Resumo de Use Cases
## Visão Geral

| Total de Use Cases | Ativos | Stand-by | Bloqueados |
| ------------------ | ------ | -------- | ---------- |
| 10                 | 7      | 2        | 1          |

---
# Use Cases Implementados

## UC-01 - Brute Force (Tentativas de Login Falhadas)
**Severidade:** Alta | **MITRE:** T1110

**Descrição:**
Deteta múltiplas tentativas de autenticação falhadas originadas no mesmo endereço IP contra um servidor SQL num curto espaço de tempo. Pode indicar tentativa de acesso não autorizado por brute force ou por dicionário.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code == "33205"
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nsucceeded:%{DATA:succeeded}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| WHERE action_id LIKE "LGIF*"
| WHERE succeeded LIKE "false*"
| WHERE server_principal_name IS NOT NULL AND server_principal_name != ""
| WHERE client_ip != "Unknown"
// | WHERE server_principal_name NOT RLIKE ".*gMSA_NAVAPPSVC.*" // descomentar se cliente confirmar comportamento esperado
| STATS
    failed_count = COUNT(*),
    target_accounts = VALUES(server_principal_name),
    first_attempt = MIN(@timestamp),
    last_attempt = MAX(@timestamp)
  BY client_ip, server_instance_name
| WHERE failed_count >= 10
| SORT failed_count DESC
```

**Threshold:** ≥ 10 falhas em 15 minutos por IP e servidor.
> ⚠️ **Finding identificado:** Durante o período de baseline foram detetadas 114 falhas de login da conta `gMSA_NAVAPPSVC$` num intervalo de 6 minutos. Este comportamento está a ser analisado em conjunto com o cliente.

---
## UC-02 - Login com Conta de Sistema ou Conta Padrão
**Severidade:** Alta | **MITRE:** T1078.001

**Descrição:**
Deteta autenticações bem sucedidas com contas de sistema, contas built-in (`sa`, `##MS_Policy*`) ou contas de serviço do Windows (`NT AUTHORITY`, `NT SERVICE`). O uso destas contas em contexto interativo pode indicar comprometimento ou acesso indevido.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code == "33205"
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nsucceeded:%{DATA:succeeded}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| WHERE action_id LIKE "LGIS*"
| WHERE succeeded LIKE "true*"
| WHERE server_principal_name LIKE "sa*"
    OR server_principal_name LIKE "##MS_Policy*"
    OR server_principal_name LIKE "NT AUTHORITY*"
    OR server_principal_name LIKE "NT SERVICE*"
| WHERE server_principal_name NOT RLIKE "NT SERVICE.SQLTELEMETRY.*"
    AND server_principal_name NOT RLIKE "NT SERVICE.MSSQLSERVER.*"
    AND server_principal_name NOT RLIKE "NT SERVICE.SQLSERVERAGENT.*"
| WHERE application_name NOT LIKE "*VSS Writer*"
| WHERE NOT (server_principal_name LIKE "NT AUTHORITY*" AND client_ip LIKE "local machine*")
| KEEP @timestamp, server_principal_name, client_ip, server_instance_name, application_name, host_name, _id, _index
| SORT @timestamp DESC
```

**Threshold:** Qualquer ocorrência.
**Resultado do baseline:** Zero falsos positivos após exclusão de comportamentos legítimos conhecidos (backups VSS, serviços internos).

---
## UC-03 - Criação de Conta SQL
**Severidade:** Média | **MITRE:** T1136.001

**Descrição:**
Deteta a criação de novos logins ou utilizadores no SQL Server. Qualquer criação de conta deve ser um evento controlado e autorizado.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code == "33205"
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\nobject_name:%{DATA:object_name}\n"""
| GROK message """\nclass_type:%{DATA:class_type}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| WHERE action_id LIKE "CR*"
| WHERE class_type LIKE "LX*" OR class_type LIKE "SL*"
| KEEP @timestamp, server_principal_name, object_name, class_type, client_ip, server_instance_name, application_name, host_name, _id, _index
| SORT @timestamp DESC
```

**Threshold:** Qualquer ocorrência.
**Resultado do baseline:** Zero falsos positivos.

---
## UC-05 - Múltiplas Contas Acedidas do Mesmo IP
**Severidade:** Média | **MITRE:** T1110

**Descrição:**
Deteta um endereço IP a tentar autenticar com cinco ou mais contas distintas. Pode indicar enumeração de credenciais ou movimento lateral.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code == "33205"
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| WHERE action_id LIKE "LGIF*" OR action_id LIKE "LGIS*"
| WHERE client_ip != "local machine"
| STATS
    distinct_accounts = COUNT_DISTINCT(server_principal_name),
    accounts = VALUES(server_principal_name),
    total_attempts = COUNT(*),
    target_servers = VALUES(server_instance_name)
  BY client_ip
| WHERE distinct_accounts >= 5
| SORT distinct_accounts DESC
```

**Threshold:** ≥ 5 contas distintas por IP.
**Resultado do baseline:** Máximo observado em 30 dias: 3 contas por IP. Zero ocorrências acima do threshold.

---
## UC-06 - Alterações de Configuração Fora de Horário Laboral
**Severidade:** Alta | **MITRE:** T1562.001

**Descrição:**
Deteta alterações de configuração no SQL Server (permissões, roles, audit specs, definições de servidor) realizadas fora do horário laboral (antes das 08h00 ou após as 18h00, e fins de semana). Alterações fora de janela podem indicar atividade não autorizada ou comprometimento.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code IN ("33205", "15457")
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\nobject_name:%{DATA:object_name}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| WHERE action_id LIKE "ALST*" OR action_id LIKE "ALSS*" OR action_id LIKE "ALRS*"
    OR action_id LIKE "ALCN*" OR action_id LIKE "ALTR*" OR action_id LIKE "AUSC*"
    OR action_id LIKE "APRL*" OR action_id LIKE "DPRL*"
| WHERE server_principal_name NOT RLIKE "NT SERVICE.SQLTELEMETRY.*"
    AND server_principal_name NOT RLIKE ".*gMSA_NAVAPPSVC.*"
| EVAL date_hour = DATE_FORMAT("HH", @timestamp),
    date_weekday = DATE_FORMAT("EEEE", @timestamp)
| WHERE ((TO_INTEGER(date_hour) >= 18 OR TO_INTEGER(date_hour) < 8)
    AND (date_weekday NOT IN ("Saturday", "Sunday")))
    OR (date_weekday IN ("Saturday", "Sunday"))
| KEEP @timestamp, action_id, server_principal_name, object_name, client_ip, server_instance_name, application_name, host_name, date_hour, date_weekday, _id, _index
| SORT @timestamp DESC
```

**Threshold:** Qualquer ocorrência fora de horário.
**Resultado do baseline:** Zero ocorrências após exclusão de ruído de telemetria e aplicações legítimas.

---
## UC-09 - Adição de Utilizador ao Role sysadmin
**Severidade:** Crítica | **MITRE:** T1098

**Descrição:**
Deteta a adição de qualquer utilizador ao role `sysadmin` do SQL Server. Este role concede controlo total sobre a instância e a sua atribuição deve ser sempre um evento excepcional e controlado.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code == "33205"
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\nobject_name:%{DATA:object_name}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| GROK message """\ntarget_server_principal_name:%{DATA:target_server_principal_name}\n"""
| GROK message """\nstatement:%{DATA:statement}\nadditional_information:"""
| WHERE action_id LIKE "APRL*"
| WHERE object_name LIKE "sysadmin*" OR statement LIKE "*sysadmin*"
| KEEP @timestamp, server_principal_name, target_server_principal_name, object_name, statement, client_ip, server_instance_name, application_name, host_name, _id, _index
| SORT @timestamp DESC
```

**Threshold:** Qualquer ocorrência.
**Resultado do baseline:** Zero falsos positivos.

---
## UC-10 - Desativação ou Alteração de Política de Auditoria
**Severidade:** Crítica | **MITRE:** T1562.002

**Descrição:**
Deteta alterações ou desativações das audit specifications do SQL Server. A modificação da política de auditoria pode ser usada por um atacante para encobrir actividade maliciosa.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code == "33205"
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\nobject_name:%{DATA:object_name}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| GROK message """\nstatement:%{DATA:statement}\nadditional_information:"""
| WHERE action_id LIKE "AUSC*"
| KEEP @timestamp, server_principal_name, object_name, statement, client_ip, server_instance_name, application_name, host_name, _id, _index
| SORT @timestamp DESC
```

**Threshold:** Qualquer ocorrência.

> ⚠️ **Finding identificado:** Durante os testes foi registada actividade do utilizador `filipealves` a modificar audit specifications. Está a ser confirmado com o cliente se este utilizador tem autorização para efectuar este tipo de alterações.


---
# Use Cases em Stand-by

## UC-04 - Logins em Múltiplos Servidores SQL (Stand-by)

**Descrição:**
Deteta um utilizador a autenticar em múltiplos servidores SQL num curto espaço de tempo, o que pode indicar movimento lateral.

**Motivo de stand-by:** Aguarda onboarding de servidores SQL adicionais na mesma stack de monitorização.

## UC-07  Eliminação Massiva de Dados (Stand-by)

**Descrição:**
Deteta operações de eliminação em massa sobre tabelas críticas de base de dados.

**Motivo de stand-by:** Aguarda expansão da audit specification ao nível de database para as tabelas relevantes.


---
# Use Cases Bloqueados

## UC-08 - Execução de xp_cmdshell (Bloqueado)
**Severidade:** Crítica | **MITRE:** T1059.003

**Descrição:**
Deteta a execução do procedimento `xp_cmdshell`, que permite executar comandos do sistema operativo directamente a partir do SQL Server. É uma das técnicas mais utilizadas por atacantes após comprometimento de uma instância SQL.

```esql
FROM winsecevt-* metadata _id, _index
| WHERE event.code == "33205"
| GROK message """\naction_id:%{DATA:action_id}\n"""
| GROK message """\nserver_principal_name:%{DATA:server_principal_name}\n"""
| GROK message """\nclient_ip:%{DATA:client_ip}\n"""
| GROK message """\nserver_instance_name:%{DATA:server_instance_name}\n"""
| GROK message """\nobject_name:%{DATA:object_name}\n"""
| GROK message """\napplication_name:%{DATA:application_name}\n"""
| GROK message """\nhost_name:%{DATA:host_name}\n"""
| GROK message """\nstatement:%{DATA:statement}\nadditional_information:"""
| WHERE action_id LIKE "EX*"
| WHERE object_name LIKE "*xp_cmdshell*" OR statement LIKE "*xp_cmdshell*"
| KEEP @timestamp, server_principal_name, object_name, statement, client_ip, server_instance_name, application_name, host_name, _id, _index
| SORT @timestamp DESC
```

**Motivo de bloqueio:**
O grupo `SCHEMA_OBJECT_ACCESS_GROUP` não está configurado na server audit specification atual, o que impede a geração dos eventos necessários. A activação deste Use Case requer a adição deste grupo à audit spec.


---
# Cobertura MITRE ATT&CK

| Tática               | Técnica                                                              | UC                |
| -------------------- | -------------------------------------------------------------------- | ----------------- |
| Credential Access    | T1110 - Brute Force                                                  | UC-01, UC-05      |
| Persistence          | T1136.001 - Create Account: Local Account                            | UC-03             |
| Privilege Escalation | T1098 - Account Manipulation                                         | UC-09             |
| Defense Evasion      | T1562.001 - Impair Defenses: Disable or Modify Tools                 | UC-06             |
| Defense Evasion      | T1562.002 - Impair Defenses: Disable Windows Event Logging           | UC-10             |
| Lateral Movement     | T1078 - Valid Accounts                                               | UC-04 (stand-by)  |
| Execution            | T1059.003 - Command and Scripting Interpreter: Windows Command Shell | UC-08 (bloqueado) |
| Impact               | T1485 - Data Destruction                                             | UC-07 (stand-by)  |
| Initial Access       | T1078.001 - Valid Accounts: Default Accounts                         | UC-02             |

---