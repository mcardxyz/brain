___

- Rodrigo confirma ~20 servidores MSSQL (2 clusters + restantes standalone).
	- Pede UCs e base de deteção
- LAYER8 testa ingestão via Logstash localmente (?)
- LAYER8 Propõe:
- Logstash + ficheiros de audit em pasta partilhada + conta de serviço com `fn_get_audit_file`
- Cliente sugere alternativa:
	- WEC (Windows Event Collector) + Winlogbeat centralizado
	- LAYER8 pede para avançar com pré-configuração do Winlogbeat

___

### Abordagem WEC

WEC centraliza eventos Windows + Winlogbeat → ELK

**Dependência:**
Configurar SQL Audit → Windows Event Log + instalar Winlogbeat em cada servidor ou WEC central

___

# Reunião

**Ponto 1 - Retomar o estado**

Em Setembro chegámos a uma proposta técnica com duas opções. Em Setembro/Outubro ficou pendente a vossa confirmação da abordagem WEC + Winlogbeat. Hoje queremos fechar essa decisão e perceber o que mudou desde então.


**Ponto 2 - Confirmar o estado atual**

- O SQL Server Audit está configurado em algum servidor?
	- O destino é Windows Event Log?
- O WEC está implementado certo? `PDLEVTSRV`
	- Existe servidor central de recolha de eventos?
- A conta `engineering.layer8@bensaude.pt` tem acesso aos servidores SQL?
- Os ~20 servidores - ainda são o mesmo número?



**Ponto 3 - Fechar a abordagem técnica**

- Se SQL Audit → Windows Event Log: avançar com WEC + Winlogbeat
- Se SQL Audit → ficheiro: avançar com Logstash + pasta partilhada
- Proposta de piloto: 1 servidor primeiro, validar logs e UCs, depois escalar


___











___
# EMAIL FOLLOW-UP
Subject: BENS - Integração SQL Servers - Configurações e Use Cases

Bom dia Rodrigo,

Conforme alinhado na reunião de ontem, seguem as configurações necessárias do vosso lado e os Use Cases iniciais propostos com os respectivos eventos/logs.

**Configuração do SQL SERVER AUDIT**
Como discutido, o destino a configurar é o Windows Application Event Log.

- Configuração do SQL Server Audit: 
	- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions
- Lista completa de Action Groups:
	- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions

Os Action Groups que recomendamos:

**Server Audit Specification (server-level):**
- FAILED_LOGIN_GROUP
- SUCCESSFUL_LOGIN_GROUP
- SERVER_PRINCIPAL_CHANGE_GROUP
- SERVER_ROLE_MEMBER_CHANGE_GROUP
- SERVER_OPERATION_GROUP
- AUDIT_CHANGE_GROUP
- SCHEMA_OBJECT_ACCESS_GROUP
- BACKUP_RESTORE_GROUP

**Database Audit Specification (por BD em scope):**
- DATABASE_PRINCIPAL_CHANGE_GROUP
- SCHEMA_OBJECT_CHANGE_GROUP
- Acção DELETE em tabelas críticas (a identificar com o DBA)

Nota: Todos os eventos de audit chegam com Event ID 33205. Eventos de configuração server-level chegam com Event ID 15457.

Precisamos da vossa parte:
- FQDN/IP do servidor WEC
- IP e porto dos servidores MSSQL
- Credenciais VPN (conforme acordado)







== 3. USE CASES ==

[UC-01] Brute Force — >5 logins falhados para a mesma conta em 5 min
Logs: FAILED_LOGIN_GROUP | EID 33205 (action_id: LGF)

[UC-02] Login com conta system default (sa, guest, dbo)
Logs: SUCCESSFUL_LOGIN_GROUP | EID 33205 (action_id: LGB)

[UC-03] Account Creation — novo login SQL criado
Logs: SERVER_PRINCIPAL_CHANGE_GROUP | EID 33205 (action_id: CR)

[UC-04] Multiple logins em sistemas diferentes pelo mesmo utilizador
Logs: SUCCESSFUL_LOGIN_GROUP (correlação entre servidores) | EID 33205

[UC-05] Multiple accounts mesmo source IP
Logs: FAILED_LOGIN_GROUP / SUCCESSFUL_LOGIN_GROUP | EID 33205

[UC-06] Configuration changes fora de horas
Logs: SERVER_OPERATION_GROUP, AUDIT_CHANGE_GROUP, SERVER_ROLE_MEMBER_CHANGE_GROUP | EID 33205 / 15457

[UC-07] Mass Data Deletion — DROP/TRUNCATE/DELETE em volume
Logs: SCHEMA_OBJECT_CHANGE_GROUP + DELETE em tabelas críticas | EID 33205

Adicionalmente sugerimos:
[UC-08] Execução de xp_cmdshell — execução de comandos OS a partir do SQL Server
Logs: SCHEMA_OBJECT_ACCESS_GROUP | EID 33205 (action_id: EX, object_name: xp_cmdshell)

[UC-09] Adição de conta ao role sysadmin — escalada de privilégios
Logs: SERVER_ROLE_MEMBER_CHANGE_GROUP | EID 33205

[UC-10] Desactivação da política de audit — técnica de evasão
Logs: AUDIT_CHANGE_GROUP | EID 33205


== 4. PRÓXIMOS PASSOS ==

Bensaude:
[ ] Configurar SQL Server Audit no servidor piloto
[ ] Identificar/configurar servidor WEC
[ ] Partilhar FQDN/IP do WEC e dos servidores MSSQL
[ ] Enviar credenciais VPN
[ ] Agendar sessão com DBA para setup inicial

Layer8:
[ ] Preparar configuração Winlogbeat no WEC
[ ] Configurar pipeline Logstash para parsing do EID 33205
[ ] Validar ingestão e arrancar com regras de detecção

Ficamos disponíveis para qualquer dúvida.

Com os melhores cumprimentos,
Miguel Cardoso
Engineering & Delivery (CSIRT Services) | Layer8