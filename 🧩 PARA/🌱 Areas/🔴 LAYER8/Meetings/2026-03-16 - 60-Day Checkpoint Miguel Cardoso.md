---
tags:
  - "#layer8/meeting"
date: "{{date}}"
---
# 2026-03-16 - 60-Day Checkpoint Miguel Cardoso
- 



**Decisões de arquitectura já estabelecidas**

- **ASIM parsers:** só implementar quando houver múltiplas fontes do mesmo tipo (ex: dois vendors de firewall diferentes). Com fonte única, as analytic rules apontam directamente à tabela.
- **CommonSecurityLog:** só usar se os logs chegarem em CEF nativo. Fortinet raw → `_CL`.
- **RawData:** não preservar na `_CL` do Sentinel (custo). O ELK guarda o raw completo para hunting.
- **Filtros DCR:** sempre filtrar tráfego de baixo valor (DNS, NTP, DHCP, ICMP, SNMP, monitoring interno) antes de ingerir no Sentinel.

---



