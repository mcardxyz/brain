___

| Source            | FortiAnalyzer (10.69.69.253)                                                                                                                                                                                                                                                              |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Destination**   | Syslog Server (csi-vm-pocsentinel - 10.69.200.133)                                                                                                                                                                                                                                        |
| **Protocol**      | 514/TCP                                                                                                                                                                                                                                                                                   |
| **Index Elastic** | - - -                                                                                                                                                                                                                                                                                     |
| Tabela Sentinel   | Fortinet_CL<br>FortinetOther_CL                                                                                                                                                                                                                                                           |
| Tempo de Retenção | 90 dias                                                                                                                                                                                                                                                                                   |
| Status            | PoC                                                                                                                                                                                                                                                                                       |
| Último update     | Mar 03, 2026                                                                                                                                                                                                                                                                              |
| Nesta página      | - [To-Do](#to-do)<br>- [Analytic Rules](#analytic%20rules)<br>- [Descrição da Implementação](#Descrição%20da%20Implementação)<br>- [Ficheiros de configuração relevantes](#Ficheiros%20de%20configuração%20relevantes)<br>- [Referências e documentação](#Referências%20e%20documentação) |

___
# To-Do
- [ ] Analytic Rules
- [ ] Descrição da Implementação
- [ ] Diagrama da Implementação
- [ ] Ficheiros de configuração relevantes
- [ ] Sugestão de automação / template cliente
- [ ] Referencias e terminar a documentação



___
# Analytic Rules



___
# Descrição da Implementação
Logs são recebidos no servidor de syslog (10.69.200.133) e colocados em diferentes ficheiros de acordo:
- Tráfego → `/var/log/collect/fw-ftnt.log`
- VPN/System/Authentication → `/var/log/collect/fw-ftnt-other.log`
- Forti EMS → `/var/log/collect/ems_ftnt.log`
- SASE Porto → `/var/log/collect/sase-porto.log`
- SASE Lisboa → `/var/log/collect/sase-lisboa.log`
- Tudo o que não for categorizado acima → `/var/log/collect/uncategorized_fortianalyzer.log`

O syslog apenas faz roteamento dos logs para os devidos ficheiros. Toda a filtragem e parsing é realizado na Azure, utilizando DCR’s.


___
# Ficheiros de configuração relevantes
Configuração do Rsyslog: `/etc/rsyslog.d/10-fortinet.conf`
```
# Template for log format
template(name="FortiFormat" type="string" string="%timestamp:::date-rfc3339% %HOSTNAME% %syslogtag%%msg%\n")
$ActionFileDefaultTemplate FortiFormat
$template FortiNetIP,"10.69.69.253"

# TRAFFIC LOGS (AMA -> DCR -> Sentinel)
if ($fromhost-ip == "10.69.69.253" and
    ($msg contains "type=traffic" or $msg contains "cat=traffic")) then {
    action(type="omfile" file="/var/log/collect/fw-ftnt.log")
}

# VPN / SYSTEM / AUTHENTICATION (AMA -> Sentinel)
if ($fromhost-ip == "10.69.69.253" and
    ($msg contains "cat=event" or
     $msg contains "cat=system" or
     $msg contains "cat=anomaly" or
     $msg contains "cat=vpn" or
     $msg contains "cat=sslvpn" or
     $msg contains "cat=ipsec" or
     $msg contains "cat=admin" or
     $msg contains "cat=auth" or
     $msg contains "subtype=utm" or
     $msg contains "subtype=event")) then {
    action(type="omfile" file="/var/log/collect/fw-ftnt-other.log")
}

# Forti EMS
if $fromhost-ip == "10.69.69.253" and $msg contains "dvchost=SRV-EMS" then /var/log/collect/ems_ftnt.log
& stop

# SASE Porto
if ($fromhost-ip == "10.69.69.253" and
    ($msg contains "dvchost=SASE-PORTO" or
     $msg contains "devname=\"SASE-PORTO\"")) then {
    action(type="omfile" file="/var/log/collect/sase-porto.log")
}

# SASE Lisboa
if ($fromhost-ip == "10.69.69.253" and
    ($msg contains "dvchost=SASE-LISBOA" or
     $msg contains "devname=\"SASE-LISBOA\"")) then {
    action(type="omfile" file="/var/log/collect/sase-lisboa.log")
}

# Everything else uncategorized
if $fromhost-ip == "10.69.69.253" then /var/log/collect/uncategorized_fortianalyzer.log
& stop
```



___
# Referências e documentação