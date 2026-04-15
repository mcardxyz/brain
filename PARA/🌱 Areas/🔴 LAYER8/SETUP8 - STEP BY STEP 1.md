---
tags:
  - setup8
  - documentation
type: documentation
---
Table of Contents

1. [Rsyslog - Instalar e configurar](#Rsyslog%20-%20Instalar%20e%20configurar)
2. [Rsyslog - Rules para separar dados](#Rsyslog%20-%20Rules%20para%20separar%20dados)
3. [Rsyslog - Criar entrada no log rotate](#Rsyslog%20-%20Criar%20entrada%20no%20log%20rotate)
4. [Rsyslog - Crontab](#Rsyslog%20-%20Crontab)
	1. [CentOS](#CentOS)
	2. [Ubuntu](#Ubuntu)
5. [Rsyslog - Debug](#Rsyslog%20-%20Debug)
6. [Rsyslog - Permissões para ler logs](#Rsyslog%20-%20Permiss%C3%B5es%20para%20ler%20logs)
7. [Node Exporter - Install](#Node%20Exporter%20-%20Install)
8. [Node Exporter - Configure](#Node%20Exporter%20-%20Configure)
9. [Node Exporter - Prometheus](#Node%20Exporter%20-%20Prometheus)
10. [ELK - First system configurations](#ELK%20-%20First%20system%20configurations)
11. [ELK - Install Elastic](#ELK%20-%20Install%20Elastic)
12. [ELK - Install Kibana](#ELK%20-%20Install%20Kibana)
13. [ELK - Install Logstash](#ELK%20-%20Install%20Logstash)
14. [ELK - Install Filebeat](#ELK%20-%20Install%20Filebeat)
15. [ELK - Install Winlogbeat](#ELK%20-%20Install%20Winlogbeat)
16. [ELK - ILM](#ELK%20-%20ILM)
17. [ELK - SOC8 Pipelines](#ELK%20-%20SOC8%20Pipelines)
	3. [Checkpoint](#Checkpoint)
	4. [Fortinet](#Fortinet)
18. [ELK - Rule and Permissions](#ELK%20-%20Rule%20and%20Permissions)
19. [Splunk - Install and configure](#Splunk%20-%20Install%20and%20configure)
20. [Splunk - Configure forwarding](#Splunk%20-%20Configure%20forwarding)
	5. [Cloud instance](#Cloud%20instance)
	6. [Heavy Forwarder](#Heavy%20Forwarder)
21. [Splunk - Configure License](#Splunk%20-%20Configure%20License)
22. [Splunk - Implementation configuration](#Splunk%20-%20Implementation%20configuration)
23. [Splunk - HEC Configuration](#Splunk%20-%20HEC%20Configuration)
24. [Splunk - Alerts Indice](#Splunk%20-%20Alerts%20Indice)
25. [Splunk - App Creation](#Splunk%20-%20App%20Creation)
26. [Splunk - User and Role Creation and Permissions](#Splunk%20-%20User%20and%20Role%20Creation%20and%20Permissions)
	7. [Role Creation](#Role%20Creation)
	8. [User Creation](#User%20Creation)
	9. [Alert permissions](#Alert%20permissions)
27. [Splunk - Handmade Apps Install](#Splunk%20-%20Handmade%20Apps%20Install)
28. [Splunk - Throubleshoot](#Splunk%20-%20Throubleshoot)
	10. [Not receiving logs on cloud index](#Not%20receiving%20logs%20on%20cloud%20index)
29. [Firewall - ELK Machine](#Firewall%20-%20ELK%20Machine)
30. [Firewall - Splunk machine](#Firewall%20-%20Splunk%20machine)



# Rsyslog
## Rsyslog - Instalar e configurar
1. Começar por instalar o rsyslog:
```bash
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install rsyslog
```

2. Criar a diretoria `/var/log/collect/`
3. Alterar o ficheiro `/etc/rsyslog.conf`:
```bash
module(load="imudp")
input(type="imudp" port="514")
module(load="imtcp")
input(type="imtcp" port="514")

# Listen ports for udp and tcp
```
## Rsyslog - Rules para separar dados
4. Criar as regras em `/etc/rsyslog.conf.d` para separar os dados por source, como no exemplo seguinte:
```bash
if $fromhost-ip == "10.10.10.200" and $msg contains "subtype=\"forward\"" then /var/log/collect/fw_ftnt.log
& stop
if $fromhost-ip == "10.126.6.220" then /var/log/collect/firewall_generica.log
& stop
```
## Rsyslog - Criar entrada no log rotate
5. Criar configuração no LogRotate para impedir que o disco do servidor encha, criar ficheiro `/etc/logrotate.d/collect`
```bash
/var/log/collect/*.log
{
        rotate 6
        missingok
        notifempty
        postrotate
                /usr/bin/systemctl reload-or-try-restart rsyslog.service
        endscript
}
```
## Rsyslog - Crontab
6. Criar entrada no crontab para executar o logrotate:
```bash
*/30 * * * *      /usr/sbin/logrotate -f /etc/logrotate.d/collect
```

```ad-warning
Erro de “Start-limit-hit”

Poderá ocorrer um erro no servidor de Syslog ao executar a instrução de logrotate que impede o seu funcionamento. O servidor de Syslog fica inativo.
```
Uma possível solução será alterar a configuração do LogRotate:
### CentOS
```bash
{
        rotate 5
        missingok
        notifempty
        postrotate
                #/usr/bin/systemctl restart rsyslog.service
                /bin/killall -HUP rsyslogd
        endscript
}
```

### Ubuntu
```bash
{
        rotate 5
        missingok
        notifempty
        postrotate
                #/usr/bin/systemctl restart rsyslog.service
                /usr/bin/rsyslog/rsyslog-rotate
        endscript
}
```
## Rsyslog - Debug
7. Ir a `/etc/rsyslog.conf` e adicionar:
```bash
*.* /var/log/debugfmt;RSYSLOG_DebugFormat
```

**Nota:** Ver no path /var/log/debugfmt
8. Dar restart ao serviço:
```bash
sudo systemctl restart rsyslog.service
```

9. Depois de validar remover o que foi adicionado e dar restart ao serviço.
## Rsyslog - Permissões para ler logs
**What it is**
setfacl **sets (replaces), modifies, or removes the access control list (ACL) to regular files and directories**. It also updates and deletes ACL entries for each file and directory that was specified by path. If path was not specified, then file and directory names are read from standard input (stdin).

10. Use `setfacl` to apply reading permissions for a user to the necessary log folder (usually `/var/log`)

```shell
sudo setfacl -R -m u:OUR_USER:r-x /var/log
```

11. OR for Splunk
```shell
setfacl -Rm u:splunk:rX,d:u:splunk:rX /var/log
```

# Node Exporter
## Node Exporter - Install
1. [Download](https://prometheus.io/download/) the Node Exporter binary to each Server that you want to monitor. The Node Exporter will export system related stats.
```bash
wget https://github.com/prometheus/node_exporter/releases/download/v1.8.1/node_exporter-1.8.1.linux-amd64.tar.gz
```

2. Create a Node Exporter user, required directories, and make prometheus user as the owner of those directories.
```bash
sudo groupadd -f node_exporter
sudo useradd -g node_exporter --no-create-home --shell /bin/false node_exporter
sudo mkdir /etc/node_exporter
sudo chown node_exporter:node_exporter /etc/node_exporter
```

3. Untar and move the downloaded Node Exporter binary
```bash
tar -xvf node_exporter-1.8.1.linux-amd64.tar.gz
mv node_exporter-1.8.1.linux-amd64 node_exporter-files
```
## Node Exporter - Configure
4. Copy `node_exporter` binary from `node_exporter-files` folder to `/usr/bin` and change the ownership to prometheus user.
```bash
sudo cp node_exporter-files/node_exporter /usr/bin/
sudo chown node_exporter:node_exporter /usr/bin/node_exporter
```

5. Setup Node Exporter service
```bash
sudo vi /usr/lib/systemd/system/node_exporter.service
```

Write the following in file `/usr/lib/systemd/system/node_exporter.service`:
```shell
# /usr/lib/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=on-failure
ExecStart=/usr/bin/node_exporter \
  --web.listen-address=:9100 \
  --web.config.file=/etc/node_exporter/node_exporter_web.yml \
  --collector.systemd


[Install]
WantedBy=multi-user.target
```

```bash
sudo chmod 664 /usr/lib/systemd/system/node_exporter.service
```

6. Configure Basic auth
Open configuration file for writing
```bash
sudo vi /etc/node_exporter/node_exporter_web.yml
```

Write the following:
```yaml
basic_auth_users:
  prometheus_user: $2a$12$Hzn6rxc5TbvtoGlxkCjkCezCFnknpe2cOAUAOPVJQ6zKxuZhkqQ1m
  # this is the bcrypt hash of our password in Bitwarden
```

Give the permitions (Not always needed):
```bash
sudo chmod 664 /etc/node_exporter/node_exporter_web.yml

sudo chown node_exporter:node_exporter /etc/node_exporter/node_exporter_web.yml
```

7. Reload the `systemd` service to register the prometheus service and start the prometheus service.

```bash
sudo systemctl daemon-reload
sudo systemctl start node_exporter
```

8. Check the node exporter service status using the following command.

```bash
sudo systemctl status node_exporter
```

9. Configure node_exporter to start at boot

```bash
sudo systemctl enable node_exporter.service
```

NOTE: You can execute node_exporter manually as the user node_exporter to debug `sudo -u node_exporter /usr/bin/node_exporter --web.listen-address=:9100 --web.config.file=/etc/node_exporter/node_exporter_web.yml --collector.systemd`

## Node Exporter - Prometheus
10. Go into `Consulting Machine`
11. Copy, edit and apply configurations on `/docker/data/prometheus/config/prometheus.yml`
12. Add host to `/etc/hosts`
13. Restart docker
```bash
docker restart prometheus
```
14. If it doesn't send results to grafana test connection `telnet <host> 443` from the **consulting machine**
# ELK
## ELK - First system configurations

1. Update and upgrade the system:
```bash
sudo apt update
sudo apt dist-upgrade
```

## ELK - Install Elastic
2. Install from [Official Source](https://www.elastic.co/guide/en/elasticsearch/reference/current/deb.html)

If it gives GPG Error try:
```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
gpg --dearmor | sudo tee /etc/apt/keyrings/elasticsearch-keyring.gpg > /dev/null

sudo chmod 644 /etc/apt/keyrings/elasticsearch-keyring.gpg

# If any list already downloaded
sudo rm -f /etc/apt/sources.list.d/elastic-*.list

echo "deb [signed-by=/etc/apt/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | \
sudo tee /etc/apt/sources.list.d/elastic-9.x.list > /dev/null
```

3. Change ownership of elastic dir
```bash
mkdir /data && cd /data
sudo mkdir elastic
sudo chown elasticsearch:elasticsearch elastic/
```
4. Configure elasticsearch
```bash
sudo su -
nano /etc/elasticsearch/elasticsearch.yml
```

Perform the following changes:

-   cluster-name: `CLIENT_NAME`
-   node.name: `HOST_NAME`
-   path.data: `/data/elastic` 
-   path.logs: `/var/log/elasticsearch`
-   bootstrap.memory_lock: `true`
-   action.destructive_requires_name: `true`
-   action.auto_create_index: `"*"`

5. Enable and start elasticsearch
```bash
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
```

## ELK - Install Kibana
6. Install from [Official Source](https://www.elastic.co/guide/en/kibana/current/deb.html)
7. Enable Kibana
```bash
sudo systemctl start kibana
sudo systemctl enable kibana
```
8. Install nginx
```bash
 sudo apt-get update && sudo apt-get install nginx
```
9. Generate nginx SSL
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
```
10. Configure nginx `/etc/nginx/sites-available/kibana.conf`
Without node exporter:
```nginx
server {
        #listen 80 default_server;
        #listen [::]:80 default_server;

        # SSL configuration
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;

        ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
        ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;

        index index.html index.htm index.nginx-debian.html;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                proxy_pass http://localhost:5601/;
                proxy_http_version 1.1;
                proxy_set_header Upgrade http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host host;
                proxy_cache_bypass http_upgrade;
        }
}

server {
        listen 80;
        listen [::]:80;

        return 302 https://server_namerequest_uri;
}
```

With node exporter:
```nginx
server {

        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;

        ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
        ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;


        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                proxy_pass http://localhost:5601/;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

        location /metrics {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                proxy_pass http://localhost:9100/metrics;
                #proxy_http_version 1.1;
                #proxy_set_header Upgrade $http_upgrade;
                #proxy_set_header Connection 'upgrade';
                #proxy_set_header Host $host;
                #proxy_cache_bypass $http_upgrade;
        }
}
```
11. Disable previous site
```bash
sudo rm /etc/nginx/sites-enabled/default
```
12. Enable new site
```bash
sudo ln -s /etc/nginx/sites-available/kibana.conf /etc/nginx/sites-enabled/kibana.conf
```
13. Start and enable nginx
```
sudo systemctl start nginx
sudo systemctl enable nginx
```
14. Configure ES with KIB [From here](https://www.elastic.co/guide/en/kibana/current/deb.html#deb-enroll) (`cd /usr/share/elasticsearch/`)
15. Create a password for elastic user
```
bin/elasticsearch-reset-password -u elastic
```
## ELK - Install Logstash
16. Install from [Official Source](https://www.elastic.co/guide/en/logstash/current/installing-logstash.html)
17. Disable logstash if not using.
18. Create role and users on Kibana Dev Tools
Role:
```json
POST /_security/role/logstash_writer
{
    "cluster": ["manage_index_templates", "monitor", "manage_ilm", "manage_ingest_pipelines", "manage_pipeline", "manage", "all"],
    "indices": [
        {
            "names": ["*"],
            "privileges": ["write", "create", "create_index", "manage", "manage_ilm"]
            }
            ]
}
```
User:
```json
POST /_security/user/logstash_internal
{
  "password" : "password",
  "roles" : ["logstash_writer"],
  "full_name" : "Internal Logstash User"
}
```
19. Copy cert to logstash
```bash
cp /var/lib/kibana/ca_1692019696741.crt /etc/logstash/elasticsearch-ca.pem
```
20. Create `/etc/logstash/conf.d/inputs.conf`
```conf
input {
  beats {
    port => 5044
  }
}
```
21. Create `/etc/logstash/conf.d/FONTE.conf`
```conf
filter {
        if [soc_source] == "forti" {
                mutate {
                        add_field => {
                                "[@metadata][target_index]" => "fw-forti-int" #alias criado nas ILM policies
                        }

                }
        }
}
```
If you have a default pipeline:
```conf
filter {
        if [soc_source] == "fw_ftnt" {
                mutate {
                        add_field => {
                                "[@metadata][target_index]" => "fw-ftnt"
                        }
                }
                mutate {
                        replace => { "[@metadata][pipeline]" => "SOC8-fortinet-firewall-pipeline" }
                }

        }
}
```

```ad-info
Logstash validation:

-   [fields][soc_source] == "fonte" if filebeat adds the field on raw logs
-   [soc_source] == "fonte" if filebeat adds the field on a log that has a filebeat module for parsing
```

22. Create `/etc/logstash/conf.d/outputs.conf`
```conf
output {
  if [@metadata][pipeline] {
    elasticsearch {
      hosts => ["https://localhost:9200"]
      user => "logstash_internal"
      password => "PASSWORD"
      ssl => true
      ssl_certificate_verification => false
      cacert => "/etc/logstash/elasticsearch-ca.pem"
      index => "%{[@metadata][target_index]}"
      pipeline => "%{[@metadata][pipeline]}"
    }
  }
  else{
    elasticsearch {
                hosts => ["https://localhost:9200"]
                index => "%{[@metadata][target_index]}"
                user => "logstash_internal"
                password => "PASSWORD"
                ssl => true
                ssl_certificate_verification => false
                cacert => "/etc/logstash/elasticsearch-ca.pem"
    }
  }
}
```

FOR ELK 9.x
```conf
output {
  if [@metadata][pipeline] {
    elasticsearch {
      hosts => ["https://localhost:9200"]
      user => "logstash_internal"
      password => "PASSWORD"
      ssl_enabled => true
      ssl_verification_mode => "none"
      ssl_certificate_authorities => "/etc/logstash/elasticsearch-ca.pem"
      index => "%{[@metadata][target_index]}"
      pipeline => "%{[@metadata][pipeline]}"
    }
  }
  else{
    elasticsearch {
                hosts => ["https://localhost:9200"]
                index => "%{[@metadata][target_index]}"
                user => "logstash_internal"
                password => "PASSWORD"
                ssl_enabled => true
                ssl_verification_mode => "none"
                ssl_certificate_authorities => "/etc/logstash/elasticsearch-ca.pem"
    }
  }
}
```

**NOTE:** If you want to test logstash config file `/usr/share/logstash/bin/logstash --path.settings /etc/logstash -t`
## ELK - Install Filebeat
23. Install from [Official Source](https://www.elastic.co/guide/en/beats/filebeat/current/setup-repositories.html)
24. Configuring log exportation `/etc/filebeat/filebeat.yml`
If we want to send raw log files **Without parsing**
```yaml
filebeat.inputs:

- type: log
  # Change to true to enable this input configuration.
  enabled: true
  # Paths that should be crawled and fetched. Glob based paths.
  paths:
          - /var/log/collect/fonte.log*
  fields:
          soc_source: fonte
```
If we want to send logs with filebeat module for parsing (E.g [Fortinet Logs]([https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-fortinet.html](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-fortinet.html)))
```yaml
filebeat.modules:
- module: fortinet
  firewall:
    enabled: true
    var.input: "file"
    var.paths: ["/var/log/collect/forti*"]
    var.rsa_fields: true
    input:
            processors:
               - add_fields:
                       target: ''
                       fields:
                               soc_source: forti
```

```ad-important
It is important to add the soc_source field for logstash filtering

When you need to ingest the pipelines to kibana you need to activate kibana and set this up to not show ssl errors `ssl.verification_mode: none`
```

25. In the case of using modules we need to send the pipeline to kibana
Configure `/etc/filebeat/filebeat.yml` to output to Elasticsearch
```yaml
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["10.10.10.123:9200"]

  # Performance preset - one of "balanced", "throughput", "scale",
  # "latency", or "custom".
  preset: balanced

  # Protocol - either `http` (default) or `https`.
  protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  username: "elastic"
  password: "aT5yLBbxSUmWRHMVqdaS"
  ssl.verification_mode: none
```

Restart filebeat:
```bash
sudo systemctl restart filebeat.service
```

Setup ingest Pipelines (E.g Fortinet module)
```
sudo filebeat setup --pipelines --modules fortinet
```

Test the pipeline on Kibana Grok Debugger.
```ad-warning
For fortinet is needed to change the grok pattern on `Manage>edit>grok`

`REMOVER: %{SYSLOG5424PRI}%{GREEDYDATA:syslog5424_sd}$` 
`INTRODUZIR: %{TIMESTAMP_ISO8601:timestamp} %{NOTSPACE:host} %{GREEDYDATA:syslog5424_sd}$`
```

Comment the output.elasticsearch on `/etc/filebeat/filebeat.yml` and add
```yaml
output.logstash:
  # The Logstash hosts
  hosts: ["<logstaship>:5044"]

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"

  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"
```

## ELK - Install Winlogbeat
AD and Windows logs are collected by the Winlogbeat agent.
26. Create role and user on Kibana Dev Console:
Role:
```json
POST /_security/role/winlogbeat_writer
{
  "cluster": ["manage_index_templates", "monitor", "manage_ilm","manage_ingest_pipelines","manage_pipeline","manage","all"],
  "indices": [
    {
      "names": ["*"],
      "privileges": ["write", "create", "create_index", "manage", "manage_ilm"]
    }
  ]
}
```
User:
```json
POST /_security/user/winlogbeat_internal
{
  "password" : "PASSWORD",
  "roles" : ["winlogbeat_writer"],
  "full_name" : "Internal Winlogbeat User"
}
```
27. Configuration file
```yaml
...

winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h

  - name: System

  - name: Security

  - name: Microsoft-Windows-Sysmon/Operational

  - name: Windows PowerShell
    event_id: 400, 403, 600, 800

  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106

  - name: ForwardedEvents
    tags: [forwarded]
    
...

output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["IP-DO-HOST:9200"]

  # Protocol - either `http` (default) or `https`.
  protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"

  username: "winlogbeat_internal"
  password: "PASSWORD"
  index: "ad"
  ssl.verification_mode: none

setup.template.name: "ad-template"
setup.template.pattern: "ad-*"
setup.ilm.enabled: false
```

YOU CAN ALSO USE **LOGSTASH**:

```yaml
output.logstash:
  # The Logstash hosts
  hosts: ["192.168.243.129:5044"]

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"

  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"
  pipeline: "winlogbeat-%{[agent.version]}-routing"
```

## ELK - ILM
28. Abrir o Dev-Tools do Kibana
29. Criar as politicas de retenção
Politica baseada em tamanho (Eg: 20GB)
```json
PUT _ilm/policy/fwcisco-rolloverdelete-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": {
            "priority": 100
          },
          "rollover": {
            "max_primary_shard_size": "20gb"
          }
        }
      },
      "delete": {
        "min_age": "0m",
        "actions": {
          "delete": {
            "delete_searchable_snapshot": true
          }
        }
      }
    }
  }
}
```
Politica baseada em tempo (E.g 15 dias)
```json
PUT _ilm/policy/fwcisco-retention-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": {
            "priority": 100
          },
          "rollover": {
            "max_age": "15d"
          }
        }
      },
      "delete": {
        "min_age": "5m",
        "actions": {
          "delete": {
            "delete_searchable_snapshot": true
          }
        }
      }
    }
  }
}
```
Politica baseada em tamanho e tempo (E.g 15gb e 20 dias)
```json
PUT _ilm/policy/fwcisco-retention-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "set_priority": {
            "priority": 100
          },
          "rollover": {
            "max_size": "15gb",
            "max_primary_shard_size": "15gb"
          }
        }
      },
      "warm": {
        "min_age": "5d",
        "actions": {
          "set_priority": {
            "priority": 50
          }
        }
      },
      "delete": {
        "min_age": "15d",
        "actions": {
          "delete": {
            "delete_searchable_snapshot": true
          }
        }
      }
    }
  }
}
```
30. Criar um Index template para aplicar a novos indices criados (Ou podes usar Mappings ja para integrações especificas feitas pelo SOC8 [[ELK - Mappings]])
```json
PUT /_index_template/fwcisco-template?pretty
{
  "index_patterns": ["fwcisco-*"],                 
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "fwcisco-retention-policy",      
      "index.lifecycle.rollover_alias": "fwcisco"    
    }
  }
}
```
31. Criar primeiro write index
```json
PUT /fwcisco-000001?pretty
{
  "aliases": {
    "fwcisco": {
      "is_write_index": true
    }
  }
}
```
32. Configurações na ingestão
Alterar o indice de escrita para o alias
**Logstash**
```yaml
output {
  elasticsearch {
                hosts => ["http://localhost:9200"]
                index => "fwcisco"
  }
```
**Filebeat**
```yaml
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["http://localhost:9200"]
  index: "fwcisco"

setup.template.pattern: "fwcisco"
setup.template.name: "fwcisco"
setup.ilm.enabled: false
  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"
```

## ELK - SOC8 Mappings
[[ELK - Mappings]]

## ELK - SOC8 Pipelines
### Checkpoint
[[SETUP8 - Checkpoint Pipelines]]

P.S:. We had to add `rename => { "service" => "log_service" }` to the logstash conf.d to change metadata.
### Fortinet
[[SETUP8 - Fortinet Pipelines]]

## ELK - Rule and Permissions
Stack Management->Rules->cliente-user
**Role name:** cliente-user
**Index Privileges:**
**Indices:***
**Privileges:** read
**Application layer:**
**Spaces:**
All Spaces->Custom
Discover->All
Dashboard->All
Visualize Library->Read

Default->Custom
Discover->All
Dashboard->All
Visualize Library->Read
# Splunk
## Splunk - Install and configure
1. Download the package using [Official Source](https://www.splunk.com/en_us/download/splunk-enterprise.html)
2. Install following [Official Source](https://docs.splunk.com/Documentation/Splunk/9.4.0/Installation/InstallonLinux)
3. `sudo dpkg -i <filename.deb>`
On a fresh install update the system:
```bash
sudo apt update
sudo apt dist-upgrade
```
Start Splunk
```bash
cd /opt/splunk/bin
sudo ./splunk start
```
Read license

Create credentials -> write to bitwarden
3. Configure splunk using boot-start [Official Source](https://docs.splunk.com/Documentation/Splunk/9.4.0/Admin/RunSplunkassystemdservice)
Enable Splunk Bootstart
```bash
cd /opt/splunk/bin
sudo ./splunk enable boot-start -systemd-managed 1 -user root
```
Change directory ownership to splunk
```bash
cd /opt/splunk
sudo chown splunk:splunk /opt/splunk -R
```
Start service and check status
```bash
sudo systemctl start Splunkd.service
sudo systemctl status Splunkd.service
```
4. Enable SSL
```ad-warning
Only do this if Node Exporter is not to be installed
```
```bash
sudo su splunk -
/opt/splunk/bin/splunk enable web-ssl
```
5. Configure nginx
If Node Exporter:
Edit Splunk default app to use port 8000 `/opt/splunk/etc/system/local/web.conf`
```config
[settings]
httpport = 8000
```

Restart splunk after the above

Create the file `sudo vim /etc/nginx/sites-available/splunk`
```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    # modern configuration
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # verify chain of trust of OCSP response using Root CA and Intermediate certs
    #ssl_trusted_certificate /path/to/root_CA_cert_plus_intermediates;

    # replace with the IP address of your resolver
    #resolver 127.0.0.1;
    server_name  _;

    location / {
        proxy_pass http://127.0.0.1:8000/;
        #client_max_body_size 500M;
        #proxy_http_version 1.1;
        #proxy_set_header Upgrade $http_upgrade;
        #proxy_set_header Connection 'upgrade';
        #proxy_set_header Host $host;
        #proxy_cache_bypass $http_upgrade;
    }

    location /metrics {
        proxy_pass http://127.0.0.1:9100/metrics;
        #proxy_set_header Host $host;
        #proxy_set_header X-Real-IP $remote_addr;
        #proxy_http_version 1.1;
        #proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        #proxy_set_header Upgrade $http_upgrade;
        #proxy_set_header Connection 'upgrade';
        #proxy_cache_bypass $http_upgrade;
    }

}
```

## Splunk - Configure forwarding
### Cloud instance
On the Splunk Cloud Instace
-  Go to `Apps` → `Cloud Monitoring Console` → `Forwarders` -> `Forwarder Monitoring Setup` 
- Click `Enable` and `Save`
- The go to  `Apps` → `Cloud Monitoring Console` → `Forwarders` -> `Forwarders: instance`
- Verify if everything is OK.
### Heavy Forwarder
Install the application obtained from the Splunk Cloud Instance
* Go to `Apps` → `Manage Apps` → `Install App from File`
* Select the `.spl` app obtained from the Splunk Cloud Instance 

## Splunk - Configure License
6.  Go to `Settings` → `Licensing` → `Add License`
7. Paste the license
```xml
<?xml version="1.0" encoding="UTF-8"?> 

<license> 
<signature>ju+aUxSWwQi0Mid82mLTVj27uw15SlL8spd19bpzcGzbZq86ENPXEmhcSp1Qcv2dMZOlHZOyXPp5DAD42aqa59sapf4MFK2ge28U0tHjwbCw7E0wuVFxIxPPXqRzoO2nJ+zAnW77NpZ7xREpOGt5NZvrmdBq8NKmlDHZ25Ve4Tnnv6OZIPJplnjuxJnkELn7mFvbDTb+Uu+pIWjolsy7E6cBCMhqLY82RacyCYb6s7TKIh/A6SKptv2+fR8TccojLOCebp+4P+42Sq8gxz9eZ1OwPTX2TV0ymyz2jHgYZkSMwZT3jc3WjMPNUpRkHcrvQLhBDhz1dURc/Y0IXVYH6A==</signature> 
<payload> 
<type>enterprise</type> 
<group_id>Enterprise</group_id> 
<quota>1</quota> 
<max_violations>5</max_violations> 
<window_period>30</window_period> 
<creation_time>1446624000</creation_time> 
<label>Splunk Cloud Enterprise Subscription</label> 
<expiration_time>2147587199</expiration_time> 
<features> 
<feature>Auth</feature> 
<feature>FwdData</feature> 
<feature>RcvData</feature> 
<feature>LocalSearch</feature> 
<feature>DistSearch</feature> 
<feature>RcvSearch</feature> 
<feature>ScheduledSearch</feature> 
<feature>Alerting</feature> 
<feature>DeployClient</feature> 
<feature>DeployServer</feature> 
<feature>SplunkWeb</feature> 
<feature>SigningProcessor</feature> 
<feature>SyslogOutputProcessor</feature> 
<feature>CanBeRemoteMaster</feature> 
<feature>AllowDuplicateKeys</feature> 
</features> 
<add_ons> 
<add_on name="retention" type="cloud"> 
<parameter key="days" value="1"/> 
</add_on> 
</add_ons> 
<sourcetypes/> 
<guid>52AAEC24-8944-47A0-86BA-2C1D995E66F8</guid> 
</payload> 
</license> 
```
## Splunk - Implementation configuration
This is a configuration for Fortinet, it's an example:
8. Validate if the Add-on `Fortinet FortiGate Add-On for Splunk` is on the Splunk Cloud
9. Verify how to apply this parsing by searching the documentation
10. Copy and paste a piece of the log file and create a local file named `prio-fw-test.log`
11. Upload the file and use the source type `fortigate_log` from the documentation and write to the index `testes_pedro` (Verify if it's parsed)
	1. Click on `Splunk Recommended->Add data->Upload->Select File`
	2. Choose the source type `fortigate_log`
		1. You can here setup parse and copy the `props.conf` if needed
	3. Select `testes_pedro` index
	4. Check if it's well-parsed
12. Validate if the Add-on `Fortinet FortiGate Add-On for Splunk` is on the Splunk Heavy Forwarder if not install on `/opt/splunk/etc/apps/` (Download from page and untar)
13. Create an app on `/opt/splunk/etc/apps/{app_name}` (To ingest logs)
14. Create a folder inside the last one called `local`
15. Create a file on `/opt/splunk/etc/apps/{app_name}/local` with name `inputs.conf`
```
[monitor:///var/log/collect/forti.log*]
sourcetype = fortigate_log
disabled =  0
index = client_fw_ftnt_int
```
16. Give `chown splunk:splunk /opt/splunk/etc/apps/{app_name} -R`
17. Create the index `client_fw_ftnt_int` on Splunk Cloud (90 days retention + 0 max size)
18. Restart splunk `systemctl restart Splunkd`
19. Make app deploy of the created app into the Heavy Forward.
## Splunk - HEC Configuration
20. Follow the instructions on [Official Source](https://docs.splunk.com/Documentation/Splunk/9.4.0/Data/UsetheHTTPEventCollector#Configure_HTTP_Event_Collector_on_Splunk_Enterprise)
21. Create an index named `cliente_fw_from_elk` on HF and Cloud
22. Choose that index on the `New Token`

## Splunk - Alerts Indice
`cliente_alerts_spl_int` - 90 Days retention, Unlimited Space

## Splunk - App Creation
Apps->Manage Apps->Create App

**Name:** CLIENTE - Dashboards
**APP ID:** CLIENTE_SOC8_Dashboards
**Version:** 1.0.0
**Visilble:** Yes
**Author**:** SOC8
**Description:** Aplicação de Dashboards do cliente CLIENTE

## Splunk - User and Role Creation and Permissions
### Role Creation
Settings->Roles->New Role

**Name:** cliente-user
**Capabilities:** accelerate_search, change_own_password, edit_own_objects, edit_search_schedule_window, export_results_is_visible, get_metadata, get_typeahead, input_file, list_accelerate_search, list_all_objects, list_inputs, list_metrics_catalog, output_file, pattern_detect, request_remote_tok, rest_apps_view, rest_properties_get, rest_properties_set, run_collect, run_custom_command, run_dump, run_mcollect, run_sendalert, schedule_rtsearch, search, upload_lookup_files
**Indexes:** prio*

### User Creation
Settings->Users->New User

**Name:** {user}
**Password:** Generate
**Assign Roles:** cliente-user

### Alert permissions
**cliente-user:** read
**sc_admin, soc8*:** read, write

## Splunk - Handmade Apps Install
Folder Structure
```
├── SOC8_CLOUD_APP
│   ├── default
│   │   ├── app.conf*
│   │   ├── props.conf*
│   │   ├── data
│   │   │   └── ui
│   │   │       ├── nav
│   │   │       │   └── default.xml
│   │   │       └── views
```
The * means that these are the only ones needed for props

**Taking into consideration** 
- The app must contain only a folder called `default` and an optional folder called `metadata`
- Put everything necessary for the App inside `default` folder
- `app.conf` file with configurations for the app itself
- `data` folder can contain the default navs of the official splunk barebones app
- All other configurations like transforms, props, lookups can be created inside the `default` folder
File `default/app.conf`:
```
#
# Splunk app configuration file
#

[install]
state = enabled
is_configured = 0

[launcher]
author = SOC8
version = 1.0.0
description = Cloud App Description

# Name that will become visible on Splunk Cloud
[ui]
is_visible = 0
label = SOC8 - Cloud App

[package]
id = SOC8_CLOUD_APP

[id]
name = SOC8_CLOUD_APP
version = 1.0.0
```
**Taking into consideration** 
- The `name` variable for the `id` stanza **MUST** be the same as the unziped folder name
- The `version` variable **MUST** start in `1.0.0` and everytime we upload a new modification we **must** increment the version

File `data/ui/nav/default.xml`:
```
<nav search_view="search">
  <view name="search" default='true' />
  <view name="analytics_workspace" />
  <view name="datasets" />
  <view name="reports" />
  <view name="alerts" />
  <view name="dashboards" />
</nav>
```

File `default/props.conf`:
Add data->Select File->Set Source type(edit here)->Copy to clipboard

**Permissions and delivery**
**Permissions**
```
find SOC8_CLOUD_APP/ -type d -exec chmod 744 {} \\;
find SOC8_CLOUD_APP/ -type f -exec chmod 644 {} \\;
tar -czvf SOC8_CLOUD_APP.tar.gz SOC8_CLOUD_APP/
```
**Delivery**
23. Go to: `<https://layer8.splunkcloud.com/en-US/manager/launcher/apps/local>`
24. Click `Install app from file`
25. Click `Upload App`
26. Fill-out Splunk personal account credentials
27. Wait for App validation
28. Install the App
29. **Done**
## Splunk - Throubleshoot
### Not receiving logs on cloud index
30. Check folder permissions
31. Check index internal on splunk cloud with `index="_internal" host="hostname"` and `index="_internal" logfile_name`
32. Check file `/opt/splunk/etc/apps/100_layer8_splunkcloud/default/outputs.conf` and check with `telnet inputs...splunkcloud.com 9997` if we have connection
33. Check file `tail -n 20 /opt/splunk/var/log/splunk/splunkd.log` for error connecting to inputs
34.  Disable the `inputs.conf` and email the client. 


# Firewall

## Firewall - ELK Machine
```
sudo ufw allow ssh
sudo ufw allow https
sudo ufw allow 5601/tcp
sudo ufw allow 5044/tcp
sudo ufw allow 9200/tcp
sudo ufw allow 9100/tcp # nodeexporter
sudo ufw enable
```

## Firewall - Splunk machine
```
sudo ufw allow ssh
sudo ufw allow https
sudo ufw allow 514/tcp #rsyslog
sudo ufw allow 514/udp #rsyslog
sudo ufw allow 8089/tcp #splunk
sudo ufw allow 8088/tcp #splunk
sudo ufw allow 9997/tcp #splunk
sudo ufw allow 9100/tcp # nodeexporter
sudo ufw enable
```