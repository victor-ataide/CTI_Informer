# Configurar CTI System como Serviço Systemd (Linux)
# Rodar 24/7 automaticamente, mesmo depois de reboot

# ============================================================================
# PASSO 1: Criar arquivo de serviço
# ============================================================================

sudo nano /etc/systemd/system/cti-system.service

# Colar conteúdo abaixo:

---

[Unit]
Description=CTI System - Cyber Threat Intelligence Platform
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/Desktop/CTI
ExecStart=/home/ubuntu/Desktop/CTI/venv/bin/python /home/ubuntu/Desktop/CTI/main.py --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Variáveis de ambiente (opcional)
Environment="PYTHONUNBUFFERED=1"
Environment="OLLAMA_URL=http://localhost:11434"

[Install]
WantedBy=multi-user.target

---

# ============================================================================
# PASSO 2: Habilitar serviço
# ============================================================================

sudo systemctl daemon-reload
sudo systemctl enable cti-system
sudo systemctl start cti-system

# ============================================================================
# COMANDOS ÚTEIS
# ============================================================================

# Ver status:
sudo systemctl status cti-system

# Ver logs em tempo real:
sudo journalctl -u cti-system -f

# Ver últimas 50 linhas:
sudo journalctl -u cti-system -n 50

# Parar serviço:
sudo systemctl stop cti-system

# Reiniciar:
sudo systemctl restart cti-system

# Desabilitar (não iniciar no boot):
sudo systemctl disable cti-system

# Ver erros:
sudo journalctl -u cti-system | grep ERROR

# ============================================================================
# ARQUIVO ALTERNATIVA: cti-system.timer (executar periodicamente)
# ============================================================================

# Se preferir rodar apenas uma vez por hora em vez de daemon contínuo:

sudo nano /etc/systemd/system/cti-system.timer

---

[Unit]
Description=Run CTI System hourly
Requires=cti-system.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Unit=cti-system.service

[Install]
WantedBy=timers.target

---

# Ativar timer:
sudo systemctl daemon-reload
sudo systemctl enable cti-system.timer
sudo systemctl start cti-system.timer

# Ver timers ativos:
sudo systemctl list-timers

# ============================================================================
# TROUBLESHOOTING
# ============================================================================

# Erro: "User ubuntu not found"
# Solução: Alterar "User=ubuntu" para seu username:
whoami  # Ver seu username
# Editar arquivo e colocar seu username

# Erro: "Permission denied"
# Solução: Dar permissões
sudo chmod +x /home/ubuntu/Desktop/CTI/main.py

# Erro: "Python module not found"
# Solução: Usar caminho completo do venv
/home/ubuntu/Desktop/CTI/venv/bin/python

# Não inicia no boot
# Solução: Garantir que enabled:
sudo systemctl enable cti-system
sudo systemctl is-enabled cti-system  # Deve retornar "enabled"

# ============================================================================
# MONITORING
# ============================================================================

# Criar script de monitoramento (monitor.sh):

#!/bin/bash
while true; do
    status=$(sudo systemctl is-active cti-system)
    if [ "$status" != "active" ]; then
        echo "CTI System caiu! Reiniciando..."
        sudo systemctl restart cti-system
    fi
    sleep 300  # Verificar a cada 5 minutos
done

# Rodar como background:
nohup bash monitor.sh > /tmp/cti-monitor.log 2>&1 &

# ============================================================================
# LOGS CENTRALIZADOS
# ============================================================================

# Ver logs do sistema:
sudo journalctl -u cti-system --since "2 hours ago"

# Exportar logs:
sudo journalctl -u cti-system > /tmp/cti-logs.txt

# Logs persistentes (por padrão são temporários):
sudo mkdir -p /var/log/cti
sudo chown syslog:adm /var/log/cti

# Editar rsyslog para guardar logs:
sudo nano /etc/rsyslog.d/cti.conf

# Adicionar:
:programname, isequal, "cti-system" /var/log/cti/cti.log
& stop

# Reiniciar rsyslog:
sudo systemctl restart rsyslog

# ============================================================================
# INTEGRAÇÃO COM MONIT (Monitoramento Automático)
# ============================================================================

sudo apt-get install monit

# Editar monit config:
sudo nano /etc/monit/monitrc

# Adicionar:
check process cti-system with pidfile /run/cti-system.pid
    start program = "/bin/systemctl start cti-system"
    stop program  = "/bin/systemctl stop cti-system"
    if failed unixsocket /run/cti-system.sock then restart
    if 5 restarts within 5 cycles then alert

# Ativar monit:
sudo systemctl enable monit
sudo systemctl start monit

# ============================================================================
# BACKUP AUTOMÁTICO DO BANCO DE DADOS
# ============================================================================

# Cron para backup a cada 6 horas:
crontab -e

# Adicionar:
0 */6 * * * tar -czf /backup/cti-$(date +\%Y\%m\%d-\%H\%M\%S).tar.gz /home/ubuntu/Desktop/CTI/data

# ============================================================================
# ALERTAS DE SAÚDE
# ============================================================================

# Script para verificar se sistema está saudável:

#!/bin/bash

EXPECTED_INTERVAL=3600  # 1 hora em segundos
LAST_RUN=$(stat -c %Y /home/ubuntu/Desktop/CTI/data/results/*.json | sort -n | tail -1)
NOW=$(date +%s)
TIME_SINCE=$((NOW - LAST_RUN))

if [ $TIME_SINCE -gt $((EXPECTED_INTERVAL * 2)) ]; then
    echo "ALERTA: CTI System não executou nos últimas 2 horas!"
    # Notificar por email ou Discord
fi

# Agendar com cron:
# 0 * * * * /usr/local/bin/check-cti-health.sh

# ============================================================================
# PERFORMANCE & RESOURCE LIMITS
# ============================================================================

# Limitar recursos (opcional - para VPS com recursos limitados):

[Service]
MemoryLimit=2G
CPUQuota=50%

# ============================================================================
# DOCKER (Opcional - Containerizar aplicação)
# ============================================================================

# Criar Dockerfile:
cat > /home/ubuntu/Desktop/CTI/Dockerfile << 'EOF'
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "main.py", "--daemon"]
EOF

# Build:
docker build -t cti-system .

# Rodar:
docker run -d \
  --name cti \
  -v /path/to/data:/app/data \
  -v /path/to/logs:/app/logs \
  -e DISCORD_WEBHOOK_URL="..." \
  cti-system

# ============================================================================
# KUBERNETES (Opcional - Escala em produção)
# ============================================================================

# Criar cti-deployment.yaml:

apiVersion: apps/v1
kind: Deployment
metadata:
  name: cti-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cti
  template:
    metadata:
      labels:
        app: cti
    spec:
      containers:
      - name: cti
        image: my-registry/cti-system:latest
        env:
        - name: DISCORD_WEBHOOK_URL
          valueFrom:
            secretKeyRef:
              name: cti-secrets
              key: webhook-url

# Deploy:
kubectl apply -f cti-deployment.yaml

# ============================================================================
