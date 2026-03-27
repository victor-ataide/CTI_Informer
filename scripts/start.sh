#!/bin/bash
# Launcher do CTI - sem interatividade

cd /home/farias/Desktop/CTI
source venv/bin/activate

mkdir -p .streamlit logs data/results

cat > .streamlit/config.toml << 'EOF'
[logger]
level = "error"

[client]
showErrorDetails = false

[server]
headless = false
enableXsrfProtection = false
enableCORS = true
port = 8502
EOF

# Iniciar daemon
echo "Iniciando daemon..."
python main.py --daemon > logs/cti_daemon.log 2>&1 &
DAEMON_PID=$!

# Pequeno delay
sleep 3

# Iniciar dashboard sem prompt (echo vazio fornece resposta automática)
echo ""
echo "Dashboard iniciando na porta 8502..."
echo ""
echo | streamlit run dashboard.py --server.port 8502 --logger.level error
