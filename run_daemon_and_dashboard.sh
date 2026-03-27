#!/bin/bash
# Script para rodar CTI em daemon e dashboard (atualiza 1 hora e envia alertas ao Discord)

# Porta do dashboard (default 8502)
PORT="${1:-8502}"

echo "🚀 Iniciando CTI System em modo daemon (1h) e Dashboard na porta $PORT"

# Ativa virtualenv
source venv/bin/activate

# Inicia daemon CTI (thread separada em background)
nohup python main.py --daemon > logs/cti_daemon.log 2>&1 &
CTI_PID=$!

echo "✅ CTI daemon iniciado (PID $CTI_PID). Logs em logs/cti_daemon.log"

# Inicia dashboard
./start_dashboard.sh "$PORT"

# Ao sair, finaliza o daemon
echo "🛑 Parando CTI daemon (PID $CTI_PID)"
kill $CTI_PID 2>/dev/null || true

echo "✅ Finalizado"