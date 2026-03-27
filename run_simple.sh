#!/bin/bash
# CTI System - Gerenciador Simplificado
# Funciona melhor que subprocess do Python

set -e

PORT="${1:-8502}"
KILL_ON_EXIT=true

cd /home/farias/Desktop/CTI
source venv/bin/activate

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          🚨 CTI SYSTEM - Iniciando...  🚨               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Função para trap (Ctrl+C)
cleanup() {
    echo ""
    echo "🛑 Parando todos os processos..."
    kill $DAEMON_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
    echo "✅ Finalizado"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Criar diretórios
mkdir -p logs data/results

# Iniciar daemon em background
echo "🚀 Iniciando CTI daemon (1 hora)..."
nohup python main.py --daemon > logs/cti_daemon.log 2>&1 &
DAEMON_PID=$!
echo "✅ Daemon PID: $DAEMON_PID"

sleep 2

# Iniciar dashboard
echo ""
echo "📊 Iniciando Dashboard na porta $PORT..."
echo "🌐 Acesse: http://localhost:$PORT"
echo ""
echo "════════════════════════════════════════════════════════════"
echo ""

python3 -c "
import streamlit as st
print('Verificando 🚀')
" || true

streamlit run dashboard.py --server.port "$PORT" --logger.level=error

echo ""
echo "❌ Dashboard encerrado"

cleanup
