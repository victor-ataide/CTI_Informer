#!/bin/bash
# CTI Node - Gerenciador simplificado

set -e

PORT="${1:-8101}"

cd /home/farias/Desktop/CTI

echo ""
echo "========================================"
echo "  CTI Node - Inicializacao simplificada"
echo "========================================"
echo ""

if [ ! -f "backend-node/package.json" ]; then
    echo "Erro: backend-node/package.json nao encontrado"
    exit 1
fi

mkdir -p logs

cleanup() {
    echo ""
    echo "Parando CTI Node..."
    if [ -n "$NODE_PID" ]; then
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
    echo "Finalizado"
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "Iniciando CTI Node na porta $PORT..."
PORT="$PORT" npm --prefix backend-node run start &
NODE_PID=$!

echo "PID: $NODE_PID"
echo "URL: http://localhost:$PORT"
echo "Pressione Ctrl+C para encerrar"

wait "$NODE_PID"
