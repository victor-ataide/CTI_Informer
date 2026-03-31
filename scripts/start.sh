#!/bin/bash
# Launcher Node-only do CTI

set -e

cd /home/farias/Desktop/CTI

if [ ! -f "backend-node/package.json" ]; then
	echo "Erro: backend-node/package.json nao encontrado"
	exit 1
fi

mkdir -p logs

if [ -f ".cti_node_pid" ] && kill -0 "$(cat .cti_node_pid)" 2>/dev/null; then
	echo "CTI Node ja esta rodando (PID: $(cat .cti_node_pid))"
	echo "URL: http://localhost:8101"
	exit 0
fi

echo "Iniciando CTI Node..."
nohup npm --prefix backend-node run start > logs/cti_node.log 2>&1 &
NODE_PID=$!
echo "$NODE_PID" > .cti_node_pid

sleep 2
if kill -0 "$NODE_PID" 2>/dev/null; then
	echo "CTI Node iniciado (PID: $NODE_PID)"
	echo "URL: http://localhost:8101"
	echo "Logs: logs/cti_node.log"
else
	echo "Falha ao iniciar CTI Node. Veja logs/cti_node.log"
	rm -f .cti_node_pid
	exit 1
fi
