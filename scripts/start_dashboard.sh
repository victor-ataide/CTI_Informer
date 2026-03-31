#!/bin/bash
# Script para iniciar o Dashboard Node (frontend servido pelo backend-node)
# Uso: ./start_dashboard.sh [porta]

set -e

PORT="${1:-8101}"

echo "Iniciando Dashboard Node..."
echo "URL: http://localhost:${PORT}"
echo ""

if [ ! -f "backend-node/package.json" ]; then
  echo "Erro: backend-node/package.json nao encontrado. Execute no diretorio CTI/"
  exit 1
fi

PORT="$PORT" npm --prefix backend-node run start