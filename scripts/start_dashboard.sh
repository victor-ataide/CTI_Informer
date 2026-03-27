#!/bin/bash
# Script para iniciar o Dashboard CTI
# Uso: ./start_dashboard.sh

PORT="${1:-8502}"

echo "🚨 Iniciando Dashboard CTI System..."
echo "📊 URL: http://localhost:${PORT}"
echo ""

# Verificar se estamos no diretório correto
if [ ! -f "dashboard.py" ]; then
    echo "❌ Erro: dashboard.py não encontrado. Execute este script do diretório CTI/"
    exit 1
fi

# Ativar ambiente virtual
if [ -d "venv" ]; then
    echo "🔧 Ativando ambiente virtual..."
    source venv/bin/activate
else
    echo "⚠️ Ambiente virtual não encontrado. Usando Python do sistema..."
fi

# Verificar se streamlit está instalado
if ! command -v streamlit &> /dev/null; then
    echo "❌ Streamlit não encontrado. Execute: pip install streamlit plotly"
    exit 1
fi

# Iniciar dashboard
echo "🎯 Iniciando Streamlit na porta ${PORT}..."
streamlit run dashboard.py --server.port "${PORT}" --logger.level="error"

echo ""
echo "✅ Dashboard encerrado."