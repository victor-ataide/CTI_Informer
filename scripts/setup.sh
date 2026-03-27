#!/bin/bash

# Script de Instalação Automática do CTI System
# Para Ubuntu/Debian - Execute como: bash setup.sh

set -e  # Exit se algum comando falhar

echo "=================================================="
echo "   CTI System - Instalação Automática"
echo "   Cyber Threat Intelligence Platform"
echo "=================================================="
echo ""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para imprimir
log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# 1. Verificar se está em Linux
log_info "Verificando sistema operacional..."
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    log_error "Este script é apenas para Linux"
    exit 1
fi
log_info "Sistema: Linux (OK)"

# 2. Atualizar sistema
log_info "Atualizando pacotes do sistema..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# 3. Instalar Python3 e pip
log_info "Verificando Python3..."
if ! command -v python3 &> /dev/null; then
    log_warn "Python3 não encontrado. Instalando..."
    sudo apt-get install -y python3 python3-pip python3-venv
fi
log_info "Python3: $(python3 --version)"

# 4. Criar ambiente virtual
log_info "Criando ambiente virtual Python..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    log_info "Ambiente virtual criado"
else
    log_warn "Ambiente virtual já existe"
fi

# 5. Ativar ambiente virtual
log_info "Ativando ambiente virtual..."
source venv/bin/activate

# 6. Instalar dependências Python
log_info "Instalando dependências Python..."
pip install --upgrade pip wheel setuptools -q
pip install -r requirements.txt -q
log_info "Dependências Python instaladas"

# 7. Verificar Ollama
log_info "Verificando Ollama..."
if ! command -v ollama &> /dev/null; then
    log_warn "Ollama não encontrado. Você precisa instalar manualmente:"
    log_warn "  curl https://ollama.ai/install.sh | sh"
    log_warn "Após instalar Ollama, execute:"
    log_warn "  ollama pull mistral"
else
    log_info "Ollama encontrado: $(ollama --version 2>/dev/null || echo 'versão desconhecida')"
    
    # Verificar se tem modelo Mistral
    log_info "Verificando modelo Mistral..."
    if ! ollama list 2>/dev/null | grep -q "mistral"; then
        log_warn "Modelo Mistral não encontrado. Baixando..."
        ollama pull mistral
        log_info "Mistral baixado com sucesso"
    fi
fi

# 8. Criar diretórios necessários
log_info "Criando diretórios..."
mkdir -p data/results
mkdir -p logs

# 9. Copiar arquivo de configuração
if [ ! -f "config.json" ]; then
    log_error "config.json não encontrado no diretório"
else
    log_info "config.json encontrado"
fi

# 10. Permissões de execução
log_info "Aplicando permissões..."
chmod +x main.py

# 11. Teste rápido
log_info "Testando importações Python..."
python3 << EOF
try:
    import requests
    import feedparser
    import bs4
    print("✓ Todos os módulos importados com sucesso")
except ImportError as e:
    print(f"✗ Erro ao importar: {e}")
    exit(1)
EOF

echo ""
echo "=================================================="
echo "   ✓ Instalação Concluída!"
echo "=================================================="
echo ""
echo "Próximos passos:"
echo ""
echo "1. Configurar webhook Discord:"
echo "   nano config.json"
echo "   # Procure por: \"webhook_url\":"
echo ""
echo "2. Iniciar Ollama (em outro terminal):"
echo "   ollama serve"
echo ""
echo "3. Executar CTI System:"
echo "   source venv/bin/activate"
echo "   python main.py          # Uma única vez"
echo "   python main.py --daemon # Modo daemon (recomendado)"
echo ""
echo "4. Testar Discord:"
echo "   python main.py --test"
echo ""
echo "5. Ver logs:"
echo "   tail -f logs/cti.log"
echo ""
echo "Documentação completa:"
echo "   cat README.md"
echo ""
