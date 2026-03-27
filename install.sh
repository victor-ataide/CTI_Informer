#!/bin/bash
# 🚀 CTI System - Instalador Automático
# Execute este script para instalar tudo automaticamente

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Funções de output
print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  🚀 CTI SYSTEM - INSTALADOR AUTOMÁTICO${NC}                           ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
}

print_step() {
    echo -e "${CYAN}➤${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC}  $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${PURPLE}ℹ️${NC}  $1"
}

# Verificações iniciais
check_requirements() {
    print_step "Verificando pré-requisitos do sistema..."

    # Verificar se é Linux
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_error "Este script é para Linux. Para outros sistemas, consulte INSTALL.md"
        exit 1
    fi

    # Verificar se tem sudo
    if ! command -v sudo &> /dev/null; then
        print_warning "sudo não encontrado. Algumas operações podem falhar."
    fi

    # Verificar Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 não encontrado. Instale com: sudo apt install python3"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ "$(printf '%s\n' "$PYTHON_VERSION" "3.8" | sort -V | head -n1)" != "3.8" ]]; then
        print_error "Python 3.8+ necessário. Versão atual: $PYTHON_VERSION"
        exit 1
    fi
    print_success "Python $PYTHON_VERSION encontrado"

    # Verificar pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 não encontrado. Instale com: sudo apt install python3-pip"
        exit 1
    fi
    print_success "pip3 encontrado"

    # Verificar git
    if ! command -v git &> /dev/null; then
        print_error "git não encontrado. Instale com: sudo apt install git"
        exit 1
    fi
    print_success "git encontrado"
}

# Instalar dependências do sistema
install_system_deps() {
    print_step "Instalando dependências do sistema..."

    # Atualizar lista de pacotes
    sudo apt update -qq

    # Instalar pacotes necessários
    sudo apt install -y -qq \
        python3-dev \
        python3-venv \
        python3-pip \
        curl \
        wget \
        jq \
        build-essential \
        libssl-dev \
        libffi-dev \
        || {
            print_warning "Algumas dependências do sistema podem não ter sido instaladas"
        }

    print_success "Dependências do sistema instaladas"
}

# Configurar ambiente virtual
setup_venv() {
    print_step "Configurando ambiente virtual Python..."

    # Criar venv se não existir
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Ambiente virtual criado"
    else
        print_info "Ambiente virtual já existe"
    fi

    # Ativar venv
    source venv/bin/activate

    # Atualizar pip
    pip install --upgrade pip -q

    # Instalar dependências
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt -q
        print_success "Dependências Python instaladas"
    else
        print_error "requirements.txt não encontrado"
        exit 1
    fi
}

# Instalar e configurar Ollama
setup_ollama() {
    print_step "Verificando Ollama (IA)..."

    if command -v ollama &> /dev/null; then
        print_info "Ollama já instalado"
    else
        print_info "Instalando Ollama..."
        curl -fsSL https://ollama.ai/install.sh | sh

        if [ $? -eq 0 ]; then
            print_success "Ollama instalado"
        else
            print_warning "Falha ao instalar Ollama. Instale manualmente depois."
        fi
    fi

    # Verificar se serviço está rodando
    if pgrep -f "ollama serve" > /dev/null; then
        print_success "Ollama está rodando"
    else
        print_info "Iniciando Ollama..."
        nohup ollama serve > /dev/null 2>&1 &
        sleep 3
        if pgrep -f "ollama serve" > /dev/null; then
            print_success "Ollama iniciado"
        else
            print_warning "Ollama não iniciou. Execute 'ollama serve &' manualmente."
        fi
    fi

    # Baixar modelo
    print_info "Baixando modelo llama3.2 (pode demorar)..."
    if ollama list | grep -q "llama3.2"; then
        print_success "Modelo llama3.2 já disponível"
    else
        ollama pull llama3.2
        if [ $? -eq 0 ]; then
            print_success "Modelo llama3.2 baixado"
        else
            print_warning "Falha ao baixar modelo. Execute 'ollama pull llama3.2' depois."
        fi
    fi
}

# Criar estrutura de diretórios
create_directories() {
    print_step "Criando estrutura de diretórios..."

    mkdir -p data/results
    mkdir -p logs
    mkdir -p .streamlit

    print_success "Diretórios criados"
}

# Configurar arquivos
setup_config() {
    print_step "Verificando configurações..."

    # config.json
    if [ ! -f "config.json" ]; then
        print_warning "config.json não encontrado. Criando template..."
        cat > config.json << 'EOF'
{
  "discord": {
    "webhook_url": "COLE_SEU_WEBHOOK_DISCORD_AQUI"
  },
  "feeds": [
    {
      "name": "SANS Internet Storm Center",
      "url": "https://isc.sans.edu/rss.xml",
      "type": "rss",
      "enabled": true
    },
    {
      "name": "Krebs on Security",
      "url": "https://krebsonsecurity.com/feed/",
      "type": "rss",
      "enabled": true
    }
  ],
  "ollama": {
    "model": "llama3.2",
    "base_url": "http://localhost:11434",
    "timeout": 30
  },
  "system": {
    "max_retries": 3,
    "request_timeout": 10,
    "log_level": "INFO"
  }
}
EOF
        print_success "config.json criado. Edite com seu webhook Discord!"
    else
        print_success "config.json já existe"
    fi

    # .streamlit/config.toml
    if [ ! -f ".streamlit/config.toml" ]; then
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
        print_success ".streamlit/config.toml criado"
    fi
}

# Testar instalação
test_installation() {
    print_step "Testando instalação..."

    source venv/bin/activate

    # Teste básico do Python
    if python -c "import streamlit, plotly, requests, json; print('OK')" 2>/dev/null; then
        print_success "Dependências Python OK"
    else
        print_error "Problema com dependências Python"
        return 1
    fi

    # Teste dos módulos do projeto
    if python -c "from main import CTISystem; print('OK')" 2>/dev/null; then
        print_success "Módulos do projeto OK"
    else
        print_error "Problema com módulos do projeto"
        return 1
    fi

    # Teste do dashboard
    if python -m py_compile dashboard.py 2>/dev/null; then
        print_success "Dashboard compila OK"
    else
        print_error "Erro no dashboard.py"
        return 1
    fi

    return 0
}

# Menu pós-instalação
show_next_steps() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  🎯 PRÓXIMOS PASSOS${NC}                                                     ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}1. Configure o Discord:${NC}"
    echo -e "   Edite ${BLUE}config.json${NC} e coloque seu webhook Discord"
    echo ""

    echo -e "${CYAN}2. Teste o sistema:${NC}"
    echo -e "   ${BLUE}source venv/bin/activate${NC}"
    echo -e "   ${BLUE}python main.py --test${NC}"
    echo ""

    echo -e "${CYAN}3. Execute o sistema:${NC}"
    echo -e "   ${BLUE}./start_cti.sh${NC}          # Modo recomendado"
    echo -e "   ${BLUE}python main.py --daemon${NC} # Apenas daemon"
    echo ""

    echo -e "${CYAN}4. Acesse o dashboard:${NC}"
    echo -e "   ${BLUE}http://localhost:8502${NC}"
    echo ""

    echo -e "${CYAN}5. Para produção (opcional):${NC}"
    echo -e "   ${BLUE}sudo cp cti-system.service /etc/systemd/system/${NC}"
    echo -e "   ${BLUE}sudo systemctl enable cti-system${NC}"
    echo ""

    echo -e "${GREEN}📚 Documentação completa em: INSTALL.md${NC}"
    echo ""
}

# Função principal
main() {
    print_header
    echo ""

    check_requirements
    echo ""

    install_system_deps
    echo ""

    setup_venv
    echo ""

    setup_ollama
    echo ""

    create_directories
    echo ""

    setup_config
    echo ""

    if test_installation; then
        echo ""
        print_success "🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO!"
        echo ""
        show_next_steps
    else
        echo ""
        print_error "❌ INSTALAÇÃO CONCLUÍDA COM ERROS!"
        print_info "Verifique os logs acima e consulte INSTALL.md"
        exit 1
    fi
}

# Executar
main "$@"