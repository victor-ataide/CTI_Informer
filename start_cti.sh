#!/bin/bash
# 🚀 CTI System - Script de Inicialização
# Facilita o uso do sistema CTI

set -e

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Funções de output
print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  🚀 CTI SYSTEM - INICIALIZAÇÃO${NC}                                   ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${PURPLE}ℹ️${NC}  $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC}  $1"
}

# Verificar se está no diretório correto
check_directory() {
    if [ ! -f "main.py" ] || [ ! -f "config.json" ]; then
        print_error "Execute este script no diretório raiz do CTI System"
        print_info "Diretório atual: $(pwd)"
        exit 1
    fi
}

# Ativar ambiente virtual
activate_venv() {
    if [ ! -d "venv" ]; then
        print_error "Ambiente virtual não encontrado. Execute ./install.sh primeiro"
        exit 1
    fi

    source venv/bin/activate
    print_success "Ambiente virtual ativado"
}

# Verificar serviços
check_services() {
    print_info "Verificando serviços..."

    # Verificar Ollama
    if pgrep -f "ollama serve" > /dev/null; then
        print_success "Ollama está rodando"
    else
        print_warning "Ollama não está rodando. Iniciando..."
        nohup ollama serve > /dev/null 2>&1 &
        sleep 3
        if pgrep -f "ollama serve" > /dev/null; then
            print_success "Ollama iniciado"
        else
            print_error "Falha ao iniciar Ollama"
            exit 1
        fi
    fi
}

# Função para executar o sistema
run_system() {
    local mode="$1"

    case "$mode" in
        "daemon")
            print_info "Iniciando sistema em modo daemon..."
            nohup python main.py --daemon > logs/daemon.log 2>&1 &
            echo $! > .cti_pid
            print_success "Sistema iniciado em background (PID: $(cat .cti_pid))"
            print_info "Logs em: logs/daemon.log"
            ;;
        "dashboard")
            print_info "Iniciando dashboard..."
            streamlit run dashboard.py --server.port 8502 --server.address 0.0.0.0
            ;;
        "test")
            print_info "Executando testes..."
            python main.py --test
            ;;
        "status")
            if [ -f ".cti_pid" ] && kill -0 $(cat .cti_pid) 2>/dev/null; then
                print_success "Sistema está rodando (PID: $(cat .cti_pid))"
            else
                print_warning "Sistema não está rodando"
                rm -f .cti_pid
            fi
            ;;
        "stop")
            if [ -f ".cti_pid" ] && kill -0 $(cat .cti_pid) 2>/dev/null; then
                print_info "Parando sistema..."
                kill $(cat .cti_pid)
                rm -f .cti_pid
                print_success "Sistema parado"
            else
                print_warning "Sistema não está rodando"
            fi
            ;;
        "logs")
            if [ -f "logs/daemon.log" ]; then
                tail -f logs/daemon.log
            else
                print_warning "Arquivo de log não encontrado"
            fi
            ;;
        *)
            print_error "Modo inválido: $mode"
            show_help
            exit 1
            ;;
    esac
}

# Mostrar ajuda
show_help() {
    echo ""
    echo -e "${CYAN}Uso: $0 [modo]${NC}"
    echo ""
    echo -e "${CYAN}Modos disponíveis:${NC}"
    echo -e "  ${BLUE}daemon${NC}     - Inicia o sistema em background"
    echo -e "  ${BLUE}dashboard${NC}  - Inicia apenas o dashboard web"
    echo -e "  ${BLUE}test${NC}       - Executa testes do sistema"
    echo -e "  ${BLUE}status${NC}     - Verifica status do sistema"
    echo -e "  ${BLUE}stop${NC}       - Para o sistema em execução"
    echo -e "  ${BLUE}logs${NC}       - Mostra logs em tempo real"
    echo ""
    echo -e "${CYAN}Exemplos:${NC}"
    echo -e "  ${BLUE}$0 daemon${NC}     # Inicia tudo"
    echo -e "  ${BLUE}$0 dashboard${NC}  # Apenas dashboard"
    echo -e "  ${BLUE}$0 status${NC}     # Verifica se está rodando"
    echo ""
}

# Menu interativo
interactive_menu() {
    echo ""
    echo -e "${CYAN}Escolha uma opção:${NC}"
    echo -e "  ${BLUE}1${NC} - Iniciar sistema completo (daemon + dashboard)"
    echo -e "  ${BLUE}2${NC} - Iniciar apenas daemon"
    echo -e "  ${BLUE}3${NC} - Iniciar apenas dashboard"
    echo -e "  ${BLUE}4${NC} - Executar testes"
    echo -e "  ${BLUE}5${NC} - Verificar status"
    echo -e "  ${BLUE}6${NC} - Parar sistema"
    echo -e "  ${BLUE}7${NC} - Ver logs"
    echo -e "  ${BLUE}0${NC} - Sair"
    echo ""
    read -p "Opção: " choice

    case "$choice" in
        1)
            run_system "daemon"
            sleep 2
            echo ""
            print_info "Aguardando inicialização..."
            sleep 3
            run_system "dashboard"
            ;;
        2)
            run_system "daemon"
            ;;
        3)
            run_system "dashboard"
            ;;
        4)
            run_system "test"
            ;;
        5)
            run_system "status"
            ;;
        6)
            run_system "stop"
            ;;
        7)
            run_system "logs"
            ;;
        0)
            exit 0
            ;;
        *)
            print_error "Opção inválida"
            interactive_menu
            ;;
    esac
}

# Função principal
main() {
    print_header

    check_directory
    activate_venv
    check_services

    # Se não passou argumentos, mostrar menu interativo
    if [ $# -eq 0 ]; then
        interactive_menu
    else
        run_system "$1"
    fi
}

# Executar
main "$@"

if [ ! -f "dashboard.py" ]; then
    print_error "dashboard.py não encontrado"
    exit 1
fi

print_status "Ambiente virtual encontrado"
print_status "Arquivos de configuração OK"
echo ""

# Ativar ambiente
source "$VENV_PATH"
print_status "Ambiente virtual ativado"
echo ""

# Verificar se streamlit está instalado
if ! python -c "import streamlit" 2>/dev/null; then
    print_error "Streamlit não está instalado"
    print_info "Execute: pip install -r requirements.txt"
    exit 1
fi

print_status "Dependências verificadas"
echo ""

# Criar diretório de logs
mkdir -p logs
print_status "Diretório de logs criado/verificado"
echo ""

# Iniciar usando o gerenciador
print_info "Iniciando Process Manager com porta $PORT..."
echo ""

python process_manager.py --port "$PORT"
