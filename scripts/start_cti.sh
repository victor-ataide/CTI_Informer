#!/bin/bash
# CTI System - Launcher Node-only

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_success() { echo -e "${GREEN}OK${NC} $1"; }
print_error() { echo -e "${RED}ERRO${NC} $1"; }
print_info() { echo -e "${BLUE}INFO${NC} $1"; }
print_warning() { echo -e "${YELLOW}AVISO${NC} $1"; }

check_directory() {
    if [ ! -f "backend-node/package.json" ]; then
        print_error "Execute este script no diretorio raiz do CTI"
        exit 1
    fi
}

check_node() {
    if ! command -v node >/dev/null 2>&1; then
        print_error "Node.js nao encontrado"
        exit 1
    fi
    if ! command -v npm >/dev/null 2>&1; then
        print_error "npm nao encontrado"
        exit 1
    fi
}

run_system() {
    local mode="$1"

    case "$mode" in
        "daemon")
            mkdir -p logs
            if [ -f ".cti_node_pid" ] && kill -0 "$(cat .cti_node_pid)" 2>/dev/null; then
                print_warning "CTI Node ja esta rodando (PID: $(cat .cti_node_pid))"
                exit 0
            fi

            print_info "Iniciando CTI Node em background..."
            nohup npm --prefix backend-node run start > logs/cti_node.log 2>&1 &
            echo $! > .cti_node_pid
            print_success "Node iniciado (PID: $(cat .cti_node_pid))"
            print_info "URL: http://localhost:8101"
            print_info "Logs: logs/cti_node.log"
            ;;

        "dashboard")
            print_info "Iniciando CTI Node (foreground)..."
            print_info "URL: http://localhost:8101"
            npm --prefix backend-node run start
            ;;

        "test")
            print_info "Testando endpoint /api/status..."
            curl -fsS http://127.0.0.1:8101/api/status >/dev/null
            print_success "API respondeu com sucesso"
            ;;

        "status")
            if [ -f ".cti_node_pid" ] && kill -0 "$(cat .cti_node_pid)" 2>/dev/null; then
                print_success "CTI Node rodando (PID: $(cat .cti_node_pid))"
                print_info "URL: http://localhost:8101"
            else
                print_warning "CTI Node nao esta rodando"
                rm -f .cti_node_pid
            fi
            ;;

        "stop")
            if [ -f ".cti_node_pid" ] && kill -0 "$(cat .cti_node_pid)" 2>/dev/null; then
                print_info "Parando CTI Node..."
                kill "$(cat .cti_node_pid)"
                rm -f .cti_node_pid
                print_success "CTI Node parado"
            else
                print_warning "CTI Node nao esta rodando"
            fi
            ;;

        "logs")
            if [ -f "logs/cti_node.log" ]; then
                tail -f logs/cti_node.log
            else
                print_warning "Arquivo logs/cti_node.log nao encontrado"
            fi
            ;;

        *)
            print_error "Modo invalido: $mode"
            show_help
            exit 1
            ;;
    esac
}

show_help() {
    echo ""
    echo -e "${CYAN}Uso: $0 [modo]${NC}"
    echo ""
    echo -e "${CYAN}Modos disponiveis:${NC}"
    echo -e "  daemon     - inicia em background"
    echo -e "  dashboard  - inicia em foreground"
    echo -e "  test       - testa endpoint da API"
    echo -e "  status     - verifica se esta rodando"
    echo -e "  stop       - para execucao em background"
    echo -e "  logs       - acompanha logs"
    echo ""
}

main() {
    check_directory
    check_node

    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi

    run_system "$1"
}

main "$@"
