#!/bin/bash
# Quick Start - CTI System
# Apenas execute este arquivo!

cat << 'EOF'

╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          🚨  CTI SYSTEM - QUICK START  🚨                         ║
║                                                                    ║
║   Threat Intelligence Dashboard + Discord Notifications           ║
║   Com deduplificação automática de alertas                        ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

EOF

# Cores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Verificações rápidas
echo -e "${BLUE}📋 Verificando pré-requisitos...${NC}"
echo ""

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 não encontrado${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python encontrado${NC}"

# Verificar venv
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}⏳ Criando ambiente virtual...${NC}"
    python3 -m venv venv
fi
echo -e "${GREEN}✅ Ambiente virtual OK${NC}"

# Ativar venv
source venv/bin/activate

# Instalar dependências
echo -e "${YELLOW}⏳ Instalando dependências...${NC}"
pip install -q -r requirements.txt 2>/dev/null
echo -e "${GREEN}✅ Dependências instaladas${NC}"

# Criar diretórios
mkdir -p logs data/results
echo -e "${GREEN}✅ Diretórios criados${NC}"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Menu de opções
echo -e "${BLUE}Escolha como executar:${NC}"
echo ""
echo -e "  ${GREEN}1)${NC} Modo Normal (Recomendado)"
echo -e "     $ ./start_cti.sh"
echo -e "     → Inicia tudo em uma janela, logs em tempo real"
echo ""
echo -e "  ${GREEN}2)${NC} Com porta customizada"
echo -e "     $ ./start_cti.sh 8503"
echo -e "     → Usa porta 8503 ao invés de 8502"
echo ""
echo -e "  ${GREEN}3)${NC} Em background"
echo -e "     $ ./start_cti.sh &"
echo -e "     → Continua no terminal, veja logs com: tail -f logs/process_manager.log"
echo ""
echo -e "  ${GREEN}4)${NC} Como serviço do sistema (sudo)"
echo -e "     $ sudo cp cti-system.service /etc/systemd/system/"
echo -e "     $ sudo systemctl enable cti-system"
echo -e "     $ sudo systemctl start cti-system"
echo -e "     → Roda automaticamente no boot"
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}📝 ANTES DE INICIAR - Verificar Configurações:${NC}"
echo ""
echo -e "  1) Discord webhook em ${BLUE}config.json${NC}"
echo -e "  2) Feeds configurados em ${BLUE}config.json${NC}"
echo -e "  3) Ollama rodando (se usar): ${BLUE}ollama serve${NC}"
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "🚀 ${GREEN}Pronto para iniciar? Execute:${NC}"
echo ""
echo -e "   ${BLUE}./start_cti.sh${NC}"
echo ""
echo -e "📊 Acesse o dashboard em: ${BLUE}http://localhost:8502${NC}"
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
