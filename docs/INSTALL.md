# 🚀 CTI System - Guia Completo de Instalação e Funcionamento

## 📋 Visão Geral

Sistema completo de Inteligência de Ameaças Cibernéticas com:
- ✅ Coleta automática de feeds RSS/JSON
- ✅ Análise de ameaças com IA (Ollama)
- ✅ Extração de IoCs (IPs, domínios, hashes, CVEs)
- ✅ Notificações Discord deduplicadas
- ✅ Dashboard web interativo
- ✅ Execução automática 24/7

---

## 🛠️ Instalação - Passo a Passo

### Pré-requisitos

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl wget

# Verificar versões
python3 --version  # 3.8+
pip3 --version     # 20.0+
```

### 1. Clonagem e Setup Inicial

```bash
# Clonar repositório
git clone <seu-repo> cti-system
cd cti-system

# Ou se já tem os arquivos localmente
cd /home/farias/Desktop/CTI
```

### 2. Ambiente Virtual

```bash
# Criar ambiente virtual
python3 -m venv venv

# Ativar ambiente
source venv/bin/activate

# Verificar ativação (deve mostrar caminho venv)
which python
which pip
```

### 3. Dependências

```bash
# Instalar dependências Python
pip install -r requirements.txt

# Verificar instalação
python -c "import streamlit, plotly, requests; print('✅ Dependências OK')"
```

### 4. Configuração do Ollama (IA)

```bash
# Instalar Ollama (se não tiver)
curl -fsSL https://ollama.ai/install.sh | sh

# Iniciar serviço
ollama serve &

# Baixar modelo de IA (recomendado: llama3.2)
ollama pull llama3.2

# Verificar
ollama list
```

### 5. Configuração do Sistema

```bash
# Copiar configuração exemplo
cp config.json config.json.backup

# Editar configuração
nano config.json
```

**Conteúdo mínimo do `config.json`:**
```json
{
  "discord": {
    "webhook_url": "https://discord.com/api/webhooks/SEU_WEBHOOK_AQUI"
  },
  "feeds": [
    {
      "name": "SANS ISC",
      "url": "https://isc.sans.edu/rss.xml",
      "type": "rss"
    }
  ],
  "ollama": {
    "model": "llama3.2",
    "base_url": "http://localhost:11434"
  }
}
```

### 6. Teste Inicial

```bash
# Teste do sistema
python main.py --test

# Deve mostrar:
# ✅ Configuração carregada
# ✅ Discord webhook válido
# ✅ Ollama conectado
# ✅ Feeds acessíveis
```

---

## 🎯 Funcionamento - Modos de Uso

### Modo 1: Execução Única (Teste)

```bash
# Ativar ambiente
source venv/bin/activate

# Executar coleta única
python main.py

# Resultados ficam em: data/results/
# Dashboard: python -m streamlit run dashboard.py
```

### Modo 2: Daemon + Dashboard (Recomendado)

```bash
# Uma linha para tudo
./start_cti.sh

# Ou manualmente:
# Terminal 1: python main.py --daemon
# Terminal 2: streamlit run dashboard.py --server.port 8502
```

### Modo 3: Serviço do Sistema (24/7)

```bash
# Instalar como serviço
sudo cp cti-system.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cti-system
sudo systemctl start cti-system

# Verificar status
sudo systemctl status cti-system

# Logs
sudo journalctl -u cti-system -f
```

---

## 📊 Dashboard Web

### Acesso
- **URL:** `http://localhost:8502`
- **Auto-refresh:** A cada 60 segundos
- **Interface:** Streamlit moderna

### Funcionalidades

#### 📈 Métricas Gerais
- Total de ameaças coletadas
- Distribuição por severidade (crítica, alta, média, baixa)
- Setores afetados (financeiro, infraestrutura crítica)
- Ameaças filtradas

#### 📋 Tabela de Ameaças
- Últimas 20 ameaças
- Colunas: Data, Fonte, Severidade, APTs, Setores, Título
- Ordenação e busca

#### 🔍 Detalhes da Ameaça
- **Seleção:** Dropdown com ameaças recentes
- **Informações:**
  - Título + Severidade (colorida)
  - Fonte + Data/Hora
  - Descrição técnica
  - Fluxo de ataque
  - Classificação (financeiro/infraestrutura)

#### 🎯 IoCs da Ameaça
- Endereços IP (IPv4/IPv6)
- Domínios
- URLs suspeitas
- Hashes (MD5/SHA1/SHA256)
- Emails
- CVEs relacionadas

#### ⚡ TTPs (Técnicas)
- Técnicas MITRE ATT&CK
- Malware identificado
- Grupos APT

#### 🔗 Links
- Link original da ameaça
- Feed RSS da fonte
- Botão copiar link

#### 🔍 IoCs Consolidados
- **9 abas organizadas:**
  - 🌐 Domínios
  - 📍 IPv4/IPv6
  - 🔗 URLs
  - 📧 Emails
  - 🔐 SHA256/MD5/SHA1
  - ⚠️ CVEs
- **Para cada IoC:**
  - Valor do IoC
  - **Ameaça de origem** (qual vulnerabilidade)
  - **Severidade** da ameaça
- Bloco de código para copiar todos

### Filtros Disponíveis

#### 🎛️ Painel Lateral
- **Severidade:** crítica, alta, média, baixa
- **Setores:** financeiro, governo, saúde, etc.
- **Período:** últimos 1-30 dias
- **Botão atualizar:** recarrega dados

---

## 🤖 Sistema de Deduplicação

### Como Funciona
- **Hash SHA256** de todos os IoCs combinados
- **Cache persistente:** `data/.alert_cache.json`
- **Retenção:** 7 dias (configurável)
- **Benefício:** Evita spam no Discord

### Exemplo
```json
{
  "iocs": {
    "a1b2c3d4...": "2026-03-27T10:30:00",
    "e5f6g7h8...": "2026-03-27T11:45:00"
  },
  "last_updated": "2026-03-27T12:00:00"
}
```

### Verificar Status
```bash
# Ver estatísticas
python -c "from deduplicator import ThreatDeduplicator; d = ThreatDeduplicator(); print(d.get_stats())"

# Limpar cache (reset)
rm data/.alert_cache.json
```

---

## 📁 Estrutura de Arquivos

```
CTI/
├── 📄 config.json              # Configurações (webhooks, feeds)
├── 📄 requirements.txt         # Dependências Python
├── 📄 .gitignore              # Arquivos ignorados pelo Git
├── 📄 .streamlit/config.toml  # Config Streamlit
├── 📁 data/                   # Dados coletados
│   ├── results/               # Resultados das coletas
│   └── .alert_cache.json      # Cache de deduplicação
├── 📁 logs/                   # Logs do sistema
├── 📁 venv/                   # Ambiente virtual (ignorado)
├── 🐍 main.py                 # Orquestrador principal
├── 🐍 dashboard.py            # Interface web
├── 🐍 deduplicator.py         # Sistema anti-duplicação
├── 🐍 collector.py            # Coleta de feeds
├── 🐍 parser.py               # Parsing de dados
├── 🐍 intel_engine.py         # Análise com IA
├── 🐍 ioc_extractor.py        # Extração de IoCs
├── 🐍 notifier.py             # Notificações Discord
└── 📄 *.md                    # Documentação
```

---

## 🔧 Configurações Avançadas

### Configurações do Sistema (`config.json`)

```json
{
  "discord": {
    "webhook_url": "https://discord.com/api/webhooks/...",
    "username": "CTI Bot",
    "avatar_url": "https://..."
  },
  "feeds": [
    {
      "name": "Nome da Fonte",
      "url": "https://feed.url/rss.xml",
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
```

### Configurações do Dashboard (`.streamlit/config.toml`)

```toml
[logger]
level = "error"

[client]
showErrorDetails = false

[server]
headless = false
enableXsrfProtection = false
enableCORS = true
port = 8502
```

### Variáveis de Ambiente (opcional)

```bash
# Arquivo .env
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
OLLAMA_MODEL=llama3.2
DASHBOARD_PORT=8502
```

---

## 🚨 Monitoramento e Troubleshooting

### Verificar Status dos Processos

```bash
# Processos rodando
ps aux | grep -E "python|streamlit"

# Portas em uso
netstat -tlnp | grep 8502

# Uso de disco
du -sh data/ logs/
```

### Logs do Sistema

```bash
# Logs principais
tail -f logs/process_manager.log
tail -f logs/cti_daemon.log

# Logs do dashboard
tail -f logs/dashboard_run.log

# Logs do sistema (se usar systemd)
sudo journalctl -u cti-system -f
```

### Problemas Comuns

#### ❌ "Connection refused" no Dashboard
```bash
# Verificar se streamlit está rodando
ps aux | grep streamlit

# Reiniciar
pkill -f streamlit
streamlit run dashboard.py --server.port 8502
```

#### ❌ Discord não recebe notificações
```bash
# Testar webhook
curl -X POST -H "Content-Type: application/json" \
  -d '{"content": "Teste CTI"}' \
  SEU_WEBHOOK_URL

# Verificar config.json
python -c "import json; print(json.load(open('config.json'))['discord'])"
```

#### ❌ Ollama não responde
```bash
# Verificar serviço
ollama list
ollama serve &

# Testar modelo
ollama run llama3.2 "teste"
```

#### ❌ Dados não aparecem
```bash
# Verificar arquivos
ls -la data/results/

# Executar coleta manual
python main.py

# Verificar logs
tail logs/cti_daemon.log
```

---

## 🔄 Atualização do Sistema

```bash
# Backup da configuração
cp config.json config.json.backup

# Pull das atualizações
git pull origin main

# Atualizar dependências
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Testar
python main.py --test

# Reiniciar serviços
sudo systemctl restart cti-system
```

---

## 📊 Métricas e Estatísticas

### Ver Estatísticas do Sistema

```bash
# Ameaças coletadas
find data/results/ -name "*.json" | wc -l

# Tamanho dos dados
du -sh data/

# Cache de deduplicação
python -c "from deduplicator import ThreatDeduplicator; d = ThreatDeduplicator(); print(d.get_stats())"
```

### Dashboard de Métricas
- Acesse `http://localhost:8502`
- Veja métricas em tempo real
- Filtros por severidade/setor/período

---

## 🔐 Segurança

### Boas Práticas

1. **Nunca commite credenciais**
   ```bash
   # Verificar antes de commit
   git status
   git diff --cached
   ```

2. **Use .env para desenvolvimento**
   ```bash
   # Arquivo .env (não versionado)
   DISCORD_WEBHOOK=secret_webhook_url
   ```

3. **Permissões restritivas**
   ```bash
   chmod 600 config.json
   chmod 700 data/
   ```

4. **Monitoramento de logs**
   ```bash
   # Alertas em logs suspeitos
   grep -i "error\|fail\|exception" logs/*.log
   ```

### Arquivos Sensíveis (já no .gitignore)
- `config.json` (contém webhooks)
- `data/.alert_cache.json` (hashes de IoCs)
- `logs/` (podem conter dados sensíveis)
- `.env` (variáveis de ambiente)

---

## 🎯 Próximos Passos

### Funcionalidades Planejadas
- [ ] Integração com MISP
- [ ] Alertas por email
- [ ] Dashboard com autenticação
- [ ] API REST para integração
- [ ] Suporte a mais feeds
- [ ] Análise de malware (sandbox)

### Melhorias Sugeridas
- [ ] Container Docker
- [ ] CI/CD pipeline
- [ ] Testes automatizados
- [ ] Documentação API
- [ ] Interface mobile

---

## 📞 Suporte

### Documentação Disponível
- `README.md` - Visão geral
- `GUIA_RAPIDO.md` - Início rápido
- `TECNICO.md` - Detalhes técnicos
- `DISCORD_SETUP.md` - Configuração Discord
- `EXECUCAO_AUTOMATICA.md` - Modos de execução

### Comandos Úteis
```bash
# Status completo
./QUICKSTART.sh

# Teste rápido
python main.py --test

# Limpeza
rm -rf logs/* data/results/* data/.alert_cache.json
```

---

**🚀 Pronto para usar! Execute `./start_cti.sh` e acesse `http://localhost:8502`**

*Última atualização: 2026-03-27*
*Versão: 1.0*