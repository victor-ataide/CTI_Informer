
# CTI System - Plataforma Global de Threat Intelligence 🚨

Sistema open-source de **Cyber Threat Intelligence (CTI)** para monitoramento de ameaças, análise com LLM local (Ollama), extração de IoCs e alertas automáticos para Discord.

---

## Principais Recursos

- Coleta de múltiplas fontes (RSS/blogs)
- Análise com LLM local (Ollama: Mistral/Llama3)
- Extração de IoCs (IPs, domínios, URLs, hashes, CVEs)
- Mapeamento MITRE ATT&CK
- Alertas automáticos para Discord
- Dashboard web interativo (Streamlit)
- 100% local, sem dependências externas

---

## Instalação Rápida

### 1. Pré-requisitos

- **Python 3.8+**
- **Ollama** (para análise LLM)
- **15GB RAM** (recomendado: 32GB)
- **Git** (opcional, para clonar o repositório)

### 2. Baixar o Projeto

```bash
# Linux/macOS
git clone <repo-url>
cd CTI

# Windows (Prompt de Comando ou PowerShell)
git clone <repo-url>
cd CTI
```

### 3. Instalar Python e Ambiente Virtual

#### Linux/macOS

```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv -y
python3 -m venv venv
source venv/bin/activate
```

#### Windows

```cmd
# Instale Python 3.8+ do site oficial: https://www.python.org/downloads/
python -m venv venv
venv\Scripts\activate
```

### 4. Instalar Dependências

```bash
pip install -r requirements.txt
```

### 5. Instalar e Configurar Ollama

Veja https://ollama.ai/download para baixar e instalar Ollama.

```bash
# Linux/macOS
curl https://ollama.ai/install.sh | sh

# Windows
# Baixe o instalador .exe do site oficial e execute

# Baixar modelo recomendado
ollama pull mistral
```

### 6. Configurar Discord Webhook

- Crie um webhook no Discord (Configurações → Integrações → Webhooks)
- Copie a URL e adicione em `config.json`:

```json
"discord": {
  "enabled": true,
  "webhook_url": "https://discord.com/api/webhooks/SEU_WEBHOOK"
}
```

---

## Como Usar

### 1. Iniciar Ollama

```bash
ollama serve
```

### 2. Executar o CTI System

```bash
# Linux/macOS
source venv/bin/activate
python main.py

# Windows
venv\Scripts\activate
python main.py
```

- Para modo daemon (executa a cada 1h): `python main.py --daemon`
- Para testar alerta Discord: `python main.py --test`

### 3. Abrir o Dashboard

```bash
streamlit run dashboard.py
```
Acesse: http://localhost:8501

---

## Estrutura do Projeto

```
CTI/
├── main.py           # Pipeline principal
├── dashboard.py      # Dashboard web
├── src/cti/          # Módulos internos
├── data/             # Resultados e fontes
├── config.json       # Configuração
├── requirements.txt  # Dependências
└── ...
```

---

## Dicas e Suporte

- Veja logs em tempo real: `tail -f logs/cti.log`
- Erros comuns? Consulte a seção "Troubleshooting" no README completo.
- Para Windows, use sempre `venv\Scripts\activate` e `python` (não `python3`).

---

## Licença

MIT License — uso livre para fins pessoais e comerciais.

---

## Contato

Dúvidas ou sugestões?  
**Email:** cti@empresa.com  
**Site:** https://cti-platform.com

---

---

## Instalação

### 1️⃣ Instalar Python (se não tiver)
```bash
# Ubuntu/Debian
sudo apt-get install python3 python3-pip python3-venv -y

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Ou no Windows:
python -m venv venv
venv\Scripts\activate
```

### 2️⃣ Instalar Ollama

```bash
# Linux
curl https://ollama.ai/install.sh | sh

# Baixar modelo Mistral (recomendado - mais rápido)
ollama pull mistral

# OU baixar Llama3 (mais preciso)
ollama pull llama2

# Ou OpenHermes
ollama pull openhermes
```

### 3️⃣ Instalar Dependências do Projeto

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Instalar pacotes
pip install -r requirements.txt
```

### 4️⃣ Configurar Discord Webhook

```bash
# No Discord:
# 1. Abrir servidor
# 2. Configurações -> Integrações -> Webhooks
# 3. Criar novo webhook
# 4. Copiar URL

# Editar config.json:
nano config.json

# Ou no Windows:
notepad config.json
```

Adicionar webhook URL:
```json
"discord": {
    "enabled": true,
    "webhook_url": "https://discordapp.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
}
```

---

## Configuração

### Arquivo config.json

```json
{
  "ollama": {
    "enabled": true,
    "url": "http://localhost:11434",
    "model": "mistral",           // ou "llama2", "openhermes"
    "fallback_to_keywords": true, // Se Ollama falhar, usa regex
    "timeout": 60
  },
  "discord": {
    "enabled": true,
    "webhook_url": "SEU_WEBHOOK_AQUI"
  },
  "scheduler": {
    "interval_hours": 1,    // Executar a cada 1 hora
    "run_on_startup": true  // Rodar imediatamente ao iniciar
  },
  "alert_rules": {
    "alert_on_critical_severity": true,
    "alert_on_financial_sector": true,
    "alert_on_critical_infrastructure": true,
    "min_severity": "alta"
  }
}
```

### Adicionar Novas Fontes de Inteligência

Editar arquivo `data/sources.json`:

```json
[
  {
    "name": "Nova Fonte",
    "url": "https://exemplo.com/feed.xml",
    "type": "rss",
    "category": "apt"
  }
]
```

---

## Execução

### 1️⃣ Iniciar Ollama (em outro terminal)

```bash
ollama serve
```

### 2️⃣ Executar CTI System

#### Opção A: Execução única
```bash
# Ativa ambiente virtual
source venv/bin/activate

# Executa uma vez
python main.py
```

#### Opção B: Modo daemon (recomendado)
```bash
# Executa a cada 1 hora
python main.py --daemon
```

#### Opção C: Teste Discord
```bash
# Testa envio de alerta para Discord
python main.py --test
```

#### Opção D: Configuração customizada
```bash
python main.py --config config_producao.json --daemon
```

---

## Estrutura do Projeto

```
CTI/
├── main.py                 # Arquivo principal - orquestra tudo
├── dashboard.py            # Dashboard web interativo (Streamlit)
├── start_dashboard.sh      # Script para iniciar dashboard
├── collector.py            # Coleta de múltiplas fontes RSS
├── parser.py               # Processamento e normalização de conteúdo
├── ioc_extractor.py        # Extração de Indicadores de Comprometimento
├── intel_engine.py         # Análise com Ollama (LLM local)
├── notifier.py             # Envio de alertas para Discord
├── config.json             # Configuração do sistema
├── requirements.txt        # Dependências Python
├── data/
│   ├── sources.json        # Fontes de inteligência
│   └── results/            # JSON com ameaças analisadas
├── logs/
│   └── cti.log             # Arquivo de log
├── DASHBOARD_README.md     # Documentação completa do dashboard
├── README.md               # Esta documentação
├── GUIA_RAPIDO.md          # Guia de 5 minutos
├── TECNICO.md              # Documentação técnica detalhada
├── DISCORD_SETUP.md        # Como configurar Discord
├── SYSTEMD_SETUP.md        # Como rodar como serviço Linux
├── EXTENSOES.py            # Exemplos de extensões
├── START_HERE.txt          # Arquivo inicial
├── CHECKLIST.txt           # Checklist de verificação
└── setup.sh                # Script de instalação automatizada
```

---

## Fluxo de Execução

```
┌─────────────────────────────────────────────────────────┐
│ 1️⃣  COLETA                                               │
│ Buscar de múltiplas fontes RSS/blogs                     │
└──────────────────┬──────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────────────┐
│ 2️⃣  PROCESSAMENTO                                        │
│ Remover HTML, limpar texto, normalizar                  │
└──────────────────┬──────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────────────┐
│ 3️⃣  ANÁLISE COM LLM (Ollama)                             │
│ • Detectar APTs e malware                               │
│ • Identificar setores afetados                          │
│ • Extrair severidade                                    │
│ • Descrever como o ataque funciona                      │
│ • Mapear TTPs MITRE ATT&CK                              │
└──────────────────┬──────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────────────┐
│ 4️⃣  EXTRAÇÃO DE IOCs                                     │
│ • IPs, Domínios, URLs                                   │
│ • Emails, Hashes (MD5/SHA1/SHA256)                      │
│ • CVEs, Registry Keys                                   │
└──────────────────┬──────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────────────────────┐
│ 5️⃣  CLASSIFICAÇÃO                                        │
│ • Severidade? (crítica/alta/média/baixa)                │
│ • Relacionado a financeiro? (sim/não)                   │
│ • Infraestrutura crítica? (sim/não)                     │
└──────────────────┬──────────────────────────────────────┘
                   ↓
         ✅ DEVE ALERTA?
         ├─ Severidade crítica/alta?
         ├─ OU Setor financeiro?
         ├─ OU Infraestrutura crítica?
                   │
            ┌──────┴──────┐
            ↓ SIM         ↓ NÃO
        📤 DISCORD      💾 JSON
```

---

## Exemplo de Alerta Discord

```
🚨 NOVA AMEAÇA DETECTADA

🎯 Grupos APT: APT-28, Fancy Bear
🦠 Malware: TrickBot v2.5
🌍 Países Afetados: Brasil, EUA, Alemanha
🏢 Setores: Financeiro, Telecomunicações

🔴 Severidade: CRÍTICA

📄 Descrição Técnica:
Campanha de phishing direcionada a bancos brasileiros com foco em roubo de credenciais...

🔄 Fluxo de Ataque:
1. Envio de email com anexo malicioso
2. Execução de downloader
3. Instalação de backdoor
4. Exfiltração de credenciais

🛡️ TTPs MITRE ATT&CK:
• T1566.002 - Phishing: Spearphishing Attachment
• T1192 - Spearphishing
• T1036.003 - Masquerading: Rename System Utilities

📍 IPs: 192.168.1.100, 10.0.0.50, ...
🌐 Domínios: maliciodomain.com, phishing-bank.ru
🔗 SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

⚙️ CVEs: CVE-2024-1234, CVE-2024-5678

🔗 Fonte: [Bleeping Computer] https://bleepingcomputer.com/...

Enviado por CTI System 🔍 2024-03-26 15:30:00 UTC
```

---

## Monitoramento e Logs

### Ver logs em tempo real
```bash
tail -f logs/cti.log
```

### Ver últimas 50 linhas
```bash
tail -50 logs/cti.log
```

### Executar em background com nohup
```bash
nohup python main.py --daemon > nohup.out 2>&1 &
```

### Acompanhar com top
```bash
top -p $(pgrep -f "python main.py")
```

---

## Troubleshooting

### ❌ Erro: "ConnectionError: Ollama não está acessível"
```bash
# Verificar se Ollama está rodando
ollama serve

# Ou em outro terminal
curl http://localhost:11434/api/generate
```

### ❌ Erro: "Webhook URL não configurado"
```bash
# Editar config.json com webhook Discord
nano config.json
```

### ❌ LLM muito lento
```bash
# Aumentar RAM ou usar modelo mais leve
# Opção 1: Usar Mistral (mais rápido)
ollama pull mistral

# Opção 2: Aumentar timeout em config.json
"timeout": 120

# Opção 3: Usar modo fallback (regex)
"fallback_to_keywords": true
```

### ❌ Erro: "No module named 'requests'"
```bash
pip install -r requirements.txt
pip install requests feedparser beautifulsoup4
```

---

## Performance e Escalabilidade

### Otimizações
- ✅ Coleta paralelizada de múltiplas fontes
- ✅ Cache de IoCs já processados
- ✅ Limite de conteúdo (5000 caracteres) para LLM
- ✅ Modo fallback sem LLM se Ollama indisponível
- ✅ Batching de alertas Discord

### Recursos Recomendados
- **RAM**: 32GB (para Ollama + análise)
- **CPU**: 8 cores (processamento paralelo)
- **Disco**: 50GB (armazenamento de modelos + dados)
- **Rede**: 100Mbps+ (para coleta contínua)

---

## Melhorias Futuras 🚀

### Dashboard Web ✅ IMPLEMENTADO
```bash
# Dashboard interativo em Streamlit
# Visualização completa de ameaças coletadas
streamlit run dashboard.py

# Acesso: http://localhost:8501
```

**Funcionalidades do Dashboard:**
- 📊 **Métricas em tempo real** (total, críticas, setores afetados)
- 🔍 **Filtros avançados** por severidade, setor e período
- 📈 **Gráficos interativos** (distribuição por severidade, setores afetados)
- 📋 **Tabela de ameaças** com detalhes organizados
- 🎯 **Visualização detalhada** de IoCs, TTPs e informações técnicas
- 🔄 **Atualização automática** dos dados

### Integração com SIEM
```python
# Enviar alertas para Splunk, ELK, SumoLogic
POST /siem/alerts
```

### Análise Preditiva
```python
# ML para detectar padrões de ataques
modelo_ml.predict(threat_data)
```

### Inteligência Colaborativa
```python
# Compartilhar IoCs com comunidade CTI
push_to_otx()  # Open Threat Exchange
push_to_misp() # MISP Platform
```

### Bot Interativo Discord
```python
# Consultar ameaças via Discord
!verdict <malware_name>
!ioc <ip_address>
```

### Inteligência de Vulnerabilidades
```python
# Matchear nVulnerabilities com exploits ativos
match_nvd_cve()
```

---

## Contribuindo

### Como adicionar novas fontes
1. Editar `data/sources.json`
2. Adicionar URL do feed RSS
3. Categoria (apt, malware, general, infrastructure)

### Como estender análise LLM
1. Editar prompts em `intel_engine.py`
2. Adicionar novos campos de extração
3. Testar com `python main.py --test`

### Como adicionar novos IoCs
1. Editar padrões regex em `ioc_extractor.py`
2. Adicionar método `extract_novo_ioc()`
3. Chamar em `extract_all()`

---

## Licença

MIT License - Use livremente em projetos comerciais e pessoais

---

## Autores e Contato

**Empresa/Autores**: Mang3ky0


---

## FAQ

### P: Posso usar isso em produção?
**R**: Sim! O sistema foi projetado para produção com logs, error handling e armazenamento estruturado.

### P: Qual modelo Ollama recomenda?
**R**: **Mistral (7B)** - melhor balance entre velocidade e qualidade. Para mais precisão, use **Llama2 (13B)**.

### P: Como adicionar Discord em português?
**R**: Já está! Todos os prompts e mensagens suportam português.

### P: Preciso de APIs externas?
**R**: Não! Tudo é 100% local. Apenas feeds RSS públicos.

### P: Como escalar para múltiplos servidores?
**R**: Use message queue (RabbitMQ) + database (PostgreSQL) + load balancer.

---

## Suporte e Dúvidas

Abrir issue no GitHub: [CTI System Issues](https://github.com/project/issues)

---

**Última atualização**: 26 de Março de 2024
**Versão**: 1.0.0
