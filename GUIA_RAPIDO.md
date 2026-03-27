# 🚀 GUIA RÁPIDO - CTI System

**Cyber Threat Intelligence Platform com Ollama + Discord**

---

## ⚡ INSTALAÇÃO RÁPIDA (5 minutos)

### 1. Instalar Ollama
```bash
curl https://ollama.ai/install.sh | sh
ollama pull mistral
```

### 2. Clonar e instalar projeto
```bash
cd ~/Desktop/CTI
bash setup.sh

# OU manual:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configurar Discord
```bash
# No Discord: Servidor -> Integrações -> Webhooks -> Criar
# Copiar a URL do webhook

nano config.json
# Adicionar: "webhook_url": "SEU_LINK_AQUI"
```

---

## 🎯 EXECUTAR

### Terminal 1: Iniciar Ollama
```bash
ollama serve
```

### Terminal 2: Rodar CTI
```bash
cd ~/Desktop/CTI
source venv/bin/activate

# Uma única vez:
python main.py

# OU contínuo (a cada 1 hora):
python main.py --daemon

# OU teste Discord:
python main.py --test
```

### 🎨 Dashboard Web (Visualização)
```bash
# Abrir dashboard interativo no navegador
streamlit run dashboard.py

# OU usar o script automático:
./start_dashboard.sh

# Acesso: http://localhost:8501
```

---

## 📊 Oque acontece?

```
1️⃣  Coleta: Busca notícias de ~15 fontes RSS de segurança
2️⃣  Análise: LLM identifica APTs, malware, setores afetados
3️⃣  IoCs: Extrai IPs, domínios, URLs, emails, hashes, CVEs
4️⃣  Classificação: Severidade + setor financeiro/infraestrutura?
5️⃣  Discord: Se crítico/financeiro/infra → Alerta no Discord!
6️⃣  JSON: Salva tudo em data/results/
```

---

## 📝 Logs

```bash
# Ver em tempo real:
tail -f logs/cti.log

# Últimas 50 linhas:
tail -50 logs/cti.log

# Todas as linhas ("ERROR"):
grep ERROR logs/cti.log
```

---

## 🔧 Editar Config

```bash
nano config.json
```

### Mudar intervalo de 1 hora para 30 minutos:
```json
"scheduler": {
    "interval_hours": 0.5,  // ← Mude aqui
    "run_on_startup": true
}
```

### Desabilitar Discord (testar sem enviar):
```json
"discord": {
    "enabled": false  // ← Mude aqui
}
```

### Usar Llama2 em vez de Mistral:
```json
"ollama": {
    "model": "llama2"  // ← Mude aqui
    // E execute: ollama pull llama2
}
```

---

## ❌ Problemas?

### "ConnectionError: Ollama não está acessível"
- ✅ Abra outro terminal e execute: `ollama serve`
- ✅ Aguarde aparecer: "Listening on..."

### "Webhook URL não configurado"
- ✅ Edite `config.json`
- ✅ Adicione webhook do Discord

### "Modelo Mistral não encontrado"
- ✅ Execute: `ollama pull mistral`
- ✅ Tente modelo mais leve: `ollama pull openhermes`

### Script muito lento
- ✅ Aumentar RAM: `"timeout": 120` em config.json
- ✅ Ou usar modelo leve: `ollama pull openhermes` (2.7GB)
- ✅ Ou modo fallback sem LLM: `"fallback_to_keywords": true`

---

## 📌 Estrutura de Arquivos

```
CTI/
├── main.py              ← Execute isto
├── dashboard.py         ← Dashboard web (streamlit)
├── collector.py         ← Coleta RSS
├── parser.py            ← Processa HTML
├── ioc_extractor.py     ← Extrai IPs, domínios, etc
├── intel_engine.py      ← LLM (Ollama)
├── notifier.py          ← Alerta Discord
├── config.json          ← Configurações
├── requirements.txt     ← Dependências
├── setup.sh             ← Script instalação
├── README.md            ← Documentação completa
├── data/
│   ├── sources.json     ← Fontes RSS
│   └── results/         ← Alertas em JSON
└── logs/
    └── cti.log          ← Log do sistema
```

---

## 🎮 Exemplos de Uso

### Apenas teste de alerta:
```bash
python main.py --test
```

### Rodar uma coleta e parar:
```bash
python main.py
```

### Rodar continuamente por 24 horas:
```bash
# Terminal:
python main.py --daemon

# Ctrl+C para parar
```

### Com config customizada:
```bash
python main.py --config config_producao.json --daemon
```

### Ver tudo acontecendo:
```bash
# Terminal 1:
tail -f logs/cti.log

# Terminal 2:
ollama serve

# Terminal 3:
python main.py --daemon

# Terminal 4 (opcional):
./start_dashboard.sh
```

---

## 💡 Dicas

### Mais detalhes nos logs:
```bash
# Config.json
"logging": {
    "level": "DEBUG"  # ← Mude INFO para DEBUG
}
```

### Adicionar nova fonte de inteligência:
```bash
nano data/sources.json
# Adicionar JSON com: name, url, type, category
```

### Rodar sem Discord (modo teste):
```json
"discord": {
    "enabled": false
}
```

### Aumentar análise (mais preciso):
```bash
ollama pull llama2  # 7GB - mais lento mas mais preciso
# Depois em config.json:
"model": "llama2"
```

---

## 📞 Dúvidas?

**Problema**: Sistema muito lento?
- Solução: Use `mistral` (padrão, mais rápido) ou modo fallback

**Problema**: Ollama consome muita RAM?
- Solução: Desabilitar Ollama e usar apenas regex/regex

**Problema**: Discord não recebe alertas?
- Solução: Execute `python main.py --test` para testar webhook

**Problema**: Quer rodar 24/7
- Solução: Usar `systemd` (veja abaixo)

---

## 🔄 Rodar como Serviço Linux (systemd)

### 1. Criar arquivo de serviço:
```bash
sudo nano /etc/systemd/system/cti-system.service
```

### 2. Adicionar conteúdo:
```ini
[Unit]
Description=CTI System - Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/Desktop/CTI
ExecStart=/home/ubuntu/Desktop/CTI/venv/bin/python /home/ubuntu/Desktop/CTI/main.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 3. Ativar:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cti-system
sudo systemctl start cti-system

# Ver status:
sudo systemctl status cti-system

# Ver logs:
sudo journalctl -u cti-system -f
```

---

**Última atualização**: Março 2024
**Versão**: 1.0.0
