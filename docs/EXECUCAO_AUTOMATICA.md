# 🚀 CTI System - Guias de Execução Automática

Três formas fáceis de rodar o dashboard + daemon automaticamente:

## Opção 1: Script Rápido (Recomendado para desenvolvimento)

### Uso Imediato
```bash
chmod +x start_cti.sh
./start_cti.sh
```

### Com porta customizada
```bash
./start_cti.sh 8503
```

**Características:**
- ✅ Inicia daemon + dashboard
- ✅ Monitora ambos os processos
- ✅ Auto-restart se um cair
- ✅ Logs em tempo real no terminal
- ✅ Fácil parar com Ctrl+C

**Output esperado:**
```
╔════════════════════════════════════════════════════════════╗
║  🚨 CTI System - Iniciador Automático                     ║
╚════════════════════════════════════════════════════════════╝

✅ Ambiente virtual encontrado
✅ Arquivos de configuração OK
✅ Ambiente virtual ativado
✅ Dependências verificadas
✅ Diretório de logs criado/verificado

ℹ️  Iniciando Process Manager com porta 8502...

============================================================
🎯 CTI Process Manager - Iniciando...
============================================================
🚀 Iniciando CTI daemon...
✅ CTI daemon iniciado com sucesso (PID: 12345)
📊 Iniciando dashboard Streamlit na porta 8502...
✅ Dashboard iniciado com sucesso (PID: 12346)

============================================================
✅ Todos os processos iniciados com sucesso!
============================================================

📊 Dashboard: http://localhost:8502
💾 Daemon: Executando a cada 1 hora
📧 Discord: Recebendo alertas deduplicated

Pressione Ctrl+C para parar todos os processos
============================================================
```

---

## Opção 2: Em Background (Para usar o terminal)

Rodar em uma aba de terminal separada ou em background:

```bash
# Em background
./start_cti.sh 8502 &

# Salvar PID para controlar depois
./start_cti.sh 8502 > cti.log 2>&1 &
echo $! > cti.pid

# Para parar depois
kill $(cat cti.pid)
```

**Monitore os logs:**
```bash
# Tempo real
tail -f logs/process_manager.log

# Últimas linhas
tail logs/process_manager.log
```

---

## Opção 3: Serviço do Sistema (Para produção/auto-boot)

Rodar automaticamente no boot da máquina:

### Setup (primeira vez)

```bash
# Copiar serviço para systemd
sudo cp cti-system.service /etc/systemd/system/

# Recarregar systemd
sudo systemctl daemon-reload

# Habilitar para iniciar no boot
sudo systemctl enable cti-system

# Iniciar o serviço
sudo systemctl start cti-system
```

### Comandos Úteis

```bash
# Ver status
sudo systemctl status cti-system

# Ver logs em tempo real
sudo journalctl -u cti-system -f

# Últimas 50 linhas
sudo journalctl -u cti-system -n 50

# Parar
sudo systemctl stop cti-system

# Reiniciar
sudo systemctl restart cti-system

# Desabilitar auto-boot
sudo systemctl disable cti-system

# Ver se está rodando
sudo systemctl is-active cti-system
```

**Logs do serviço:** `/var/log/syslog` ou `journalctl`

---

## Opção 4: Docker (Opcional - Futuro)

Se precisar isolar em container:

```dockerfile
FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "process_manager.py", "--port", "8502"]
```

---

## O que cada processo faz?

### 🚀 CTI Daemon (main.py --daemon)
- Roda continuamente em background
- A cada 1 hora: coleta ameaças de feeds
- Envia alertas ao Discord (deduplicated)
- Salva resultados em `data/results/`
- Mantém cache em `data/.alert_cache.json`

### 📊 Dashboard (streamlit)
- Interface web em http://localhost:PORT
- Auto-refresh a cada 60 segundos
- Mostra ameaças, IoCs, gráficos
- Atualiza em tempo real com dados do daemon
- Abas organizadas: Descrição, IoCs, TTPs, Links

### 🎛️ Process Manager (process_manager.py)
- Monitora ambos os processos
- Auto-restart se um cair
- Logs centralizados
- Tratamento de sinais (Ctrl+C)

---

## Troubleshooting

### Porta já está em uso
```bash
# Ver qual processo está usando a porta 8502
lsof -i :8502

# Usar porta diferente
./start_cti.sh 8503
```

### Daemon não está alertando
```bash
# Verificar logs
tail -f logs/process_manager.log
tail -f logs/cti_daemon.log

# Verificar cache de deduplicated
cat data/.alert_cache.json | jq '.'

# Testar manualmente
python main.py --test
```

### Dashboard não aparece
```bash
# Verificar se streamlit está rodando
ps aux | grep streamlit

# Verificar logs do dashboard
tail -f logs/process_manager.log | grep dashboard
```

### Limpar cache (resetar deduplicated)
```bash
rm data/.alert_cache.json
# Daemon vai criar novo na próxima execução
```

---

## Recomendações

| Cenário | Opção |
|---------|-------|
| Desenvolvimento local | **Opção 1** (`./start_cti.sh`) |
| Testes em produção | **Opção 2** (background) |
| Servidor 24/7 | **Opção 3** (systemd) |
| Cloud/Kubernetes | **Opção 4** (Docker) |

---

## Checklist de Inicialização

- [ ] Ambiente virtual criado: `python3 -m venv venv`
- [ ] Dependências instaladas: `pip install -r requirements.txt`
- [ ] `config.json` configurado com Discord webhook
- [ ] `logs/` diretório existe
- [ ] `data/` diretório existe
- [ ] `process_manager.py` existe
- [ ] `start_cti.sh` tem permissão de execução: `chmod +x start_cti.sh`

Depois é só executar:
```bash
./start_cti.sh
```

E acessar: **http://localhost:8502** 🎉

---

**Versão:** 1.0  
**Data:** 2026-03-27  
**Mantém:** Dashboard + Daemon + Discord sincronizados automaticamente
