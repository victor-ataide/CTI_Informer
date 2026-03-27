# 📱 Guia de Configuração Discord - CTI System

## Como Criar Webhook Discord

### 1. Criar Servidor Discord
- Abra https://discord.com
- Clique em "+"
- "Criar Servidor"
- Dê um nome: "CTI Alerts" (exemplo)

### 2. Criar Canal
- No servidor, clique em "+"
- Crie canal: **#alertas-cti** (ou nome de sua preferência)

### 3. Criar Webhook
- Clique no ícone ⚙️ do canal
- Vá em "Integrações"
- Procure "Webhooks"
- Clique "Novo Webhook"
- Clique em "Copiar URL do Webhook"

**URL aparecerá assim:**
```
https://discordapp.com/api/webhooks/1081234567890123456/abcDEF_ghi-JKL_mNoPQRstUvWxYZ
```

### 4. Salvar em config.json
```json
{
  "discord": {
    "enabled": true,
    "webhook_url": "https://discordapp.com/api/webhooks/SEU_ID/SEU_TOKEN"
  }
}
```

---

## Testando Webhook

### Teste Manual com curl
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"🚨 Teste do CTI System"}' \
  https://discordapp.com/api/webhooks/SEU_ID/SEU_TOKEN
```

### Teste Python
```python
import requests
webhook_url = "https://discordapp.com/api/webhooks/SEU_ID/SEU_TOKEN"
payload = {"text": "✅ Teste de webhook Python"}
requests.post(webhook_url, json=payload)
```

### Teste via CTI System
```bash
python main.py --test
```

Se receber alerta no Discord: **✅ Webhook funcionando!**

---

## Estrutura de Alertas Discord

### Componentes

```
┌──────────────────────────────────────────────────────────┐
│  🚨 NOVA AMEAÇA DETECTADA                                │
│                                                          │
│  🎯 Grupos APT: APT-28, Fancy Bear                       │
│  🦠 Malware: TrickBot v2.5                               │
│  🌍 Países: Brasil, EUA, Alemanha                        │
│  🏢 Setores: Financeiro, Governo                         │
│                                                          │
│  🔴 Severidade: CRÍTICA                                  │
│                                                          │
│  📄 Descrição: Campanha de phishing...                   │
│  🔄 Fluxo: 1. Email... 2. Anexo... 3. Roubo...          │
│                                                          │
│  🛡️ TTPs: T1566, T1192, T1059                           │
│  📍 IPs: 192.168.1.100, 10.0.0.50                       │
│  🌐 Domínios: malware.com, phishing.ru                   │
│  📌 Hashes: e3b0c44298fc...                              │
│  ⚙️ CVEs: CVE-2024-1234, CVE-2024-5678                  │
│                                                          │
│  🔗 [Fonte] https://bleepingcomputer.com/...             │
│                                                          │
│  CTI System | 2024-03-26 15:30:00 UTC                   │
└──────────────────────────────────────────────────────────┘
```

### Cores por Severidade
- 🔴 **Crítica**: Vermelho (#FF0000)
- 🟠 **Alta**: Laranja (#FFA500)
- 🟡 **Média**: Amarelo (#FFFF00)
- 🟢 **Baixa**: Verde (#00FF00)

---

## Permissões Necessárias para Bot/Webhook

No Discord, webhook precisa:
- ✅ Enviar mensagens
- ✅ Mencionar @roles (opcional)
- ✅ Usar emojis
- ✅ Incorporar links

**Não precisa:**
- ❌ Deletar mensagens
- ❌ Gerenciar canais
- ❌ Kickar membros

---

## Configuração Avançada

### Diferentes Canais por Severidade

Editar `notifier.py` e adicionar:

```python
def send_alert_to_severity_channel(self, enriched_data: Dict) -> bool:
    """Envia para canal específico baseado em severidade"""
    severity = enriched_data["threat_info"]["severity"]
    
    channels = {
        "crítica": "https://discord.com/.../webhook_critica",
        "alta": "https://discord.com/.../webhook_alta",
        "média": "https://discord.com/.../webhook_media"
    }
    
    webhook = channels.get(severity, self.webhook_url)
    
    # Enviar para canal específico
    payload = {"embeds": [self._build_embed(enriched_data)]}
    return requests.post(webhook, json=payload).status_code == 204
```

### Menção de Roles

Adicione em `config.json`:

```json
"discord": {
    "enable_mentions": true,
    "mention_on_critical": "@SOC-Team",
    "mention_on_financial": "@Finance-Security",
    "mention_on_infrastructure": "@Infrastructure-Team"
}
```

Editar `notifier.py`:

```python
def add_mentions(self, enriched_data: Dict) -> str:
    """Adiciona menções apropriadas"""
    mentions = []
    if enriched_data["threat_info"]["severity"] == "crítica":
        mentions.append("<@&ROLE_ID>")  # Role ID do SOC
    return " ".join(mentions)
```

### Threads Discord

Dividir alertas em threads:

```python
def send_as_thread(self, enriched_data: Dict) -> bool:
    """Envia alerta em thread"""
    # Mensagem inicial
    main_msg = requests.post(self.webhook_url, json={
        "content": f"🚨 Nova ameaça: {enriched_data['source']['title'][:100]}"
    })
    
    # Enviar detalhes em respostas
    # (Requer token do bot, não apenas webhook)
```

---

## Troubleshooting Discord

### Problema: "Webhook retorna 401 Unauthorized"
**Solução:**
1. Copiar webhook URL novamente
2. Verificar se não tem caracteres extras
3. Deletar e criar novo webhook
4. Testar com curl antes

### Problema: "Messagem vazia no Discord"
**Solução:**
1. Verificar se `content` ou `embeds` têm dados
2. Validar JSON com: `python -m json.tool`
3. Checar limite de caracteres (2000 chars por embed)

### Problema: "Webhook trabalho mas sem emojis"
**Solução:**
1. Discord suporta emojis Unicode ✅
2. Não suporta emojis customizados do servidor
3. Use apenas Unicode padrão

### Problema: "Rate limit - muitas mensagens"
**Solução:**
1. Discord limita 10 requisições/segundo por webhook
2. Implementar fila (não enviar muitos simultaneamente)
3. Adicionar delay: `time.sleep(1)` entre alertas
4. Usar batch processing (já implementado em `notifier.py`)

### Problema: "Webhook URL não funciona"
**Solução:**
```bash
# Testar endpoint
curl -i https://discordapp.com/api/webhooks/SEU_ID/SEU_TOKEN

# Deve retornar 200 OK
```

---

## Exemplos de Payload Discord

### Embed Simples
```json
{
  "embeds": [
    {
      "title": "🚨 Ameaça Detectada",
      "description": "APT-28 ataques financeiro",
      "color": 16711680,
      "fields": [
        {
          "name": "Severidade",
          "value": "🔴 CRÍTICA",
          "inline": true
        }
      ]
    }
  ]
}
```

### Mencionar Usuário
```json
{
  "content": "<@123456789>",
  "embeds": [...]
}
```

### Mencionar Role
```json
{
  "content": "<@&987654321>",
  "embeds": [...]
}
```

---

## Monitorar Webhooks

### Ver Logs Discord
- Servidor → Auditoria → Filtrar "Integração"
- Verá tentativas de envio

### Metrics
```bash
# Contar alertas enviados
grep "Alerta enviado" logs/cti.log | wc -l

# Ver erros Discord
grep "Discord\|webhook" logs/cti.log | grep ERROR
```

---

## Manutenção Webhook

### Quando Mudar Webhook
- Depois de 1 ano (boa prática)
- Se suspeitar de vazamento
- Se quer novo canal

### Como Revogar Webhook
- Servidor → Integrações → Webhooks
- Clicar no webhook
- "Deletar"
- Qualquer POST retornará 404

### Backup Webhook
```bash
# Salvar em variável de ambiente
export CTI_WEBHOOK_URL="https://..."
```

---

## Integração com Múltiplos Servidores

```python
notifiers = {
    "soc_team": DiscordNotifier("webhook_soc"),
    "finance": DiscordNotifier("webhook_finance"),
    "ciso": DiscordNotifier("webhook_ciso")
}

# Por severidade
if severity == "crítica":
    notifiers["soc_team"].send_alert(data)
    notifiers["ciso"].send_alert(data)
elif is_financial:
    notifiers["finance"].send_alert(data)
```

---

## Suporte Discord

- **Documentação Oficial**: https://discord.com/developers/docs/resources/webhook
- **Status Page**: https://status.discord.com
- **Discord Server Suporte**: https://discord.gg/discord-developers

---

**Última atualização**: Março 2024
