# 🔄 Deduplicação de Alertas Discord - Sistema Inteligente

## Como Funciona

O sistema agora **evita alertas duplicados no Discord** usando hash de IoCs (Indicators of Compromise).

### 🎯 Benefícios

- ✅ **Sem spam**: Mesma ameaça não é alertada 2x no Discord
- ✅ **Rastreamento**: Arquivo `data/.alert_cache.json` mantém histórico
- ✅ **Limpeza automática**: Entradas antigas removidas após 7 dias
- ✅ **Alertas novos**: Apenas novas ameaças com IoCs diferentes são enviadas

---

## 📊 Como É Identificada Uma Ameaça?

Combinação de:
- **IPs** (IPv4, IPv6)
- **Domínios**
- **URLs**
- **Hashes** (MD5, SHA256)
- **CVEs**

Se uma ameaça tem `IP=1.2.3.4 + SHA256=abc123...` e aparece novamente com o **mesmo conjunto**, é marcada como duplicata.

---

## 📈 Estatísticas

A cada execução do daemon, você vê:

```
✅ Pipeline completado com sucesso em 45.23s
   📊 Artigos processados: 150
   🚨 Ameaças analisadas: 23
   📤 Alertas enviados: 3
   💾 Ameaças no cache: 47
```

- **Alertas enviados**: Apenas ameaças NOVAS
- **Ameaças no cache**: Total rastreado (últimos 7 dias)

---

## 📁 Arquivo Cache

```
data/.alert_cache.json
```

Estrutura:
```json
{
  "iocs": {
    "a1b2c3d4e5f6g7h8i9j0...": "2026-03-27T15:30:00",
    "z9y8x7w6v5u4t3s2r1q0...": "2026-03-27T14:20:00"
  },
  "last_updated": "2026-03-27T15:49:48"
}
```

- Chave = hash SHA256 dos IoCs
- Valor = timestamp do alerta

---

## ⚙️ Configuração

Editar `main.py`, função `__init__`:

```python
self.deduplicator = ThreatDeduplicator(
    cache_file="data/.alert_cache.json",  # Arquivo cache
    retention_days=7  # Manter histórico 7 dias
)
```

Mudar `retention_days` para:
- `1` = Limpar cache diário (alertar duplicatas após 1 dia)
- `30` = Manter 1 mês de histórico

---

## 🚀 Uso

**Daemon ao vivo (com deduplicação):**
```bash
python main.py --daemon
```

**Dashboard + Daemon:**
```bash
./run_daemon_and_dashboard.sh 8502
```

A deduplicação roda **automaticamente** em background!

---

## 🔍 Debug

Ver logs completos:
```bash
tail -f logs/cti.log | grep -E "(Duplicata|alerta|cache)"
```

Ver cache atual:
```bash
cat data/.alert_cache.json | jq '.iocs | length'
```

Limpar cache manualmente:
```bash
rm data/.alert_cache.json
```

---

## 💡 Exemplo Real

**Hora 1:**
- CPR detecta IP `192.168.1.1` + malware `TrickBot`
- ✅ Alerta enviado para Discord
- Cache: `{hash1: "2026-03-27T12:00"}`

**Hora 2 (1 depois):**
- CPR detecta **novamente** IP `192.168.1.1` + `TrickBot` (mesma ameaça)
- ⊘ Duplicata detectada
- ❌ Alerta NÃO é enviado (economiza spam Discord)

**Hora 3 (2 depois):**
- CPR detecta IP `10.0.0.1` + malware `Zeus` (ameaça **nova**)
- ✅ Alerta enviado para Discord
- Cache: `{hash1: "2026-03-27T12:00", hash2: "2026-03-27T14:00"}`

---

## ✨ Resultado Final

Seu Discord recebe:
- ✅ Toda ameaça **nova** (nunca vista)
- ❌ Sem duplicatas de ameaças anteriores
- 📊 Mantém histórico 7 dias
- 🧹 Limpeza automática