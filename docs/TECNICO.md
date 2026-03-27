"""
DOCUMENTAÇÃO TÉCNICA - CTI System
Referência de Architecture, APIs e Extensões
"""

# ============================================================================
# 1. ARQUITETURA DO SISTEMA
# ============================================================================

"""
┌─────────────────────────────────────────────────────────────────────────┐
│                     CTI SYSTEM ARCHITECTURE                             │
└─────────────────────────────────────────────────────────────────────────┘

CAMADAS:

┌─────────────────────────────────────────────────────────────────────────┐
│ INPUT LAYER                                                              │
│ - RSS Feeds (15+ fontes)                                                │
│ - Blogs de segurança                                                    │
│ - Twitter/X                                                              │
└─────────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ COLLECTION LAYER (collector.py)                                         │
│ Classe: ThreatCollector                                                  │
│ - collect_all()       → Coleta de todas as fontes                       │
│ - collect_from_rss()  → Coleta de um feed RSS                           │
│ - add_source()        → Adiciona nova fonte                             │
└─────────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ PROCESSING LAYER (parser.py)                                            │
│ Classe: ContentParser                                                    │
│ - parse_article()     → Processa um artigo                              │
│ - _remove_html()      → Remove tags HTML                                │
│ - _clean_text()       → Normaliza texto                                 │
│ - detect_severity()   → Detecta severidade                              │
│ - is_financial_related() → Verifica setor financeiro                    │
│ - is_critical_infrastructure() → Verifica infraestrutura crítica        │
└─────────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ IOC EXTRACTION LAYER (ioc_extractor.py)                                 │
│ Classe: IOCExtractor                                                     │
│ - extract_ipv4()      → IPv4 addresss                                   │
│ - extract_domains()   → Domínios                                        │
│ - extract_urls()      → URLs                                            │
│ - extract_emails()    → Emails                                          │
│ - extract_hashes()    → Hashes (MD5/SHA1/SHA256/SHA512)                │
│ - extract_cves()      → CVE Identifiers                                 │
│ - extract_files()     → Arquivo suspeitos                               │
│ - extract_all()       → Todos os IoCs                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ INTELLIGENCE LAYER (intel_engine.py)                                    │
│ Classe: IntelligenceEngine                                               │
│ - extract_threat_info()    → LLM Analysis (Ollama)                      │
│ - classify_threat()        → Classificação de ameaça                    │
│ - enrich_threat_data()     → Enriquecimento de dados                    │
│ - format_threat_for_discord() → Formata para Discord                    │
└─────────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ NOTIFICATION LAYER (notifier.py)                                        │
│ Classe: DiscordNotifier                                                  │
│ - send_alert()        → Envia alerta individual                         │
│ - send_batch()        → Envia múltiplos alertas                         │
│ - send_test_alert()   → Envia alerta de teste                           │
│ - _build_embed()      → Constrói embed Discord                          │
└─────────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ OUTPUT LAYER                                                             │
│ - Discord Webhooks                                                       │
│ - JSON Storage (data/results/)                                          │
│ - Logs (logs/cti.log)                                                   │
└─────────────────────────────────────────────────────────────────────────┘
"""

# ============================================================================
# 2. FLUXO DE DADOS
# ============================================================================

"""
Raw Article (HTML)
    ↓
[Parser] Remove HTML, normaliza
    ↓
Clean Text Article
    ↓
[IOC Extractor] Extrai IoCs
    ↓
Article + IoCs
    ↓
[Intel Engine] Analisa com LLM (Ollama)
    ↓
Article + IoCs + Threat Info
    ↓
[Classifier] Verifica: crítico? financeiro? infra?
    ↓
Enriched Threat Data
    ↓
if should_alert:
    [Discord Notifier] Envia webhook
else:
    [Storage] Salva em JSON
"""

# ============================================================================
# 3. ESTRUTURA DE DADOS
# ============================================================================

"""
ARTIGO BRUTO (do feed RSS):
{
    "title": "Ataque ransomware...",
    "link": "https://...",
    "summary": "<p>HTML aqui</p>",
    "published": "2024-03-26T...",
    "source": "Bleeping Computer",
    "source_name": "Bleeping Computer",
    "source_category": "general",
    "collected_at": "2024-03-26T15:30:00"
}

ARTIGO PROCESSADO:
{
    "original_title": "...",
    "title": "Limpo",
    "summary": "Texto limpo sem HTML",
    "full_text": "Conteúdo completo",
    "detected_severity": "alta",
    "is_financial_related": true,
    "is_critical_infrastructure": false,
    "parsed_at": "2024-03-26T..."
}

IoCs EXTRAÍDOS:
{
    "ipv4": ["192.168.1.100", "10.0.0.50"],
    "ipv6": ["::1"],
    "domains": ["malware.com", "phishing.ru"],
    "urls": ["http://malware.com/payload"],
    "emails": ["attacker@evil.com"],
    "hashes": {
        "md5": ["5d41402abc..."],
        "sha1": ["356a192b79..."],
        "sha256": ["e3b0c44298..."],
        "sha512": ["cf83e1357..."]
    },
    "files": ["malware.exe", "payload.dll"],
    "registry_keys": ["HKLM\\Software\\Malware"],
    "cves": ["CVE-2024-1234", "CVE-2024-5678"]
}

INFORMAÇÕES DE AMEAÇA (LLM):
{
    "apt_groups": ["APT-28", "Fancy Bear"],
    "malware_names": ["TrickBot", "IcedID"],
    "affected_countries": ["Brasil", "EUA", "Alemanha"],
    "affected_sectors": ["Financeiro", "Governo"],
    "severity": "crítica",
    "technical_description": "Ataque distribuído...",
    "attack_flow": "1. Phishing\n2. Malware\n3. Roubo",
    "ttps": ["T1566.002", "T1192", "T1059.001"],
    "key_findings": "Campanha coordenada..."
}

CLASSIFICAÇÃO:
{
    "is_high_severity": true,
    "is_financial_related": true,
    "is_critical_infrastructure": false,
    "should_alert": true
}

DADOS ENRIQUECIDOS (FINAL):
{
    "id": "20240326_015",
    "timestamp": "2024-03-26T15:30:00",
    "source": {
        "name": "Bleeping Computer",
        "link": "https://...",
        "title": "..."
    },
    "threat_info": { ... },
    "iocs": { ... },
    "classification": { ... },
    "analysis_quality": "high"
}
"""

# ============================================================================
# 4. APIs E MOD
ULOS
# ============================================================================

"""
COLLECTOR API:
- ThreatCollector(sources_file=None, timeout=10)
  .add_source(name, url, source_type, category) → None
  .remove_source(name) → bool
  .list_sources() → List[Dict]
  .save_sources_to_file(filepath) → None
  .load_sources_from_file(filepath) → None
  .collect_from_rss(feed_url) → List[Dict]
  .collect_all() → List[Dict]
  .collect_since(hours=24) → List[Dict]

PARSER API:
- ContentParser()
  .parse_article(article) → Dict
  .parse_batch(articles) → List[Dict]
  .detect_severity(content) → str ("crítica"|"alta"|"média"|"baixa")
  .is_financial_related(content) → bool
  .is_critical_infrastructure(content) → bool

IOC EXTRACTOR API:
- IOCExtractor()
  .extract_ipv4(text) → List[str]
  .extract_ipv6(text) → List[str]
  .extract_domains(text) → List[str]
  .extract_urls(text) → List[str]
  .extract_emails(text) → List[str]
  .extract_hashes(text) → Dict[str, List[str]]
  .extract_files(text) → List[str]
  .extract_registry_keys(text) → List[str]
  .extract_cves(text) → List[str]
  .extract_all(text) → Dict
  .format_iocs_for_report(iocs) → str

INTELLIGENCE ENGINE API:
- IntelligenceEngine(ollama_url="http://localhost:11434", model="mistral")
  .extract_threat_info(content) → Dict
  .classify_threat(threat_info) → Dict
  .enrich_threat_data(article, threat_info, iocs) → Dict
  .format_threat_for_discord(enriched_data) → str

DISCORD NOTIFIER API:
- DiscordNotifier(webhook_url=None)
  .set_webhook_url(webhook_url) → None
  .send_alert(enriched_data) → bool
  .send_batch(enriched_threats) → int
  .send_test_alert() → bool
  @staticmethod
  .format_webhook_url(token, channel_id) → str
"""

# ============================================================================
# 5. MODS E EXTENSÕES
# ============================================================================

"""
Como adicionar novo tipo de IoC:

1. Adicionar padrão regex em ioc_extractor.py:
   ├── NOVO_IOC_PATTERN = re.compile(r'...seu_padrão...')

2. Adicionar método:
   def extract_novo_ioc(self, text: str) -> List[str]:
       '''Extrai meu novo tipo de IoC'''
       results = list(set(self.NOVO_IOC_PATTERN.findall(text)))
       return results

3. Adicionar à função extract_all():
   iocs["novo_ioc"] = self.extract_novo_ioc(text)

4. Testar:
   python -c "from ioc_extractor import IOCExtractor; e = IOCExtractor(); print(e.extract_novo_ioc('seu_texto_aqui'))"


Como integrar com SIEM (Splunk/ELK):

1. Criar nova classe em notifier.py:
   class SIEMNotifier:
       def send_to_splunk(self, threat_data):
           # POST para http://splunk:8088/services/collector
           pass
       
       def send_to_elk(self, threat_data):
           # POST para http://elasticsearch:9200/threats/
           pass

2. Chamar em main.py:
   siem = SIEMNotifier(...)
   siem.send_to_splunk(enriched_threats)


Como usar modelo LLM customizado:

1. Baixar modelo em Ollama:
   ollama pull neural-chat

2. Editar config.json:
   "model": "neural-chat"

3. Ou código:
   engine = IntelligenceEngine(
       ollama_url="http://localhost:11434",
       model="neural-chat"
   )


Como adicionar nova fonte de dados:

1. Editar data/sources.json e adicionar:
   {
       "name": "Nova Fonte",
       "url": "https://...",
       "type": "rss",
       "category": "apt"
   }

OU via código:
   collector = ThreatCollector()
   collector.add_source("Nova", "https://...", "rss", "apt")
   collector.save_sources_to_file("data/sources.json")
"""

# ============================================================================
# 6. CONFIGURAÇÃO AVANÇADA
# ============================================================================

"""
config.json COMPLETO:

{
  "cti_system": {
    "name": "CTI Platform",
    "version": "1.0.0"
  },
  
  "ollama": {
    "enabled": true,
    "url": "http://localhost:11434",
    "model": "mistral",
    "fallback_to_keywords": true,  // Se LLM falhar
    "timeout": 60
  },
  
  "discord": {
    "enabled": true,
    "webhook_url": "https://discordapp.com/api/webhooks/...",
    "send_test_alert": false
  },
  
  "collector": {
    "timeout": 10,
    "max_retries": 3,
    "batch_size": 20,
    "sources_file": "data/sources.json"
  },
  
  "scheduler": {
    "interval_hours": 1,
    "run_on_startup": true
  },
  
  "logging": {
    "level": "INFO",  // ou DEBUG
    "log_file": "logs/cti.log",
    "max_size_mb": 100,
    "backup_count": 5
  },
  
  "storage": {
    "results_dir": "data/results",
    "format": "json"
  },
  
  "alert_rules": {
    "alert_on_critical_severity": true,
    "alert_on_financial_sector": true,
    "alert_on_critical_infrastructure": true,
    "min_severity": "alta"
  }
}

Variáveis de Ambiente:
- OLLAMA_URL: Override para URL do Ollama
- DISCORD_WEBHOOK: Override para webhook Discord
- CTI_LOG_LEVEL: Override para nível de log
"""

# ============================================================================
# 7. PERFORMANCE E OTIMIZAÇÃO
# ============================================================================

"""
BENCHMARKS (com Mistral):
- Coleta de 15 fontes: ~30 segundos
- Processamento de 50 artigos: ~15 segundos
- Análise LLM (1 artigo): ~10-30 segundos (depende tamanho)
- Extração de IoCs: ~5 segundos
- Envio Discord (webhook): ~1 segundo

OTIMIZAÇÕES APLICADAS:
1. Paralelização de coleta de fontes
2. Cache de IoCs extraídos
3. Limite de 5000 caracteres por artigo para LLM
4. Modelo Mistral (7B, rápido)
5. Batch processing de alertas
6. JSON output otimizado

COMO ACELERAR:
1. Reduzir intervalo de coleta (menos fontes)
2. Usar Mistral em vez de Llama2 (2x mais rápido)
3. Aumentar timeout em config.json se timeouts
4. Desabilitar coleta de URL (remove fetch completo)
5. Usar modo fallback (sem LLM)

COMO MELHORAR PRECISÃO:
1. Usar Llama2 em vez de Mistral
2. Fine-tuning do modelo com dados próprios
3. Adicionar mais fontes RSS
4. Ajustar prompts em intel_engine.py
5. Treinar modelo local específico para CTI
"""

# ============================================================================
# 8. TROUBLESHOOTING AVANÇADO
# ============================================================================

"""
PROBLEMA: "Modelo não encontrado no Ollama"
SOLUÇÃO:
  ollama list                    # Listar modelos
  ollama pull mistral            # Baixar modelo
  curl http://localhost:11434/api/tags  # Verificar via API

PROBLEMA: "LLM muito lento (>1min por artigo)"
SOLUÇÃO:
  1. Verificar RAM: free -h
  2. Usar modelo menor: ollama pull openhermes
  3. Ou desabilitar LLM: "fallback_to_keywords": true

PROBLEMA: "Discord webhook retorna 401"
SOLUÇÃO:
  1. Verificar URL webhook (copiar novamente)
  2. Verificar se webhook ainda é válido (não foi deletado)
  3. Testar com curl:
     curl -X POST -H 'Content-type: application/json' \
       --data '{\"text\":\"teste\"}' \
       YOUR_WEBHOOK_URL

PROBLEMA: "Muita memória sendo usada"
SOLUÇÃO:
  1. Ver uso: ps aux | grep ollama
  2. Reduzir tamanho modelo
  3. Limitar batch size em config.json

PROBLEMA: "RSS feed retorna vazio"
SOLUÇÃO:
  1. Testar feed: python -c "import feedparser; print(feedparser.parse('URL').entries[:3])"
  2. Verificar SSL: curl https://...
  3. Adicionar headers User-Agent
  4. Try alternate feed URL
"""

# ============================================================================
# 9. ROADMAP E FUTURO
# ============================================================================

"""
VERSÃO 1.1:
- Dashboard Streamlit
- Busca/query de ameaças
- Gráficos de tendências
- Export PDF

VERSÃO 1.2:
- Integração MISP
- Integração OTX (Open Threat Exchange)
- API REST própria

VERSÃO 1.3:
- ML para detecção de falsos positivos
- Correlação de IoCs
- Análise comportamental

VERSÃO 2.0:
- Web UI completo
- Multi-user support
- Banco de dados (PostgreSQL)
- Horizontal scaling
"""

print(__doc__)
