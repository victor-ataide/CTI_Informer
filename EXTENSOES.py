"""
EXEMPLOS DE EXTENSÃO - Como Estender o CTI System
Adicionar novas funcionalidades, integrações e fontes
"""

# ============================================================================
# 1. ADICIONAR NOVO TIPO DE IOC (Exemplo: Mutexes)
# ============================================================================

"""
Arquivo: ioc_extractor.py

Adição 1: Novo padrão regex
"""

# Adicionar a classe IOCExtractor:
MUTEX_PATTERN = re.compile(
    r'(?:(?:Local|Global)\\)?[a-zA-Z0-9_\-\.]{1,255}(?:\{[A-F0-9\-]+\})?',
    re.IGNORECASE
)

def extract_mutexes(self, text: str) -> List[str]:
    """Extrai nomes de mutex do texto."""
    mutexes = set(self.MUTEX_PATTERN.findall(text))
    return list(mutexes)

# Adicionar em extract_all():
iocs["mutexes"] = self.extract_mutexes(text)
# Retorno:
# {
#     "mutexes": ["Global\\{12345678-1234-1234-1234-123456789012}"]
# }


# ============================================================================
# 2. INTEGRAÇÃO COM THREAT INTELLIGENCE EXTERNO (OTX)
# ============================================================================

"""
Arquivo novo: intel_external.py
Integração com Open Threat Exchange (OTX)
"""

import requests
from typing import Dict, List

class OTXIntelligence:
    """
    Integração com AlienVault OTX (Open Threat Exchange).
    API pública, não requer API key para leitura.
    """
    
    def __init__(self):
        self.otx_api = "https://otx.alienvault.com/api/v1"
    
    def lookup_ip(self, ip: str) -> Dict:
        """Lookup IP em OTX"""
        try:
            resp = requests.get(
                f"{self.otx_api}/indicators/IPv4/{ip}",
                timeout=5
            )
            return resp.json()
        except:
            return {}
    
    def lookup_domain(self, domain: str) -> Dict:
        """Lookup domínio em OTX"""
        try:
            resp = requests.get(
                f"{self.otx_api}/indicators/domain/{domain}",
                timeout=5
            )
            return resp.json()
        except:
            return {}
    
    def lookup_hash(self, hash_value: str) -> Dict:
        """Lookup hash em OTX"""
        try:
            resp = requests.get(
                f"{self.otx_api}/indicators/file/{hash_value}",
                timeout=5
            )
            return resp.json()
        except:
            return {}

# Uso em intel_engine.py:
from intel_external import OTXIntelligence

class IntelligenceEngine:
    def __init__(self, ...):
        ...
        self.otx = OTXIntelligence()
    
    def enrich_with_external_intel(self, iocs: Dict) -> Dict:
        """Enriquecer com intel externa"""
        enriched = iocs.copy()
        
        for ip in iocs.get("ipv4", [])[:3]:  # Limitar 3 lookups
            otx_data = self.otx.lookup_ip(ip)
            if otx_data.get("pulse_info"):
                enriched[f"otx_{ip}"] = otx_data
        
        return enriched


# ============================================================================
# 3. NOVO COLLECTOR PARA TWITTER/X (TWINT)
# ============================================================================

"""
Arquivo novo: collector_twitter.py
Coletar ameaças de posts no Twitter/X
"""

import tweepy
from datetime import datetime, timedelta
from typing import List, Dict

class TwitterCollector:
    """Coleta tweets sobre ameaças cibernéticas"""
    
    def __init__(self, api_key: str = None, api_secret: str = None):
        self.key = api_key
        self.secret = api_secret
        # Usar credentials se disponíveis
        if api_key and api_secret:
            self.client = tweepy.Client(bearer_token=api_key)
        else:
            self.client = None
    
    def search_threats(self, keywords: List[str], hours: int = 24) -> List[Dict]:
        """Busca tweets sobre ameaças"""
        if not self.client:
            return []
        
        tweets = []
        query = " OR ".join(keywords)
        query += " -is:retweet lang:en"
        
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        try:
            results = self.client.search_recent_tweets(
                query=query,
                max_results=100,
                start_time=start_time,
                tweet_fields=['created_at', 'author_id'],
                expansions=['author_id']
            )
            
            for tweet in results.data:
                tweets.append({
                    "title": tweet.text,
                    "source": "Twitter",
                    "link": f"https://twitter.com/i/web/status/{tweet.id}",
                    "published": tweet.created_at.isoformat(),
                    "collected_at": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logging.error(f"Erro ao coletar tweets: {e}")
        
        return tweets

# Uso em main.py:
twitter_collector = TwitterCollector(api_key="sua_api_key")
twitter_tweets = twitter_collector.search_threats([
    "ransomware", "APT", "malware", "breach", "exploit"
])
articles.extend(twitter_tweets)


# ============================================================================
# 4. DASHBOARD STREAMLIT
# ============================================================================

"""
Arquivo novo: dashboard.py
Dashboard web para visualizar ameaças
Instalar: pip install streamlit

Rodar: streamlit run dashboard.py
"""

import streamlit as st
import json
import pandas as pd
from datetime import datetime
import os

st.set_page_config(page_title="CTI Dashboard", layout="wide")
st.title("🚨 CTI System Dashboard")

# Sidebar
st.sidebar.title("Filtros")
severity_filter = st.sidebar.multiselect(
    "Severidade",
    ["crítica", "alta", "média", "baixa"],
    default=["crítica", "alta"]
)

# Carregar dados
results_dir = "data/results"
files = sorted([f for f in os.listdir(results_dir) if f.endswith(".json")])

if not files:
    st.warning("Nenhuma ameaça coletada ainda.")
else:
    # Carregar último arquivo
    latest_file = files[-1]
    with open(os.path.join(results_dir, latest_file)) as f:
        threats = json.load(f)
    
    # Filtrar
    filtered = [t for t in threats 
               if t["threat_info"]["severity"] in severity_filter]
    
    # Métricas
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total de Ameaças", len(threats))
    col2.metric("Críticas", len([t for t in threats if t["threat_info"]["severity"] == "crítica"]))
    col3.metric("Setores Financeiros", len([t for t in threats if t["classification"]["is_financial_related"]]))
    col4.metric("Infraestrutura Crítica", len([t for t in threats if t["classification"]["is_critical_infrastructure"]]))
    
    # Tabela
    st.subheader("Ameaças Recentes")
    df_data = []
    for t in filtered:
        df_data.append({
            "Timestamp": t["timestamp"],
            "Fonte": t["source"]["name"],
            "Severidade": t["threat_info"]["severity"],
            "APTs": ", ".join(t["threat_info"].get("apt_groups", [])[:2]),
            "Setores": ", ".join(t["threat_info"].get("affected_sectors", []))
        })
    
    if df_data:
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True)
    
    # Detalhes
    st.subheader("Detalhes da Ameaça")
    threat_idx = st.selectbox("Selecione ameaça", range(len(filtered)))
    
    if threat_idx < len(filtered):
        threat = filtered[threat_idx]
        
        with st.expander("Informações Técnicas", expanded=True):
            col1, col2 = st.columns(2)
            col1.write(f"**Descrição:** {threat['threat_info']['technical_description'][:200]}...")
            col2.write(f"**Fluxo de Ataque:** {threat['threat_info']['attack_flow'][:200]}...")
        
        with st.expander("IoCs"):
            st.write(f"**IPs:** {', '.join(threat['iocs']['ipv4'][:3])}")
            st.write(f"**Domínios:** {', '.join(threat['iocs']['domains'][:3])}")
            st.write(f"**Hashes:** {', '.join(threat['iocs']['hashes']['sha256'][:3])}")
        
        with st.expander("TTPs"):
            st.write(", ".join(threat['threat_info']['ttps']))


# ============================================================================
# 5. INTEGRAÇÃO SIEM (SPLUNK)
# ============================================================================

"""
Arquivo novo: siem_splunk.py
Enviar alertas para Splunk
"""

import requests
from typing import Dict

class SplunkNotifier:
    """Enviar eventos para Splunk HEC"""
    
    def __init__(self, hec_url: str, hec_token: str):
        self.hec_url = hec_url
        self.hec_token = hec_token
    
    def send_event(self, event_data: Dict) -> bool:
        """Enviar evento para Splunk"""
        try:
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "event": event_data,
                "sourcetype": "cti_threat",
                "source": "cti_system"
            }
            
            response = requests.post(
                f"{self.hec_url}/services/collector",
                json=payload,
                headers=headers,
                timeout=10
            )
            
            return response.status_code == 200
        
        except Exception as e:
            logging.error(f"Erro ao enviar para Splunk: {e}")
            return False

# Uso em main.py:
splunk = SplunkNotifier(
    hec_url="https://splunk.empresa.com:8088",
    hec_token="your_hec_token"
)
splunk.send_event(enriched_threat)


# ============================================================================
# 6. ANÁLISE PREDITIVA COM SKLEARN
# ============================================================================

"""
Arquivo novo: predictor.py
Prever qual ameaça provavelmente afetará sua empresa
"""

import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from typing import Dict

class ThreatPredictor:
    """ML para prever alvos de ataques"""
    
    def __init__(self, model_path: str = "model.pkl"):
        self.model = None
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
        except:
            self.model = None
    
    def extract_features(self, threat: Dict) -> np.ndarray:
        """Extrair features de uma ameaça"""
        features = [
            1 if threat["threat_info"]["severity"] == "crítica" else 0,
            1 if threat["classification"]["is_financial_related"] else 0,
            1 if threat["classification"]["is_critical_infrastructure"] else 0,
            len(threat["iocs"]["ipv4"]),
            len(threat["iocs"]["domains"]),
            len(threat["threat_info"]["apt_groups"]),
        ]
        return np.array([features])
    
    def predict_risk(self, threat: Dict) -> float:
        """Prever risco para sua org (0-1)"""
        if not self.model:
            return 0.5
        
        features = self.extract_features(threat)
        probability = self.model.predict_proba(features)[0][1]
        
        return probability

# Uso:
predictor = ThreatPredictor()
risk = predictor.predict_risk(threat)
if risk > 0.7:
    st.warning(f"Alta probabilidade de afetar sua organização: {risk:.1%}")


# ============================================================================
# 7. EXPORTAR PARA MISP
# ============================================================================

"""
Arquivo novo: misp_exporter.py
Enviar IoCs para MISP (Malware Information Sharing Platform)
"""

from pymisp import PyMISP
from datetime import datetime

class MISPExporter:
    """Exportar IoCs para MISP"""
    
    def __init__(self, misp_url: str, misp_key: str):
        self.misp = PyMISP(misp_url, misp_key, ssl=False)
    
    def create_event_from_threat(self, threat: Dict) -> bool:
        """Criar evento MISP a partir de ameaça CTI"""
        try:
            event = {
                "info": threat["source"]["title"][:100],
                "threat_level_id": 4 if threat["threat_info"]["severity"] == "crítica" else 3,
                "distribution": 0,  # Interno
                "date": datetime.fromisoformat(threat["timestamp"]).date()
            }
            
            event = self.misp.new_event(**event)
            event_id = event["Event"]["id"]
            
            # Adicionar IoCs
            for ip in threat["iocs"]["ipv4"]:
                self.misp.add_attribute(event_id, {
                    "type": "ip-dst",
                    "value": ip,
                    "category": "Network activity"
                })
            
            for domain in threat["iocs"]["domains"]:
                self.misp.add_attribute(event_id, {
                    "type": "domain",
                    "value": domain,
                    "category": "Network activity"
                })
            
            return True
        except Exception as e:
            logging.error(f"Erro ao criar evento MISP: {e}")
            return False

# Uso:
misp = MISPExporter("https://misp.empresa.com", "your_api_key")
misp.create_event_from_threat(threat)


# ============================================================================
# 8. BOT INTERATIVO DISCORD
# ============================================================================

"""
Arquivo novo: discord_bot.py
Bot Discord interativo para consultar ameaças
"""

import discord
from discord.ext import commands
import json

bot = commands.Bot(command_prefix="!")

@bot.command(name="verdict")
async def verdict(ctx, malware_name: str):
    """Consultar veredicto de malware"""
    # Buscar em data/results/
    verdict = f"Malware {malware_name}: Alto risco (Trojan)"
    await ctx.send(embed=discord.Embed(description=verdict))

@bot.command(name="ioc")
async def check_ioc(ctx, ioc_value: str):
    """Verificar IoC"""
    # Buscar em banco de dados
    await ctx.send(f"IoC {ioc_value}: Encontrado em 3 ameaças recentes")

# Rodar: bot.run("token_discord")


# ============================================================================
# 9. INTEGRAÇÃO SLACK
# ============================================================================

"""
Arquivo novo: notifier_slack.py
Enviar alertas para Slack
"""

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

class SlackNotifier:
    """Enviar alertas para Slack"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_alert(self, threat: Dict) -> bool:
        """Enviar alerta para Slack"""
        try:
            import requests
            
            message = {
                "text": f"🚨 {threat['source']['title']}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "Ameaça Detectada"}
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": 
                            f"*Severidade*: {threat['threat_info']['severity']}\n"
                            f"*APTs*: {', '.join(threat['threat_info']['apt_groups'])}"
                        }
                    }
                ]
            }
            
            requests.post(self.webhook_url, json=message)
            return True
        except:
            return False


# ============================================================================
# 10. ANÁLISE DE TENDÊNCIAS
# ============================================================================

"""
Arquivo novo: analytics.py
Analisar tendências de ataques
"""

import json
from collections import Counter
from datetime import datetime, timedelta

class ThreatAnalytics:
    """Análise de tendências"""
    
    def __init__(self, results_dir: str = "data/results"):
        self.results_dir = results_dir
    
    def top_apts(self, days: int = 30) -> Dict:
        """APTs mais ativos"""
        apts = Counter()
        
        # Carregar todos os JSONs dos últimos N dias
        # Contar ocorrências
        
        return dict(apts.most_common(10))
    
    def top_malware(self, days: int = 30) -> Dict:
        """Malware mais mencionado"""
        # Similar ao top_apts
        pass
    
    def sectors_under_attack(self, days: int = 30) -> Dict:
        """Setores mais atacados"""
        # Análise por setor
        pass
    
    def generate_report(self) -> str:
        """Gerar relatório de tendências"""
        report = f"""
        === Relatório de Tendências ({datetime.now()})
        
        Top 10 APTs:
        {self.top_apts()}
        
        Setores Mais Atacados:
        {self.sectors_under_attack()}
        """
        return report


# CONCLUSÃO:
# Este arquivo demonstra como estender o CTI System com:
# 1. Novos IoCs (mutexes, registry, etc)
# 2. Inteligência externa (OTX, VirusTotal)
# 3. Novos collectors (Twitter, Telegram, etc)
# 4. Dashboards (Streamlit, Grafana)
# 5. Integrações SIEM (Splunk, ELK)
# 6. ML/IA (Previsão, classificação)
# 7. Compartilhamento (MISP, STIX)
# 8. Bots interativos (Discord, Slack)
# 9. Análise avançada
# 10. E muito mais!

print("""
Todos os exemplos acima podem ser integrados.
Escolha o que faz sentido para sua organização.
""")
