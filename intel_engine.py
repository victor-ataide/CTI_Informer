"""
Módulo Intel Engine: Motor de análise usando Ollama (LLM local).
Extrai informações de ameaças: APTs, malware, setores, severidade, TTPs.
"""

import json
import logging
from typing import Dict, Optional, List
import requests
from datetime import datetime

logger = logging.getLogger(__name__)


class IntelligenceEngine:
    """
    Classe responsável por análise de inteligência usando LLM local (Ollama).
    
    Extrai:
    - Grupos de APT e malware
    - Setores afetados
    - Países envolvidos
    - Severidade
    - Descrição técnica
    - Mapeamento TTPs MITRE ATT&CK
    """
    
    # Mapeamento de técnicas MITRE ATT&CK comuns
    MITRE_TACTICS = {
        "reconnaissance": ["T1592", "T1589", "T1590"],
        "resource_development": ["T1583", "T1586", "T1589"],
        "initial_access": ["T1189", "T1190", "T1195", "T1566"],
        "execution": ["T1059", "T1609", "T1203", "T1559"],
        "persistence": ["T1098", "T1197", "T1547", "T1547.001"],
        "privilege_escalation": ["T1548", "T1134", "T1547", "T1611"],
        "defense_evasion": ["T1548", "T1197", "T1140", "T1222"],
        "credential_access": ["T1110", "T1555", "T1187", "T1056"],
        "discovery": ["T1087", "T1010", "T1217", "T1580"],
        "lateral_movement": ["T1570", "T1570", "T1570", "T1021"],
        "collection": ["T1123", "T1119", "T1123", "T1056"],
        "command_and_control": ["T1071", "T1071", "T1071", "T1001"],
        "exfiltration": ["T1020", "T1030", "T1048", "T1041"],
        "impact": ["T1531", "T1561", "T1485", "T1530"],
    }
    
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "mistral"):
        """
        Inicializa o Intelligence Engine.
        
        Args:
            ollama_url (str): URL base do Ollama
            model (str): Modelo a usar (mistral, llama3, etc)
        """
        self.ollama_url = ollama_url
        self.model = model
        self.api_endpoint = f"{ollama_url}/api/generate"
        
        logger.info(f"Intelligence Engine inicializado com modelo: {model}")
    
    def _call_ollama(self, prompt: str, max_tokens: int = 2048) -> Optional[str]:
        """
        Faz chamada ao Ollama com um prompt.
        
        Args:
            prompt (str): Prompt para o modelo
            max_tokens (int): Máximo de tokens na resposta
            
        Returns:
            Optional[str]: Resposta do modelo ou None
        """
        try:
            logger.debug(f"Chamando Ollama com prompt: {prompt[:100]}...")
            
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "num_predict": max_tokens,
            }
            
            response = requests.post(
                self.api_endpoint,
                json=payload,
                timeout=60
            )
            
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "").strip()
            
        except requests.exceptions.ConnectionError:
            logger.error("Erro: Ollama não está acessível. Verifique se está rodando (ollama serve)")
            return None
        except Exception as e:
            logger.error(f"Erro ao chamar Ollama: {str(e)}")
            return None
    
    def extract_threat_info(self, content: str) -> Dict:
        """
        Extrai informações de ameaça do conteúdo usando LLM.
        
        Args:
            content (str): Conteúdo para analisar
            
        Returns:
            Dict: Informações extraídas
        """
        logger.info("Iniciando análise com LLM...")
        
        # Limitar tamanho do conteúdo para o LLM
        content_limited = content[:2000] if len(content) > 2000 else content
        
        prompt = f"""Analise o seguinte texto sobre uma ameaça cibernética e extraia as informações em formato JSON:

TEXTO:
{content_limited}

Extraia e retorne APENAS um JSON válido com as seguintes chaves (deixe vazio se não encontrar):
{{
    "apt_groups": ["lista de grupos APT"],
    "malware_names": ["lista de nomes de malware"],
    "affected_sectors": ["lista de setores afetados"],
    "affected_countries": ["lista de países afetados"],
    "severity": "crítica|alta|média|baixa",
    "technical_description": "descrição técnica resumida",
    "attack_flow": "passo a passo de como funciona o ataque",
    "ttps": ["lista de técnicas MITRE ATT&CK ou nomes"],
    "key_findings": "achados principais"
}}

Retorne APENAS o JSON, sem explicações adicionais."""

        response = self._call_ollama(prompt)
        
        if not response:
            logger.warning("Ollama não retornou resposta")
            return self._default_extraction(content)
        
        # Tentar parsear JSON
        try:
            # Tentar encontrar JSON na resposta
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                threat_info = json.loads(json_match.group())
            else:
                threat_info = json.loads(response)
            
            logger.info("Análise LLM completada com sucesso")
            return threat_info
            
        except json.JSONDecodeError:
            logger.warning(f"Falha ao parsear JSON da resposta: {response[:200]}")
            return self._default_extraction(content)
    
    def _default_extraction(self, content: str) -> Dict:
        """
        Extração padrão sem LLM (fallback).
        
        Args:
            content (str): Conteúdo para analisar
            
        Returns:
            Dict: Informações extraídas
        """
        logger.info("Usando extração fallback (sem LLM)")
        
        # Buscar palavras-chave comuns
        content_lower = content.lower()
        
        return {
            "apt_groups": self._extract_apt_keywords(content),
            "malware_names": self._extract_malware_keywords(content),
            "affected_sectors": self._extract_sectors(content),
            "affected_countries": self._extract_countries(content),
            "severity": "média",
            "technical_description": content[:200],
            "attack_flow": "Não disponível - análise sem LLM",
            "ttps": self._extract_ttp_keywords(content),
            "key_findings": ""
        }
    
    @staticmethod
    def _extract_apt_keywords(content: str) -> List[str]:
        """Extrai nomes de APTs com regex."""
        apt_keywords = [
            r'\bAPT\d+\b', r'\bLazarus\b', r'\bFancy\s*Bear\b',
            r'\bCozy\s*Bear\b', r'\bUrsnif\b', r'\bTrickbot\b',
            r'\bEmperor\s*Dragonfly\b', r'\bCobalt\b'
        ]
        apts = []
        for pattern in apt_keywords:
            import re
            matches = re.findall(pattern, content, re.IGNORECASE)
            apts.extend(matches)
        return list(set(apts))
    
    @staticmethod
    def _extract_malware_keywords(content: str) -> List[str]:
        """Extrai nomes de malware."""
        malware_keywords = [
            r'\b(?:malware|trojan|worm|ransomware|botnet)\s+([A-Za-z0-9\-]+)\b'
        ]
        malware = []
        for pattern in malware_keywords:
            import re
            matches = re.findall(pattern, content, re.IGNORECASE)
            malware.extend(matches)
        return list(set(malware))[:5]
    
    @staticmethod
    def _extract_sectors(content: str) -> List[str]:
        """Extrai setores afetados."""
        sectors_keywords = {
            r'\bbank|financial|fintech': 'Financeiro',
            r'\bpower|electric|grid|energy': 'Energia',
            r'\bgovernment|gov|federal': 'Governo',
            r'\bhealth|hospital|medical': 'Saúde',
            r'\btelecom|telecomun': 'Telecomunicações',
            r'\bwater|água': 'Recursos Hídricos',
            r'\btransport|transport\b': 'Transporte',
        }
        sectors = []
        for pattern, sector in sectors_keywords.items():
            import re
            if re.search(pattern, content, re.IGNORECASE):
                sectors.append(sector)
        return sectors
    
    @staticmethod
    def _extract_countries(content: str) -> List[str]:
        """Extrai países mencionados."""
        countries_keywords = {
            r'\bUSA|United\s*States\b': 'USA',
            r'\bChina|Chinese\b': 'China',
            r'\bRussia|Russian\b': 'Rússia',
            r'\bKorea|DPRK|North\s*Korea\b': 'Coreia do Norte',
            r'\bIran\b': 'Irã',
            r'\bBrazil|Brasil\b': 'Brasil',
            r'\bUK|United\s*Kingdom\b': 'Reino Unido',
            r'\bGermany|German\b': 'Alemanha',
            r'\bIsrael\b': 'Israel',
        }
        countries = []
        for pattern, country in countries_keywords.items():
            import re
            if re.search(pattern, content, re.IGNORECASE):
                countries.append(country)
        return countries
    
    @staticmethod
    def _extract_ttp_keywords(content: str) -> List[str]:
        """Extrai TTPs mencionados."""
        ttp_pattern = r'\b(?:T\d{4}(?:\.\d{3})?)\b'
        import re
        ttps = re.findall(ttp_pattern, content, re.IGNORECASE)
        return list(set(ttps))
    
    def classify_threat(self, threat_info: Dict) -> Dict:
        """
        Classifica uma ameaça com base nas informações extraídas.
        
        Args:
            threat_info (Dict): Informações da ameaça
            
        Returns:
            Dict: Classificação completa
        """
        classification = {
            "is_high_severity": threat_info.get("severity") in ["crítica", "alta"],
            "is_financial_related": any(
                sector in ["Financeiro"] 
                for sector in threat_info.get("affected_sectors", [])
            ),
            "is_critical_infrastructure": any(
                sector in ["Energia", "Governo", "Saúde", "Telecomunicações", "Recursos Hídricos"]
                for sector in threat_info.get("affected_sectors", [])
            ),
            "should_alert": False  # Será setado como True se crítico/financeiro/infra
        }
        
        # Determinar se deve alertar
        classification["should_alert"] = (
            classification["is_high_severity"] or
            classification["is_financial_related"] or
            classification["is_critical_infrastructure"]
        )
        
        return classification
    
    def enrich_threat_data(self, article: Dict, threat_info: Dict, iocs: Dict) -> Dict:
        """
        Enriquece dados de ameaça com informações de múltiplas análises.
        
        Args:
            article (Dict): Dados do artigo original
            threat_info (Dict): Informações extraídas pelo LLM
            iocs (Dict): IoCs extraídos
            
        Returns:
            Dict: Dados enriquecidos completos
        """
        classification = self.classify_threat(threat_info)
        
        enriched = {
            "id": article.get("link", "").replace("/", "_")[:50],
            "timestamp": datetime.utcnow().isoformat(),
            "source": {
                "name": article.get("source_name", ""),
                "link": article.get("link", ""),
                "title": article.get("title", "")
            },
            "threat_info": threat_info,
            "iocs": iocs,
            "classification": classification,
            "analysis_quality": "high" if threat_info else "low"
        }
        
        return enriched
    
    def format_threat_for_discord(self, enriched_data: Dict) -> str:
        """
        Formata dados de ameaça para mensagem Discord.
        
        Args:
            enriched_data (Dict): Dados enriquecidos da ameaça
            
        Returns:
            str: Mensagem formatada em Markdown para Discord
        """
        threat = enriched_data["threat_info"]
        iocs = enriched_data["iocs"]
        classification = enriched_data["classification"]
        
        # Se não deve alertar, retornar vazio
        if not classification["should_alert"]:
            return ""
        
        severity_emoji = {
            "crítica": "🔴",
            "alta": "🟠",
            "média": "🟡",
            "baixa": "🟢"
        }
        
        message = f"""🚨 **NOVA AMEAÇA DETECTADA**

🎯 **APT**: {', '.join(threat.get('apt_groups', ['Desconhecido']))}
🦠 **Malware**: {', '.join(threat.get('malware_names', ['N/A']))}
🌍 **Países**: {', '.join(threat.get('affected_countries', ['N/A']))}
🏢 **Setores**: {', '.join(threat.get('affected_sectors', ['N/A']))}

{severity_emoji.get(threat.get('severity', 'média'), '⚠️')} **Severidade**: {threat.get('severity', 'média').upper()}

📄 **Descrição Técnica**:
{threat.get('technical_description', 'N/A')[:500]}

🔄 **Como Funciona**:
{threat.get('attack_flow', 'N/A')[:500]}

🛡️ **TTPs MITRE ATT&CK**:
"""
        
        # Adicionar TTPs
        ttps = threat.get('ttps', [])
        if ttps:
            for ttp in ttps[:5]:
                message += f"• {ttp}\n"
        else:
            message += "• Não especificado\n"
        
        # Adicionar IoCs
        message += "\n🌐 **Indicadores de Comprometimento (IoCs)**:\n"
        
        if iocs.get("ipv4"):
            message += f"**IPs**: {', '.join(iocs['ipv4'][:3])}\n"
        
        if iocs.get("domains"):
            message += f"**Domínios**: {', '.join(iocs['domains'][:3])}\n"
        
        hashes = iocs.get("hashes", {})
        if hashes.get("sha256"):
            message += f"**SHA256**: `{hashes['sha256'][0]}`\n"
        
        if iocs.get("cves"):
            message += f"**CVEs**: {', '.join(iocs['cves'][:3])}\n"
        
        # Adicionar fonte
        message += f"\n🔗 **Fonte**: [{enriched_data['source']['title'][:50]}...]({enriched_data['source']['link']})\n"
        
        return message
