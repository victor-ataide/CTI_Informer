"""
Módulo Parser: Processa e normaliza conteúdo de múltiplas fontes.
Remove HTML, limpa texto e extrai metadados relevantes.
"""

import re
import logging
from typing import Dict, Optional
from bs4 import BeautifulSoup
from datetime import datetime
import requests

logger = logging.getLogger(__name__)


class ContentParser:
    """
    Classe responsável por processar e normalizar conteúdo de diferentes fontes.
    
    Realiza limpeza de HTML, normalização de texto e extração de metadados.
    """
    
    # Palavras-chave indicadoras de ameaça crítica
    CRITICAL_KEYWORDS = [
        "ransomware", "apt", "zero-day", "exploit", "malware",
        "backdoor", "trojan", "worm", "botnet", "c2", "command control",
        "rce", "remote code execution", "sql injection", "xss",
        "breach", "data leak", "insider threat", "credential",
        "phishing", "spear-phishing", "whaling", "vishing"
    ]
    
    # Palavras-chave setores financeiros/críticos
    FINANCIAL_KEYWORDS = [
        "bank", "banco", "financial", "fintech", "credit card", "payment",
        "swift", "cryptocurrency", "bitcoin", "ethereum", "blockchain"
    ]
    
    CRITICAL_INFRASTRUCTURE_KEYWORDS = [
        "power", "energia", "electric", "grid", "telecom", "government",
        "governo", "saúde", "health", "hospital", "water", "água",
        "transporte", "transport", "nuclear", "scada", "industrial"
    ]
    
    def __init__(self):
        """Inicializa o parser."""
        self.html_cleaner = re.compile(r'<[^>]+>')
        
    @staticmethod
    def _remove_html(text: str) -> str:
        """
        Remove tags HTML do texto.
        
        Args:
            text (str): Texto com HTML
            
        Returns:
            str: Texto limpo
        """
        # Tentar com BeautifulSoup primeiro (mais robusto)
        try:
            soup = BeautifulSoup(text, 'html.parser')
            # Remover scripts e styles
            for script in soup(["script", "style"]):
                script.decompose()
            text = soup.get_text()
        except:
            # Fallback para regex
            text = re.sub(r'<[^>]+>', '', text)
        
        return text
    
    @staticmethod
    def _clean_text(text: str) -> str:
        """
        Limpa e normaliza texto.
        
        Args:
            text (str): Texto bruto
            
        Returns:
            str: Texto normalizado
        """
        # Remover espaços múltiplos
        text = re.sub(r'\s+', ' ', text)
        
        # Remover espaços no início e fim
        text = text.strip()
        
        # Remover caracteres de controle
        text = ''.join(char for char in text if ord(char) >= 32 or char == '\n')
        
        # Limitar a 5000 caracteres (para LLM não ficar sobrecarregado)
        if len(text) > 5000:
            text = text[:4997] + "..."
        
        return text
    
    @staticmethod
    def _fetch_full_content(url: str, timeout: int = 5) -> Optional[str]:
        """
        Busca o conteúdo completo de uma URL.
        
        Args:
            url (str): URL para buscar
            timeout (int): Timeout em segundos
            
        Returns:
            Optional[str]: Conteúdo da página ou None
        """
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, timeout=timeout, headers=headers)
            response.raise_for_status()
            
            # Extrair texto da página HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remover scripts e styles
            for script in soup(["script", "style"]):
                script.decompose()
            
            text = soup.get_text()
            return text
            
        except Exception as e:
            logger.warning(f"Erro ao buscar conteúdo de {url}: {str(e)}")
            return None
    
    def detect_severity(self, content: str) -> str:
        """
        Detecta severidade baseado em palavras-chave.
        
        Args:
            content (str): Conteúdo a analisar
            
        Returns:
            str: Nível de severidade (crítica, alta, média, baixa)
        """
        content_lower = content.lower()
        
        # Palavras-chave de severidade crítica
        critical_phrases = [
            "zero-day", "apto", "apt ", "ransomware", "RCE", "remote code execution",
            "exploit de 0-day", "explorado ativamente", "actively exploited"
        ]
        
        for phrase in critical_phrases:
            if phrase in content_lower:
                return "crítica"
        
        # Palavras-chave de severidade alta
        high_phrases = [
            "malware", "trojan", "backdoor", "breach", "data leak",
            "vulnerability", "vuln", "infecção", "infection"
        ]
        
        for phrase in high_phrases:
            if phrase in content_lower:
                return "alta"
        
        # Palavras-chave de severidade média
        medium_phrases = [
            "phishing", "alertar", "alert", "warning", "cuidado"
        ]
        
        for phrase in medium_phrases:
            if phrase in content_lower:
                return "média"
        
        return "baixa"
    
    def is_financial_related(self, content: str) -> bool:
        """
        Verifica se a ameaça está relacionada a setor financeiro.
        
        Args:
            content (str): Conteúdo a analisar
            
        Returns:
            bool: True se relacionado a financeiro
        """
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in self.FINANCIAL_KEYWORDS)
    
    def is_critical_infrastructure(self, content: str) -> bool:
        """
        Verifica se a ameaça afeta infraestrutura crítica.
        
        Args:
            content (str): Conteúdo a analisar
            
        Returns:
            bool: True se afeta infraestrutura crítica
        """
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in self.CRITICAL_INFRASTRUCTURE_KEYWORDS)
    
    def parse_article(self, article: Dict) -> Dict:
        """
        Processa e normaliza um artigo completo.
        
        Args:
            article (Dict): Dicionário com dados do artigo
            
        Returns:
            Dict: Artigo normalizado e enriquecido
        """
        try:
            # Copiar dados originais
            parsed = {
                "original_title": article.get("title", ""),
                "link": article.get("link", ""),
                "source": article.get("source", ""),
                "source_name": article.get("source_name", ""),
                "source_category": article.get("source_category", "general"),
                "collected_at": article.get("collected_at", datetime.utcnow().isoformat()),
            }
            
            # Combinar título e resumo inicial
            text_raw = f"{article.get('title', '')} {article.get('summary', '')}"
            
            # Tentar buscar conteúdo completo se temos URL
            if article.get("link"):
                full_content = self._fetch_full_content(article.get("link"))
                if full_content:
                    text_raw += f" {full_content}"
            
            # Remover HTML
            text_clean = self._remove_html(text_raw)
            
            # Normalizar texto
            text_normalized = self._clean_text(text_clean)
            
            # Adicionar conteúdo processado
            parsed["title"] = self._clean_text(article.get("title", ""))
            parsed["summary"] = text_normalized
            parsed["full_text"] = text_normalized
            
            # Detectar severidade
            parsed["detected_severity"] = self.detect_severity(text_normalized)
            
            # Verificar setores
            parsed["is_financial_related"] = self.is_financial_related(text_normalized)
            parsed["is_critical_infrastructure"] = self.is_critical_infrastructure(text_normalized)
            
            # Parsed timestamp
            parsed["parsed_at"] = datetime.utcnow().isoformat()
            
            logger.info(f"Artigo processado: {parsed['title'][:50]}...")
            
            return parsed
            
        except Exception as e:
            logger.error(f"Erro ao processar artigo: {str(e)}")
            return article
    
    def parse_batch(self, articles: list) -> list:
        """
        Processa um lote de artigos.
        
        Args:
            articles (list): Lista de artigos
            
        Returns:
            list: Artigos processados
        """
        parsed_articles = []
        
        for i, article in enumerate(articles, 1):
            logger.info(f"Processando artigo {i}/{len(articles)}")
            parsed = self.parse_article(article)
            parsed_articles.append(parsed)
        
        return parsed_articles
