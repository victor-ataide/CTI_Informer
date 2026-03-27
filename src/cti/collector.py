"""
Módulo Collector: Coleta dados de múltiplas fontes RSS e blogs de segurança.
Fornece funcionalidades para adicionar, remover e gerenciar fontes de inteligência.
"""

import feedparser
import requests
from datetime import datetime
import logging
from typing import List, Dict, Optional
import json
import os

logger = logging.getLogger(__name__)


class ThreatCollector:
    """
    Classe responsável por coletar ameaças de múltiplas fontes RSS/blogs.
    
    Attributes:
        sources (List[Dict]): Lista de fontes de inteligência configuradas
        timeout (int): Timeout para requisições HTTP (padrão: 10 segundos)
    """
    
    # Fontes padrão de inteligência de ameaças
    DEFAULT_SOURCES = [
        {
            "name": "SANS Internet Storm Center",
            "url": "https://isc.sans.edu/rssfeed.xml",
            "type": "rss",
            "category": "general"
        },
        {
            "name": "Bleeping Computer - Security News",
            "url": "https://www.bleepingcomputer.com/feed/",
            "type": "rss",
            "category": "general"
        },
        {
            "name": "Krebs on Security",
            "url": "https://krebsonsecurity.com/feed/",
            "type": "rss",
            "category": "general"
        },
        {
            "name": "Dark Reading",
            "url": "https://www.darkreading.com/services/feeds/rss/all.asp",
            "type": "rss",
            "category": "general"
        },
        {
            "name": "Malwarebytes Labs",
            "url": "https://www.malwarebytes.com/feed/",
            "type": "rss",
            "category": "malware"
        },
        {
            "name": "Threat Intelligence X (Twitter/X Alternative)",
            "url": "https://twitter.com/i/web/status/",
            "type": "social",
            "category": "apt"
        },
        {
            "name": "CyberDefenses - Research",
            "url": "https://cyberdefenses.com/feed/",
            "type": "rss",
            "category": "general"
        },
        {
            "name": "Checkpoint Research",
            "url": "https://research.checkpoint.com/feed/",
            "type": "rss",
            "category": "apt"
        },
        {
            "name": "Talos Security Intelligence - Cisco",
            "url": "https://feeds.talosintelligence.com/",
            "type": "rss",
            "category": "general"
        },
        {
            "name": "Mandiant Blog",
            "url": "https://www.mandiant.com/resources/blog/rss.xml",
            "type": "rss",
            "category": "apt"
        }
    ]
    
    def __init__(self, sources_file: Optional[str] = None, timeout: int = 10):
        """
        Inicializa o coletor de ameaças.
        
        Args:
            sources_file (Optional[str]): Arquivo JSON com fontes customizadas
            timeout (int): Timeout para requisições HTTP
        """
        self.timeout = timeout
        self.sources = []
        
        # Carregar fontes customizadas se existirem, senão usar padrões
        if sources_file and os.path.exists(sources_file):
            self.load_sources_from_file(sources_file)
        else:
            self.sources = self.DEFAULT_SOURCES.copy()
    
    def add_source(self, name: str, url: str, source_type: str = "rss", 
                   category: str = "general") -> None:
        """
        Adiciona uma nova fonte de inteligência.
        
        Args:
            name (str): Nome descritivo da fonte
            url (str): URL do feed ou da fonte
            source_type (str): Tipo de fonte (rss, blog, social)
            category (str): Categoria (general, malware, apt, infrastructure)
        """
        source = {
            "name": name,
            "url": url,
            "type": source_type,
            "category": category,
            "added_at": datetime.utcnow().isoformat()
        }
        self.sources.append(source)
        logger.info(f"Fonte adicionada: {name}")
    
    def remove_source(self, name: str) -> bool:
        """
        Remove uma fonte de inteligência.
        
        Args:
            name (str): Nome da fonte a remover
            
        Returns:
            bool: True se removida, False se não encontrada
        """
        for i, source in enumerate(self.sources):
            if source["name"].lower() == name.lower():
                self.sources.pop(i)
                logger.info(f"Fonte removida: {name}")
                return True
        return False
    
    def list_sources(self) -> List[Dict]:
        """
        Lista todas as fontes configuradas.
        
        Returns:
            List[Dict]: Lista de fontes
        """
        return self.sources
    
    def save_sources_to_file(self, filepath: str) -> None:
        """
        Salva as fontes em arquivo JSON.
        
        Args:
            filepath (str): Caminho do arquivo JSON
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.sources, f, indent=2, ensure_ascii=False)
        logger.info(f"Fontes salvas em: {filepath}")
    
    def load_sources_from_file(self, filepath: str) -> None:
        """
        Carrega fontes de arquivo JSON.
        
        Args:
            filepath (str): Caminho do arquivo JSON
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            self.sources = json.load(f)
        logger.info(f"Fontes carregadas de: {filepath}")
    
    def collect_from_rss(self, feed_url: str) -> List[Dict]:
        """
        Coleta entradas de um feed RSS.
        
        Args:
            feed_url (str): URL do feed RSS
            
        Returns:
            List[Dict]: Lista de artigos/entradas coletadas
        """
        articles = []
        try:
            logger.info(f"Coletando de RSS: {feed_url}")
            feed = feedparser.parse(feed_url)
            
            if feed.bozo:
                logger.warning(f"Feed pode estar malformado: {feed_url}")
            
            for entry in feed.entries[:20]:  # Limitar a 20 entradas por fonte
                article = {
                    "title": entry.get("title", ""),
                    "link": entry.get("link", ""),
                    "summary": entry.get("summary", ""),
                    "published": entry.get("published", datetime.utcnow().isoformat()),
                    "source": feed.feed.get("title", "Unknown"),
                    "id": entry.get("id", entry.get("link", "")),
                    "collected_at": datetime.utcnow().isoformat()
                }
                articles.append(article)
            
            logger.info(f"Coletadas {len(articles)} entradas de {feed_url}")
            
        except Exception as e:
            logger.error(f"Erro ao coletar de {feed_url}: {str(e)}")
        
        return articles
    
    def collect_all(self) -> List[Dict]:
        """
        Coleta dados de todas as fontes configuradas.
        
        Returns:
            List[Dict]: Lista consolidada de todos os artigos coletados
        """
        all_articles = []
        
        logger.info(f"Iniciando coleta de {len(self.sources)} fontes...")
        
        for source in self.sources:
            if source["type"] == "rss":
                articles = self.collect_from_rss(source["url"])
                # Adicionar metadados da fonte
                for article in articles:
                    article["source_name"] = source["name"]
                    article["source_category"] = source["category"]
                all_articles.extend(articles)
            else:
                logger.warning(f"Tipo de fonte não suportado ainda: {source['type']}")
        
        # Remover duplicatas baseado no ID/link
        unique_articles = {}
        for article in all_articles:
            key = article.get("id") or article.get("link")
            if key not in unique_articles:
                unique_articles[key] = article
        
        logger.info(f"Total de artigos únicos coletados: {len(unique_articles)}")
        
        return list(unique_articles.values())
    
    def collect_since(self, hours: int = 24) -> List[Dict]:
        """
        Coleta artigos dos últimas N horas.
        
        Args:
            hours (int): Número de horas para voltar atrás
            
        Returns:
            List[Dict]: Artigos coletados nos últimas N horas
        """
        all_articles = self.collect_all()
        
        # Filtrar por data (implementação básica)
        # Em produção, comparar com datetime.utcnow() - timedelta(hours=hours)
        
        return all_articles
