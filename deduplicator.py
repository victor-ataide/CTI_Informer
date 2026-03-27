"""
Módulo Deduplicator: Evita alertas duplicados no Discord
Rastreia IoCs já alertados usando hash SHA256
"""

import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, Set, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ThreatDeduplicator:
    """
    Rastreia ameaças já alertadas para evitar duplicatas no Discord.
    Armazena hash de IoCs e timestamp do último alerta.
    """
    
    def __init__(self, cache_file: str = "data/.alert_cache.json", retention_days: int = 7):
        """
        Inicializa deduplicador.
        
        Args:
            cache_file (str): Arquivo para armazenar cache de alertas
            retention_days (int): Dias para manter trace de IoCs (padrão: 7)
        """
        self.cache_file = cache_file
        self.retention_days = retention_days
        self.cache = self._load_cache()
        
        logger.info(f"Deduplicador inicializado (cache: {cache_file})")
    
    def _load_cache(self) -> Dict:
        """
        Carrega cache de alertas anteriores.
        
        Returns:
            Dict: Cache com IoCs hash e timestamps
        """
        try:
            if Path(self.cache_file).exists():
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Erro ao carregar cache: {e}")
        
        return {"iocs": {}, "last_updated": datetime.utcnow().isoformat()}
    
    def _save_cache(self) -> None:
        """Salva cache em disco."""
        try:
            Path(self.cache_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Erro ao salvar cache: {e}")
    
    def _generate_ioc_hash(self, iocs: Dict) -> str:
        """
        Gera hash único a partir dos IoCs.
        Combina IPs, domínios, hashes, CVEs para identificar ameaça única.
        
        Args:
            iocs (Dict): Dicionário de IoCs
            
        Returns:
            str: Hash SHA256 dos IoCs
        """
        # Coletar todos os IoCs em lista
        ioc_list = []
        
        if iocs.get("ipv4"):
            ioc_list.extend(sorted(iocs["ipv4"]))
        if iocs.get("ipv6"):
            ioc_list.extend(sorted(iocs["ipv6"]))
        if iocs.get("domains"):
            ioc_list.extend(sorted(iocs["domains"]))
        if iocs.get("urls"):
            ioc_list.extend(sorted(iocs["urls"]))
        
        # Hashes
        hashes = iocs.get("hashes", {})
        if hashes.get("sha256"):
            ioc_list.extend(sorted(hashes["sha256"]))
        if hashes.get("md5"):
            ioc_list.extend(sorted(hashes["md5"]))
        
        # CVEs
        if iocs.get("cves"):
            ioc_list.extend(sorted(iocs["cves"]))
        
        # Gerar hash único
        ioc_str = "|".join(ioc_list)
        ioc_hash = hashlib.sha256(ioc_str.encode()).hexdigest()
        
        return ioc_hash
    
    def is_duplicate(self, threat_data: Dict) -> bool:
        """
        Verifica se ameaça já foi alertada.
        
        Args:
            threat_data (Dict): Dados enriquecidos da ameaça
            
        Returns:
            bool: True se já foi alertada, False caso contrário
        """
        if not threat_data.get("iocs"):
            return False
        
        ioc_hash = self._generate_ioc_hash(threat_data["iocs"])
        
        if ioc_hash in self.cache["iocs"]:
            last_alert = self.cache["iocs"][ioc_hash]
            logger.info(f"✓ IoC hash {ioc_hash[:8]}... já foi alertado em {last_alert}")
            return True
        
        return False
    
    def mark_as_alerted(self, threat_data: Dict) -> None:
        """
        Marca ameaça como alertada no Discord.
        
        Args:
            threat_data (Dict): Dados da ameaça
        """
        ioc_hash = self._generate_ioc_hash(threat_data["iocs"])
        
        self.cache["iocs"][ioc_hash] = datetime.utcnow().isoformat()
        self.cache["last_updated"] = datetime.utcnow().isoformat()
        
        self._save_cache()
        
        logger.info(f"✓ Ameaça marcada como alertada: {ioc_hash[:8]}...")
    
    def cleanup_old_entries(self) -> int:
        """
        Remove entradas antigas do cache (> retention_days).
        
        Returns:
            int: Número de entradas removidas
        """
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
        old_keys = []
        
        for ioc_hash, timestamp_str in self.cache["iocs"].items():
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
                if timestamp < cutoff_date:
                    old_keys.append(ioc_hash)
            except:
                old_keys.append(ioc_hash)
        
        for key in old_keys:
            del self.cache["iocs"][key]
        
        if old_keys:
            self._save_cache()
            logger.info(f"✓ Limpeza: {len(old_keys)} entradas antigas removidas")
        
        return len(old_keys)
    
    def get_stats(self) -> Dict:
        """
        Retorna estatísticas do cache.
        
        Returns:
            Dict: Estatísticas
        """
        return {
            "total_cached": len(self.cache["iocs"]),
            "last_updated": self.cache["last_updated"],
            "retention_days": self.retention_days,
            "cache_file": self.cache_file
        }
