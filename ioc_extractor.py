"""
Módulo IOC Extractor: Extrai Indicadores de Comprometimento de texto.
Identifica: IPs, domínios, URLs, emails, hashes MD5/SHA1/SHA256.
"""

import re
import logging
from typing import Dict, List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class IOCExtractor:
    """
    Classe responsável por extrair Indicadores de Comprometimento (IoCs) de texto.
    
    Extrai: IPs (v4/v6), domínios, URLs, emails, hashes e outros artefatos técnicos.
    """
    
    # Expressões regulares para diferentes tipos de IoCs
    
    # IPv4
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    # IPv6
    IPV6_PATTERN = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
    )
    
    # Domínios (incluindo subdomínios)
    DOMAIN_PATTERN = re.compile(
        r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
        re.IGNORECASE
    )
    
    # URLs
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]*',
        re.IGNORECASE
    )
    
    # Emails
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    
    # MD5 (32 caracteres hex)
    MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
    
    # SHA1 (40 caracteres hex)
    SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
    
    # SHA256 (64 caracteres hex)
    SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    # SHA512 (128 caracteres hex)
    SHA512_PATTERN = re.compile(r'\b[a-fA-F0-9]{128}\b')
    
    # Nomes de arquivo com extensões suspeitas
    SUSPICIOUS_FILES_PATTERN = re.compile(
        r'\b[a-zA-Z0-9_\-]+\.(?:exe|dll|scr|vbs|js|bat|cmd|com|pif|msi|'
        r'ps1|psm1|psd1|psc1|cpp|c|rb|php|jsp|asp|aspx|jar|apk|deb|rpm|zip|rar|7z)\b',
        re.IGNORECASE
    )
    
    # Registry keys (Windows)
    REGISTRY_PATTERN = re.compile(
        r'(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[a-zA-Z0-9_\\-]+',
        re.IGNORECASE
    )
    
    # Processo/Mutexes
    MUTEX_PATTERN = re.compile(
        r'(?:Mutex:|mutex\s*[:=]\s*)([a-zA-Z0-9_\-\.]+)',
        re.IGNORECASE
    )
    
    # CVEs
    CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
    
    # Portas
    PORT_PATTERN = re.compile(r':(?!//)\b(?:[0-9]{1,5})\b')
    
    def __init__(self):
        """Inicializa o extractor de IoCs."""
        self.excludes_domains = {
            'example.com', 'localhost', 'test.com', '127.0.0.1',
            'no-reply.com', 'noreply.com', 'github.com', 'google.com'
        }
        self.excludes_emails = {
            'noreply@', 'no-reply@', 'support@github.com'
        }
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """
        Valida se é um IP válido (não em ranges privados/locais).
        
        Args:
            ip (str): String do IP
            
        Returns:
            bool: True se IP válido e roteável
        """
        private_ranges = [
            (0, 9242880),  # 0.0.0.0 - 0.255.255.255
            (167772160, 184549376),  # 10.0.0.0 - 10.255.255.255
            (2130706432, 2147483647),  # 127.0.0.0 - 127.255.255.255
            (2886729728, 2887778304),  # 172.16.0.0 - 172.31.255.255
            (3232235520, 3232301055),  # 192.168.0.0 - 192.168.255.255
            (3758096384, 3758096639),  # 224.0.0.0 - 224.0.0.255
        ]
        
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            if any(p > 255 for p in parts):
                return False
            
            ip_num = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            
            for start, end in private_ranges:
                if start <= ip_num <= end:
                    return False
            
            return True
        except:
            return False
    
    def extract_ipv4(self, text: str) -> List[str]:
        """
        Extrai endereços IPv4 do texto.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de IPs encontrados
        """
        ips = set(self.IPV4_PATTERN.findall(text))
        # Filtrar IPs privados/locais
        valid_ips = [ip for ip in ips if self._is_valid_ip(ip)]
        return list(valid_ips)
    
    def extract_ipv6(self, text: str) -> List[str]:
        """
        Extrai endereços IPv6 do texto.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de IPv6s encontrados
        """
        ipv6s = list(set(self.IPV6_PATTERN.findall(text)))
        return ipv6s
    
    def extract_domains(self, text: str) -> List[str]:
        """
        Extrai domínios do texto.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de domínios encontrados
        """
        domains = set(self.DOMAIN_PATTERN.findall(text))
        # Filtrar domínios conhecidos/não relevantes
        valid_domains = [d for d in domains if not any(
            ex in d.lower() for ex in self.excludes_domains
        )]
        return list(valid_domains)
    
    def extract_urls(self, text: str) -> List[str]:
        """
        Extrai URLs do texto.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de URLs encontradas
        """
        urls = set(self.URL_PATTERN.findall(text))
        # Remover URLs duplicadas e muito compridas
        valid_urls = [
            u for u in urls 
            if len(u) < 2000  # URL muito comprida provavelmente é falso positivo
        ]
        return list(valid_urls)
    
    def extract_emails(self, text: str) -> List[str]:
        """
        Extrai endereços email do texto.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de emails encontrados
        """
        emails = set(self.EMAIL_PATTERN.findall(text))
        # Filtrar emails conhecidos
        valid_emails = [e for e in emails if not any(
            ex in e.lower() for ex in self.excludes_emails
        )]
        return list(valid_emails)
    
    def extract_hashes(self, text: str) -> Dict[str, List[str]]:
        """
        Extrai hashes (MD5, SHA1, SHA256, SHA512) do texto.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            Dict[str, List[str]]: Dicionário com hashes por tipo
        """
        # SHA512 deve ser checado primeiro (maior tamanho)
        sha512 = list(set(self.SHA512_PATTERN.findall(text)))
        
        # SHA256
        sha256 = list(set(self.SHA256_PATTERN.findall(text)))
        # Remover SHA256s já encontrados em SHA512
        sha256 = [h for h in sha256 if h not in sha512]
        
        # SHA1
        sha1 = list(set(self.SHA1_PATTERN.findall(text)))
        sha1 = [h for h in sha1 if h not in sha256 and h not in sha512]
        
        # MD5
        md5 = list(set(self.MD5_PATTERN.findall(text)))
        md5 = [h for h in md5 if h not in sha1]
        
        return {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "sha512": sha512
        }
    
    def extract_files(self, text: str) -> List[str]:
        """
        Extrai nomes de arquivo com extensões suspeitas.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de arquivos encontrados
        """
        files = list(set(self.SUSPICIOUS_FILES_PATTERN.findall(text)))
        return files
    
    def extract_registry_keys(self, text: str) -> List[str]:
        """
        Extrai chaves de registro Windows.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de registry keys encontradas
        """
        keys = list(set(self.REGISTRY_PATTERN.findall(text)))
        return keys
    
    def extract_cves(self, text: str) -> List[str]:
        """
        Extrai identificadores de CVE.
        
        Args:
            text (str): Texto para buscar
            
        Returns:
            List[str]: Lista de CVEs encontrados
        """
        cves = list(set(self.CVE_PATTERN.findall(text)))
        return cves
    
    def extract_all(self, text: str) -> Dict:
        """
        Extrai todos os tipos de IoCs do texto.
        
        Args:
            text (str): Texto para analisar
            
        Returns:
            Dict: Dicionário com todos os IoCs encontrados
        """
        logger.info("Iniciando extração de IoCs...")
        
        try:
            iocs = {
                "ipv4": self.extract_ipv4(text),
                "ipv6": self.extract_ipv6(text),
                "domains": self.extract_domains(text),
                "urls": self.extract_urls(text),
                "emails": self.extract_emails(text),
                "hashes": self.extract_hashes(text),
                "files": self.extract_files(text),
                "registry_keys": self.extract_registry_keys(text),
                "cves": self.extract_cves(text),
            }
            
            # Contar IoCs totais
            total = sum(
                len(v) if isinstance(v, list) else len(v.get("md5", []) + v.get("sha1", []) + v.get("sha256", []) + v.get("sha512", []))
                for v in iocs.values()
            )
            
            logger.info(f"Extração completada. Total de IoCs: {total}")
            
            return iocs
            
        except Exception as e:
            logger.error(f"Erro ao extrair IoCs: {str(e)}")
            return {}
    
    def format_iocs_for_report(self, iocs: Dict) -> str:
        """
        Formata IoCs para relatório legível.
        
        Args:
            iocs (Dict): Dicionário de IoCs
            
        Returns:
            str: Texto formatado para relatório
        """
        report = "🌐 **INDICADORES DE COMPROMETIMENTO (IoCs)**\n\n"
        
        if iocs.get("ipv4"):
            report += f"**IPv4**: {', '.join(iocs['ipv4'][:10])}\n"
        
        if iocs.get("domains"):
            report += f"**Domínios**: {', '.join(iocs['domains'][:10])}\n"
        
        if iocs.get("urls"):
            report += f"**URLs**: {', '.join(iocs['urls'][:5])}\n"
        
        hashes = iocs.get("hashes", {})
        if hashes.get("sha256"):
            report += f"**SHA256**: {hashes['sha256'][0]}\n"
        if hashes.get("md5"):
            report += f"**MD5**: {hashes['md5'][0]}\n"
        
        if iocs.get("cves"):
            report += f"**CVEs**: {', '.join(iocs['cves'][:5])}\n"
        
        return report
