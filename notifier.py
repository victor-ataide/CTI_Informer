"""
Módulo Notifier: Envia alertas de ameaças para Discord via webhook.
Formata mensagens em estilo SOC com todos os detalhes técnicos.
"""

import requests
import logging
import json
from typing import Dict, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class DiscordNotifier:
    """
    Classe responsável por enviar notificações para Discord.
    
    Envia alertas formatados com:
    - Informações de APT/Malware
    - IoCs
    - TTPs
    - Severidade
    - Fonte e link
    """
    
    # Cores Discord (em decimal)
    COLORS = {
        "crítica": 0xFF0000,      # Vermelho
        "alta": 0xFFA500,         # Laranja
        "média": 0xFFFF00,        # Amarelo
        "baixa": 0x00FF00,        # Verde
    }
    
    def __init__(self, webhook_url: Optional[str] = None):
        """
        Inicializa o notificador Discord.
        
        Args:
            webhook_url (Optional[str]): URL do webhook Discord
        """
        self.webhook_url = webhook_url
        
        if webhook_url:
            logger.info(f"Discord Notifier inicializado com webhook")
        else:
            logger.warning("Webhook URL não configurado. Notificações serão desabilidadas.")
    
    def set_webhook_url(self, webhook_url: str) -> None:
        """
        Define a URL do webhook Discord.
        
        Args:
            webhook_url (str): URL do webhook
        """
        self.webhook_url = webhook_url
        logger.info("Webhook URL atualizado")
    
    def _build_embed(self, enriched_data: Dict) -> Dict:
        """
        Constrói um embed Discord a partir dos dados de ameaça.
        
        Args:
            enriched_data (Dict): Dados enriquecidos da ameaça
            
        Returns:
            Dict: Embed formatado para Discord
        """
        threat = enriched_data["threat_info"]
        iocs = enriched_data["iocs"]
        classification = enriched_data["classification"]
        source = enriched_data["source"]
        
        severity = threat.get("severity", "média")
        color = self.COLORS.get(severity, 0x808080)
        
        # Preparar campos
        fields = []
        
        # Campo: APT Groups
        apt_groups = ', '.join(threat.get("apt_groups", ["Desconhecido"]))[:1024]
        fields.append({
            "name": "🎯 Grupos APT",
            "value": apt_groups or "N/A",
            "inline": True
        })
        
        # Campo: Malware
        malware = ', '.join(threat.get("malware_names", ["N/A"]))[:1024]
        fields.append({
            "name": "🦠 Malware",
            "value": malware or "N/A",
            "inline": True
        })
        
        # Campo: Países
        countries = ', '.join(threat.get("affected_countries", ["N/A"]))[:1024]
        fields.append({
            "name": "🌍 Países Afetados",
            "value": countries or "N/A",
            "inline": True
        })
        
        # Campo: Setores
        sectors = ', '.join(threat.get("affected_sectors", ["N/A"]))[:1024]
        fields.append({
            "name": "🏢 Setores",
            "value": sectors or "N/A",
            "inline": True
        })
        
        # Campo: Severidade
        severity_badge = {
            "crítica": "🔴 CRÍTICA",
            "alta": "🟠 ALTA",
            "média": "🟡 MÉDIA",
            "baixa": "🟢 BAIXA"
        }
        fields.append({
            "name": "⚠️ Severidade",
            "value": severity_badge.get(severity, "⚠️ DESCONHECIDA"),
            "inline": True
        })
        
        # Campo: Descrição Técnica
        description = threat.get("technical_description", "N/A")[:1024]
        fields.append({
            "name": "📄 Descrição Técnica",
            "value": description or "N/A",
            "inline": False
        })
        
        # Campo: Como Funciona
        attack_flow = threat.get("attack_flow", "N/A")[:1024]
        fields.append({
            "name": "🔄 Fluxo de Ataque",
            "value": attack_flow or "N/A",
            "inline": False
        })
        
        # Campo: TTPs
        ttps = threat.get("ttps", [])
        ttps_str = ', '.join(ttps[:10]) if ttps else "Não especificado"
        if len(ttps_str) > 1024:
            ttps_str = ttps_str[:1021] + "..."
        fields.append({
            "name": "🛡️ TTPs MITRE ATT&CK",
            "value": ttps_str,
            "inline": False
        })
        
        # Campo: IoCs - IPs
        if iocs.get("ipv4"):
            ips_str = ', '.join(iocs["ipv4"][:5])
            if len(ips_str) > 1024:
                ips_str = ips_str[:1021] + "..."
            fields.append({
                "name": "📍 IPs",
                "value": ips_str,
                "inline": False
            })
        
        # Campo: IoCs - Domínios
        if iocs.get("domains"):
            domains_str = ', '.join(iocs["domains"][:5])
            if len(domains_str) > 1024:
                domains_str = domains_str[:1021] + "..."
            fields.append({
                "name": "🌐 Domínios",
                "value": domains_str,
                "inline": False
            })
        
        # Campo: IoCs - URLs
        if iocs.get("urls"):
            urls_str = ', '.join(iocs["urls"][:3])
            if len(urls_str) > 1024:
                urls_str = urls_str[:1021] + "..."
            fields.append({
                "name": "🔗 URLs",
                "value": urls_str,
                "inline": False
            })
        
        # Campo: IoCs - Hashes
        hashes = iocs.get("hashes", {})
        hashes_str = ""
        if hashes.get("sha256"):
            hashes_str += f"SHA256: `{hashes['sha256'][0]}`\n"
        if hashes.get("md5"):
            hashes_str += f"MD5: `{hashes['md5'][0]}`\n"
        
        if hashes_str:
            if len(hashes_str) > 1024:
                hashes_str = hashes_str[:1021] + "..."
            fields.append({
                "name": "📌 Hashes",
                "value": hashes_str.strip(),
                "inline": False
            })
        
        # Campo: CVEs
        if iocs.get("cves"):
            cves_str = ', '.join(iocs["cves"][:5])
            if len(cves_str) > 1024:
                cves_str = cves_str[:1021] + "..."
            fields.append({
                "name": "⚙️ CVEs",
                "value": cves_str,
                "inline": False
            })
        
        # Construir embed
        embed = {
            "title": "🚨 NOVA AMEAÇA DETECTADA",
            "description": f"**{source['title'][:200]}**",
            "color": color,
            "fields": fields,
            "footer": {
                "text": f"CTI System | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "icon_url": "https://media.discordapp.net/attachments/936659667973431296/1159087625697570836/cti_icon.png"
            },
            "url": source.get("link", ""),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return embed
    
    def send_alert(self, enriched_data: Dict) -> bool:
        """
        Envia um alerta para Discord.
        
        Args:
            enriched_data (Dict): Dados enriquecidos da ameaça
            
        Returns:
            bool: True se enviado com sucesso, False caso contrário
        """
        if not self.webhook_url:
            logger.warning("Webhook URL não configurado. Alerta não será enviado.")
            return False
        
        # Verificar se deve alertar
        if not enriched_data["classification"].get("should_alert"):
            logger.info("Ameaça não atende critérios de alerta. Pulando Discord.")
            return False
        
        try:
            embed = self._build_embed(enriched_data)
            
            payload = {
                "username": "CTI System 🔍",
                "avatar_url": "https://media.discordapp.net/attachments/936659667973431296/1159087625697570836/cti_icon.png",
                "embeds": [embed],
                "content": f"🚨 Ameaça detectada: SEVERIDADE {enriched_data['threat_info'].get('severity', 'DESCONHECIDA').upper()}"
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204:
                logger.info(f"Alerta enviado para Discord com sucesso")
                return True
            else:
                logger.error(f"Erro ao enviar para Discord: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar alerta Discord: {str(e)}")
            return False
    
    def send_batch(self, enriched_threats: List[Dict]) -> int:
        """
        Envia múltiplos alertas para Discord.
        
        Args:
            enriched_threats (List[Dict]): Lista de ameaças enriquecidas
            
        Returns:
            int: Número de alertas enviados com sucesso
        """
        count = 0
        for threat in enriched_threats:
            if self.send_alert(threat):
                count += 1
        
        logger.info(f"Enviados {count}/{len(enriched_threats)} alertas")
        return count
    
    def send_test_alert(self) -> bool:
        """
        Envia um alerta de teste para Discord.
        
        Returns:
            bool: True se enviado com sucesso
        """
        test_data = {
            "threat_info": {
                "apt_groups": ["APT-TEST"],
                "malware_names": ["TestMalware"],
                "affected_countries": ["Brasil"],
                "affected_sectors": ["Financeiro"],
                "severity": "alta",
                "technical_description": "Este é um alerta de teste do sistema CTI.",
                "attack_flow": "1. Teste\n2. Validação\n3. Confirmação",
                "ttps": ["T1566.002", "T1192"],
                "key_findings": "Sistema funcionando corretamente"
            },
            "iocs": {
                "ipv4": ["192.168.1.100"],
                "domains": ["test.example.com"],
                "urls": ["http://test.example.com/malware"],
                "emails": ["attacker@test.com"],
                "hashes": {
                    "md5": ["5d41402abc4b2a76b9719d911017c592"],
                    "sha1": ["356a192b7913b04c54574d18c28d46e6395428ab"],
                    "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
                },
                "files": ["malware.exe"],
                "registry_keys": ["HKLM\\Software\\Test"],
                "cves": ["CVE-2024-1234"]
            },
            "source": {
                "name": "CTI Test Source",
                "link": "http://localhost",
                "title": "Teste de Alerta CTI"
            },
            "classification": {
                "is_high_severity": True,
                "is_financial_related": True,
                "is_critical_infrastructure": False,
                "should_alert": True
            }
        }
        
        logger.info("Enviando alerta de teste...")
        return self.send_alert(test_data)
    
    @staticmethod
    def format_webhook_url(token: str, channel_id: str) -> str:
        """
        Formata uma URL de webhook Discord baseada em token e channel ID.
        
        Args:
            token (str): Token do bot Discord
            channel_id (str): ID do canal
            
        Returns:
            str: URL do webhook
        """
        return f"https://discordapp.com/api/webhooks/{channel_id}/{token}"
