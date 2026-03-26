#!/usr/bin/env python3
"""
CTI System - Plataforma Global de Threat Intelligence
Módulo Principal: Orquestra coleta, análise e alertas

Execução:
    python main.py              # Executa uma única vez
    python main.py --daemon     # Executa periodicamente (a cada 1 hora)
    python main.py --config config.json  # Usa arquivo de config customizado
    python main.py --test       # Envia alerta de teste Discord
"""

import sys
import json
import logging
import argparse
import time
from datetime import datetime
from pathlib import Path
import schedule
from typing import Optional

# Importar módulos do projeto
from collector import ThreatCollector
from parser import ContentParser
from ioc_extractor import IOCExtractor
from intel_engine import IntelligenceEngine
from notifier import DiscordNotifier


class CTISystem:
    """
    Sistema completo de Threat Intelligence.
    
    Fluxo:
    1. Coleta dados de múltiplas fontes RSS
    2. Processa e normaliza conteúdo
    3. Extrai IoCs
    4. Analisa com LLM (Ollama)
    5. Classifica e enriquece dados
    6. Envia alertas para Discord (se crítico/financeiro/infra)
    7. Armazena em JSON
    """
    
    def __init__(self, config_file: str = "config.json"):
        """
        Inicializa o sistema CTI.
        
        Args:
            config_file (str): Caminho do arquivo de configuração
        """
        self.config = self._load_config(config_file)
        self._setup_logging()
        
        logger = logging.getLogger(__name__)
        logger.info("=" * 60)
        logger.info("Iniciando CTI System - Plataforma Global de Threat Intelligence")
        logger.info("=" * 60)
        
        # Inicializar componentes
        self.collector = ThreatCollector(
            timeout=self.config["collector"]["timeout"]
        )
        self.parser = ContentParser()
        self.ioc_extractor = IOCExtractor()
        self.intel_engine = IntelligenceEngine(
            ollama_url=self.config["ollama"]["url"],
            model=self.config["ollama"]["model"]
        )
        self.notifier = DiscordNotifier(
            webhook_url=self.config["discord"]["webhook_url"]
        )
        
        # Criar diretórios se não existirem
        Path(self.config["storage"]["results_dir"]).mkdir(parents=True, exist_ok=True)
        Path("logs").mkdir(exist_ok=True)
        
        logger.info("CTI System inicializado com sucesso")
    
    def _load_config(self, config_file: str) -> dict:
        """
        Carrega arquivo de configuração.
        
        Args:
            config_file (str): Caminho do arquivo config
            
        Returns:
            dict: Configuração
        """
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Arquivo de configuração não encontrado: {config_file}")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"❌ Erro ao parsear JSON em: {config_file}")
            sys.exit(1)
    
    def _setup_logging(self) -> None:
        """Configura logging do sistema."""
        log_config = self.config["logging"]
        
        # Criar handler para arquivo
        handler_file = logging.FileHandler(log_config["log_file"])
        handler_file.setLevel(getattr(logging, log_config["level"]))
        
        # Criar handler para console
        handler_console = logging.StreamHandler()
        handler_console.setLevel(getattr(logging, log_config["level"]))
        
        # Formatar logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler_file.setFormatter(formatter)
        handler_console.setFormatter(formatter)
        
        # Configurar logger root
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_config["level"]))
        root_logger.addHandler(handler_file)
        root_logger.addHandler(handler_console)
    
    def run_once(self) -> None:
        """Executa pipeline completo uma única vez."""
        logger = logging.getLogger(__name__)
        
        logger.info("\n" + "="*60)
        logger.info("🚀 Iniciando execução do pipeline CTI")
        logger.info("="*60)
        
        start_time = time.time()
        
        try:
            # 1. COLETA
            logger.info("\n📥 FASE 1: Coleta de Dados")
            logger.info("-" * 60)
            articles = self._collect_phase()
            
            if not articles:
                logger.warning("Nenhum artigo coletado!")
                return
            
            # 2. PROCESSAMENTO
            logger.info("\n🔧 FASE 2: Processamento de Conteúdo")
            logger.info("-" * 60)
            parsed_articles = self._parse_phase(articles)
            
            # 3. ANÁLISE
            logger.info("\n🧠 FASE 3: Análise de Inteligência")
            logger.info("-" * 60)
            enriched_threats = self._analysis_phase(parsed_articles)
            
            # 4. ALERTAS
            logger.info("\n🚨 FASE 4: Envio de Alertas")
            logger.info("-" * 60)
            alerts_sent = self._alerting_phase(enriched_threats)
            
            # 5. ARMAZENAMENTO
            logger.info("\n💾 FASE 5: Armazenamento de Resultados")
            logger.info("-" * 60)
            self._storage_phase(enriched_threats)
            
            elapsed = time.time() - start_time
            
            logger.info("\n" + "="*60)
            logger.info(f"✅ Pipeline completado com sucesso em {elapsed:.2f}s")
            logger.info(f"   📊 Artigos processados: {len(parsed_articles)}")
            logger.info(f"   🎯 Alertas enviados: {alerts_sent}")
            logger.info("="*60 + "\n")
            
        except Exception as e:
            logger.error(f"❌ Erro durante execução: {str(e)}", exc_info=True)
    
    def _collect_phase(self) -> list:
        """
        Fase 1: Coleta de dados de múltiplas fontes.
        
        Returns:
            list: Artigos coletados
        """
        logger = logging.getLogger(__name__)
        
        logger.info(f"Coletando de {len(self.collector.list_sources())} fontes...")
        articles = self.collector.collect_all()
        
        logger.info(f"✅ {len(articles)} artigos coletados")
        
        return articles
    
    def _parse_phase(self, articles: list) -> list:
        """
        Fase 2: Processamento e normalização de conteúdo.
        
        Args:
            articles (list): Artigos brutos
            
        Returns:
            list: Artigos processados
        """
        logger = logging.getLogger(__name__)
        
        logger.info(f"Processando {len(articles)} artigos...")
        parsed_articles = self.parser.parse_batch(articles)
        
        # Filtrar apenas ameaças (básico)
        threat_articles = [
            a for a in parsed_articles
            if a.get("detected_severity") in ["crítica", "alta", "média"] or
               a.get("is_financial_related") or
               a.get("is_critical_infrastructure")
        ]
        
        logger.info(f"✅ {len(threat_articles)} ameaças identificadas")
        
        return threat_articles
    
    def _analysis_phase(self, articles: list) -> list:
        """
        Fase 3: Análise com LLM e extração de IoCs.
        
        Args:
            articles (list): Artigos processados
            
        Returns:
            list: Dados enriquecidos
        """
        logger = logging.getLogger(__name__)
        
        enriched_threats = []
        
        for i, article in enumerate(articles, 1):
            logger.info(f"Analisando {i}/{len(articles)}: {article.get('title', 'N/A')[:60]}")
            
            try:
                # Extrair informações com LLM
                threat_info = self.intel_engine.extract_threat_info(
                    article.get("full_text", "")
                )
                
                # Extrair IoCs
                iocs = self.ioc_extractor.extract_all(
                    article.get("full_text", "")
                )
                
                # Enriquecer dados
                enriched = self.intel_engine.enrich_threat_data(
                    article, threat_info, iocs
                )
                
                enriched_threats.append(enriched)
                
            except Exception as e:
                logger.error(f"Erro ao analisar artigo: {str(e)}")
                continue
        
        logger.info(f"✅ {len(enriched_threats)} ameaças analisadas")
        
        return enriched_threats
    
    def _alerting_phase(self, enriched_threats: list) -> int:
        """
        Fase 4: Envio de alertas para Discord.
        
        Args:
            enriched_threats (list): Ameaças enriquecidas
            
        Returns:
            int: Número de alertas enviados
        """
        logger = logging.getLogger(__name__)
        
        if not self.config["discord"]["enabled"]:
            logger.warning("⚠️  Discord desabilitado na configuração")
            return 0
        
        logger.info(f"Enviando alertas para Discord...")
        alerts_sent = self.notifier.send_batch(enriched_threats)
        
        logger.info(f"✅ {alerts_sent} alertas enviados")
        
        return alerts_sent
    
    def _storage_phase(self, enriched_threats: list) -> None:
        """
        Fase 5: Armazenamento de resultados.
        
        Args:
            enriched_threats (list): Ameaças enriquecidas
        """
        logger = logging.getLogger(__name__)
        
        if not enriched_threats:
            logger.info("Nenhuma ameaça para armazenar")
            return
        
        # Gerar nome do arquivo
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.config['storage']['results_dir']}/threats_{timestamp}.json"
        
        # Salvar em JSON
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(enriched_threats, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ Resultados salvos em: {filename}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar resultados: {str(e)}")
    
    def run_daemon(self) -> None:
        """Executa o sistema periodicamente (daemon)."""
        logger = logging.getLogger(__name__)
        
        interval = self.config["scheduler"]["interval_hours"]
        
        logger.info(f"\n🔄 Iniciando modo daemon")
        logger.info(f"⏰ Executando a cada {interval} hora(s)")
        logger.info(f"   (Pressione Ctrl+C para sair)\n")
        
        # Rodar na startup se configurado
        if self.config["scheduler"]["run_on_startup"]:
            self.run_once()
        
        # Agendar execuções periódicas
        schedule.every(interval).hours.do(self.run_once)
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(30)  # Verificar a cada 30 segundos
        except KeyboardInterrupt:
            logger.info("\n\n🛑 Daemon interrompido pelo usuário")
            sys.exit(0)
    
    def test_discord(self) -> None:
        """Envia um alerta de teste para Discord."""
        logger = logging.getLogger(__name__)
        
        logger.info("📤 Enviando alerta de teste para Discord...")
        
        if self.notifier.send_test_alert():
            logger.info("✅ Alerta de teste enviado com sucesso!")
        else:
            logger.error("❌ Falha ao enviar alerta de teste")


def main():
    """Função principal."""
    parser = argparse.ArgumentParser(
        description="CTI System - Plataforma Global de Threat Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python main.py                      # Executar uma única vez
  python main.py --daemon             # Executar periodicamente (daemon)
  python main.py --config custom.json # Usar arquivo de config customizado
  python main.py --test               # Testar envio para Discord
        """
    )
    
    parser.add_argument(
        "--daemon", "-d",
        action="store_true",
        help="Executa em modo daemon (repetidamente)"
    )
    parser.add_argument(
        "--config", "-c",
        default="config.json",
        help="Arquivo de configuração (padrão: config.json)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Envia alerta de teste para Discord"
    )
    
    args = parser.parse_args()
    
    # Inicializar sistema
    cti = CTISystem(config_file=args.config)
    
    # Executar com base em argumentos
    if args.test:
        cti.test_discord()
    elif args.daemon:
        cti.run_daemon()
    else:
        cti.run_once()


if __name__ == "__main__":
    main()
