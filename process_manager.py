#!/usr/bin/env python3
"""
CTI Process Manager - Gerenciador robusto de daemon + dashboard
Mantém ambos os processos rodando com monitoramento em tempo real
"""

import subprocess
import time
import signal
import sys
import os
import logging
from pathlib import Path
from datetime import datetime
import json

# Configurar logging
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / "process_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ProcessManager:
    def __init__(self, port=8502):
        self.port = port
        self.daemon_process = None
        self.dashboard_process = None
        self.running = True
        pass
    
    def start_daemon(self):
        """Inicia o daemon CTI (atualiza a cada 1 hora)"""
        try:
            logger.info("🚀 Iniciando CTI daemon...")
            self.daemon_process = subprocess.Popen(
                ["python", "main.py", "--daemon"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            logger.info("✅ CTI daemon iniciado com sucesso (PID: %d)", self.daemon_process.pid)
            return True
        except Exception as e:
            logger.error("❌ Erro ao iniciar daemon: %s", e)
            return False
    
    def start_dashboard(self):
        """Inicia o dashboard Streamlit"""
        try:
            logger.info("📊 Iniciando dashboard Streamlit na porta %d...", self.port)
            self.dashboard_process = subprocess.Popen(
                ["streamlit", "run", "dashboard.py", 
                 "--server.port", str(self.port),
                 "--server.headless", "false",
                 "--logger.level=warning"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            logger.info("✅ Dashboard iniciado com sucesso (PID: %d)", self.dashboard_process.pid)
            return True
        except Exception as e:
            logger.error("❌ Erro ao iniciar dashboard: %s", e)
            return False
    
    def check_processes(self):
        """Monitora estado dos processos"""
        daemon_alive = False
        dashboard_alive = False
        
        if self.daemon_process:
            daemon_alive = self.daemon_process.poll() is None
            if not daemon_alive:
                logger.warning("⚠️  Daemon morreu! Reiniciando...")
                self.daemon_process = None
                self.start_daemon()
        
        if self.dashboard_process:
            dashboard_alive = self.dashboard_process.poll() is None
            if not dashboard_alive:
                logger.warning("⚠️  Dashboard morreu! Reiniciando...")
                self.dashboard_process = None
                self.start_dashboard()
        
        return daemon_alive or self.daemon_process is None, dashboard_alive or self.dashboard_process is None
    
    def handle_signal(self, signum, frame):
        """Trata sinais de interrupção (Ctrl+C)"""
        logger.info("\n🛑 Recebido sinal de interrupção...")
        self.running = False
        self.stop_all()
        sys.exit(0)
    
    def stop_all(self):
        """Para ambos os processos"""
        logger.info("🛑 Parando todos os processos...")
        
        if self.daemon_process:
            try:
                self.daemon_process.terminate()
                self.daemon_process.wait(timeout=5)
                logger.info("✅ Daemon parado")
            except subprocess.TimeoutExpired:
                self.daemon_process.kill()
                logger.warning("⚠️  Daemon forçadamente killado")
        
        if self.dashboard_process:
            try:
                self.dashboard_process.terminate()
                self.dashboard_process.wait(timeout=5)
                logger.info("✅ Dashboard parado")
            except subprocess.TimeoutExpired:
                self.dashboard_process.kill()
                logger.warning("⚠️  Dashboard forçadamente killado")
    
    def run(self):
        """Loop principal de gerenciamento"""
        logger.info("=" * 60)
        logger.info("🎯 CTI Process Manager - Iniciando...")
        logger.info("=" * 60)
        
        # Registrar handlers de sinais
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
        
        # Iniciar processos
        if not self.start_daemon():
            logger.error("Falha ao iniciar daemon. Abortando.")
            sys.exit(1)
        
        time.sleep(2)  # Esperar daemon começar
        
        if not self.start_dashboard():
            logger.error("Falha ao iniciar dashboard. Abortando.")
            self.stop_all()
            sys.exit(1)
        
        time.sleep(2)  # Dashboard pronto
        
        logger.info("=" * 60)
        logger.info("✅ Todos os processos iniciados com sucesso!")
        logger.info("=" * 60)
        logger.info("")
        logger.info("📊 Dashboard: http://localhost:%d", self.port)
        logger.info("💾 Daemon: Executando a cada 1 hora")
        logger.info("📧 Discord: Recebendo alertas deduplicated")
        logger.info("")
        logger.info("Pressione Ctrl+C para parar todos os processos")
        logger.info("=" * 60)
        
        # Loop de monitoramento
        while self.running:
            try:
                daemon_ok, dashboard_ok = self.check_processes()
                
                if not daemon_ok or not dashboard_ok:
                    logger.warning(
                        "⚠️  Status - Daemon: %s | Dashboard: %s",
                        "✅ OK" if daemon_ok else "❌ ERRO",
                        "✅ OK" if dashboard_ok else "❌ ERRO"
                    )
                
                time.sleep(10)  # Check a cada 10 segundos
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error("Erro no loop de monitoramento: %s", e)
                time.sleep(5)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Gerenciador de processos CTI - daemon + dashboard"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8502,
        help="Porta para o dashboard (default: 8502)"
    )
    
    args = parser.parse_args()
    
    try:
        manager = ProcessManager(port=args.port)
        manager.run()
    except Exception as e:
        logger.critical("Erro crítico: %s", e)
        sys.exit(1)
