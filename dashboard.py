#!/usr/bin/env python3
"""
CTI System Dashboard - Visualização Web Local
Dashboard Streamlit para visualizar ameaças coletadas pelo sistema CTI

Uso:
    streamlit run dashboard.py

Acesso: http://localhost:8501
"""

import streamlit as st
from streamlit_autorefresh import st_autorefresh
import json
import pandas as pd
from datetime import datetime, timedelta
import os
import glob
import hashlib
from typing import List, Dict, Any
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv
from src.cti.deduplicator import ThreatDeduplicator
from src.cti.db import save_threats_to_db, load_threats_from_db

# Configuração da página
st.set_page_config(
    page_title="🚨 CTI System Dashboard",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Auto refresh padrão: 60 segundos
refresh_count = st_autorefresh(interval=60_000, limit=None, key="dashboard_autorefresh")

# Carregar variáveis de ambiente
load_dotenv()

# Título principal
st.title("🚨 Sistema de Inteligência de Ameaças Cibernéticas")
st.caption(f"Atualização automática ativada (60s). Contador: {refresh_count}")

# Função para título seguro

def get_threat_title(threat: Dict[str, Any]) -> str:
    title = threat.get("title") or threat.get("source", {}).get("title") or threat.get("source", {}).get("name")
    if not title or title.strip() == "":
        return "Sem título"
    return title


def get_ioc_hash(iocs: Dict[str, Any]) -> str:
    dedup = ThreatDeduplicator()
    try:
        return dedup._generate_ioc_hash(iocs)
    except Exception:
        merged = []
        for kind in ["ipv4", "ipv6", "domains", "urls", "emails", "cves"]:
            merged.extend(sorted(iocs.get(kind, [])))
        hashes = iocs.get("hashes", {})
        for hdict in [hashes.get("sha256", []), hashes.get("sha1", []), hashes.get("md5", [])]:
            merged.extend(sorted(hdict))
        return hashlib.sha256("|".join(merged).encode()).hexdigest()


def remove_duplicate_threats(threat_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []
    for threat in threat_list:
        iocs = threat.get("iocs", {})
        h = get_ioc_hash(iocs)
        if h not in seen:
            seen.add(h)
            unique.append(threat)
    return unique


st.markdown("---")

# Funções auxiliares
def load_threats_data() -> List[Dict]:
    """Carrega dados de ameaças do diretório results e sincroniza com banco SQLite"""
    results_dir = "data/results"
    threats = []

    if not os.path.exists(results_dir):
        return []

    # Buscar todos os arquivos JSON de resultados
    json_files = glob.glob(os.path.join(results_dir, "*.json"))

    for file_path in json_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_threats = json.load(f)
                if isinstance(file_threats, list):
                    threats.extend(file_threats)
                else:
                    threats.append(file_threats)
        except Exception as e:
            st.warning(f"Erro ao carregar {file_path}: {e}")

    # Remover ameaças duplicadas (por IoC)
    threats = remove_duplicate_threats(threats)

    # Persistir no banco de dados conforme config
    db_config = {
        "engine": "sqlite",
        "sqlite_path": "data/cti_threats.db"
    }

    if os.path.exists("config.json"):
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                app_config = json.load(f)
                if "database" in app_config:
                    db_config = app_config["database"]
        except Exception:
            pass

    # Adicionar credenciais do .env se PostgreSQL
    if db_config.get("engine") == "postgresql":
        db_config["postgresql"] = {
            "host": os.getenv("POSTGRES_HOST", "localhost"),
            "port": int(os.getenv("POSTGRES_PORT", 5432)),
            "dbname": os.getenv("POSTGRES_DBNAME", "cti"),
            "user": os.getenv("POSTGRES_USER", ""),
            "password": os.getenv("POSTGRES_PASSWORD", "")
        }

    try:
        save_threats_to_db(threats, db_config)
        db_threats = load_threats_from_db(db_config)
    except Exception as e:
        st.warning(f"Falha ao salvar/carregar banco de dados: {e}")
        db_threats = []

    if db_threats:
        return db_threats
    return threats

def get_severity_color(severity: str) -> str:
    """Retorna cor baseada na severidade"""
    colors = {
        "crítica": "#FF0000",
        "alta": "#FF6B35",
        "média": "#FFD23F",
        "baixa": "#06FFA5"
    }
    return colors.get(severity.lower(), "#808080")

def format_timestamp(timestamp: str) -> str:
    """Formata timestamp para exibição"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%d/%m/%Y %H:%M")
    except:
        return timestamp

def consolidate_iocs(threat_list: List[Dict]) -> Dict[str, List[str]]:
    """Consolida todos os IoCs de uma lista de ameaças, removendo duplicatas"""
    consolidated = {
        "ipv4": set(),
        "ipv6": set(),
        "domains": set(),
        "urls": set(),
        "emails": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
        "cves": set()
    }
    
    for threat in threat_list:
        iocs = threat.get("iocs", {})
        
        # IPv4 e IPv6
        consolidated["ipv4"].update(iocs.get("ipv4", []))
        consolidated["ipv6"].update(iocs.get("ipv6", []))
        
        # Domínios
        consolidated["domains"].update(iocs.get("domains", []))
        
        # URLs
        consolidated["urls"].update(iocs.get("urls", []))
        
        # Emails
        consolidated["emails"].update(iocs.get("emails", []))
        
        # Hashes
        hashes = iocs.get("hashes", {})
        consolidated["md5"].update(hashes.get("md5", []))
        consolidated["sha1"].update(hashes.get("sha1", []))
        consolidated["sha256"].update(hashes.get("sha256", []))
        
        # CVEs
        consolidated["cves"].update(iocs.get("cves", []))
    
    # Converter sets para listas ordenadas
    return {k: sorted(list(v)) for k, v in consolidated.items()}

def get_iocs_with_source(threat_list: List[Dict]) -> Dict[str, List[Dict]]:
    """Consolida IoCs com informação da ameaça de origem"""
    iocs_with_source = {
        "ipv4": [],
        "ipv6": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
        "cves": []
    }
    
    seen = {}  # Para evitar duplicatas
    
    for threat in threat_list:
        threat_title = get_threat_title(threat)
        threat_severity = threat.get("threat_info", {}).get("severity", "desconhecida")
        iocs = threat.get("iocs", {})
        
        # IPv4
        for ip in iocs.get("ipv4", []):
            key = f"ipv4:{ip}"
            if key not in seen:
                iocs_with_source["ipv4"].append({"IoC": ip, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        # IPv6
        for ip in iocs.get("ipv6", []):
            key = f"ipv6:{ip}"
            if key not in seen:
                iocs_with_source["ipv6"].append({"IoC": ip, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        # Domínios
        for domain in iocs.get("domains", []):
            key = f"domain:{domain}"
            if key not in seen:
                iocs_with_source["domains"].append({"IoC": domain, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        # URLs
        for url in iocs.get("urls", []):
            key = f"url:{url}"
            if key not in seen:
                iocs_with_source["urls"].append({"IoC": url, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        # Emails
        for email in iocs.get("emails", []):
            key = f"email:{email}"
            if key not in seen:
                iocs_with_source["emails"].append({"IoC": email, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        # Hashes
        hashes = iocs.get("hashes", {})
        for h in hashes.get("md5", []):
            key = f"md5:{h}"
            if key not in seen:
                iocs_with_source["md5"].append({"IoC": h, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        for h in hashes.get("sha1", []):
            key = f"sha1:{h}"
            if key not in seen:
                iocs_with_source["sha1"].append({"IoC": h, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        for h in hashes.get("sha256", []):
            key = f"sha256:{h}"
            if key not in seen:
                iocs_with_source["sha256"].append({"IoC": h, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
        
        # CVEs
        for cve in iocs.get("cves", []):
            key = f"cve:{cve}"
            if key not in seen:
                iocs_with_source["cves"].append({"IoC": cve, "Ameaça": threat_title, "Severidade": threat_severity})
                seen[key] = True
    
    return iocs_with_source


def render_ioc_source_table(ioc_key: str, iocs_with_source: Dict[str, List[Dict]]):
    data = iocs_with_source.get(ioc_key, [])
    if data:
        st.dataframe(pd.DataFrame(data), width='stretch')
        # botão de copiar
        st.code("\n".join([x['IoC'] for x in data]), language=None)
    else:
        st.info(f"Nenhum {ioc_key} identificado.")

# Carregar dados
threats = load_threats_data()

# Sidebar com filtros
st.sidebar.title("🎛️ Filtros e Controles")

if threats:
    # Filtro de severidade - com tratamento de erro
    severities = []
    for t in threats:
        try:
            severity = t.get("threat_info", {}).get("severity", "desconhecida")
            if severity and severity != "desconhecida":
                severities.append(severity)
        except:
            continue

    severities = sorted(list(set(severities)))
    if not severities:
        severities = ["crítica", "alta", "média", "baixa"]

    severity_filter = st.sidebar.multiselect(
        "Severidade",
        severities,
        default=[s for s in severities if s in ["crítica", "alta"]]
    )

    search_query = st.sidebar.text_input("🔍 Buscar (texto, APT, malware)", value="")
    diamond_mode = st.sidebar.checkbox("💎 Ativar modo Diamond Model", value=False)

    # Filtro de setores - com tratamento de erro
    all_sectors = set()
    for t in threats:
        try:
            sectors = t.get("threat_info", {}).get("affected_sectors", [])
            if sectors:
                all_sectors.update(sectors)
        except:
            continue
    sectors = sorted(list(all_sectors))
    sector_filter = st.sidebar.multiselect("Setores Afetados", sectors)

    # Filtro de período
    days_filter = st.sidebar.slider("Dias recentes", 1, 30, 7)

    # Aplicar filtros
    filtered_threats = []
    cutoff_date = datetime.now() - timedelta(days=days_filter)

    for threat in threats:
        try:
            timestamp = threat.get("timestamp", "")
            if timestamp:
                threat_date = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if threat_date < cutoff_date:
                    continue
        except:
            pass  # Se não conseguir parsear data, incluir

        # Verificar severidade com segurança
        threat_severity = threat.get("threat_info", {}).get("severity", "desconhecida")
        if threat_severity not in severity_filter:
            continue

        if sector_filter:
            threat_sectors = threat.get("threat_info", {}).get("affected_sectors", [])
            if not any(sector in threat_sectors for sector in sector_filter):
                continue

        filtered_threats.append(threat)

    if search_query and filtered_threats:
        q = search_query.strip().lower()
        def match_search(threat: Dict[str, Any]) -> bool:
            if q in get_threat_title(threat).lower():
                return True
            ti = threat.get("threat_info", {})
            if q in (ti.get("technical_description", "") or "").lower():
                return True
            if any(q in w.lower() for w in ti.get("apt_groups", [])):
                return True
            if any(q in w.lower() for w in ti.get("malware_names", [])):
                return True
            attack_flow = ti.get("attack_flow", "")
            if isinstance(attack_flow, str):
                words = attack_flow.split()
            else:
                words = attack_flow if isinstance(attack_flow, list) else []
            if any(q in w.lower() for w in words):
                return True
            return False

        filtered_threats = [t for t in filtered_threats if match_search(t)]

    # Botão de atualização
    if st.sidebar.button("🔄 Atualizar Dados"):
        st.rerun()

else:
    filtered_threats = []
    st.sidebar.info("Nenhum dado encontrado ainda.")

# Layout principal
if not threats:
    st.info("🚀 **Bem-vindo ao Dashboard CTI!**")
    st.markdown("""
    ### Como usar:
    1. **Configure o sistema** seguindo o `GUIA_RAPIDO.md`
    2. **Execute uma coleta**: `python main.py`
    3. **Os dados aparecerão aqui automaticamente**

    ### Funcionalidades:
    - 📊 **Métricas em tempo real** de ameaças
    - 🔍 **Filtros avançados** por severidade e setor
    - 📈 **Gráficos interativos** de tendências
    - 📋 **Detalhes completos** de cada ameaça
    - 🎯 **Visualização de IoCs** e TTPs
    """)

    st.markdown("---")
    st.subheader("📖 Próximos Passos")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        **1. Configuração Inicial**
        ```bash
        # Ativar ambiente virtual
        source venv/bin/activate

        # Instalar dependências
        pip install -r requirements.txt

        # Iniciar Ollama (em outro terminal)
        ollama serve
        ```

        **2. Configurar Discord**
        - Edite `config.json`
        - Adicione webhook do Discord
        """)

    with col2:
        st.markdown("""
        **3. Primeira Execução**
        ```bash
        # Teste do sistema
        python main.py --test

        # Coleta única
        python main.py

        # Modo daemon (24/7)
        python main.py --daemon
        ```

        **4. Visualizar**
        ```bash
        # Este dashboard
        streamlit run dashboard.py
        ```
        """)

else:
    # Métricas principais
    st.subheader("📊 Métricas Gerais")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        total = len(threats)
        st.metric("Total de Ameaças", f"{total:,}")

    with col2:
        criticas = len([t for t in threats if t.get("threat_info", {}).get("severity") == "crítica"])
        st.metric("Críticas", criticas, delta=f"{criticas/total*100:.1f}%" if total > 0 else "0%")

    with col3:
        financeiras = len([t for t in threats if t.get("classification", {}).get("is_financial_related")])
        st.metric("Financeiro", financeiras)

    with col4:
        infraestrutura = len([t for t in threats if t.get("classification", {}).get("is_critical_infrastructure")])
        st.metric("Infraestrutura", infraestrutura)

    with col5:
        filtradas = len(filtered_threats)
        st.metric("Filtradas", filtradas)

    st.markdown("---")

    # Países afetados (nova aba/visão)
    st.subheader("🌍 Distribuição por País")
    country_counts = {}
    for threat in filtered_threats:
        for country in threat.get("affected_countries", []):
            if not country:
                continue
            country_counts[country] = country_counts.get(country, 0) + 1

    if country_counts:
        country_df = pd.DataFrame(
            sorted(country_counts.items(), key=lambda x: x[1], reverse=True),
            columns=["País", "Ocorrências"]
        )
        st.bar_chart(country_df.set_index("País"))
    else:
        st.info("Nenhum país detectado nas ameaças atuais.")

    st.markdown("---")

    # Gráficos
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📈 Distribuição por Severidade")

        severity_counts = {}
        for threat in filtered_threats:
            sev = threat.get("threat_info", {}).get("severity", "desconhecida")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts:
            fig = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                color=list(severity_counts.keys()),
                color_discrete_map={
                    "crítica": "#FF0000",
                    "alta": "#FF6B35",
                    "média": "#FFD23F",
                    "baixa": "#06FFA5"
                }
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, width='stretch')

    with col2:
        st.subheader("🏢 Setores Afetados")

        sector_counts = {}
        for threat in filtered_threats:
            sectors = threat.get("threat_info", {}).get("affected_sectors", [])
            for sector in sectors:
                sector_counts[sector] = sector_counts.get(sector, 0) + 1

        if sector_counts:
            # Top 10 setores
            top_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            fig = px.bar(
                x=[s[0] for s in top_sectors],
                y=[s[1] for s in top_sectors],
                color=[s[1] for s in top_sectors],
                color_continuous_scale="Reds"
            )
            fig.update_layout(xaxis_title="Setor", yaxis_title="Quantidade")
            st.plotly_chart(fig, width='stretch')

    st.markdown("---")

    # Diamond model
    if diamond_mode:
        st.subheader("💎 Diamond Model - Visão de Ameaças")
        diamond_items = []
        for threat in filtered_threats:
            ti = threat.get("threat_info", {})
            adversary = ", ".join(ti.get("apt_groups", [])) or "Desconhecido"
            capabilities = ", ".join(ti.get("malware_names", [])) or ", ".join(threat.get("iocs", {}).get("hashes", {}).get("sha256", [])[:3]) or "Desconhecido"
            infrastructure_sources = []
            infra_iocs = threat.get("iocs", {})
            infrastructure_sources.extend(infra_iocs.get("domains", [])[:2])
            infrastructure_sources.extend(infra_iocs.get("ipv4", [])[:2])
            infrastructure_sources.extend(infra_iocs.get("urls", [])[:2])
            infrastructure = ", ".join(infrastructure_sources) if infrastructure_sources else "Desconhecido"
            victim = ", ".join(ti.get("affected_sectors", [])[:2]) or "Desconhecido"
            diamond_items.append({
                "Ameaça": get_threat_title(threat),
                "Adversary": adversary,
                "Infrastructure": infrastructure,
                "Capability": capabilities,
                "Victim": victim,
                "Severidade": ti.get("severity", "desconhecida")
            })

        if diamond_items:
            st.dataframe(pd.DataFrame(diamond_items), width='stretch')
        else:
            st.info("Nenhuma ameaça disponível para o modo Diamond.")

        st.markdown("---")

    # Tabela de ameaças
    st.subheader("📋 Ameaças Recentes")

    if filtered_threats:
        # Preparar dados para tabela
        table_data = []
        for threat in filtered_threats:  
            threat_info = threat.get("threat_info", {})
            countries = ", ".join(sorted(set(threat.get("affected_countries", []))))
            table_data.append({
                "Data/Hora": format_timestamp(threat.get("timestamp", "")),
                "Fonte": threat.get("source", {}).get("name", "Desconhecida"),
                "Severidade": threat_info.get("severity", "desconhecida").upper(),
                "APTs": ", ".join((threat_info.get("apt_groups") or [])[:2]),
                "Malware": ", ".join((threat_info.get("malware_names") or [])[:2]),
                "Países": countries or "N/A",
                "Título": get_threat_title(threat)[:50] + "..." if len(get_threat_title(threat)) > 50 else get_threat_title(threat)
            })

        df = pd.DataFrame(table_data)
        st.dataframe(df, width='stretch')
    else:
        st.info("Nenhuma ameaça encontrada com os filtros atuais.")

    # Detalhes da ameaça selecionada
    st.markdown("---")
    st.subheader("🔍 Detalhes da Ameaça")
    
    if filtered_threats:
        # Selecionar ameaça
        threat_options = [f"{format_timestamp(t.get('timestamp', ''))} - {get_threat_title(t)[:40]}..." for t in filtered_threats]
        selected_title = st.selectbox("Selecione uma ameaça para ver detalhes:", threat_options)
        selected_idx = threat_options.index(selected_title) if selected_title in threat_options else 0

        if filtered_threats:
            threat = filtered_threats[selected_idx]

            # Header com severidade colorida
            severity_color = get_severity_color(threat.get("threat_info", {}).get("severity", "desconhecida"))
            st.markdown(f"### 🎯 {get_threat_title(threat)}")
            st.markdown(f"**Severidade:** <span style='color:{severity_color};font-weight:bold'>{threat.get('threat_info', {}).get('severity', 'desconhecida').upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"**Fonte:** {threat.get('source', {}).get('name', 'Desconhecida')} | **Data:** {format_timestamp(threat['timestamp'])}")

            # Tabs para organizar informações
            tab1, tab2, tab3, tab4 = st.tabs(["📝 Descrição", "🎯 IoCs", "⚡ TTPs", "🔗 Links"])

            with tab1:
                col1, col2 = st.columns(2)

                threat_info = threat.get("threat_info", {})
                classification = threat.get("classification", {})

                with col1:
                    st.markdown("**Descrição Técnica:**")
                    st.write(threat_info.get("technical_description", "Não disponível"))

                with col2:
                    st.markdown("**Fluxo de Ataque:**")
                    st.write(threat_info.get("attack_flow", "Não especificado"))

                    st.markdown("**Países afetados:**")
                    countries = sorted(set(threat.get("affected_countries", [])))
                    st.write(", ".join(countries) if countries else "N/A")

                    st.markdown("**Classificação:**")
                    if classification.get("is_financial_related"):
                        st.success("🏦 Relacionado ao Setor Financeiro")
                    if classification.get("is_critical_infrastructure"):
                        st.error("🏭 Infraestrutura Crítica")

            with tab2:
                iocs = threat.get("iocs", {})

                if iocs.get("ipv4"):
                    st.markdown("**📍 Endereços IP:**")
                    for ip in iocs["ipv4"][:10]:
                        st.code(ip, language=None)
                    if len(iocs["ipv4"]) > 10:
                        st.info(f"E mais {len(iocs['ipv4']) - 10} IPs...")

                if iocs.get("domains"):
                    st.markdown("**🌐 Domínios:**")
                    for domain in iocs["domains"][:10]:
                        st.code(domain, language=None)
                    if len(iocs["domains"]) > 10:
                        st.info(f"E mais {len(iocs['domains']) - 10} domínios...")

                if iocs.get("hashes", {}).get("sha256"):
                    st.markdown("**🔐 Hashes SHA256:**")
                    for hash_val in iocs["hashes"]["sha256"][:5]:
                        st.code(hash_val, language=None)
                    if len(iocs["hashes"]["sha256"]) > 5:
                        st.info(f"E mais {len(iocs['hashes']['sha256']) - 5} hashes...")

                if iocs.get("urls"):
                    st.markdown("**🔗 URLs:**")
                    for url in iocs["urls"][:5]:
                        st.code(url, language=None)

                if iocs.get("emails"):
                    st.markdown("**📧 Emails:**")
                    for email in iocs["emails"][:5]:
                        st.code(email, language=None)

            with tab3:
                ttps = threat_info.get("ttps", [])
                if ttps:
                    st.markdown("**Técnicas MITRE ATT&CK:**")
                    for ttp in ttps:
                        st.code(ttp, language=None)
                else:
                    st.info("Nenhuma TTP identificada.")

                malware = threat_info.get("malware_names", [])
                if malware:
                    st.markdown("**🦠 Malware Identificado:**")
                    for mal in malware:
                        st.code(mal, language=None)

                apts = threat_info.get("apt_groups", [])
                if apts:
                    st.markdown("**🎭 Grupos APT:**")
                    for apt in apts:
                        st.code(apt, language=None)

            with tab4:
                st.markdown("**🔗 Link Original:**")
                url = threat.get("url") or threat.get("source", {}).get("link") or threat.get("source", {}).get("feed_url")
                if url:
                    # Garantir URL completa
                    if not (url.startswith("http://") or url.startswith("https://")):
                        url = "http://" + url

                    # Link para nova aba usando HTML
                    st.markdown(
                        f"<a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">🔗 Abrir artigo completo</a>",
                        unsafe_allow_html=True
                    )

                    # Botão de copiar para clipboard via HTML + JS
                    st.markdown(
                        f"<button onclick=\"navigator.clipboard.writeText('{url}').then(() => alert('Link copiado!')).catch(() => alert('Falha ao copiar.'));\">📋 Copiar link</button>",
                        unsafe_allow_html=True
                    )

                    st.write(f"URL: {url}")
                else:
                    st.warning("Link da ameaça indisponível")

                feed_link = threat.get("source", {}).get("feed_url")
                if feed_link:
                    st.markdown(f"**📡 Feed RSS:** {feed_link}")

    # Aba de IoCs Consolidados - COM ORIGEM
    st.markdown("---")
    st.subheader("🔍 IoCs Consolidados (Por Vulnerabilidade)")

    # Consolidar IoCs das ameaças filtradas
    consolidated_iocs = consolidate_iocs(filtered_threats)
    iocs_with_source = get_iocs_with_source(filtered_threats)

    # Calcular totais
    total_iocs = sum(len(ioc_list) for ioc_list in consolidated_iocs.values())

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total IoCs", total_iocs)
    with col2:
        st.metric("Domínios", len(consolidated_iocs["domains"]))
    with col3:
        st.metric("IPs", len(consolidated_iocs["ipv4"]) + len(consolidated_iocs["ipv6"]))
    with col4:
        st.metric("Hashes", len(consolidated_iocs["md5"]) + len(consolidated_iocs["sha1"]) + len(consolidated_iocs["sha256"]))
    with col5:
        st.metric("CVEs", len(consolidated_iocs["cves"]))
    
    # Criar abas para cada tipo de IoC
    if total_iocs > 0:
        ioc_tab1, ioc_tab2, ioc_tab3, ioc_tab4, ioc_tab5, ioc_tab6, ioc_tab7, ioc_tab8, ioc_tab9 = st.tabs([
            f"🌐 Domínios ({len(consolidated_iocs['domains'])})",
            f"📍 IPv4 ({len(consolidated_iocs['ipv4'])})",
            f"🔗 IPv6 ({len(consolidated_iocs['ipv6'])})",
            f"🔗 URLs ({len(consolidated_iocs['urls'])})",
            f"📧 Emails ({len(consolidated_iocs['emails'])})",
            f"🔐 SHA256 ({len(consolidated_iocs['sha256'])})",
            f"🔐 MD5 ({len(consolidated_iocs['md5'])})",
            f"🔐 SHA1 ({len(consolidated_iocs['sha1'])})",
            f"⚠️ CVEs ({len(consolidated_iocs['cves'])})"
        ])
        
        # Domínios
        with ioc_tab1:
            render_ioc_source_table("domains", iocs_with_source)

        # IPv4
        with ioc_tab2:
            render_ioc_source_table("ipv4", iocs_with_source)

        # IPv6
        with ioc_tab3:
            render_ioc_source_table("ipv6", iocs_with_source)

        # URLs
        with ioc_tab4:
            render_ioc_source_table("urls", iocs_with_source)

        # Emails
        with ioc_tab5:
            render_ioc_source_table("emails", iocs_with_source)

        # SHA256
        with ioc_tab6:
            render_ioc_source_table("sha256", iocs_with_source)

        # MD5
        with ioc_tab7:
            render_ioc_source_table("md5", iocs_with_source)

        # SHA1
        with ioc_tab8:
            render_ioc_source_table("sha1", iocs_with_source)

        # CVEs
        with ioc_tab9:
            render_ioc_source_table("cves", iocs_with_source)
    else:
        st.info("Nenhum IoC disponível com os filtros atuais.")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <small>🚨 CTI System Dashboard | Desenvolvido para Inteligência de Ameaças Cibernéticas</small>
</div>
""", unsafe_allow_html=True)