# 🎨 CTI Dashboard - Visualização Web

**Dashboard interativo para visualizar ameaças coletadas pelo Sistema CTI**

## 🚀 Como Usar

### Iniciar Dashboard
```bash
# Opção 1: Script automático
./start_dashboard.sh

# Opção 2: Comando direto
streamlit run dashboard.py
```

### Acesso
- **URL Local**: http://localhost:8501
- **Compatível**: Chrome, Firefox, Safari, Edge

## 📊 Funcionalidades

### 🏠 Página Inicial
- **Métricas em Tempo Real**: Total de ameaças, críticas, setores afetados
- **Status do Sistema**: Indicadores visuais do estado atual

### 🎛️ Filtros (Sidebar)
- **Severidade**: crítica, alta, média, baixa
- **Setores**: financeiro, infraestrutura, governo, etc.
- **Período**: Últimos 1-30 dias
- **Atualização**: Botão para recarregar dados

### 📈 Gráficos Interativos
- **Pizza**: Distribuição por severidade (com cores)
- **Barras**: Top 10 setores mais afetados

### 📋 Tabela de Ameaças
- **Últimas 20 ameaças** com detalhes organizados
- **Colunas**: Data/Hora, Fonte, Severidade, APTs, Setores, Título

### 🔍 Detalhes da Ameaça
- **Seleção interativa** de ameaças específicas
- **4 Abas organizadas**:
  - 📝 **Descrição**: Técnica + Fluxo de ataque
  - 🎯 **IoCs**: IPs, domínios, hashes, URLs, emails
  - ⚡ **TTPs**: Técnicas MITRE ATT&CK, malware, APTs
  - 🔗 **Links**: Artigo original + feed RSS

## 🎨 Design

### Cores por Severidade
- 🔴 **Crítica**: Vermelho (#FF0000)
- 🟠 **Alta**: Laranja (#FF6B35)
- 🟡 **Média**: Amarelo (#FFD23F)
- 🟢 **Baixa**: Verde (#06FFA5)

### Layout Responsivo
- **Colunas adaptáveis** para diferentes telas
- **Expansores** para organizar informações
- **Tabelas roláveis** para muitos dados

## 🔧 Dependências

```bash
pip install streamlit plotly
```

## 📁 Estrutura de Dados

O dashboard lê arquivos JSON de:
```
data/results/*.json
```

Cada arquivo contém ameaças com:
- `timestamp`: Data/hora da coleta
- `title`: Título da ameaça
- `source`: Fonte RSS
- `threat_info`: Análise do LLM
- `iocs`: Indicadores extraídos
- `classification`: Critérios de alerta

## ⚡ Performance

- **Carregamento**: Lê todos os arquivos JSON uma vez
- **Filtragem**: Aplicada em memória (rápida)
- **Atualização**: Botão manual (não automático)
- **Limite**: Últimas 20 ameaças na tabela principal

## 🐛 Troubleshooting

### "Nenhuma ameaça encontrada"
- Execute o sistema: `python main.py`
- Verifique se há arquivos em `data/results/`

### Dashboard não carrega
- Instale dependências: `pip install streamlit plotly`
- Verifique porta 8501 livre

### Dados desatualizados
- Clique "🔄 Atualizar Dados" no sidebar
- Ou reinicie o dashboard

## 🔗 Integração

O dashboard funciona independente do sistema principal:
- ✅ Pode rodar enquanto CTI coleta dados
- ✅ Lê dados em tempo real dos arquivos JSON
- ✅ Não interfere na operação do daemon

## 🎯 Casos de Uso

1. **Monitoramento**: Visualizar ameaças em tempo real
2. **Análise**: Investigar detalhes específicos de ameaças
3. **Relatórios**: Gerar insights visuais para stakeholders
4. **Filtragem**: Focar em setores ou severidades específicas
5. **Tendências**: Acompanhar evolução temporal das ameaças

---

## 🐛 Correções Recentes

### KeyError: 'title' - RESOLVIDO ✅
**Problema**: Dashboard falhava ao tentar acessar campo 'title' ausente em algumas ameaças.

**Solução**: Acesso seguro ao campo title:
- `t.get('title', 'Sem título')` em vez de `t['title']`
- Fallback para "Sem título" quando ausente

### TypeError: 'NoneType' object is not subscriptable - RESOLVIDO ✅
**Problema**: Erro ao tentar fatiar listas que eram `None` em vez de listas vazias.

**Solução**: Uso de operador `or` para garantir listas vazias:
- `(threat_info.get("apt_groups") or [])[:2]` em vez de `threat_info.get("apt_groups", [])[:2]`
- Trata casos onde campos existem mas são `None`

### use_container_width deprecated - RESOLVIDO ✅
**Problema**: Avisos de depreciação do Streamlit sobre `use_container_width`.

**Solução**: Atualizado para nova API:
- `use_container_width=True` → `width='stretch'`
- Compatível com Streamlit 2026+

### Timestamp access - MELHORADO ✅
**Problema**: Acesso direto a `threat["timestamp"]` poderia falhar.

**Solução**: Acesso seguro com verificação:
- `threat.get("timestamp", "")` com verificação de existência
- Tratamento robusto de timestamps ausentes ou malformados

**Resultado**: Dashboard agora funciona com qualquer estrutura de dados, mesmo incompleta, é compatível com versões recentes do Streamlit, e trata todos os campos de forma segura.