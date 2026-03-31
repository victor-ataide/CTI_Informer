const state = {
  token: localStorage.getItem('cti_token') || '',
  theme: localStorage.getItem('cti_theme') || 'dark',
  allThreats: [],
  visibleThreats: [],
  sourceFilter: 'all',
  severityFilter: 'all',
  analysisFilter: 'all',
  typeFilter: 'all',
  sortFilter: 'date_desc',
  textFilter: '',
  lastFinishedAt: null,
  activeTab: 'threats',
  iocData: null,
};

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalize(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim();
}

function setStatus(text) {
  const el = document.getElementById('statusBar');
  if (el) el.textContent = text;
}

function toast(message, icon = 'i') {
  const root = document.getElementById('toast');
  if (!root) return;
  document.getElementById('toastMsg').textContent = message;
  document.getElementById('toastIcon').textContent = icon;
  root.classList.add('show');
  setTimeout(() => root.classList.remove('show'), 2600);
}

function formatDate(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString('pt-BR');
}

function normalizeSeverity(sev) {
  const s = normalize(sev);
  if (s === 'critica' || s === 'critico') return 'critica';
  if (s === 'alta' || s === 'alto') return 'alta';
  if (s === 'media' || s === 'medio') return 'media';
  if (s === 'baixa' || s === 'baixo') return 'baixa';
  if (s === 'informativo' || s === 'informativa' || s === 'info') return 'info';
  return s;
}

function severityLabel(sev) {
  const s = normalizeSeverity(sev);
  if (s === 'critica') return 'CRITICA';
  if (s === 'alta') return 'ALTA';
  if (s === 'media') return 'MEDIA';
  if (s === 'baixa') return 'BAIXA';
  if (s === 'info') return 'INFO';
  return (sev || '-').toUpperCase();
}

function severityClass(sev) {
  const s = normalizeSeverity(sev);
  if (s === 'critica') return 'sc';
  if (s === 'alta') return 'sh';
  if (s === 'media') return 'sm';
  if (s === 'info') return 'si';
  return 'sl';
}

function severityRank(sev) {
  const s = normalizeSeverity(sev);
  if (s === 'critica') return 5;
  if (s === 'alta') return 4;
  if (s === 'media') return 3;
  if (s === 'baixa') return 2;
  if (s === 'info') return 1;
  return 0;
}

function riskTag(level) {
  const v = normalize(level);
  if (v.includes('critico')) return '<span class="risk-tag critical">critico</span>';
  if (v.includes('alto')) return '<span class="risk-tag high">alto</span>';
  if (v.includes('medio')) return '<span class="risk-tag medium">medio</span>';
  return '<span class="risk-tag low">baixo</span>';
}

function sourceTypeClass(name) {
  const n = normalize(name);
  if (n.includes('otx') || n.includes('virustotal') || n.includes('newsapi')) return 'ta';
  return 'tt';
}

async function apiGet(path) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { headers });
  if (res.status === 401) {
    state.token = '';
    localStorage.removeItem('cti_token');
    throw new Error('Nao autenticado. Faca login novamente.');
  }
  if (!res.ok) throw new Error(`Erro ${res.status} em ${path}`);
  return res.json();
}

async function apiPost(path, payload) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload || {}),
  });
  if (res.status === 401) {
    state.token = '';
    localStorage.removeItem('cti_token');
    throw new Error('Nao autenticado. Faca login novamente.');
  }
  if (!res.ok) throw new Error(`Erro ${res.status} em ${path}`);
  return res.json();
}

async function loadAfterLogin() {
  await loadThreats();
  await loadIocs();
  await loadFeedStatus();
  setupEventsStream();
}

function inferredType(item) {
  const text = normalize(
    [
      item.title,
      ...(item.apt_groups || []),
      ...(item.malware_names || []),
      (item.cti_analysis || {}).tipo_ameaca,
    ].join(' ')
  );
  if (text.includes('apt')) return 'apt';
  if (text.includes('ransom')) return 'ransomware';
  if (text.includes('phish')) return 'phishing';
  if (text.includes('exploit') || text.includes('vulnerab')) return 'exploracao';
  return 'outros';
}

function hasStructured(item) {
  const cti = item.cti_analysis || {};
  return Boolean(cti.resumo || cti.tipo_ameaca || cti.nivel_risco || cti.score_risco !== undefined);
}

function structuredRisk(item) {
  const cti = item.cti_analysis || {};
  const level = normalize(cti.nivel_risco);
  if (level) return level;

  const score = Number(cti.score_risco);
  if (!Number.isNaN(score)) {
    if (score >= 85) return 'critico';
    if (score >= 65) return 'alto';
    if (score >= 40) return 'medio';
  }

  const sev = normalize(item.severity);
  if (sev === 'critica') return 'critico';
  if (sev === 'alta') return 'alto';
  if (sev === 'media') return 'medio';
  return 'baixo';
}

function mitreTechniques(item) {
  const list = ((item.cti_analysis || {}).ttps_mitre || []).filter(Boolean);
  return Array.from(new Set(list));
}

function correlationData(item) {
  const c = (item.cti_analysis || {}).correlation || {};
  return {
    score: Number(c.score || 0),
    level: c.nivel || 'baixa',
    shared: Number(c.iocs_compartilhados || 0),
    related: Number(c.ameacas_relacionadas || 0),
  };
}

function diamondMap(item) {
  const cti = item.cti_analysis || {};
  const iocs = cti.iocs || {};
  const threatInfo = item.threat_info || {};

  const adversary = cti.apt_grupo || (item.apt_groups || []).join(', ') || 'Desconhecido';
  const capability = (item.malware_names || []).join(', ') || inferredType(item) || 'Desconhecido';

  const infraParts = [];
  infraParts.push(...(iocs.dominios || []).slice(0, 2));
  infraParts.push(...(iocs.ips || []).slice(0, 2));
  infraParts.push(...(iocs.urls || []).slice(0, 1));
  const infrastructure = infraParts.join(', ') || item.source || 'Desconhecido';

  const victim = (item.affected_sectors || threatInfo.affected_sectors || []).join(', ') || 'Geral';

  return {
    adversary,
    capability,
    infrastructure,
    victim,
  };
}

function applyFilters() {
  const q = normalize(state.textFilter);
  let list = [...state.allThreats];

  if (state.severityFilter !== 'all') {
    const wanted = normalizeSeverity(state.severityFilter);
    list = list.filter((item) => normalizeSeverity(item.severity) === wanted);
  }

  if (state.sourceFilter !== 'all') {
    const wantedSource = normalize(state.sourceFilter);
    list = list.filter((item) => normalize(item.source) === wantedSource);
  }

  if (state.analysisFilter === 'structured') {
    list = list.filter(hasStructured);
  }

  if (state.analysisFilter === 'mitre') {
    list = list.filter((item) => mitreTechniques(item).length > 0);
  }

  if (state.typeFilter !== 'all') {
    list = list.filter((item) => inferredType(item) === state.typeFilter);
  }

  if (q) {
    list = list.filter((item) => {
      const cti = item.cti_analysis || {};
      const text = normalize(
        [
          item.title,
          item.source,
          item.severity,
          ...(item.apt_groups || []),
          ...(item.malware_names || []),
          ...(cti.cves || []),
          cti.apt_grupo,
          cti.tipo_ameaca,
          cti.resumo,
        ].join(' ')
      );
      return text.includes(q);
    });
  }

  if (state.sortFilter === 'date_desc') {
    list.sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));
  } else if (state.sortFilter === 'date_asc') {
    list.sort((a, b) => String(a.timestamp || '').localeCompare(String(b.timestamp || '')));
  } else if (state.sortFilter === 'risk_desc') {
    list.sort((a, b) => {
      const sa = Number((a.cti_analysis || {}).score_risco || 0);
      const sb = Number((b.cti_analysis || {}).score_risco || 0);
      return sb - sa;
    });
  } else if (state.sortFilter === 'severity') {
    list.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  }

  state.visibleThreats = list;
}

function rowHtml(item, idx) {
  const risk = structuredRisk(item);
  const diamond = diamondMap(item);
  const apt = diamond.adversary || '-';
  const srcClass = sourceTypeClass(item.source);
  const mitre = mitreTechniques(item);
  const corr = correlationData(item);

  return `
    <tr data-idx="${idx}">
      <td><span class="sev ${severityClass(item.severity)}">${severityLabel(item.severity)}</span></td>
      <td>${item.title || '-'}</td>
      <td><span class="src-tag ${srcClass}">${item.source || '-'}</span></td>
      <td>${inferredType(item)}</td>
      <td>${apt || '-'}</td>
      <td><span class="diamond-pill">${diamond.capability || '-'}</span> ${mitre.length ? `<span class="mitre-chip">${mitre[0]}</span>` : riskTag(risk)} <span class="corr-chip">corr ${corr.score}</span></td>
      <td class="mono-sm">${formatDate(item.timestamp)}</td>
      <td><button class="btn" data-open="${idx}">Abrir</button></td>
    </tr>
  `;
}

function renderTable() {
  const tbody = document.getElementById('tbody');
  const count = state.visibleThreats.length;

  if (!count) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="8">Nenhum registro com os filtros atuais</td></tr>';
  } else {
    tbody.innerHTML = state.visibleThreats.map((item, idx) => rowHtml(item, idx)).join('');
  }

  document.getElementById('tbl-count').textContent = `${count} itens`;

  tbody.querySelectorAll('tr[data-idx]').forEach((tr) => {
    tr.addEventListener('click', (event) => {
      const openBtn = event.target.closest('button[data-open]');
      const source = openBtn || tr;
      const idx = Number(source.getAttribute('data-open') || tr.getAttribute('data-idx'));
      openDetail(idx);
    });
  });
}

function countBySeverity(items) {
  const map = { critica: 0, alta: 0, media: 0, baixa: 0, info: 0 };
  for (const item of items) {
    const sev = normalizeSeverity(item.severity);
    if (map[sev] !== undefined) map[sev] += 1;
  }
  return map;
}

function renderSidebarCounts() {
  const all = state.allThreats;
  const sev = countBySeverity(all);
  const structured = all.filter(hasStructured).length;
  const mitreMapped = all.filter((item) => mitreTechniques(item).length > 0).length;

  document.getElementById('b-all').textContent = String(all.length);
  document.getElementById('b-crit').textContent = String(sev.critica || 0);
  document.getElementById('b-hi').textContent = String(sev.alta || 0);
  document.getElementById('b-med').textContent = String(sev.media || 0);
  document.getElementById('b-low').textContent = String(sev.baixa || 0);
  document.getElementById('b-info').textContent = String(sev.info || 0);
  document.getElementById('b-cti').textContent = String(structured);
  document.getElementById('b-mitre').textContent = String(mitreMapped);
}

function renderSourceFilters() {
  const sourceList = document.getElementById('sourceList');
  const counts = new Map();

  for (const item of state.allThreats) {
    const name = item.source || 'Desconhecida';
    counts.set(name, (counts.get(name) || 0) + 1);
  }

  sourceList.innerHTML = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([name, count]) => {
      const value = normalize(name);
      const active = normalize(state.sourceFilter) === value ? ' active' : '';
      return `<div class="src-item${active}" data-filter-group="source" data-filter-value="${value}"><div class="dot" style="background:var(--info)"></div>${name}<span class="sb-badge b">${count}</span></div>`;
    })
    .join('');

  bindSidebarFilters();
}

function renderMetrics() {
  const all = state.visibleThreats;
  const criticalHigh = all.filter((t) => {
    const s = normalize(t.severity);
    return s === 'critica' || s === 'alta';
  }).length;

  const withIoc = all.filter((t) => {
    const ioc = t.threat_info || {};
    return (ioc.apt_groups || []).length > 0 || (ioc.malware_names || []).length > 0;
  }).length;

  const withCve = all.filter((t) => ((t.cti_analysis || {}).cves || []).length > 0).length;

  document.getElementById('mt').textContent = String(all.length);
  document.getElementById('mca').textContent = String(criticalHigh);
  document.getElementById('mioc').textContent = String(withIoc);
  document.getElementById('mcve').textContent = String(withCve);
}

function refreshDashboardText() {
  const ts = new Date().toLocaleTimeString('pt-BR');
  document.getElementById('pg-sub').textContent = `Atualizacao automatica ativa | ultimo refresh ${ts}`;
}

function setActiveTab(tab) {
  state.activeTab = tab;
  const threatsView = document.getElementById('threatsView');
  const iocsView = document.getElementById('iocsView');
  const tabThreats = document.getElementById('tabThreats');
  const tabIocs = document.getElementById('tabIocs');

  const isThreats = tab !== 'iocs';
  threatsView.classList.toggle('hidden-view', !isThreats);
  iocsView.classList.toggle('hidden-view', isThreats);
  tabThreats.classList.toggle('active', isThreats);
  tabIocs.classList.toggle('active', !isThreats);
}

function toTagList(items, cssClass = '') {
  if (!Array.isArray(items) || !items.length) return '<div class="ioc-empty">Sem dados</div>';
  return items
    .slice(0, 120)
    .map((item) => `<span class="ioc-tag ${cssClass}">${escapeHtml(item)}</span>`)
    .join('');
}

function renderIocs() {
  const data = state.iocData;
  if (!data) return;

  const counts = data.counts || {};
  document.getElementById('iocCounts').innerHTML = [
    ['IPv4', counts.ipv4 || 0],
    ['IPv6', counts.ipv6 || 0],
    ['Dominios', counts.domains || 0],
    ['URLs', counts.urls || 0],
    ['Emails', counts.emails || 0],
    ['CVEs', counts.cves || 0],
    ['MD5', counts.md5 || 0],
    ['SHA1', counts.sha1 || 0],
    ['SHA256', counts.sha256 || 0],
  ]
    .map(([label, value]) => `<div class="ioc-metric"><div class="ioc-metric-label">${label}</div><div class="ioc-metric-value">${value}</div></div>`)
    .join('');

  const ips = [...(data.ips?.ipv4 || []), ...(data.ips?.ipv6 || [])];
  const domains = data.iocs?.domains || [];
  const urls = data.iocs?.urls || [];
  const hashes = [...(data.hashes?.sha256 || []), ...(data.hashes?.sha1 || []), ...(data.hashes?.md5 || [])];
  const cves = data.iocs?.cves || [];
  const emails = data.iocs?.emails || [];

  document.getElementById('iocIps').innerHTML = toTagList(ips, 'ioc-ip');
  document.getElementById('iocDomains').innerHTML = toTagList(domains, 'ioc-domain');
  document.getElementById('iocUrls').innerHTML = toTagList(urls, 'ioc-url');
  document.getElementById('iocHashes').innerHTML = toTagList(hashes, 'ioc-hash');
  document.getElementById('iocCves').innerHTML = toTagList(cves, 'ioc-cve');
  document.getElementById('iocEmails').innerHTML = toTagList(emails, 'ioc-email');
}

function openDetail(idx) {
  const item = state.visibleThreats[idx];
  if (!item) return;

  const cti = item.cti_analysis || {};
  const diamond = diamondMap(item);
  const iocs = cti.iocs || {};
  const threatInfo = item.threat_info || {};
  const correlated = ((cti.enriquecimento || {}).fontes_correlacionadas || []).join(', ') || '-';
  const mitre = mitreTechniques(item);
  const correlation = correlationData(item);
  const correlationClass = correlation.level === 'alta' ? 'critical' : correlation.level === 'media' ? 'high' : 'low';

  const html = `
    <div class="p-section">
      <div class="p-sec-title">Resumo</div>
      <div style="font-size:16px;font-weight:700;margin-bottom:8px;line-height:1.35">${item.title || '-'}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <span class="sev ${severityClass(item.severity)}">${severityLabel(item.severity)}</span>
        <span class="mitre-chip">MITRE ${mitre.length ? mitre[0] : '-'}</span>
        <span class="risk-tag ${correlationClass}">correlacao ${correlation.score}</span>
        <span class="src-tag ${sourceTypeClass(item.source)}">${item.source || '-'}</span>
      </div>
      <div style="margin-top:10px;font-size:12px;color:var(--muted)">${formatDate(item.timestamp)}</div>
    </div>

    <div class="p-section">
      <div class="p-sec-title">Atributos</div>
      <div class="p-row"><div class="p-key">Tipo</div><div class="p-val">${cti.tipo_ameaca || inferredType(item)}</div></div>
      <div class="p-row"><div class="p-key">APT / Campanha</div><div class="p-val">${cti.apt_grupo || (item.apt_groups || []).join(', ') || '-'}</div></div>
      <div class="p-row"><div class="p-key">Malwares</div><div class="p-val">${(item.malware_names || []).join(', ') || '-'}</div></div>
      <div class="p-row"><div class="p-key">Setores</div><div class="p-val">${(item.affected_sectors || []).join(', ') || '-'}</div></div>
      <div class="p-row"><div class="p-key">Confianca</div><div class="p-val">${cti.confianca || '-'}</div></div>
      <div class="p-row"><div class="p-key">Score risco</div><div class="p-val">${cti.score_risco ?? '-'}</div></div>
      <div class="p-row"><div class="p-key">URL</div><div class="p-val">${item.url || '-'}</div></div>
    </div>

    <div class="p-section">
      <div class="p-sec-title">Diamond Model Profissional</div>
      <div class="diamond-grid-detail">
        <div class="diamond-node">
          <div class="diamond-node-label">Adversario</div>
          <div class="diamond-node-value">${diamond.adversary}</div>
        </div>
        <div class="diamond-node">
          <div class="diamond-node-label">Capacidade</div>
          <div class="diamond-node-value">${diamond.capability}</div>
        </div>
        <div class="diamond-node">
          <div class="diamond-node-label">Infraestrutura</div>
          <div class="diamond-node-value">${diamond.infrastructure}</div>
        </div>
        <div class="diamond-node">
          <div class="diamond-node-label">Vitima</div>
          <div class="diamond-node-value">${diamond.victim}</div>
        </div>
      </div>
      <div class="analysis-meta" style="margin-top:10px">
        <span class="analysis-chip">Correlacao: ${correlation.level} (${correlation.score})</span>
        <span class="analysis-chip">IOCs compartilhados: ${correlation.shared}</span>
        <span class="analysis-chip">Ameacas relacionadas: ${correlation.related}</span>
      </div>
    </div>

    <div class="p-section">
      <div class="p-sec-title">Contexto da ameaca</div>
      <div class="analysis-box">
        <div style="font-size:12px;line-height:1.55">${cti.resumo || threatInfo.technical_description || 'Sem resumo estruturado.'}</div>
        <div class="analysis-meta">
          <span class="analysis-chip">Correlacao: ${correlated}</span>
          <span class="analysis-chip">MITRE ATT&CK: ${(mitre.slice(0, 6) || []).join(', ') || '-'}</span>
          <span class="analysis-chip">CVEs: ${((cti.cves || []).slice(0, 4) || []).join(', ') || '-'}</span>
        </div>
      </div>
      <ul class="analysis-list">
        ${((cti.recomendacoes || []).slice(0, 6) || []).map((txt) => `<li>${txt}</li>`).join('') || '<li>Sem recomendacoes disponiveis.</li>'}
      </ul>
    </div>

    <div class="p-section">
      <div class="p-sec-title">Indicadores</div>
      <div class="p-row"><div class="p-key">IPs</div><div class="p-val">${(iocs.ips || []).slice(0, 8).join(', ') || '-'}</div></div>
      <div class="p-row"><div class="p-key">Dominios</div><div class="p-val">${(iocs.dominios || []).slice(0, 8).join(', ') || '-'}</div></div>
      <div class="p-row"><div class="p-key">URLs</div><div class="p-val">${(iocs.urls || []).slice(0, 5).join(', ') || '-'}</div></div>
      <div class="p-row"><div class="p-key">Hashes</div><div class="p-val">${(iocs.hashes || []).slice(0, 5).join(', ') || '-'}</div></div>
    </div>
  `;

  document.getElementById('detailContent').innerHTML = html;
  document.getElementById('detailOverlay').classList.add('open');
}

function closeDetail(event) {
  if (event && event.target && event.target.id !== 'detailOverlay') return;
  document.getElementById('detailOverlay').classList.remove('open');
}

function closeDetailBtn() {
  document.getElementById('detailOverlay').classList.remove('open');
}

window.closeDetail = closeDetail;
window.closeDetailBtn = closeDetailBtn;

function bindSidebarFilters() {
  document.querySelectorAll('[data-filter-group]').forEach((el) => {
    el.onclick = async () => {
      const group = el.getAttribute('data-filter-group');
      const value = el.getAttribute('data-filter-value') || 'all';

      if (group === 'severity') state.severityFilter = value;
      if (group === 'source') state.sourceFilter = value;
      if (group === 'analysis') state.analysisFilter = value;

      document.querySelectorAll(`[data-filter-group="${group}"]`).forEach((item) => item.classList.remove('active'));
      el.classList.add('active');

      applyFilters();
      renderMetrics();
      renderTable();
      refreshDashboardText();
    };
  });
}

function bindTopEvents() {
  document.getElementById('tabThreats').addEventListener('click', () => setActiveTab('threats'));
  document.getElementById('tabIocs').addEventListener('click', () => setActiveTab('iocs'));

  document.getElementById('themeToggleBtn').addEventListener('click', () => {
    state.theme = state.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('cti_theme', state.theme);
    applyTheme();
  });

  document.getElementById('loginBtn').addEventListener('click', async () => {
    const username = document.getElementById('userInput').value.trim();
    const password = document.getElementById('passInput').value;
    if (!username || !password) {
      toast('Informe usuario e senha', '!');
      return;
    }

    setStatus('Autenticando...');
    try {
      const data = await apiPost('/api/auth/login', { username, password });
      state.token = data.access_token;
      localStorage.setItem('cti_token', state.token);
      setStatus(`Autenticado como ${username} (${data.role})`);
      toast('Login realizado', 'ok');
      await loadAfterLogin();
    } catch (error) {
      setStatus(`Falha no login: ${error.message}`);
      toast('Falha no login', 'x');
    }
  });

  document.getElementById('runPipelineBtn').addEventListener('click', async () => {
    setStatus('Executando pipeline manual...');
    try {
      const result = await apiPost('/api/pipeline/run', {});
      toast(`Pipeline concluida (${result.saved_count || 0})`, 'ok');
      await loadThreats();
      await loadIocs();
      await loadFeedStatus();
    } catch (error) {
      setStatus(`Falha ao executar pipeline: ${error.message}`);
      toast('Falha no pipeline', 'x');
    }
  });

  document.getElementById('refreshThreatsBtn').addEventListener('click', async () => {
    setStatus('Atualizando ameacas com coleta forcada...');
    try {
      const result = await apiPost('/api/pipeline/refresh', {});
      toast(`Ameacas atualizadas (${result.saved_count || 0})`, 'ok');
      await loadThreats();
      await loadIocs();
      await loadFeedStatus();
    } catch (error) {
      setStatus(`Falha ao atualizar ameacas: ${error.message}`);
      toast('Falha ao atualizar', 'x');
    }
  });

  document.getElementById('exportCsvBtn').addEventListener('click', () => {
    window.open('/api/export/threats.csv?days=30', '_blank');
  });

  document.getElementById('exportJsonBtn').addEventListener('click', () => {
    window.open('/api/export/threats.json?days=30', '_blank');
  });

  document.getElementById('searchInput').addEventListener('input', () => {
    state.textFilter = document.getElementById('searchInput').value;
    applyFilters();
    renderMetrics();
    renderTable();
  });

  document.getElementById('typeFilter').addEventListener('change', () => {
    state.typeFilter = document.getElementById('typeFilter').value;
    applyFilters();
    renderMetrics();
    renderTable();
  });

  document.getElementById('sortFilter').addEventListener('change', () => {
    state.sortFilter = document.getElementById('sortFilter').value;
    applyFilters();
    renderTable();
  });

  document.getElementById('clearFiltersBtn').addEventListener('click', () => {
    state.sourceFilter = 'all';
    state.severityFilter = 'all';
    state.analysisFilter = 'all';
    state.typeFilter = 'all';
    state.sortFilter = 'date_desc';
    state.textFilter = '';

    document.getElementById('searchInput').value = '';
    document.getElementById('typeFilter').value = 'all';
    document.getElementById('sortFilter').value = 'date_desc';

    document.querySelectorAll('[data-filter-group]').forEach((item) => {
      const group = item.getAttribute('data-filter-group');
      const value = item.getAttribute('data-filter-value');
      if (value === 'all' && (group === 'severity' || group === 'source')) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    applyFilters();
    renderMetrics();
    renderTable();
    toast('Filtros limpos', 'ok');
  });
}

function applyTheme() {
  document.body.classList.toggle('light', state.theme === 'light');
  const btn = document.getElementById('themeToggleBtn');
  btn.textContent = state.theme === 'light' ? 'Tema Escuro' : 'Tema Claro';
}

async function loadThreats() {
  setStatus('Carregando ameacas...');

  const pageSize = 100;
  const first = await apiGet(`/api/threats?page=1&page_size=${pageSize}&days=30`);
  const pages = Number(first.pages || 1);
  let all = [...(first.items || [])];

  if (pages > 1) {
    const jobs = [];
    for (let page = 2; page <= Math.min(pages, 6); page += 1) {
      jobs.push(apiGet(`/api/threats?page=${page}&page_size=${pageSize}&days=30`));
    }
    const extra = await Promise.all(jobs);
    for (const chunk of extra) all = all.concat(chunk.items || []);
  }

  state.allThreats = all;
  applyFilters();
  renderSidebarCounts();
  renderSourceFilters();
  renderMetrics();
  renderTable();
  refreshDashboardText();
  setStatus(`Atualizado em ${new Date().toLocaleTimeString('pt-BR')} | ${all.length} ameacas`);
}

async function loadIocs() {
  try {
    const data = await apiGet('/api/iocs?days=30');
    state.iocData = data;
    renderIocs();
  } catch (error) {
    setStatus(`Falha ao carregar IOCs: ${error.message}`);
  }
}

async function loadFeedStatus() {
  try {
    const feed = await apiGet('/api/feed/status');
    const ok = Number(feed.ok_sources || 0);
    const fail = Number(feed.failed_sources || 0);
    const news = Number(feed.total_new_items || 0);
    setStatus(`Feed: ${ok} OK, ${fail} falhas, ${news} novos itens`);
  } catch (_) {
    // Feed status is optional in UI.
  }
}

function setupEventsStream() {
  try {
    const events = new EventSource('/api/events');
    events.onmessage = async (event) => {
      const payload = JSON.parse(event.data || '{}');
      const run = payload.run || {};
      const running = run.running ? ' | pipeline em execucao' : '';
      setStatus(`Tempo real ativo | ameacas: ${payload.threat_count || 0}${running}`);

      const finished = run.last_finished_at || null;
      if (finished && finished !== state.lastFinishedAt) {
        state.lastFinishedAt = finished;
        toast('Novo ciclo concluido, atualizando', 'ok');
        await loadThreats();
      }
    };
  } catch (_) {
    // SSE is optional and should not break the page.
  }
}

async function init() {
  applyTheme();
  bindTopEvents();
  bindSidebarFilters();
  setActiveTab('threats');
  await loadAfterLogin();

  setInterval(async () => {
    try {
      await loadThreats();
      await loadIocs();
      await loadFeedStatus();
    } catch (_) {
      // Silent timer refresh.
    }
  }, 60000);
}

init().catch((error) => {
  setStatus(`Erro ao iniciar dashboard: ${error.message}`);
  toast('Erro ao iniciar dashboard', 'x');
});
