const criticalWords = ['ransomware', 'zero-day', 'actively exploited', 'remote code execution', 'apt'];
const highWords = ['malware', 'trojan', 'backdoor', 'breach', 'data leak', 'vulnerability', 'exploit'];
const mediumWords = ['phishing', 'campaign', 'attack'];

const mitreRules = [
  { id: 'T1566', pattern: /phish|spear[-\s]?phish|email lure/i },
  { id: 'T1190', pattern: /exploit|rce|remote code execution|cve-/i },
  { id: 'T1071', pattern: /c2|command and control|beacon|tunnel|websocket/i },
  { id: 'T1059', pattern: /powershell|cmd|shell|script/i },
  { id: 'T1110', pattern: /credential|password|brute force|login/i },
  { id: 'T1041', pattern: /exfil|data leak|stolen data|dump/i },
  { id: 'T1486', pattern: /ransom|encrypt|locker/i },
  { id: 'T1021', pattern: /rdp|remote desktop|lateral movement/i },
  { id: 'T1105', pattern: /download|payload|loader|stager/i },
  { id: 'T1547', pattern: /persistence|autorun|scheduled task|registry/i }
];

export function classifyThreat(text) {
  const body = String(text || '').toLowerCase();

  let severity = 'baixa';
  if (criticalWords.some((k) => body.includes(k))) severity = 'crítica';
  else if (highWords.some((k) => body.includes(k))) severity = 'alta';
  else if (mediumWords.some((k) => body.includes(k))) severity = 'média';

  const threatType = body.includes('ransom')
    ? 'ransomware'
    : body.includes('phish')
      ? 'phishing'
      : body.includes('apt')
        ? 'apt'
        : body.includes('exploit') || body.includes('cve-')
          ? 'exploração'
          : 'geral';

  const riskScore = severity === 'crítica' ? 90 : severity === 'alta' ? 70 : severity === 'média' ? 45 : 25;
  return { severity, threatType, riskScore };
}

export function buildDiamond(raw, classification, iocs) {
  const text = `${raw.title || ''} ${raw.summary || ''}`.toLowerCase();
  return {
    adversary: text.includes('apt') ? 'APT (não atribuído)' : 'Desconhecido',
    capability: classification.threatType,
    infrastructure: (iocs.domains[0] || iocs.ipv4[0] || iocs.urls[0] || raw.sourceName || 'Desconhecida'),
    victim: text.includes('bank') || text.includes('financial') ? 'Financeiro' : 'Geral'
  };
}

export function inferMitreTechniques(text, threatType, iocs = {}) {
  const body = String(text || '').toLowerCase();
  const found = new Set();

  for (const rule of mitreRules) {
    if (rule.pattern.test(body)) found.add(rule.id);
  }

  if ((iocs.cves || []).length > 0) found.add('T1190');
  if ((iocs.urls || []).length > 0 || (iocs.domains || []).length > 0) found.add('T1071');
  if ((iocs.md5 || []).length > 0 || (iocs.sha1 || []).length > 0 || (iocs.sha256 || []).length > 0) found.add('T1105');

  if (threatType === 'phishing') found.add('T1566');
  if (threatType === 'ransomware') found.add('T1486');
  if (threatType === 'exploração') found.add('T1190');

  return Array.from(found).slice(0, 8);
}
