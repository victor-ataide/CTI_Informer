import { inferMitreTechniques } from '../pipeline/classifier.js';

export async function threatsRoutes(fastify) {
  fastify.get('/threats', async (request) => {
    const page = Number(request.query.page || 1);
    const pageSize = Number(request.query.page_size || 50);

    const [total, items] = await Promise.all([
      fastify.prisma.threat.count(),
      fastify.prisma.threat.findMany({
        include: {
          rawItem: { include: { source: true } },
          threatIocs: { include: { ioc: true } }
        },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      })
    ]);

    const iocIds = Array.from(
      new Set(
        items.flatMap((t) => t.threatIocs.map((x) => x.iocId))
      )
    );

    const iocUsage = new Map();
    if (iocIds.length > 0) {
      const grouped = await fastify.prisma.threatIOC.groupBy({
        by: ['iocId'],
        where: { iocId: { in: iocIds } },
        _count: { threatId: true }
      });

      for (const row of grouped) {
        iocUsage.set(row.iocId, Number(row._count?.threatId || 0));
      }
    }

    return {
      page,
      page_size: pageSize,
      total,
      pages: Math.max(1, Math.ceil(total / pageSize)),
      items: items.map((t) => {
        const raw = t.rawItem.rawJson && typeof t.rawItem.rawJson === 'object' ? t.rawItem.rawJson : {};
        const enrichment = raw.enrichment && typeof raw.enrichment === 'object' ? raw.enrichment : {};
        const fontesCorrelacionadas = Array.isArray(enrichment.fontes_correlacionadas)
          ? enrichment.fontes_correlacionadas
          : [];
        const mitreText = [t.rawItem.title, t.summary, t.threatType].filter(Boolean).join(' ');
        const iocBag = {
          cves: t.threatIocs.filter((x) => x.ioc.type === 'cve').map((x) => x.ioc.value),
          urls: t.threatIocs.filter((x) => x.ioc.type === 'url').map((x) => x.ioc.value),
          domains: t.threatIocs.filter((x) => x.ioc.type === 'domain').map((x) => x.ioc.value),
          md5: t.threatIocs.filter((x) => x.ioc.type === 'md5').map((x) => x.ioc.value),
          sha1: t.threatIocs.filter((x) => x.ioc.type === 'sha1').map((x) => x.ioc.value),
          sha256: t.threatIocs.filter((x) => x.ioc.type === 'sha256').map((x) => x.ioc.value)
        };
        const mitreTechniques = inferMitreTechniques(mitreText, t.threatType, iocBag);

        const sharedIocs = t.threatIocs.filter((x) => (iocUsage.get(x.iocId) || 0) > 1).length;
        const relatedThreats = t.threatIocs.reduce((acc, x) => acc + Math.max((iocUsage.get(x.iocId) || 1) - 1, 0), 0);
        const correlationScore = Math.min(100, sharedIocs * 20 + Math.min(relatedThreats, 10) * 5 + fontesCorrelacionadas.length * 10);
        const correlationLevel = correlationScore >= 70 ? 'alta' : correlationScore >= 40 ? 'media' : 'baixa';

        return {
          timestamp: t.createdAt,
          title: t.rawItem.title,
          source: t.rawItem.source.name,
          severity: t.severity,
          apt_groups: t.adversary && t.adversary !== 'Desconhecido' ? [t.adversary] : [],
          malware_names: t.capability && t.capability !== 'Desconhecido' ? [t.capability] : [],
          affected_sectors: t.victim && t.victim !== 'Geral' ? [t.victim] : [],
          affected_countries: [],
          url: t.rawItem.link,
          threat_info: {
            severity: t.severity,
            apt_groups: t.adversary && t.adversary !== 'Desconhecido' ? [t.adversary] : [],
            malware_names: t.capability && t.capability !== 'Desconhecido' ? [t.capability] : [],
            affected_sectors: t.victim && t.victim !== 'Geral' ? [t.victim] : [],
            technical_description: t.summary || ''
          },
          classification: {
            is_high_severity: ['crítica', 'alta'].includes(String(t.severity || '').toLowerCase()),
            is_financial_related: String(t.victim || '').toLowerCase().includes('finan'),
            is_critical_infrastructure: ['infraestrutura crítica', 'energia', 'saúde', 'telecom'].includes(String(t.victim || '').toLowerCase())
          },
          cti_analysis: {
            resumo: t.summary || '',
            tipo_ameaca: t.threatType || 'geral',
            apt_grupo: t.adversary || 'Desconhecido',
            score_risco: t.riskScore,
            nivel_risco: t.riskScore >= 85 ? 'crítico' : t.riskScore >= 65 ? 'alto' : t.riskScore >= 40 ? 'médio' : 'baixo',
            iocs: {
              ips: t.threatIocs.filter((x) => x.ioc.type === 'ipv4').map((x) => x.ioc.value),
              dominios: t.threatIocs.filter((x) => x.ioc.type === 'domain').map((x) => x.ioc.value),
              urls: t.threatIocs.filter((x) => x.ioc.type === 'url').map((x) => x.ioc.value),
              hashes: t.threatIocs.filter((x) => ['md5', 'sha1', 'sha256'].includes(x.ioc.type)).map((x) => x.ioc.value)
            },
            cves: t.threatIocs.filter((x) => x.ioc.type === 'cve').map((x) => x.ioc.value),
            ttps_mitre: mitreTechniques,
            correlation: {
              score: correlationScore,
              nivel: correlationLevel,
              iocs_compartilhados: sharedIocs,
              ameacas_relacionadas: relatedThreats
            },
            enriquecimento: {
              fontes_correlacionadas: fontesCorrelacionadas,
              detalhes: enrichment
            },
            recomendacoes: []
          }
        };
      })
    };
  });
}
