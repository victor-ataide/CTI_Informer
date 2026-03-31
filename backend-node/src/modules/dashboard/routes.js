import { Readable } from 'node:stream';

function toCsv(rows) {
  const headers = ['timestamp', 'title', 'source', 'severity', 'threatType', 'riskScore', 'url'];
  const escape = (v) => {
    const s = String(v ?? '');
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  const lines = [headers.join(',')];
  for (const r of rows) {
    lines.push(headers.map((h) => escape(r[h])).join(','));
  }
  return `${lines.join('\n')}\n`;
}

export async function dashboardRoutes(fastify) {
  fastify.get('/feed/status', async () => {
    const sources = await fastify.prisma.source.findMany({ where: { enabled: true }, orderBy: { name: 'asc' } });
    const ok = sources.filter((s) => s.healthStatus === 'ok').length;
    const failed = sources.filter((s) => s.healthStatus !== 'ok').length;

    return {
      total_sources: sources.length,
      ok_sources: ok,
      failed_sources: failed,
      total_new_items: 0,
      sources: sources.map((s) => ({
        source: s.name,
        url: s.url,
        ok: s.healthStatus === 'ok',
        error: s.healthStatus === 'ok' ? null : s.healthStatus,
        new_items: 0,
        total_items: 0,
        skipped: false,
        next_retry_at: null
      }))
    };
  });

  fastify.get('/export/threats.json', async () => {
    const items = await fastify.prisma.threat.findMany({
      include: { rawItem: { include: { source: true } } },
      orderBy: { createdAt: 'desc' },
      take: 1000
    });

    return {
      total: items.length,
      items: items.map((t) => ({
        timestamp: t.createdAt,
        title: t.rawItem.title,
        source: t.rawItem.source.name,
        severity: t.severity,
        threatType: t.threatType,
        riskScore: t.riskScore,
        url: t.rawItem.link
      }))
    };
  });

  fastify.get('/export/threats.csv', async (_, reply) => {
    const items = await fastify.prisma.threat.findMany({
      include: { rawItem: { include: { source: true } } },
      orderBy: { createdAt: 'desc' },
      take: 1000
    });

    const rows = items.map((t) => ({
      timestamp: t.createdAt.toISOString(),
      title: t.rawItem.title,
      source: t.rawItem.source.name,
      severity: t.severity,
      threatType: t.threatType,
      riskScore: t.riskScore,
      url: t.rawItem.link
    }));

    reply.header('Content-Type', 'text/csv');
    reply.header('Content-Disposition', 'attachment; filename=threats_export.csv');
    return toCsv(rows);
  });

  fastify.get('/events', async (request, reply) => {
    reply.raw.setHeader('Content-Type', 'text/event-stream');
    reply.raw.setHeader('Cache-Control', 'no-cache');
    reply.raw.setHeader('Connection', 'keep-alive');

    const stream = new Readable({ read() {} });
    const send = async () => {
      const [lastRun, threatCount] = await Promise.all([
        fastify.prisma.feedRun.findFirst({ orderBy: { startedAt: 'desc' } }),
        fastify.prisma.threat.count()
      ]);
      const payload = {
        ts: new Date().toISOString(),
        run: {
          running: false,
          last_started_at: lastRun?.startedAt ?? null,
          last_finished_at: lastRun?.finishedAt ?? null,
          last_saved_count: lastRun?.savedThreats ?? 0,
          last_error: lastRun?.error ?? null
        },
        threat_count: threatCount
      };
      stream.push(`data: ${JSON.stringify(payload)}\n\n`);
    };

    const timer = setInterval(() => {
      void send();
    }, 10000);

    request.raw?.on?.('close', () => {
      clearInterval(timer);
      stream.push(null);
    });

    await send();
    return reply.send(stream);
  });
}
