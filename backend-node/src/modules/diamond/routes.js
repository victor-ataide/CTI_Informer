export async function diamondRoutes(fastify) {
  fastify.get('/diamond-model', async (request) => {
    const page = Number(request.query.page || 1);
    const pageSize = Number(request.query.page_size || 50);

    const [total, items] = await Promise.all([
      fastify.prisma.threat.count(),
      fastify.prisma.threat.findMany({
        include: { rawItem: true },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize
      })
    ]);

    return {
      page,
      page_size: pageSize,
      total,
      pages: Math.max(1, Math.ceil(total / pageSize)),
      items: items.map((t) => ({
        timestamp: t.createdAt,
        title: t.rawItem.title,
        severity: t.severity,
        adversary: t.adversary || 'Desconhecido',
        capability: t.capability || 'Desconhecido',
        infrastructure: t.infrastructure || 'Desconhecida',
        victim: t.victim || 'Geral'
      }))
    };
  });
}
