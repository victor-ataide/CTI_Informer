import { runPipeline } from './service.js';

export async function pipelineRoutes(fastify) {
  fastify.post('/pipeline/run', async () => runPipeline({ forceRefresh: false }));
  fastify.post('/pipeline/refresh', async () => runPipeline({ forceRefresh: true }));

  fastify.get('/pipeline/last-run', async () => {
    const last = await fastify.prisma.feedRun.findFirst({ orderBy: { startedAt: 'desc' } });
    return { run: last };
  });
}
