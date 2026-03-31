import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import fastifyJwt from '@fastify/jwt';
import fastifyRateLimit from '@fastify/rate-limit';
import { Registry, collectDefaultMetrics } from 'prom-client';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { env } from './config/env.js';
import { prisma } from './db/client.js';
import { logger } from './lib/logger.js';
import { pipelineRoutes } from './modules/pipeline/routes.js';
import { threatsRoutes } from './modules/threats/routes.js';
import { iocRoutes } from './modules/iocs/routes.js';
import { diamondRoutes } from './modules/diamond/routes.js';
import { dashboardRoutes } from './modules/dashboard/routes.js';
import { authRoutes } from './modules/auth/routes.js';

const metricsRegistry = new Registry();
collectDefaultMetrics({ register: metricsRegistry });

export function buildApp() {
  const app = Fastify({ logger });
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const frontendDir = path.resolve(__dirname, '../../frontend');

  app.decorate('prisma', prisma);
  app.decorate('env', env);

  app.register(cors, {
    origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN
  });

  app.register(fastifyStatic, {
    root: frontendDir,
    prefix: '/assets/',
    wildcard: false
  });

  app.register(fastifyRateLimit, {
    global: false
  });

  app.register(fastifyJwt, {
    secret: env.JWT_SECRET
  });

  app.decorate('authenticate', async (request, reply) => {
    try {
      await request.jwtVerify();
    } catch {
      reply.code(401).send({ message: 'Nao autenticado' });
    }
  });

  app.addHook('onRequest', async (request, reply) => {
    const pathOnly = String(request.url || '').split('?')[0];
    if (!pathOnly.startsWith('/api')) return;
    if (request.method === 'OPTIONS') return;
    if (request.method === 'GET' || request.method === 'HEAD') return;
    if (pathOnly === '/api/auth/login') return;
    await app.authenticate(request, reply);
  });

  app.get('/health', async () => ({ status: 'ok' }));
  app.get('/ready', async () => ({ status: 'ready' }));

  app.get('/metrics', async (_, reply) => {
    reply.header('Content-Type', metricsRegistry.contentType);
    return metricsRegistry.metrics();
  });

  app.register(authRoutes, { prefix: '/api' });
  app.register(pipelineRoutes, { prefix: '/api' });
  app.register(threatsRoutes, { prefix: '/api' });
  app.register(iocRoutes, { prefix: '/api' });
  app.register(diamondRoutes, { prefix: '/api' });
  app.register(dashboardRoutes, { prefix: '/api' });

  app.get('/api/status', async () => {
    const last = await prisma.feedRun.findFirst({ orderBy: { startedAt: 'desc' } });
    return {
      status: 'ok',
      scheduler_running: true,
      run: last
    };
  });

  app.get('/', async (_, reply) => reply.sendFile('index.html'));

  return app;
}
