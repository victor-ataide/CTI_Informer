import { buildApp } from './app.js';
import { env } from './config/env.js';
import { startScheduler } from './jobs/scheduler.js';
import { logger } from './lib/logger.js';

const app = buildApp();

const shutdown = async () => {
  try {
    await app.prisma.$disconnect();
    await app.close();
  } finally {
    process.exit(0);
  }
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

app
  .listen({ port: env.PORT, host: '0.0.0.0' })
  .then(() => {
    startScheduler();
    logger.info(`CTI Node backend listening on ${env.PORT}`);
  })
  .catch((err) => {
    logger.error({ err }, 'Failed to start server');
    process.exit(1);
  });
