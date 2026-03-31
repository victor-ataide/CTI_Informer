import cron from 'node-cron';
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';
import { runPipeline } from '../modules/pipeline/service.js';

let running = false;

async function safeRun(forceRefresh) {
  if (running) {
    logger.warn('Pipeline already running. Skipping cron tick.');
    return;
  }

  running = true;
  try {
    const result = await runPipeline({ forceRefresh });
    logger.info({ result }, 'Pipeline execution finished');
  } catch (error) {
    logger.error({ err: error }, 'Pipeline execution failed');
  } finally {
    running = false;
  }
}

export function startScheduler() {
  cron.schedule(env.CRON_COLLECT, () => {
    void safeRun(false);
  });

  cron.schedule(env.CRON_REFRESH, () => {
    void safeRun(true);
  });

  logger.info({ collect: env.CRON_COLLECT, refresh: env.CRON_REFRESH }, 'Cron scheduler started');
}
