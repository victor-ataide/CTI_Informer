import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { prisma } from '../../db/client.js';
import { env } from '../../config/env.js';
import { logger } from '../../lib/logger.js';
import { fetchFeed, isValidFeed } from '../../lib/rss.js';
import { extractIocs } from '../../lib/ioc.js';
import { applyEnrichmentToClassification, enrichIocs } from '../../lib/enrichment.js';
import { buildDiamond, classifyThreat } from './classifier.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendNodeRoot = path.resolve(__dirname, '../../..');
const sourcesPath = path.resolve(backendNodeRoot, env.SOURCES_FILE);

function hashItem(sourceName, link, title, published) {
  const raw = `${sourceName}|${link || ''}|${title || ''}|${published || ''}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function normalizeIoc(type, value) {
  return `${type}:${String(value || '').trim().toLowerCase()}`;
}

async function loadSourcesFromJson() {
  const content = await fs.readFile(sourcesPath, 'utf-8');
  const list = JSON.parse(content);
  return Array.isArray(list) ? list.filter((s) => s.enabled !== false) : [];
}

async function upsertSources(sources) {
  for (const s of sources) {
    await prisma.source.upsert({
      where: { url: s.url },
      update: {
        name: s.name,
        category: s.category || 'general',
        enabled: s.enabled !== false,
        maxEntries: Number(s.max_entries || env.FEED_MAX_ENTRIES)
      },
      create: {
        name: s.name,
        url: s.url,
        category: s.category || 'general',
        enabled: s.enabled !== false,
        maxEntries: Number(s.max_entries || env.FEED_MAX_ENTRIES)
      }
    });
  }
}

async function saveThreatAndIocs(rawItem, iocs, classification, diamond) {
  const threat = await prisma.threat.upsert({
    where: { rawItemId: rawItem.id },
    update: {
      severity: classification.severity,
      threatType: classification.threatType,
      riskScore: classification.riskScore,
      summary: rawItem.summary,
      adversary: diamond.adversary,
      capability: diamond.capability,
      infrastructure: diamond.infrastructure,
      victim: diamond.victim
    },
    create: {
      rawItemId: rawItem.id,
      severity: classification.severity,
      threatType: classification.threatType,
      riskScore: classification.riskScore,
      summary: rawItem.summary,
      adversary: diamond.adversary,
      capability: diamond.capability,
      infrastructure: diamond.infrastructure,
      victim: diamond.victim
    }
  });

  const groups = [
    ['ipv4', iocs.ipv4],
    ['domain', iocs.domains],
    ['url', iocs.urls],
    ['cve', iocs.cves],
    ['md5', iocs.md5],
    ['sha1', iocs.sha1],
    ['sha256', iocs.sha256]
  ];

  for (const [type, values] of groups) {
    for (const value of values || []) {
      const normalizedValue = normalizeIoc(type, value);
      const ioc = await prisma.iOC.upsert({
        where: { normalizedValue },
        update: { value: String(value) },
        create: { type, value: String(value), normalizedValue }
      });

      await prisma.threatIOC.upsert({
        where: { threatId_iocId: { threatId: threat.id, iocId: ioc.id } },
        update: {},
        create: { threatId: threat.id, iocId: ioc.id }
      });
    }
  }
}

export async function runPipeline({ forceRefresh = false } = {}) {
  const run = await prisma.feedRun.create({
    data: {
      status: 'running',
      forceRefresh
    }
  });

  try {
    if (forceRefresh) {
      await prisma.rawItem.deleteMany({});
    }

    const configured = await loadSourcesFromJson();
    await upsertSources(configured);

    const dbSources = await prisma.source.findMany({ where: { enabled: true } });
    let okSources = 0;
    let failedSources = 0;
    let newItems = 0;
    let savedThreats = 0;

    for (const source of dbSources) {
      const healthy = await isValidFeed(source.url, env.FEED_TIMEOUT_MS);
      if (!healthy) {
        failedSources += 1;
        await prisma.source.update({
          where: { id: source.id },
          data: { healthStatus: 'offline' }
        });
        continue;
      }

      let parsed;
      try {
        parsed = await fetchFeed(source.url);
      } catch (error) {
        failedSources += 1;
        await prisma.source.update({
          where: { id: source.id },
          data: { healthStatus: 'degraded' }
        });
        logger.warn({ err: error, source: source.name }, 'Feed parse failed');
        continue;
      }

      okSources += 1;
      await prisma.source.update({
        where: { id: source.id },
        data: { healthStatus: 'ok', lastSuccessAt: new Date() }
      });

      const items = (parsed.items || []).slice(0, source.maxEntries || env.FEED_MAX_ENTRIES);
      for (const item of items) {
        const hash = hashItem(source.name, item.link, item.title, item.pubDate);
        const rawText = `${item.title || ''} ${item.contentSnippet || ''}`;
        const baseClassification = classifyThreat(rawText);
        const iocs = extractIocs(rawText);
        const enrichment = await enrichIocs(iocs, env, logger);
        const classification = applyEnrichmentToClassification(baseClassification, enrichment);
        const diamond = buildDiamond(
          {
            sourceName: source.name,
            title: item.title,
            summary: item.contentSnippet || ''
          },
          classification,
          iocs
        );

        const rawItem = await prisma.rawItem.upsert({
          where: { hash },
          update: {
            title: item.title || 'Sem título',
            link: item.link || '',
            summary: item.contentSnippet || '',
            publishedAt: item.pubDate ? new Date(item.pubDate) : null,
            rawJson: { ...item, enrichment }
          },
          create: {
            sourceId: source.id,
            guid: item.guid || null,
            title: item.title || 'Sem título',
            link: item.link || '',
            summary: item.contentSnippet || '',
            publishedAt: item.pubDate ? new Date(item.pubDate) : null,
            hash,
            rawJson: { ...item, enrichment }
          }
        });

        if (rawItem.createdAt.getTime() > Date.now() - 15000) {
          newItems += 1;
        }

        await saveThreatAndIocs(rawItem, iocs, classification, diamond);
        savedThreats += 1;
      }
    }

    const result = {
      status: 'ok',
      forceRefresh,
      totalSources: dbSources.length,
      okSources,
      failedSources,
      newItems,
      savedThreats,
      saved_count: savedThreats,
      feed: {
        total_sources: dbSources.length,
        ok_sources: okSources,
        failed_sources: failedSources,
        total_new_items: newItems
      }
    };

    await prisma.feedRun.update({
      where: { id: run.id },
      data: {
        finishedAt: new Date(),
        status: 'ok',
        totalSources: result.totalSources,
        okSources: result.okSources,
        failedSources: result.failedSources,
        newItems: result.newItems,
        savedThreats: result.savedThreats
      }
    });

    return result;
  } catch (error) {
    await prisma.feedRun.update({
      where: { id: run.id },
      data: {
        finishedAt: new Date(),
        status: 'error',
        error: String(error?.message || error)
      }
    });
    throw error;
  }
}
