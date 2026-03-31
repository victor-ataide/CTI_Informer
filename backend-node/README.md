# CTI Backend Node (Fastify + Cron + PostgreSQL)

Backend moderno para ingestao de feeds CTI com Node.js, cron e PostgreSQL.

## Stack
- Node.js 22+
- Fastify
- Prisma + PostgreSQL
- node-cron
- rss-parser

## Setup
1. Copie o env:

```bash
cp .env.example .env
```

2. Instale dependencias:

```bash
npm install
```

3. Gere cliente Prisma e sincronize schema:

```bash
npm run prisma:generate
npm run prisma:push
```

4. Rode em desenvolvimento:

```bash
npm run dev
```

Servidor sobe na porta definida em `PORT` (padrao 8101).

## Endpoints
- `GET /health`
- `GET /ready`
- `GET /metrics`
- `GET /api/status`
- `POST /api/pipeline/run`
- `POST /api/pipeline/refresh`
- `GET /api/pipeline/last-run`
- `GET /api/threats`
- `GET /api/iocs`
- `GET /api/diamond-model`

## Cron
- `CRON_COLLECT`: coleta incremental (default `*/10 * * * *`)
- `CRON_REFRESH`: refresh completo (default `0 3 * * *`)

## Enriquecimento Externo (OTX + VirusTotal)
- `ENRICH_ENABLED`: ativa/desativa enriquecimento (default `true`)
- `ENRICH_TIMEOUT_MS`: timeout por requisicao (default `6000`)
- `ENRICH_MAX_IOCS`: quantidade maxima de IOCs consultados por noticia (default `6`)
- `OTX_API_KEY`: chave da API OTX (opcional)
- `VIRUSTOTAL_API_KEY`: chave da API VirusTotal (opcional)

Quando habilitado, o pipeline adiciona detalhes em `cti_analysis.enriquecimento` na resposta de `GET /api/threats`.

## Fonte de dados
Lê fontes de `../data/sources.json` para manter compatibilidade com o setup atual.
