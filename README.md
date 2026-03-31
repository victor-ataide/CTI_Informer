# CTI System (Node-only)

Plataforma de Cyber Threat Intelligence operando exclusivamente em Node.js.

## Stack

- Backend: Fastify + Prisma
- Banco: PostgreSQL
- Coleta: RSS + pipeline agendado (cron)
- Frontend: estatico servido pelo backend

## Estrutura Limpa

- `backend-node/`: aplicacao principal
- `frontend/`: interface web
- `data/`: fontes e resultados
- `scripts/`: comandos de operacao
- `docs/`: documentacao curta de operacao

## Operacao

### 1) Configurar ambiente

Arquivo de ambiente: `backend-node/.env`

Valores principais:

- `PORT=8101`
- `DATABASE_URL=postgresql://.../cti?schema=cti_node`
- `OTX_API_KEY` e `VIRUSTOTAL_API_KEY` para enriquecimento externo (opcional)

### 2) Instalar dependencias

```bash
npm --prefix backend-node install
npm --prefix backend-node run prisma:generate
npm --prefix backend-node run prisma:push
```

### 3) Iniciar

Foreground:

```bash
./scripts/start_cti.sh dashboard
```

Background:

```bash
./scripts/start_cti.sh daemon
```

### 4) Controle

```bash
./scripts/start_cti.sh status
./scripts/start_cti.sh logs
./scripts/start_cti.sh stop
```

## Endpoints uteis

- `GET /health`
- `GET /api/status`
- `GET /api/threats`
- `GET /api/iocs`
- `GET /api/feed/status`

## Enriquecimento de IOCs e Noticias

O pipeline agora consulta OTX e VirusTotal para enriquecer IOCs extraidos das noticias.

Variaveis opcionais em `backend-node/.env`:

- `ENRICH_ENABLED=true`
- `ENRICH_TIMEOUT_MS=6000`
- `ENRICH_MAX_IOCS=6`
- `OTX_API_KEY=...`
- `VIRUSTOTAL_API_KEY=...`

Resultado do enriquecimento aparece em `GET /api/threats` em `cti_analysis.enriquecimento`.

## Observacao

Este repositorio foi limpo para Node-only. O legado Python foi removido.
