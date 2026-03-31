# Node-only Guide

## Start rapido

- `./scripts/start_cti.sh daemon`
- abrir `http://localhost:8101`

## Diagnostico

- `./scripts/start_cti.sh status`
- `./scripts/start_cti.sh logs`
- `curl -sS http://127.0.0.1:8101/api/status`

## Atualizar schema Prisma

- `npm --prefix backend-node run prisma:push`

## Reinicio limpo

1. `./scripts/start_cti.sh stop`
2. `./scripts/start_cti.sh daemon`
