FROM node:22-alpine AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

FROM base AS builder
WORKDIR /app
COPY pnpm-lock.yaml* pnpm-workspace.yaml package.json tsconfig.base.json tsconfig.json ./
COPY packages/ ./packages/
COPY apps/controller/ ./apps/controller/

RUN pnpm install --frozen-lockfile || pnpm install
RUN pnpm --filter @security-lab/controller build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=4000
ENV HOST=0.0.0.0

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/pnpm-workspace.yaml ./pnpm-workspace.yaml
COPY --from=builder /app/packages/ ./packages/
COPY --from=builder /app/apps/controller/ ./apps/controller/
COPY --from=builder /app/node_modules/ ./node_modules/

RUN mkdir -p /app/data

EXPOSE 4000

CMD ["node", "apps/controller/dist/server.js"]
