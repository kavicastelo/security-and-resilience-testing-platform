# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9.15.4 --activate

# Copy root manifests for monorepo workspace resolution
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY packages ./packages
COPY apps/agent ./apps/agent

# Install dependencies and build contracts, test-sdk, and agent
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @security-lab/contracts build
RUN pnpm --filter @security-lab/test-sdk build
RUN pnpm --filter @security-lab/agent build

# Stage 2: Runtime
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Install Docker CLI to support Class B/C containerized test executions
RUN apk add --no-cache docker-cli ca-certificates curl

# Create non-root system group and user
RUN addgroup -S securitylab && adduser -S securitylab -G securitylab

# Copy workspace dependencies and built dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/apps/agent/dist ./apps/agent/dist
COPY --from=builder /app/apps/agent/package.json ./apps/agent/package.json
COPY --from=builder /app/package.json ./package.json

USER securitylab

WORKDIR /app/apps/agent

ENV PORT=8080
ENV SECURITY_LAB_CONTROLLER_URL=http://controller:3000
ENV SECURITY_LAB_AGENT_POLL_INTERVAL_MS=3000
ENV SECURITY_LAB_AGENT_HEARTBEAT_INTERVAL_MS=10000

ENTRYPOINT ["node", "dist/index.js", "start"]
