#!/usr/bin/env bash
set -e

echo "Starting Security Lab Local Development..."

if [ ! -f ".env" ]; then
    echo "No .env found. Copying from .env.example..."
    cp .env.example .env
fi

echo "Starting backing services (PostgreSQL)..."
docker compose up -d postgres

echo "Starting monorepo dev processes..."
pnpm run dev:all
