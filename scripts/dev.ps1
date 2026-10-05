# Security Lab Local Development Launcher
Write-Host "Starting Security Lab Local Development..." -ForegroundColor Cyan

# 1. Verify .env exists
if (-not (Test-Path ".env")) {
    Write-Host "No .env found. Copying from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
}

# 2. Check docker compose status
Write-Host "Starting backing services (PostgreSQL)..." -ForegroundColor Cyan
docker compose up -d postgres

# 3. Start controller and dashboard in watch mode
Write-Host "Starting monorepo dev processes..." -ForegroundColor Green
pnpm run dev:all
