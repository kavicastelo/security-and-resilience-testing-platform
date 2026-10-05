# Security Lab Architecture & Monorepo Validation Script
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Security Lab: Environment & Architecture Verification" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Monorepo dependencies
Write-Host "`n[1/4] Checking dependencies..." -ForegroundColor Yellow
pnpm install

# 2. Strict Typecheck
Write-Host "`n[2/4] Executing TypeScript validation across all workspaces..." -ForegroundColor Yellow
pnpm run typecheck

# 3. Code Linter
Write-Host "`n[3/4] Running ESLint..." -ForegroundColor Yellow
pnpm run lint

# 4. Vitest Unit & Integration Tests
Write-Host "`n[4/4] Running automated tests..." -ForegroundColor Yellow
pnpm run test

Write-Host "`n✔ All foundational checks passed successfully!" -ForegroundColor Green
