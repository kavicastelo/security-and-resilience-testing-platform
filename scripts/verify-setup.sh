#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "  Security Lab: Environment & Architecture Verification"
echo "=========================================================="

echo -e "\n[1/4] Checking dependencies..."
pnpm install

echo -e "\n[2/4] Executing TypeScript validation across all workspaces..."
pnpm run typecheck

echo -e "\n[3/4] Running ESLint..."
pnpm run lint

echo -e "\n[4/4] Running automated tests..."
pnpm run test

echo -e "\n✔ All foundational checks passed successfully!"
