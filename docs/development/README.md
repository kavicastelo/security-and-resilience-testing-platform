# Development Guide

## Getting Started
Follow these steps to set up the development environment:

### Prerequisites
* Node.js >= 20.0.0
* pnpm >= 9.0.0 (or pnpm 12)
* Docker & Docker Compose

### Local Setup
1. Clone the repository and install dependencies:
   ```bash
   pnpm install
   ```

2. Copy the environment configuration:
   ```bash
   cp .env.example .env
   ```

3. Start backing services (PostgreSQL):
   ```bash
   docker compose up -d postgres
   ```

4. Launch services in development watch mode:
   ```bash
   pnpm dev:all
   ```
   * Dashboard: `http://localhost:3000`
   * Controller API: `http://localhost:4000`
   * Controller Health: `http://localhost:4000/health`
