# Web Application DAST Crawler Engine (`@security-lab/web-crawler`)

## Overview
`@security-lab/web-crawler` is a native Class A crawler engine for the Security & Resilience Testing Platform. It discovers modern dynamic routes, client-side Single Page Application (SPA) paths, interactive HTML forms, input parameters, buttons, and underlying REST/GraphQL API endpoints.

## Capabilities & Architecture
- **Dual-Mode Crawling**:
  - **Headless Browser Execution**: Uses Playwright to load dynamic client JavaScript, evaluate React/Vue/Angular DOM state, and capture XHR/Fetch network traffic in real time.
  - **Resilient Native SPA Engine Fallback**: If Playwright browser binaries cannot be launched due to system constraints or security policies, the engine automatically falls back to an intelligent HTTP/DOM/SPA route parser using `safeFetch`.
- **Target Scope Adherence**:
  - Enforces `validateUrlAgainstScope()` across all discovered links, form targets, and API requests to ensure no out-of-scope destinations are visited.
- **Contract Compliance**:
  - Emits `CrawledTargetInventory` conforming to `@security-lab/contracts`.

## Usage
```typescript
import { webCrawlerEngine } from '@security-lab/web-crawler';

const result = await webCrawlerEngine.execute(
  {
    targetUrl: 'https://staging.example.com',
    parameters: {
      maxDepth: 3,
      maxPages: 50,
      interceptNetwork: true,
      extractSpaRoutes: true,
    },
  },
  context,
);
```
