# GraphQL Security & Schema Conformance Engine (`@security-lab/graphql-security`)

## Overview
`@security-lab/graphql-security` is a native Class A security engine for the Security & Resilience Testing Platform. It performs automated security analysis of GraphQL APIs, discovering introspection exposure, circular query depth Denial of Service vulnerabilities, batch query amplification attacks, and field suggestion schema leakages.

## Vulnerability Checks
1. **Schema Introspection Exposure (`GRAPHQL_INTROSPECTION_ENABLED`)**:
   - Executes standard full `__schema` queries.
   - Detects exposed queries, mutations, types, and administrative operations in staging or production environments.
2. **Circular Query Depth Fuzzing (`GRAPHQL_UNRESTRICTED_QUERY_DEPTH`)**:
   - Generates recursive nested circular queries (up to depth 25) using self-referencing schema types or traversal paths.
   - Asserts whether the server enforces depth limits (HTTP 400 rejection) or processes the deep query.
3. **Batch Query Array Amplification (`GRAPHQL_BATCH_AMPLIFICATION_ALLOWED`)**:
   - Submits arrays of 50 operations in a single HTTP POST request.
   - Identifies whether the GraphQL server allows batch amplification, bypassing HTTP rate limiters and amplifying brute-force attacks.
4. **Field Suggestion Harvesting (`GRAPHQL_FIELD_SUGGESTIONS_ENABLED`)**:
   - Sends misspelled query probes to harvest "Did you mean ...?" error feedback.
   - Reconstructs private schemas when introspection is disabled.

## Usage
```typescript
import { graphQLSecurityEngine } from '@security-lab/graphql-security';

const result = await graphQLSecurityEngine.execute(
  {
    targetUrl: 'https://staging.example.com/graphql',
    options: {
      environment: 'production',
      maxDepth: 25,
      batchSize: 50,
      testIntrospection: true,
      testDepth: true,
      testBatching: true,
      testSuggestions: true,
    },
  },
  context,
);
```
