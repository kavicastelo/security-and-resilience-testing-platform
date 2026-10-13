export interface GraphQLSecurityOptions {
  /**
   * Relative or absolute GraphQL endpoint path (defaults to auto-discovering /graphql, /api/graphql, /query).
   */
  graphqlPath?: string;

  /**
   * Deployment environment profile. If 'production', introspection exposure is marked CRITICAL.
   */
  environment?: 'development' | 'staging' | 'production';

  /**
   * Whether to test schema introspection. Defaults to true.
   */
  testIntrospection?: boolean;

  /**
   * Whether to test query depth limits. Defaults to true.
   */
  testDepth?: boolean;

  /**
   * Maximum recursion depth to test for circular query DoS. Defaults to 25.
   */
  maxDepth?: number;

  /**
   * Whether to test batch query array amplification. Defaults to true.
   */
  testBatching?: boolean;

  /**
   * Number of operations in batch query payload (capped at 50 for safety). Defaults to 50.
   */
  batchSize?: number;

  /**
   * Whether to test for schema field suggestions leaking private fields. Defaults to true.
   */
  testSuggestions?: boolean;
}

export interface IntrospectionTypeField {
  name: string;
  description?: string;
  type: {
    kind: string;
    name?: string;
    ofType?: {
      kind: string;
      name?: string;
      ofType?: {
        kind: string;
        name?: string;
      };
    };
  };
}

export interface IntrospectionType {
  kind: string;
  name: string;
  description?: string;
  fields?: IntrospectionTypeField[];
}

export interface IntrospectionSchema {
  queryType?: { name: string };
  mutationType?: { name: string };
  subscriptionType?: { name: string };
  types: IntrospectionType[];
}

export interface IntrospectionResult {
  enabled: boolean;
  schema?: IntrospectionSchema;
  queryTypeName?: string;
  mutationTypeName?: string;
  typesCount: number;
  fieldsCount: number;
  queries: string[];
  mutations: string[];
}
