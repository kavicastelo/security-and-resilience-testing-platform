import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app/index.js';
import { getDatabase, closeDatabase } from '../src/services/db.js';
import { workspacesService } from '../src/services/workspaces.service.js';
import { projectsService } from '../src/services/projects.service.js';
import { targetsService } from '../src/services/targets.service.js';
import { billingService } from '../src/services/billing/billing.service.js';
import { computeStripeSignature } from '../src/services/billing/stripe.js';
import { signJwt } from '../src/services/auth-token.service.js';

describe('Phase 21: Multi-Tenant SaaS Control Plane & Enterprise Governance', () => {
  let app: FastifyInstance;
  let workspace1: any;
  let workspace2: any;
  let user1Token: string;
  let user2Token: string;
  let auditor1Token: string;
  let adminToken: string;
  let project1: any;
  let project2: any;
  let target1: any;
  let target2: any;

  const testWebhookSecret = 'whsec_test_secret_key_12345';

  beforeAll(async () => {
    process.env.STRIPE_WEBHOOK_SECRET = testWebhookSecret;
    app = buildApp({ disableLogging: true, enableReaper: false, bypassAuth: false });
    await app.ready();

    // 1. Provision Workspace 1 (Tenant Alpha)
    workspace1 = await workspacesService.createWorkspace({
      name: `Tenant Alpha ${Date.now()}`,
      description: 'Alpha workspace for tenant isolation tests',
    });

    // 2. Provision Workspace 2 (Tenant Beta)
    workspace2 = await workspacesService.createWorkspace({
      name: `Tenant Beta ${Date.now()}`,
      description: 'Beta workspace for tenant isolation tests',
    });

    // 3. Provision Users
    const u1 = await workspacesService.createUser({
      email: `engineer.alpha.${Date.now()}@alpha.test`,
      name: 'Alpha Engineer',
      role: 'ENGINEER',
      workspaceId: workspace1.id,
    });
    user1Token = signJwt({
      sub: u1.id,
      email: u1.email,
      name: u1.name,
      workspaceId: workspace1.id,
      role: 'ENGINEER',
    });

    const aud1 = await workspacesService.createUser({
      email: `auditor.alpha.${Date.now()}@alpha.test`,
      name: 'Alpha Auditor',
      role: 'AUDITOR',
      workspaceId: workspace1.id,
    });
    auditor1Token = signJwt({
      sub: aud1.id,
      email: aud1.email,
      name: aud1.name,
      workspaceId: workspace1.id,
      role: 'AUDITOR',
    });

    const u2 = await workspacesService.createUser({
      email: `engineer.beta.${Date.now()}@beta.test`,
      name: 'Beta Engineer',
      role: 'ENGINEER',
      workspaceId: workspace2.id,
    });
    user2Token = signJwt({
      sub: u2.id,
      email: u2.email,
      name: u2.name,
      workspaceId: workspace2.id,
      role: 'ENGINEER',
    });

    adminToken = signJwt({
      sub: '00000000-0000-0000-0000-000000000001',
      email: 'admin@security-lab.local',
      name: 'Global Administrator',
      workspaceId: workspace1.id,
      role: 'ADMIN',
    });

    // 4. Provision Projects & Targets
    project1 = await projectsService.createProject({
      name: `Alpha Project ${Date.now()}`,
      description: 'Project in Workspace 1',
    }, undefined, workspace1.id);

    target1 = await targetsService.createTarget({
      projectId: project1.id,
      name: 'Alpha Target',
      baseUrl: 'http://127.0.0.1:8081',
      allowedHosts: ['127.0.0.1'],
      allowedPorts: [8081],
      excludedPaths: [],
    });

    project2 = await projectsService.createProject({
      name: `Beta Project ${Date.now()}`,
      description: 'Project in Workspace 2',
    }, undefined, workspace2.id);

    target2 = await targetsService.createTarget({
      projectId: project2.id,
      name: 'Beta Target',
      baseUrl: 'http://127.0.0.1:8082',
      allowedHosts: ['127.0.0.1'],
      allowedPorts: [8082],
      excludedPaths: [],
    });
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  describe('1. Tenant Isolation & Zero Cross-Tenant Data Leakage', () => {
    it('prevents user in Workspace 1 from accessing Workspace 2 details', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/workspaces/${workspace2.id}`,
        headers: {
          authorization: `Bearer ${user1Token}`,
        },
      });

      expect(res.statusCode).toBe(403);
      const json = res.json();
      expect(json.success).toBe(false);
      expect(json.error.code).toBe('FORBIDDEN');
    });

    it('prevents user in Workspace 2 from accessing Workspace 1 details', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/workspaces/${workspace1.id}`,
        headers: {
          authorization: `Bearer ${user2Token}`,
        },
      });

      expect(res.statusCode).toBe(403);
      const json = res.json();
      expect(json.success).toBe(false);
      expect(json.error.code).toBe('FORBIDDEN');
    });

    it('prevents user in Workspace 1 from listing Workspace 2 members', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/workspaces/${workspace2.id}/members`,
        headers: {
          authorization: `Bearer ${user1Token}`,
        },
      });

      expect(res.statusCode).toBe(403);
      const json = res.json();
      expect(json.success).toBe(false);
    });

    it('prevents auditor in Workspace 1 from inspecting Workspace 2 audit logs', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/workspaces/${workspace2.id}/audit-events`,
        headers: {
          authorization: `Bearer ${auditor1Token}`,
        },
      });

      expect(res.statusCode).toBe(403);
      const json = res.json();
      expect(json.success).toBe(false);
    });

    it('prevents user in Workspace 1 from launching test run against Workspace 2 project', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: {
          authorization: `Bearer ${user1Token}`,
        },
        payload: {
          projectId: project2.id,
          targetId: target2.id,
        },
      });

      expect(res.statusCode).toBe(400);
      const json = res.json();
      expect(json.success).toBe(false);
      expect(json.error.message).toContain('not found or access denied in workspace');
    });
  });

  describe('2. Enterprise SSO (SAML 2.0 & OIDC)', () => {
    it('generates valid SAML 2.0 SP Metadata XML', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/auth/sso/saml/${workspace1.id}/metadata`,
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('xml');
      const xml = res.body;
      expect(xml).toContain('<md:EntityDescriptor');
      expect(xml).toContain('<md:AssertionConsumerService');
      expect(xml).toContain(`/api/v1/auth/sso/saml/${workspace1.id}/acs`);
    });

    it('processes SAML 2.0 ACS assertion, performs JIT provisioning, and maps roles', async () => {
      // 1. Configure SAML on Workspace 1
      await app.inject({
        method: 'PUT',
        url: `/api/v1/workspaces/${workspace1.id}/sso`,
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
        payload: {
          enabled: true,
          provider: 'saml',
          domain: 'alpha.corp',
          saml: {
            entryPoint: 'https://idp.okta.com/app/sso',
            issuer: 'https://idp.okta.com/idp-issuer-123',
            cert: 'test-cert-dummy',
          },
          roleMapping: {
            SecurityAdmins: 'ADMIN',
            Developers: 'ENGINEER',
          },
          defaultRole: 'ENGINEER',
        },
      });

      // 2. Synthesize SAML Response XML with fresh timestamps and role claim
      const nowIso = new Date().toISOString();
      const notBeforeIso = new Date(Date.now() - 60000).toISOString();
      const notOnOrAfterIso = new Date(Date.now() + 300000).toISOString();
      const samlEmail = `saml.user.${Date.now()}@alpha.corp`;

      const samlXml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  IssueInstant="${nowIso}">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion IssueInstant="${nowIso}">
    <saml:Issuer>https://idp.okta.com/idp-issuer-123</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${samlEmail}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBeforeIso}" NotOnOrAfter="${notOnOrAfterIso}">
      <saml:AudienceRestriction>
        <saml:Audience>http://localhost:80/api/v1/auth/sso/saml/${workspace1.id}/metadata</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="displayName">
        <saml:AttributeValue>SAML Alpha Admin</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="groups">
        <saml:AttributeValue>SecurityAdmins</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

      const samlResponseB64 = Buffer.from(samlXml).toString('base64');

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/auth/sso/saml/${workspace1.id}/acs`,
        payload: {
          SAMLResponse: samlResponseB64,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.success).toBe(true);
      expect(json.data.token).toBeDefined();
      expect(json.data.user.email).toBe(samlEmail.toLowerCase());
      expect(json.data.role).toBe('ADMIN'); // Mapped from SecurityAdmins
      expect(json.data.workspaceId).toBe(workspace1.id);
    });

    it('rejects expired SAML assertion (anti-replay defense)', async () => {
      const expiredNotOnOrAfter = new Date(Date.now() - 600000).toISOString(); // 10 minutes ago
      const expiredSamlXml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Issuer>https://idp.okta.com/idp-issuer-123</saml:Issuer>
    <saml:Subject>
      <saml:NameID>replay@alpha.corp</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="${expiredNotOnOrAfter}"/>
  </saml:Assertion>
</samlp:Response>`;

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/auth/sso/saml/${workspace1.id}/acs`,
        payload: {
          SAMLResponse: Buffer.from(expiredSamlXml).toString('base64'),
        },
      });

      expect(res.statusCode).toBe(401);
      const json = res.json();
      expect(json.success).toBe(false);
      expect(json.error.message).toContain('expired');
    });

    it('handles OIDC login redirect generation and token callback', async () => {
      // 1. Configure OIDC on Workspace 2
      await app.inject({
        method: 'PUT',
        url: `/api/v1/workspaces/${workspace2.id}/sso`,
        headers: {
          authorization: `Bearer ${adminToken}`,
        },
        payload: {
          enabled: true,
          provider: 'oidc',
          domain: 'beta.corp',
          oidc: {
            issuer: 'https://login.microsoftonline.com/tenant/v2.0',
            clientId: 'azure-client-123',
            clientSecret: 'secret-xyz',
          },
          roleMapping: {
            SecurityAuditors: 'AUDITOR',
          },
          defaultRole: 'ENGINEER',
        },
      });

      // 2. Test Login URL initiation
      const loginRes = await app.inject({
        method: 'GET',
        url: `/api/v1/auth/sso/oidc/${workspace2.id}/login`,
      });
      expect(loginRes.statusCode).toBe(200);
      expect(loginRes.json().data.authUrl).toContain('client_id=azure-client-123');

      // 3. Test OIDC Callback with claims
      const oidcEmail = `oidc.user.${Date.now()}@beta.corp`;
      const callbackRes = await app.inject({
        method: 'POST',
        url: `/api/v1/auth/sso/oidc/${workspace2.id}/callback`,
        payload: {
          claims: {
            sub: `azure-sub-${Date.now()}`,
            email: oidcEmail,
            name: 'Azure Beta Auditor',
            groups: ['SecurityAuditors'],
            iss: 'https://login.microsoftonline.com/tenant/v2.0',
            aud: 'azure-client-123',
            exp: Math.floor(Date.now() / 1000) + 3600,
          },
        },
      });

      expect(callbackRes.statusCode).toBe(200);
      const json = callbackRes.json();
      expect(json.success).toBe(true);
      expect(json.data.user.email).toBe(oidcEmail.toLowerCase());
      expect(json.data.role).toBe('AUDITOR');
      expect(json.data.workspaceId).toBe(workspace2.id);
    });
  });

  describe('3. SCIM 2.0 Directory Synchronization', () => {
    let createdScimUserId: string;

    it('returns standard SCIM ServiceProviderConfig', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/scim/v2/ServiceProviderConfig',
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/scim+json');
      const json = res.json();
      expect(json.schemas).toContain('urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig');
      expect(json.patch.supported).toBe(true);
    });

    it('provisions a new user into the workspace via SCIM POST /scim/v2/Users', async () => {
      const scimEmail = `scim.user.${Date.now()}@alpha.test`;
      const res = await app.inject({
        method: 'POST',
        url: '/scim/v2/Users',
        headers: {
          'x-workspace-id': workspace1.id,
        },
        payload: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: scimEmail,
          name: {
            formatted: 'SCIM Provisioned User',
            givenName: 'SCIM',
            familyName: 'User',
          },
          emails: [{ value: scimEmail, primary: true }],
          active: true,
          roles: [{ value: 'ENGINEER' }],
        },
      });

      expect(res.statusCode).toBe(201);
      const json = res.json();
      expect(json.id).toBeDefined();
      expect(json.userName).toBe(scimEmail.toLowerCase());
      expect(json.active).toBe(true);
      expect(json.roles[0].value).toBe('ENGINEER');
      createdScimUserId = json.id;
    });

    it('retrieves user details via SCIM GET /scim/v2/Users/:id', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/scim/v2/Users/${createdScimUserId}`,
        headers: {
          'x-workspace-id': workspace1.id,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.id).toBe(createdScimUserId);
    });

    it('deprovisions user via SCIM PATCH active: false', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/scim/v2/Users/${createdScimUserId}`,
        headers: {
          'x-workspace-id': workspace1.id,
        },
        payload: {
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [
            {
              op: 'replace',
              path: 'active',
              value: false,
            },
          ],
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.active).toBe(false);

      // Verify user no longer in workspace members
      const checkRes = await app.inject({
        method: 'GET',
        url: `/scim/v2/Users/${createdScimUserId}`,
        headers: {
          'x-workspace-id': workspace1.id,
        },
      });
      expect(checkRes.statusCode).toBe(404);
    });

    it('returns workspace role groups via SCIM GET /scim/v2/Groups', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/scim/v2/Groups',
        headers: {
          'x-workspace-id': workspace1.id,
        },
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.totalResults).toBe(3); // ADMIN, ENGINEER, AUDITOR
      const displayNames = json.Resources.map((r: any) => r.displayName);
      expect(displayNames).toContain('ADMIN');
      expect(displayNames).toContain('ENGINEER');
      expect(displayNames).toContain('AUDITOR');
    });
  });

  describe('4. Stripe Usage-Based Metering & Quota Enforcement', () => {
    it('processes Stripe subscription webhook to upgrade workspace tier', async () => {
      const customerId = `cus_test_${Date.now()}`;

      // Associate customerId with workspace1
      await billingService.updateSubscriptionTier(workspace1.id, 'free', customerId);

      const payload = {
        id: `evt_test_${Date.now()}`,
        type: 'customer.subscription.created',
        data: {
          object: {
            customer: customerId,
            metadata: {
              workspace_id: workspace1.id,
              tier: 'starter',
            },
          },
        },
      };

      const rawBody = JSON.stringify(payload);
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = computeStripeSignature(rawBody, timestamp, testWebhookSecret);

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/billing/webhook',
        headers: {
          'content-type': 'application/json',
          'stripe-signature': `t=${timestamp},v1=${signature}`,
        },
        payload: rawBody,
      });

      expect(res.statusCode).toBe(200);
      const json = res.json();
      expect(json.received).toBe(true);
      expect(json.handled).toBe(true);

      // Verify workspace is now starter tier with 1000 mins quota
      const billing = await billingService.getWorkspaceBilling(workspace1.id);
      expect(billing?.subscriptionTier).toBe('starter');
      expect(billing?.quotaLimits.maxExecutionMinutesPerMonth).toBe(1000);
    });

    it('records run execution minutes and exports Prometheus metrics', async () => {
      // Record 120 seconds of execution
      await billingService.recordRunUsage(workspace1.id, 120);

      const billing = await billingService.getWorkspaceBilling(workspace1.id);
      expect(billing?.usageMinutes).toBeGreaterThanOrEqual(2);

      // Verify Prometheus exporter reflects metric
      const metricsRes = await app.inject({
        method: 'GET',
        url: '/metrics',
      });
      expect(metricsRes.statusCode).toBe(200);
      expect(metricsRes.body).toContain('security_lab_tenant_usage_seconds_total');
      expect(metricsRes.body).toContain(`workspace_id="${workspace1.id}"`);
    });

    it('enforces Quota Guard (402 Payment Required) when monthly execution limit is exceeded', async () => {
      // Simulate over-quota by updating usage_minutes past limit
      const { db } = getDatabase();
      const { workspaces } = await import('../src/services/db/schema.js');
      const { eq } = await import('drizzle-orm');

      await db
        .update(workspaces)
        .set({ usageMinutes: 1500 }) // Over starter tier 1000 min limit
        .where(eq(workspaces.id, workspace1.id));

      // Attempt to launch a new test run
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/test-runs',
        headers: {
          authorization: `Bearer ${user1Token}`,
        },
        payload: {
          projectId: project1.id,
          targetId: target1.id,
        },
      });

      expect(res.statusCode).toBe(402); // 402 Payment Required
      const json = res.json();
      expect(json.success).toBe(false);
      expect(json.error.code).toBe('QUOTA_EXCEEDED');
      expect(json.error.message).toContain('Monthly execution quota exceeded');
    });

    it('handles customer.subscription.deleted to downgrade workspace to free tier', async () => {
      const billing = await billingService.getWorkspaceBilling(workspace1.id);
      const customerId = billing?.stripeCustomerId || 'cus_unknown';

      const payload = {
        id: `evt_cancel_${Date.now()}`,
        type: 'customer.subscription.deleted',
        data: {
          object: {
            customer: customerId,
            metadata: {
              workspace_id: workspace1.id,
            },
          },
        },
      };

      const rawBody = JSON.stringify(payload);
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = computeStripeSignature(rawBody, timestamp, testWebhookSecret);

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/billing/webhook',
        headers: {
          'content-type': 'application/json',
          'stripe-signature': `t=${timestamp},v1=${signature}`,
        },
        payload: rawBody,
      });

      expect(res.statusCode).toBe(200);
      const updatedBilling = await billingService.getWorkspaceBilling(workspace1.id);
      expect(updatedBilling?.subscriptionTier).toBe('free');
      expect(updatedBilling?.quotaLimits.maxExecutionMinutesPerMonth).toBe(100);
    });
  });
});
