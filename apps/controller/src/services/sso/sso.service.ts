import { eq, and } from 'drizzle-orm';
import { getDatabase } from '../db.js';
import { workspaces, users, workspaceMemberships } from '../db/schema.js';
import { Role, SsoConfig } from '@security-lab/contracts';
import { signJwt } from '../auth-token.service.js';
import {
  generateSamlMetadata,
  verifyAndParseSamlResponse,
  mapGroupsToRole,
} from './saml.js';
import {
  generateOidcAuthUrl,
  verifyAndParseOidcClaims,
} from './oidc.js';

export interface SsoLoginResult {
  token: string;
  user: {
    id: string;
    email: string;
    name: string;
    createdAt: Date;
    updatedAt: Date;
  };
  role: Role;
  workspaceId: string;
}

export class SsoService {
  /**
   * Retrieves the configured SSO settings for a workspace.
   */
  async getWorkspaceSsoConfig(workspaceId: string): Promise<SsoConfig | null> {
    const { db } = getDatabase();
    const [row] = await db
      .select({ ssoConfig: workspaces.ssoConfig })
      .from(workspaces)
      .where(eq(workspaces.id, workspaceId));

    if (!row || !row.ssoConfig) {
      return null;
    }
    return row.ssoConfig as SsoConfig;
  }

  /**
   * Generates SAML SP metadata for the specified workspace.
   */
  async getSamlMetadata(workspaceId: string, hostUrl: string): Promise<string> {
    const baseUrl = hostUrl.replace(/\/$/, '');
    const entityId = `${baseUrl}/api/v1/auth/sso/saml/${workspaceId}/metadata`;
    const acsUrl = `${baseUrl}/api/v1/auth/sso/saml/${workspaceId}/acs`;

    return generateSamlMetadata({
      entityId,
      acsUrl,
      orgName: 'Security & Resilience Testing Platform',
    });
  }

  /**
   * Processes an incoming SAML Response assertion, enforces anti-replay,
   * maps roles, JIT provisions the user, and returns an authenticated session JWT.
   */
  async processSamlResponse(
    workspaceId: string,
    samlResponseBase64: string,
    hostUrl?: string,
  ): Promise<SsoLoginResult> {
    const ssoConfig = await this.getWorkspaceSsoConfig(workspaceId);
    if (!ssoConfig || !ssoConfig.enabled || ssoConfig.provider !== 'saml' || !ssoConfig.saml) {
      throw new Error(`SAML SSO is not enabled or configured for workspace "${workspaceId}"`);
    }

    const expectedAudience = hostUrl
      ? `${hostUrl.replace(/\/$/, '')}/api/v1/auth/sso/saml/${workspaceId}/metadata`
      : undefined;

    const assertion = verifyAndParseSamlResponse({
      samlResponseBase64,
      certPem: ssoConfig.saml.cert,
      expectedIssuer: ssoConfig.saml.issuer,
      expectedAudience,
    });

    // Role Mapping
    const role = mapGroupsToRole(
      assertion.groups,
      ssoConfig.roleMapping,
      ssoConfig.defaultRole || 'ENGINEER',
    );

    // JIT User Provisioning
    const user = await this.provisionUserJit(workspaceId, {
      email: assertion.email,
      name: assertion.name || assertion.email.split('@')[0],
      role,
    });

    // Generate JWT
    const token = signJwt({
      sub: user.id,
      email: user.email,
      name: user.name,
      workspaceId,
      role,
    });

    return {
      token,
      user,
      role,
      workspaceId,
    };
  }

  /**
   * Generates an OIDC login redirect URL for the specified workspace.
   */
  async getOidcAuthUrl(
    workspaceId: string,
    hostUrl: string,
    state?: string,
  ): Promise<string> {
    const ssoConfig = await this.getWorkspaceSsoConfig(workspaceId);
    if (!ssoConfig || !ssoConfig.enabled || ssoConfig.provider !== 'oidc' || !ssoConfig.oidc) {
      throw new Error(`OIDC SSO is not enabled or configured for workspace "${workspaceId}"`);
    }

    const redirectUri = `${hostUrl.replace(/\/$/, '')}/api/v1/auth/sso/oidc/${workspaceId}/callback`;
    return generateOidcAuthUrl(ssoConfig.oidc, state || workspaceId, redirectUri);
  }

  /**
   * Processes an incoming OIDC ID token or callback payload, maps roles, JIT provisions,
   * and returns an authenticated platform session.
   */
  async processOidcCallback(
    workspaceId: string,
    idTokenOrClaims: string | Record<string, unknown>,
  ): Promise<SsoLoginResult> {
    const ssoConfig = await this.getWorkspaceSsoConfig(workspaceId);
    if (!ssoConfig || !ssoConfig.enabled || ssoConfig.provider !== 'oidc' || !ssoConfig.oidc) {
      throw new Error(`OIDC SSO is not enabled or configured for workspace "${workspaceId}"`);
    }

    const claims = verifyAndParseOidcClaims(
      idTokenOrClaims,
      ssoConfig.oidc.clientId,
      ssoConfig.oidc.issuer,
    );

    // Role Mapping
    const role = mapGroupsToRole(
      claims.groups,
      ssoConfig.roleMapping,
      ssoConfig.defaultRole || 'ENGINEER',
    );

    // JIT Provisioning
    const user = await this.provisionUserJit(workspaceId, {
      email: claims.email,
      name: claims.name || claims.email.split('@')[0],
      role,
    });

    const token = signJwt({
      sub: user.id,
      email: user.email,
      name: user.name,
      workspaceId,
      role,
    });

    return {
      token,
      user,
      role,
      workspaceId,
    };
  }

  /**
   * Performs Just-In-Time (JIT) user creation and workspace membership assignment.
   */
  async provisionUserJit(
    workspaceId: string,
    identity: { email: string; name?: string; role: Role },
  ): Promise<{ id: string; email: string; name: string; createdAt: Date; updatedAt: Date }> {
    const { db } = getDatabase();
    const cleanEmail = identity.email.toLowerCase().trim();

    // 1. Find or create user
    let [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, cleanEmail));

    if (!existingUser) {
      const [created] = await db
        .insert(users)
        .values({
          email: cleanEmail,
          name: identity.name || cleanEmail.split('@')[0] || 'SSO User',
          passwordHash: null, // SSO users have no local password
        })
        .returning();
      existingUser = created!;
    } else if (identity.name && existingUser.name !== identity.name) {
      // Update name if changed
      await db
        .update(users)
        .set({ name: identity.name, updatedAt: new Date() })
        .where(eq(users.id, existingUser.id));
      existingUser.name = identity.name;
    }

    // 2. Find or create / update workspace membership
    const [existingMembership] = await db
      .select()
      .from(workspaceMemberships)
      .where(
        and(
          eq(workspaceMemberships.workspaceId, workspaceId),
          eq(workspaceMemberships.userId, existingUser.id),
        ),
      );

    if (!existingMembership) {
      await db.insert(workspaceMemberships).values({
        workspaceId,
        userId: existingUser.id,
        role: identity.role,
      });
    } else if (existingMembership.role !== identity.role) {
      // Sync role claim
      await db
        .update(workspaceMemberships)
        .set({ role: identity.role, updatedAt: new Date() })
        .where(eq(workspaceMemberships.id, existingMembership.id));
    }

    return {
      id: existingUser.id,
      email: existingUser.email,
      name: existingUser.name,
      createdAt: existingUser.createdAt,
      updatedAt: existingUser.updatedAt,
    };
  }
}

export const ssoService = new SsoService();
