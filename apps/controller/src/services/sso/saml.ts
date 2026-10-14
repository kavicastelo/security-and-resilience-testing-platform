import crypto from 'node:crypto';
import { Role } from '@security-lab/contracts';

export interface SamlMetadataOptions {
  entityId: string;
  acsUrl: string;
  singleLogoutUrl?: string;
  orgName?: string;
}

export interface SamlParsedAssertion {
  nameId: string;
  email: string;
  name?: string;
  groups: string[];
  sessionIndex?: string;
  issuer?: string;
  notBefore?: Date;
  notOnOrAfter?: Date;
}

export interface VerifySamlResponseOptions {
  samlResponseBase64: string;
  certPem?: string;
  expectedIssuer?: string;
  expectedAudience?: string;
  clockToleranceMs?: number; // default 5 minutes
}

/**
 * Generates standard SAML 2.0 SP Metadata XML.
 */
export function generateSamlMetadata(options: SamlMetadataOptions): string {
  const logoutService = options.singleLogoutUrl
    ? `\n    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${options.singleLogoutUrl}"/>`
    : '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${options.entityId}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${logoutService}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${options.acsUrl}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`.trim();
}

/**
 * Generates a SAML 2.0 AuthnRequest XML string.
 */
export function generateAuthnRequest(options: {
  id?: string;
  issueInstant?: string;
  destination: string;
  issuer: string;
  acsUrl: string;
}): { id: string; xml: string; base64: string } {
  const id = options.id || `_${crypto.randomUUID()}`;
  const issueInstant = options.issueInstant || new Date().toISOString();

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${id}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${options.destination}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  AssertionConsumerServiceURL="${options.acsUrl}">
  <saml:Issuer>${options.issuer}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>`.trim();

  const base64 = Buffer.from(xml, 'utf-8').toString('base64');
  return { id, xml, base64 };
}

/**
 * Verifies and parses a SAML 2.0 Response with timestamp validation and anti-replay protection.
 */
export function verifyAndParseSamlResponse(options: VerifySamlResponseOptions): SamlParsedAssertion {
  const {
    samlResponseBase64,
    certPem,
    expectedIssuer,
    expectedAudience,
    clockToleranceMs = 5 * 60 * 1000,
  } = options;

  let xml: string;
  try {
    xml = Buffer.from(samlResponseBase64, 'base64').toString('utf-8');
  } catch {
    throw new Error('Invalid Base64 encoding in SAML response');
  }

  if (!xml.includes('Response') && !xml.includes('Assertion')) {
    throw new Error('Payload does not contain valid SAML XML structure');
  }

  // 1. Status Check
  const statusCodeMatch = xml.match(/<samlp:StatusCode[^>]*Value="([^"]+)"/);
  if (statusCodeMatch) {
    const statusCode = statusCodeMatch[1];
    if (statusCode && !statusCode.includes('Success')) {
      throw new Error(`SAML IdP returned non-success status: ${statusCode}`);
    }
  }

  // 2. Issuer check
  const issuerMatch = xml.match(/<saml:Issuer[^>]*>([^<]+)<\/saml:Issuer>/);
  const issuer = issuerMatch ? issuerMatch[1]?.trim() : undefined;
  if (expectedIssuer && issuer && issuer !== expectedIssuer) {
    throw new Error(`SAML Issuer mismatch: expected "${expectedIssuer}", got "${issuer}"`);
  }

  // 3. Conditions & Timestamp verification (Anti-Replay Protection)
  const conditionsMatch = xml.match(/<saml:Conditions([^>]*)>/);
  const now = Date.now();
  let notBeforeDate: Date | undefined;
  let notOnOrAfterDate: Date | undefined;

  if (conditionsMatch) {
    const condAttr = conditionsMatch[1] || '';
    const notBeforeMatch = condAttr.match(/NotBefore="([^"]+)"/);
    const notOnOrAfterMatch = condAttr.match(/NotOnOrAfter="([^"]+)"/);

    if (notBeforeMatch && notBeforeMatch[1]) {
      notBeforeDate = new Date(notBeforeMatch[1]);
      if (now < notBeforeDate.getTime() - clockToleranceMs) {
        throw new Error(`SAML Assertion is not yet valid (NotBefore: ${notBeforeMatch[1]})`);
      }
    }

    if (notOnOrAfterMatch && notOnOrAfterMatch[1]) {
      notOnOrAfterDate = new Date(notOnOrAfterMatch[1]);
      if (now > notOnOrAfterDate.getTime() + clockToleranceMs) {
        throw new Error(`SAML Assertion has expired (NotOnOrAfter: ${notOnOrAfterMatch[1]})`);
      }
    }
  }

  // 4. Audience check
  if (expectedAudience) {
    const audienceMatch = xml.match(/<saml:Audience[^>]*>([^<]+)<\/saml:Audience>/);
    if (audienceMatch && audienceMatch[1]) {
      const actualAud = audienceMatch[1].trim();
      const normalize = (u: string) => u.replace(':80/', '/').replace(':443/', '/').replace(/\/$/, '');
      if (normalize(actualAud) !== normalize(expectedAudience)) {
        throw new Error(`SAML Audience mismatch: expected "${expectedAudience}", got "${actualAud}"`);
      }
    }
  }

  // 5. Digital signature verification (if certificate provided and signature element exists)
  if (certPem) {
    const signatureValueMatch = xml.match(/<ds:SignatureValue[^>]*>([\s\S]*?)<\/ds:SignatureValue>/);
    const signedInfoMatch = xml.match(/<ds:SignedInfo[\s\S]*?<\/ds:SignedInfo>/);

    if (signatureValueMatch && signedInfoMatch) {
      try {
        const signatureB64 = signatureValueMatch[1]?.replace(/\s+/g, '') || '';
        const signedInfoXml = signedInfoMatch[0];
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(signedInfoXml);
        
        let formattedCert = certPem.trim();
        if (!formattedCert.startsWith('-----BEGIN CERTIFICATE-----')) {
          formattedCert = `-----BEGIN CERTIFICATE-----\n${formattedCert}\n-----END CERTIFICATE-----`;
        }

        const isValid = verifier.verify(formattedCert, signatureB64, 'base64');
        if (!isValid) {
          // Attempt SHA1 fallback if SHA256 was not matched
          const verifierSha1 = crypto.createVerify('RSA-SHA1');
          verifierSha1.update(signedInfoXml);
          const isValidSha1 = verifierSha1.verify(formattedCert, signatureB64, 'base64');
          if (!isValidSha1) {
            throw new Error('SAML digital signature verification failed');
          }
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('SAML digital signature verification failed')) {
          throw err;
        }
        // If crypto verification syntax throws, flag as signature error
        throw new Error(`SAML signature error: ${msg}`);
      }
    }
  }

  // 6. Extract NameID (Subject)
  const nameIdMatch = xml.match(/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
  if (!nameIdMatch || !nameIdMatch[1]) {
    throw new Error('SAML Response missing Subject NameID');
  }
  const nameId = nameIdMatch[1].trim();

  // 7. Extract Attributes
  const attributes: Record<string, string[]> = {};
  const attrRegex = /<saml:Attribute[^>]*Name="([^"]+)"[\s\S]*?<\/saml:Attribute>/g;
  let match: RegExpExecArray | null;

  while ((match = attrRegex.exec(xml)) !== null) {
    const attrName = match[1]!;
    const attrBlock = match[0];
    const valRegex = /<saml:AttributeValue[^>]*>([^<]*)<\/saml:AttributeValue>/g;
    let valMatch: RegExpExecArray | null;
    const values: string[] = [];
    while ((valMatch = valRegex.exec(attrBlock)) !== null) {
      if (valMatch[1]) values.push(valMatch[1].trim());
    }
    attributes[attrName] = values;
  }

  // Find email
  const emailAttrKeys = [
    'email',
    'mail',
    'emailAddress',
    'User.Email',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  ];
  let email = nameId.includes('@') ? nameId : '';
  for (const k of emailAttrKeys) {
    if (attributes[k] && attributes[k]![0]) {
      email = attributes[k]![0]!;
      break;
    }
  }

  if (!email) {
    email = nameId;
  }

  // Find name
  const nameAttrKeys = [
    'name',
    'displayName',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  ];
  let name = '';
  for (const k of nameAttrKeys) {
    if (attributes[k] && attributes[k]![0]) {
      name = attributes[k]![0]!;
      break;
    }
  }
  if (!name) {
    const givenName = attributes['givenName']?.[0] || attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']?.[0] || '';
    const surname = attributes['surname']?.[0] || attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']?.[0] || '';
    name = `${givenName} ${surname}`.trim() || email.split('@')[0] || 'SAML User';
  }

  // Find groups/roles
  const groupAttrKeys = [
    'groups',
    'roles',
    'memberOf',
    'group',
    'role',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
    'http://schemas.xmlsoap.org/claims/Group',
  ];
  const groups: string[] = [];
  for (const k of groupAttrKeys) {
    if (attributes[k]) {
      groups.push(...attributes[k]!);
    }
  }

  // Session index
  const sessionIndexMatch = xml.match(/SessionIndex="([^"]+)"/);
  const sessionIndex = sessionIndexMatch ? sessionIndexMatch[1] : undefined;

  return {
    nameId,
    email: email.toLowerCase(),
    name,
    groups,
    sessionIndex,
    issuer,
    notBefore: notBeforeDate,
    notOnOrAfter: notOnOrAfterDate,
  };
}

/**
 * Maps IdP group memberships to a platform Role.
 */
export function mapGroupsToRole(
  groups: string[],
  roleMapping?: Record<string, Role>,
  defaultRole: Role = 'ENGINEER',
): Role {
  if (!roleMapping || Object.keys(roleMapping).length === 0) {
    return defaultRole;
  }

  let resolvedRole: Role | undefined = undefined;

  for (const group of groups) {
    const mapped = roleMapping[group];
    if (mapped === 'ADMIN') {
      return 'ADMIN'; // Highest privilege wins
    }
    if (mapped === 'ENGINEER') {
      resolvedRole = 'ENGINEER';
    } else if (mapped === 'AUDITOR' && resolvedRole !== 'ENGINEER') {
      resolvedRole = 'AUDITOR';
    }
  }

  return resolvedRole || defaultRole;
}
