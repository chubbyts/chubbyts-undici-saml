import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import selfsigned from 'selfsigned';
import { SignedXml } from 'xml-crypto';

export type IdpKeyMaterial = {
  privateKey: string;
  certificatePem: string;
  certificate: string;
};

export const generateIdpKeyMaterial = async (): Promise<IdpKeyMaterial> => {
  const pems = await selfsigned.generate([{ name: 'commonName', value: 'idp.example.com' }], {
    keySize: 2048,
    days: 365,
    algorithm: 'sha256',
  });

  return {
    privateKey: pems.private,
    certificatePem: pems.cert,
    certificate: pems.cert
      .replace('-----BEGIN CERTIFICATE-----', '')
      .replace('-----END CERTIFICATE-----', '')
      .replaceAll(/\s+/g, ''),
  };
};

export type IdpMetadataXmlOptions = {
  entityId: string;
  certificates: Array<string>;
  singleSignOnServiceLocation: string;
};

export const createIdpMetadataXml = ({
  entityId,
  certificates,
  singleSignOnServiceLocation,
}: IdpMetadataXmlOptions): string => {
  const keyDescriptors = certificates
    .map(
      (certificate) =>
        `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
    )
    .join('');

  return `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keyDescriptors}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${singleSignOnServiceLocation}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${singleSignOnServiceLocation}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
};

export type SamlResponseXmlOptions = {
  idpEntityId: string;
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  assertionId?: string;
  nameId?: string;
  sessionIndex?: string;
  authnContextClassRef?: string | null;
  attributes?: Record<string, Array<string>>;
  issueInstant?: Date;
  notBefore?: Date;
  notOnOrAfter?: Date;
  // null omits the attribute, default: notOnOrAfter
  subjectConfirmationNotOnOrAfter?: Date | null;
  conditionsNotOnOrAfter?: Date | null;
  inResponseTo?: string;
  audience?: string;
  status?: string;
  includeAssertion?: boolean;
  signAssertion?: boolean;
  signResponse?: boolean;
};

const signXml = (keyMaterial: IdpKeyMaterial, xml: string, localName: 'Assertion' | 'Response'): string => {
  const signedXml = new SignedXml({ privateKey: keyMaterial.privateKey, publicCert: keyMaterial.certificatePem });

  signedXml.addReference({
    xpath: `//*[local-name(.)='${localName}']`,
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
  });

  // oxlint-disable-next-line functional/immutable-data
  signedXml.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  // oxlint-disable-next-line functional/immutable-data
  signedXml.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

  signedXml.computeSignature(xml, {
    location: { reference: `//*[local-name(.)='${localName}']/*[local-name(.)='Issuer']`, action: 'after' },
  });

  return signedXml.getSignedXml();
};

export const createSamlResponseXml = (keyMaterial: IdpKeyMaterial, options: SamlResponseXmlOptions): string => {
  const {
    idpEntityId,
    spEntityId,
    assertionConsumerServiceUrl,
    assertionId = `_assertion-${randomUUID()}`,
    nameId = 'user@example.com',
    sessionIndex,
    authnContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    attributes = {},
    issueInstant = new Date(),
    notBefore = new Date(Date.now() - 60_000),
    notOnOrAfter = new Date(Date.now() + 300_000),
    subjectConfirmationNotOnOrAfter = notOnOrAfter,
    conditionsNotOnOrAfter = notOnOrAfter,
    inResponseTo,
    audience = spEntityId,
    status = 'urn:oasis:names:tc:SAML:2.0:status:Success',
    includeAssertion = true,
    signAssertion = true,
    signResponse = false,
  } = options;

  const inResponseToAttribute = inResponseTo !== undefined ? ` InResponseTo="${inResponseTo}"` : '';

  const attributeStatements = Object.entries(attributes)
    .map(
      ([name, values]) =>
        `<saml:Attribute Name="${name}">${values
          .map((value) => `<saml:AttributeValue>${value}</saml:AttributeValue>`)
          .join('')}</saml:Attribute>`,
    )
    .join('');

  const subjectConfirmationNotOnOrAfterAttribute =
    subjectConfirmationNotOnOrAfter !== null ? ` NotOnOrAfter="${subjectConfirmationNotOnOrAfter.toISOString()}"` : '';

  const conditionsNotOnOrAfterAttribute =
    conditionsNotOnOrAfter !== null ? ` NotOnOrAfter="${conditionsNotOnOrAfter.toISOString()}"` : '';

  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant.toISOString()}"><saml:Issuer>${idpEntityId}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${subjectConfirmationNotOnOrAfterAttribute} Recipient="${assertionConsumerServiceUrl}"${inResponseToAttribute}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${notBefore.toISOString()}"${conditionsNotOnOrAfterAttribute}><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${issueInstant.toISOString()}"${
    sessionIndex !== undefined ? ` SessionIndex="${sessionIndex}"` : ''
  }>${
    authnContextClassRef !== null
      ? `<saml:AuthnContext><saml:AuthnContextClassRef>${authnContextClassRef}</saml:AuthnContextClassRef></saml:AuthnContext>`
      : ''
  }</saml:AuthnStatement>${
    attributeStatements !== '' ? `<saml:AttributeStatement>${attributeStatements}</saml:AttributeStatement>` : ''
  }</saml:Assertion>`;

  const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response-1" Version="2.0" IssueInstant="${issueInstant.toISOString()}" Destination="${assertionConsumerServiceUrl}"${inResponseToAttribute}><saml:Issuer>${idpEntityId}</saml:Issuer><samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>${
    includeAssertion ? (signAssertion ? signXml(keyMaterial, assertion, 'Assertion') : assertion) : ''
  }</samlp:Response>`;

  return signResponse ? signXml(keyMaterial, response, 'Response') : response;
};

export const createSamlResponse = (keyMaterial: IdpKeyMaterial, options: SamlResponseXmlOptions): string => {
  return Buffer.from(createSamlResponseXml(keyMaterial, options)).toString('base64');
};
