import { Buffer } from 'node:buffer';
import { createSign, randomUUID } from 'node:crypto';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
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
  singleLogoutServiceLocation?: string;
};

export const createIdpMetadataXml = ({
  entityId,
  certificates,
  singleSignOnServiceLocation,
  singleLogoutServiceLocation,
}: IdpMetadataXmlOptions): string => {
  const keyDescriptors = certificates
    .map(
      (certificate) =>
        `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
    )
    .join('');

  const singleLogoutServices =
    singleLogoutServiceLocation !== undefined
      ? `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${singleLogoutServiceLocation}"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${singleLogoutServiceLocation}"/>`
      : '';

  return `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keyDescriptors}${singleLogoutServices}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${singleSignOnServiceLocation}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${singleSignOnServiceLocation}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
};

export type LogoutRequestXmlOptions = {
  idpEntityId: string;
  destination: string;
  id?: string;
  nameId?: string;
  nameIdFormat?: string | null;
  sessionIndex?: string;
  issueInstant?: Date;
  notOnOrAfter?: Date;
};

export const createLogoutRequestXml = (options: LogoutRequestXmlOptions): string => {
  const {
    idpEntityId,
    destination,
    id = '_logout-request-1',
    nameId = 'user@example.com',
    nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    sessionIndex,
    issueInstant = new Date(),
    notOnOrAfter,
  } = options;

  return `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${issueInstant.toISOString()}" Destination="${destination}"${
    notOnOrAfter !== undefined ? ` NotOnOrAfter="${notOnOrAfter.toISOString()}"` : ''
  }><saml:Issuer>${idpEntityId}</saml:Issuer><saml:NameID${nameIdFormat !== null ? ` Format="${nameIdFormat}"` : ''}>${nameId}</saml:NameID>${
    sessionIndex !== undefined ? `<samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex>` : ''
  }</samlp:LogoutRequest>`;
};

export type LogoutResponseXmlOptions = {
  idpEntityId: string;
  destination: string;
  id?: string;
  inResponseTo?: string;
  status?: string;
  issueInstant?: Date;
};

export const createLogoutResponseXml = (options: LogoutResponseXmlOptions): string => {
  const {
    idpEntityId,
    destination,
    id = '_logout-response-1',
    inResponseTo,
    status = 'urn:oasis:names:tc:SAML:2.0:status:Success',
    issueInstant = new Date(),
  } = options;

  return `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${issueInstant.toISOString()}" Destination="${destination}"${
    inResponseTo !== undefined ? ` InResponseTo="${inResponseTo}"` : ''
  }><saml:Issuer>${idpEntityId}</saml:Issuer><samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status></samlp:LogoutResponse>`;
};

export type RedirectQueryOptions = {
  relayState?: string;
  sign?: boolean;
  sigAlg?: string;
  hashAlgorithm?: string;
  deflate?: boolean;
};

// the query of a http-redirect binding message: deflated, base64 and url encoded message, optional relay state and
// (by default) a signature over the url encoded parameters as sent (the way an identity provider signs it)
export const createRedirectQuery = (
  keyMaterial: IdpKeyMaterial,
  type: 'SAMLRequest' | 'SAMLResponse',
  xml: string,
  options: RedirectQueryOptions = {},
): string => {
  const {
    relayState,
    sign = true,
    sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    hashAlgorithm = 'RSA-SHA256',
    deflate = true,
  } = options;

  const message = (deflate ? deflateRawSync(Buffer.from(xml)) : Buffer.from(xml)).toString('base64');

  const parameters = [
    `${type}=${encodeURIComponent(message)}`,
    ...(relayState !== undefined ? [`RelayState=${encodeURIComponent(relayState)}`] : []),
  ];

  if (!sign) {
    return parameters.join('&');
  }

  const signedParameters = [...parameters, `SigAlg=${encodeURIComponent(sigAlg)}`].join('&');

  const signature = createSign(hashAlgorithm).update(signedParameters).sign(keyMaterial.privateKey, 'base64');

  return `${signedParameters}&Signature=${encodeURIComponent(signature)}`;
};

// the message within a http-redirect binding url created by the service provider
export const inflateRedirectMessage = (url: URL, type: 'SAMLRequest' | 'SAMLResponse'): string => {
  return inflateRawSync(Buffer.from(url.searchParams.get(type) as string, 'base64')).toString();
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
  // null omits the attribute, default: assertionConsumerServiceUrl
  recipient?: string | null;
  destination?: string | null;
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
    recipient = assertionConsumerServiceUrl,
    destination = assertionConsumerServiceUrl,
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

  const recipientAttribute = recipient !== null ? ` Recipient="${recipient}"` : '';
  const destinationAttribute = destination !== null ? ` Destination="${destination}"` : '';

  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant.toISOString()}"><saml:Issuer>${idpEntityId}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${subjectConfirmationNotOnOrAfterAttribute}${recipientAttribute}${inResponseToAttribute}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${notBefore.toISOString()}"${conditionsNotOnOrAfterAttribute}><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${issueInstant.toISOString()}"${
    sessionIndex !== undefined ? ` SessionIndex="${sessionIndex}"` : ''
  }>${
    authnContextClassRef !== null
      ? `<saml:AuthnContext><saml:AuthnContextClassRef>${authnContextClassRef}</saml:AuthnContextClassRef></saml:AuthnContext>`
      : ''
  }</saml:AuthnStatement>${
    attributeStatements !== '' ? `<saml:AttributeStatement>${attributeStatements}</saml:AttributeStatement>` : ''
  }</saml:Assertion>`;

  const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response-1" Version="2.0" IssueInstant="${issueInstant.toISOString()}"${destinationAttribute}${inResponseToAttribute}><saml:Issuer>${idpEntityId}</saml:Issuer><samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>${
    includeAssertion ? (signAssertion ? signXml(keyMaterial, assertion, 'Assertion') : assertion) : ''
  }</samlp:Response>`;

  return signResponse ? signXml(keyMaterial, response, 'Response') : response;
};

export const createSamlResponse = (keyMaterial: IdpKeyMaterial, options: SamlResponseXmlOptions): string => {
  return Buffer.from(createSamlResponseXml(keyMaterial, options)).toString('base64');
};
