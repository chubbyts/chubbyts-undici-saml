# chubbyts-undici-saml

[![CI](https://github.com/chubbyts/chubbyts-undici-saml/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/chubbyts/chubbyts-undici-saml/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/chubbyts/chubbyts-undici-saml/badge.svg?branch=master)](https://coveralls.io/github/chubbyts/chubbyts-undici-saml?branch=master)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fchubbyts%2Fchubbyts-undici-saml%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/chubbyts/chubbyts-undici-saml/master)
[![npm-version](https://img.shields.io/npm/v/@chubbyts/chubbyts-undici-saml.svg)](https://www.npmjs.com/package/@chubbyts/chubbyts-undici-saml)

[![bugs](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=bugs)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![code_smells](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=code_smells)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![coverage](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=coverage)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![duplicated_lines_density](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![ncloc](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=ncloc)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![sqale_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![alert_status](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=alert_status)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![reliability_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![security_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=security_rating)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![sqale_index](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=sqale_index)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)
[![vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-saml&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-saml)

## Description

A minimal SAML 2.0 service provider ([Web Browser SSO Profile][10] and [Single Logout Profile][10]) integration for chubbyts-undici-server: resolves the identity provider's [metadata][11], redirects unauthenticated requests to the identity provider (HTTP-Redirect binding), consumes and verifies saml responses at the assertion consumer service (HTTP-POST binding, via [@node-saml/node-saml][4]), keeps the verified identity within an encrypted session cookie, passes it to the handler via request attributes and optionally handles single logout (HTTP-Redirect binding, service provider and identity provider initiated).

## Requirements

 * node: >=22
 * [@chubbyts/chubbyts-dic-types][14]: ^2.3.0
 * [@chubbyts/chubbyts-log-types][2]: ^3.3.0
 * [@chubbyts/chubbyts-undici-server][3]: ^1.2.0
 * [@node-saml/node-saml][4]: ^5.1.0
 * [@xmldom/xmldom][5]: ^0.9.12
 * [jose][6]: ^6.2.8

## Installation

Through [NPM](https://www.npmjs.com) as [@chubbyts/chubbyts-undici-saml][1].

```sh
npm i @chubbyts/chubbyts-undici-saml@^1.0.0
```

## Usage

```ts
import { createIdpMetadataResolver } from '@chubbyts/chubbyts-undici-saml/dist/metadata';
import type { SamlAttributes } from '@chubbyts/chubbyts-undici-saml/dist/middleware';
import { createSamlAuthenticationMiddleware } from '@chubbyts/chubbyts-undici-saml/dist/middleware';
import { createSamlServiceProvider } from '@chubbyts/chubbyts-undici-saml/dist/service-provider';
import { createSamlSession } from '@chubbyts/chubbyts-undici-saml/dist/session';
import type { Handler, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response } from '@chubbyts/chubbyts-undici-server/dist/server';

const samlAuthenticationMiddleware = createSamlAuthenticationMiddleware(
  createSamlSession({ secret: process.env.SESSION_SECRET as string }),
  createSamlServiceProvider(createIdpMetadataResolver('https://idp.example.com/metadata'), {
    entityId: 'https://sp.example.com',
    assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs',
  }),
  '/saml/acs',
);

// or with single logout (the logout messages must be signed, so a key pair is required):
// createSamlServiceProvider(idpMetadataResolver, { ..., singleLogoutServiceUrl: 'https://sp.example.com/saml/slo', privateKey, certificate })
// createSamlAuthenticationMiddleware(samlSession, samlServiceProvider, { assertionConsumerServicePath: '/saml/acs', singleLogoutServicePath: '/saml/slo' })

// add the middleware to the routes you want to protect, e.g. within chubbyts-framework:
// createGroup({ path: '/', ..., middlewares: [samlAuthenticationMiddleware, ...] })

const handler: Handler = async (serverRequest: ServerRequest<SamlAttributes>): Promise<Response> => {
  // attributes are typed as partial, the middleware guarantees "saml" for every handler behind it
  const { identity } = serverRequest.attributes.saml!; // { nameId, nameIdFormat, sessionIndex?, authnContextClassRef?, issuer, attributes }

  return new Response(JSON.stringify({ nameId: identity.nameId }), {
    headers: { 'content-type': 'application/json' },
  });
};
```

 * **Flow:** An unauthenticated `GET` / `HEAD` request is answered with a `302` redirect to the identity provider's single sign-on location (a deflated `AuthnRequest` within the query, the current path and query as `RelayState`). The identity provider posts its saml response to the assertion consumer service path, where it is verified (signatures, issuer, audience, `Destination` / `Recipient`, validity period, replay, see below): on success a session cookie is set and a `303` redirect to the `RelayState` follows (only a same-origin absolute path is followed, anything else would be an open redirect and falls back to `/`), on failure a `403` is returned. Any other unauthenticated request (an expired session within a `POST`, a fetch from a spa, ...) is answered with a `401` instead of a redirect: it could not carry the login redirect anyway.
 * **Logout:** With a `singleLogoutServicePath` the middleware also handles single logout (see below). A `POST` to that path (e.g. a logout form, optionally with the path to end up at as `RelayState` field) removes the session cookie and answers with a `303` redirect to the identity provider's single logout location carrying a signed `LogoutRequest`, the identity provider ends its own session and sends the browser back with a `LogoutResponse` (`GET` on the same path), which is verified and answered with a `303` redirect to the `RelayState`. The other way round, a `LogoutRequest` of the identity provider (`GET` on the same path, e.g. after a logout at another service provider) removes the session cookie and answers with a `303` redirect back to the identity provider carrying a signed `LogoutResponse`. Without single logout, a logout endpoint of your own answers with the `createRemovalCookie()` value as `set-cookie` header.
 * **Rejected saml messages:** The actual reason (wrong signature, expired, wrong audience, ...) is only logged (level `info`) via the optional logger, never sent to the client (`403`). Errors not related to the saml message (unreachable identity provider, an encrypted assertion without `decryptionKey`, ...) are rethrown, so your error handling responds with a `5xx`.
 * **Session:** The verified identity is stored within an encrypted (`dir` / `A256GCM`, key derived from the secret via sha256) and therefore also tamper-proof jwt cookie (`HttpOnly`, `Secure`, `SameSite=Lax` by default): stateless, no session storage needed. Trade-offs: a session cannot be revoked before its `maxAge` (default one hour), and it is not bound to the client: a stolen cookie (`HttpOnly` keeps it away from scripts, but not from a compromised device or proxy) can be replayed from elsewhere until it expires. Keep `maxAge` short, use the `__Host-` cookie prefix where possible (see cookie hardening below), and if revocation or client binding is required, put a server side session on top of the resolved identity.
 * **Signatures:** Both the saml response and the assertion must be signed by default (`wantAuthnResponseSigned` / `wantAssertionsSigned`). Many identity providers only sign one of them, disable the other explicitly instead of both.

### Options

```ts
import { createIdpMetadataResolver } from '@chubbyts/chubbyts-undici-saml/dist/metadata';
import { createSamlAuthenticationMiddleware } from '@chubbyts/chubbyts-undici-saml/dist/middleware';
import { createSamlServiceProvider } from '@chubbyts/chubbyts-undici-saml/dist/service-provider';
import { createSamlSession } from '@chubbyts/chubbyts-undici-saml/dist/session';

// resolves and caches the identity provider metadata (entity id, single sign-on / single logout location, signing certificates),
// lazily on first use
const idpMetadataResolver = createIdpMetadataResolver('https://idp.example.com/metadata', {
  entityId: 'https://idp.example.com', // expected idp entity id, default: not checked
  fetch, // custom fetch for the metadata request, default: globalThis.fetch
  maxAge: 3600, // seconds resolved metadata is cached (non-negative), default: 3600
  timeout: 5, // seconds until the metadata request is aborted (non-negative), default: 5
  cooldown: 30, // seconds until a failed (re)fetch is retried (non-negative), default: 30
  maxSize: 1048576, // bytes the metadata response may have at most (non-negative), default: 1048576 (1 MiB)
});

// creates the authn request redirect url and verifies saml responses (signature, issuer, audience, conditions),
// creates logout request / response redirect urls and verifies logout requests / responses (single logout)
const samlServiceProvider = createSamlServiceProvider(idpMetadataResolver, {
  entityId: 'https://sp.example.com', // required: the service provider entity id (issuer of authn requests, audience of assertions)
  assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs', // required: where the identity provider posts the saml response to
  singleLogoutServiceUrl: 'https://sp.example.com/saml/slo', // where the identity provider sends logout requests / responses to (requires privateKey), default: no single logout
  clockTolerance: 5, // seconds (non-negative), default: 0
  maxAssertionAge: 300, // seconds an assertion is accepted after its issue instant (non-negative), default: 0 (only the assertion's own NotOnOrAfter applies)
  identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', // requested name id format (null: omit), default: emailAddress
  forceAuthn: true, // request a fresh authentication, default: false
  wantAssertionsSigned: true, // default: true
  wantAuthnResponseSigned: true, // default: true
  validateInResponseTo: 'ifPresent', // 'never' | 'ifPresent' | 'always', default: 'never'
  authnContext: {
    // requested authentication context classes (RequestedAuthnContext), default: none (the identity provider chooses)
    classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken'],
    comparison: 'minimum', // 'exact' | 'minimum' | 'maximum' | 'better', default: 'exact' (the asserted class is verified, see below)
  },
  privateKey, // pem encoded private key to sign authn requests and logout requests / responses, default: not signed
  certificate, // pem encoded certificate belonging to the privateKey
  signatureAlgorithm: 'sha256', // 'sha256' | 'sha512' (sha1 is deliberately not offered), default: 'sha256'
  decryptionKey, // pem encoded private key to decrypt encrypted assertions, default: not decrypted
  assertionIdStore, // SamlAssertionIdStore remembering consumed assertion ids (replay detection), default: in memory
});

const samlSession = createSamlSession({
  secret: process.env.SESSION_SECRET as string, // required: at least 32 characters
  maxAge: 3600, // seconds a session stays valid (non-negative), default: 3600
  cookieName: 'saml-session', // default: 'saml-session' (consider '__Host-saml-session', see hardening below)
  path: '/', // default: '/' (a rfc 6265 path-value)
  secure: true, // default: true, disable for plain http local development only
  sameSite: 'Lax', // 'Lax' | 'Strict' | 'None', default: 'Lax' ('Strict' would drop the cookie on the redirect after login)
});

const samlAuthenticationMiddleware = createSamlAuthenticationMiddleware(
  samlSession,
  samlServiceProvider,
  {
    assertionConsumerServicePath: '/saml/acs', // the path of the assertionConsumerServiceUrl (a plain string is accepted as well)
    singleLogoutServicePath: '/saml/slo', // the path of the singleLogoutServiceUrl, default: no single logout
  },
  logger, // @chubbyts/chubbyts-log-types compatible logger, optional, default: no-op
);
```

 * **Metadata:** The metadata document is the trust anchor: whoever controls its signing certificates controls which saml responses are accepted. The transport (tls) is what makes it trustworthy, an xml signature on the metadata document itself is not verified: use a `https` metadata url in production, plain `http` is only meant for local development. A `https` metadata url advertising a plain `http` single sign-on or single logout location is rejected in any case, the metadata request does not follow redirects (a `https` → `http` redirect would silently bypass these checks), urls with embedded credentials (`https://user:pass@...`) are rejected, and a response larger than `maxSize` is discarded (a misbehaving identity provider must not exhaust memory). If tls alone is not enough for your threat model (e.g. a federation with signed metadata), verify the signature within a custom `IdpMetadataResolver` (see custom parts). The root element must be an `EntityDescriptor` (a federation `EntitiesDescriptor` aggregate is out of scope), certificate rotation is picked up with the next refresh (`maxAge`). The validity period of the signing certificates is deliberately not checked: within saml metadata the certificate is a key container, the identity provider decides which keys are trusted by publishing them (a long expired certificate within the metadata is a widespread, harmless situation, and a leaked key is retired by removing it from the metadata, not by waiting for its expiry). A certificate removed from the metadata stops being trusted with the next refresh.
 * **Outages:** An identity provider outage should not take the service provider down: if the metadata is expired and the refetch fails, the last known metadata keeps being used (retried after `cooldown`). Only if there never was a successful fetch the error is thrown (`5xx`), within the cooldown immediately without hitting the identity provider again. A failed or invalid metadata response is reported as `IdpMetadataError` (`@chubbyts/chubbyts-undici-saml/dist/error`, with the original error as `cause`), errors of the fetch implementation itself (dns, connection refused, ...) are passed through as they are.
 * **Issuer:** node-saml only verifies the signature of an authn response against the trusted certificates, therefore the issuer of the assertion is additionally checked against the metadata's entity id: an identity provider signing for multiple issuers (e.g. tenants) with one key must not be able to cross them.
 * **Endpoints:** The `Destination` of the saml response and the `Recipient` of the assertion's subject confirmation must both be the `assertionConsumerServiceUrl` ([profiles][10] 4.1.4.5, node-saml verifies neither): a response or assertion issued for another endpoint (of this or another service provider sharing the entity id) is rejected (`403`). An unsigned response (`wantAuthnResponseSigned: false`) does not protect its `Destination` anyway, it is then only checked if present.
 * **Replay:** A bearer assertion must not be accepted twice ([profiles][10] 4.1.4.5): the id of every accepted assertion is remembered as long as the assertion could still be valid (the later of the subject confirmation's and the conditions' `NotOnOrAfter`, plus `clockTolerance`), and a saml response carrying a known id is rejected (`403`). The default store keeps the ids in memory: they do not survive a restart and are not shared between multiple instances, so a captured response can still be replayed against another instance. For a multi instance deployment implement `SamlAssertionIdStore` (`@chubbyts/chubbyts-undici-saml/dist/assertion-id-store`, `{ consume: (id, expiresAt) => Promise<boolean> }`, `false` for an already consumed id) on top of a shared store (database, redis, ...) and pass it as `assertionIdStore`. Note that an assertion without both `NotOnOrAfter` attributes is rejected by node-saml already.
 * **Unsolicited responses:** With the default `validateInResponseTo: 'never'` an identity provider initiated (unsolicited) saml response is accepted: anyone able to obtain a valid saml response for *some* account can log a victim's browser into that account (login csrf). If your application only expects service provider initiated logins, set `'ifPresent'` (verifies the `InResponseTo` against the pending authn request ids if given, and rejects a replayed one) or `'always'` (additionally rejects unsolicited responses). The pending request ids are held in memory: they do not survive a restart and are not shared between multiple instances, which is why `'never'` is the default: with `'ifPresent'` or `'always'` a service provider initiated login only succeeds if the saml response reaches the instance that issued the authn request (single instance, sticky sessions). Note that `'ifPresent'` alone does not prevent login csrf, only replay: an unsolicited response carries no `InResponseTo` and is still accepted, use `'always'` for that.
 * **Authentication context:** Without `authnContext` no `RequestedAuthnContext` is sent, the identity provider authenticates the way it is configured (password, kerberos, mfa, ...). Use `authnContext` to ask for a specific class (e.g. a multi factor class for sensitive applications). The request is only a wish, so with the default `exact` comparison the class the identity provider asserts within the `AuthnStatement` must be one of the requested `classRefs`, otherwise the saml response is rejected (`403`): an identity provider ignoring the request (e.g. a password login instead of the requested multi factor class) would otherwise be trusted for a login it never performed. The other comparisons (`minimum`, `maximum`, `better`) depend on an ordering of the classes only the identity provider knows: check `identity.authnContextClassRef` yourself before relying on it.
 * **Single logout:** Supported via the HTTP-Redirect binding in both directions, if the identity provider metadata advertises a HTTP-Redirect `SingleLogoutService` location and `singleLogoutServiceUrl` / `singleLogoutServicePath` are configured (otherwise a `POST` to the single logout service path only removes the session cookie and redirects to the `RelayState`). Logout requests and responses sent via a redirect must be signed ([profiles][10] 4.4.4.1), so `privateKey` / `certificate` are required and an unsigned or `sha1` signed logout message of the identity provider is rejected (`403`), as is one whose `Destination` is not the `singleLogoutServiceUrl`, whose issuer is not the metadata's entity id, which was issued more than five minutes ago or in the future (`IssueInstant`, `clockTolerance` applies: a captured logout message could otherwise be replayed for as long as the identity provider's key is trusted, to log a user out again and again) or which is expired (`NotOnOrAfter`, if the logout request carries one). `validateInResponseTo` applies to logout responses as well (same in-memory caveat as for logins). A logout request of the identity provider names the principal and session to log out: the session cookie is only removed if its `nameId` (and `sessionIndex`, if the request carries one) match, another principal's session within the same browser is kept and the identity provider gets a failure response. Trade-offs of the stateless session: a logout request only reaches the cookie of the browser it comes through (no back-channel / SOAP binding, a copied cookie stays valid until it expires) and with `sameSite: 'Strict'` the cookie is not sent along the redirect from the identity provider, so its logout request cannot be matched (the cookie is not removed, but the identity provider still gets a success response as there is no session to see). The service provider initiated logout is a `POST` on purpose: with the `SameSite=Lax` cookie a cross-site request carries no session, so another site cannot log the user out (logout csrf). The HTTP-POST binding for logout messages is not supported: configure the HTTP-Redirect binding for the service provider's single logout service at the identity provider.
 * **Sessions across instances:** The session cookie itself is stateless: multiple instances only need the same `secret`.
 * **Cookie hardening:** With the defaults (`path: '/'`, `secure: true`) the cookie qualifies for the `__Host-` prefix (`cookieName: '__Host-saml-session'`): browsers then refuse to accept it from an insecure origin, a subdomain or with another path, so a sibling host cannot plant a session cookie. It is not the default because it breaks plain `http` local development (`secure: false`).
 * **Request size:** The assertion consumer service and the logout `POST` are reachable without authentication, so a form body larger than 256 KiB (`MAX_SAML_RESPONSE_SIZE`, a real saml response is a few dozen kilobytes at most) is rejected with `413` before it is parsed or a signature is verified (an arbitrarily large, adversarial xml document would exhaust cpu and memory). A `Content-Length` header is checked before anything is read, and the body itself is read in a streaming way and dropped as soon as it exceeds the limit, so neither a chunked body nor a lying `Content-Length` gets around it. Rate limit the endpoints within the server or proxy in front nevertheless.
 * **Caching:** The responses of the middleware (login redirect, the assertion consumer service response carrying the session cookie, `401`, `403`, ...) are sent with `Cache-Control: no-store`, so that no shared cache ever serves them to another client.
 * **Redirect target:** The `RelayState` is only followed if it is a same-origin absolute path made of printable ascii (`/path?query`): a scheme, an authority (`//host`, `/\\host`), whitespace or control characters fall back to `/`.
 * **Browser clients:** The login is a top-level navigation (redirects, form post), not something a `fetch` based client can follow: protect html routes with this middleware and use it as-is, or let your spa handle the `401` of api requests by navigating to a protected route.
 * **Custom parts:** Each part is replaceable: `IdpMetadataResolver` is `() => Promise<IdpMetadata>`, `SamlServiceProvider` is `{ resolveLoginUrl, verifySamlResponse, resolveLogoutUrl, verifyLogoutRequest, resolveLogoutResponseUrl, verifyLogoutResponse }`, `SamlSession` is `{ resolveIdentity, createCookie, createRemovalCookie }`, `SamlAssertionIdStore` is `{ consume }` (see replay). Throw an `InvalidSamlResponseError` (`@chubbyts/chubbyts-undici-saml/dist/error`) within a custom verifier to get the `403` response, any other error is rethrown.

### Service factories (chubbyts-dic-config)

The package ships service factories for a [chubbyts-dic-config][15] (or any [chubbyts-dic-types][14] compatible) container within `@chubbyts/chubbyts-undici-saml/dist/service-factory`, configured through `config.chubbyts.saml`:

```ts
import type { ConfigFactory } from '@chubbyts/chubbyts-dic-config/dist/dic-config';
import { createContainerByConfigFactory } from '@chubbyts/chubbyts-dic-config/dist/dic-config';
import type { SamlConfig } from '@chubbyts/chubbyts-undici-saml/dist/service-factory';
import { samlAuthenticationMiddlewareServiceFactory } from '@chubbyts/chubbyts-undici-saml/dist/service-factory';
import type { Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';

const container = createContainerByConfigFactory({
  chubbyts: {
    saml: {
      idpMetadataUrl: 'https://idp.example.com/metadata', // required
      entityId: 'https://sp.example.com', // required
      assertionConsumerServiceUrl: 'https://sp.example.com/saml/acs', // required
      sessionSecret: process.env.SESSION_SECRET as string, // required
      // singleLogoutServiceUrl: 'https://sp.example.com/saml/slo',
      // idpEntityId: 'https://idp.example.com',
      // fetch,
      // maxAge: 3600,
      // timeout: 5,
      // cooldown: 30,
      // maxSize: 1048576,
      // clockTolerance: 5,
      // maxAssertionAge: 300,
      // identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      // forceAuthn: true,
      // wantAssertionsSigned: true,
      // wantAuthnResponseSigned: true,
      // validateInResponseTo: 'ifPresent',
      // authnContext: { classRefs: ['urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken'], comparison: 'minimum' },
      // privateKey,
      // certificate,
      // signatureAlgorithm: 'sha256',
      // decryptionKey,
      // assertionIdStore,
      // sessionMaxAge: 3600,
      // sessionCookieName: '__Host-saml-session',
      // sessionCookiePath: '/',
      // sessionCookieSecure: true,
      // sessionCookieSameSite: 'Lax',
    } satisfies SamlConfig,
  },
  dependencies: {
    factories: new Map<string, ConfigFactory>([
      ['samlAuthenticationMiddleware', samlAuthenticationMiddlewareServiceFactory()],
    ]),
  },
})();

const samlAuthenticationMiddleware = container.get<Middleware>('samlAuthenticationMiddleware');
```

The `samlAuthenticationMiddlewareServiceFactory` uses the services `samlSession`, `samlServiceProvider` and (the `samlServiceProviderServiceFactory` behind it) `samlIdpMetadataResolver` of the container if registered, and creates them through the shipped `samlSessionServiceFactory`, `samlServiceProviderServiceFactory` and `idpMetadataResolverServiceFactory` otherwise. Register any of them under its name to replace it (e.g. a custom `SamlServiceProvider`) or to share it with other services. A `logger` service is used if registered, a missing `idpMetadataUrl` / `entityId` / `assertionConsumerServiceUrl` / `sessionSecret` throws at construction time. The paths of the middleware are derived from the `assertionConsumerServiceUrl` and (if given) `singleLogoutServiceUrl`.

#### With names

To protect different parts of an application through different identity providers, the same factories can be registered multiple times with a name: the config is then read from `config.chubbyts.saml.<name>` and the name gets appended to each service id (`samlAuthenticationMiddlewarepartner`, `samlSessionpartner`, ...). Use a distinct `assertionConsumerServiceUrl` and `sessionCookieName` per name, so that the responses and sessions of the identity providers do not collide.

```ts
const container = createContainerByConfigFactory({
  chubbyts: {
    saml: {
      internal: {
        idpMetadataUrl: 'https://internal-idp.example.com/metadata',
        entityId: 'https://sp.example.com',
        assertionConsumerServiceUrl: 'https://sp.example.com/saml/internal/acs',
        sessionSecret: process.env.INTERNAL_SESSION_SECRET as string,
        sessionCookieName: 'saml-session-internal',
      },
      partner: {
        idpMetadataUrl: 'https://partner-idp.example.com/metadata',
        entityId: 'https://sp.example.com',
        assertionConsumerServiceUrl: 'https://sp.example.com/saml/partner/acs',
        sessionSecret: process.env.PARTNER_SESSION_SECRET as string,
        sessionCookieName: 'saml-session-partner',
      },
    } satisfies Record<string, SamlConfig>,
  },
  dependencies: {
    factories: new Map<string, ConfigFactory>([
      ['samlAuthenticationMiddlewareinternal', samlAuthenticationMiddlewareServiceFactory('internal')],
      ['samlAuthenticationMiddlewarepartner', samlAuthenticationMiddlewareServiceFactory('partner')],
    ]),
  },
})();

const partnerSamlAuthenticationMiddleware = container.get<Middleware>('samlAuthenticationMiddlewarepartner');
```

## Testing against a local SAML identity provider

[Keycloak][7] as a docker container is the easiest way to test manually:

```sh
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7 start-dev
```

Within the admin console at http://localhost:8080 (admin/admin) create a realm `test` and a client with the `saml` protocol whose *Client ID* is your `entityId` (e.g. `https://sp.example.com`), set *Valid redirect URIs* to your `assertionConsumerServiceUrl` and disable *Client signature required* (or configure the `privateKey` / `certificate` options, and upload the certificate within the client's *Keys* tab). For single logout enable *Front channel logout*, set *Logout Service Redirect Binding URL* to your `singleLogoutServiceUrl` and configure the `privateKey` / `certificate` options, then:

```ts
const idpMetadataResolver = createIdpMetadataResolver('http://localhost:8080/realms/test/protocol/saml/descriptor');
```

Keycloak specifics: by default Keycloak signs the response but not the assertion (`wantAssertionsSigned: false`, or enable *Sign assertions* within the client), and the metadata is served for the URL the request comes through, so use the same host for the resolver and the browser (or pin it, e.g. `KC_HOSTNAME=http://keycloak:8080` in docker compose).

The tests of this repository are self-contained: the integration tests run against an in-process http server serving generated metadata and saml responses signed with a generated certificate ([selfsigned][8], [xml-crypto][9]), no docker required:

```sh
pnpm test:integration --run
```

## Copyright

2026 Dominik Zogg

[1]: https://www.npmjs.com/package/@chubbyts/chubbyts-undici-saml
[2]: https://www.npmjs.com/package/@chubbyts/chubbyts-log-types
[3]: https://www.npmjs.com/package/@chubbyts/chubbyts-undici-server
[4]: https://www.npmjs.com/package/@node-saml/node-saml
[5]: https://www.npmjs.com/package/@xmldom/xmldom
[6]: https://www.npmjs.com/package/jose
[7]: https://www.keycloak.org
[8]: https://www.npmjs.com/package/selfsigned
[9]: https://www.npmjs.com/package/xml-crypto
[10]: https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
[11]: https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
[14]: https://www.npmjs.com/package/@chubbyts/chubbyts-dic-types
[15]: https://www.npmjs.com/package/@chubbyts/chubbyts-dic-config
