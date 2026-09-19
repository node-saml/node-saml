# Node SAML

[![Build Status](https://github.com/node-saml/node-saml/actions/workflows/workflow.yml/badge.svg?branch=master)](https://github.com/node-saml/node-saml/actions/workflows/workflow.yml)
[![npm version](https://badge.fury.io/js/@node-saml%2Fnode-saml.svg)](https://badge.fury.io/js/@node-saml%2Fnode-saml)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)
[![codecov](https://codecov.io/gh/node-saml/node-saml/branch/master/graph/badge.svg?token=PQWCMBWBFB)](https://codecov.io/gh/node-saml/node-saml)
[![DeepScan grade](https://deepscan.io/api/teams/17569/projects/20921/branches/586237/badge/grade.svg)](https://deepscan.io/dashboard#view=project&tid=17569&pid=20921&bid=586237)

[![NPM](https://nodei.co/npm/@node-saml/node-saml.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/@node-saml/node-saml)

A [SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0) implementation for Node.js. It acts as the
service provider (SP) half of a SAML exchange: it builds the `AuthnRequest` and logout messages you
send to an identity provider (IdP), and it decides whether the responses that come back are
trustworthy.

This package is transport-agnostic and framework-agnostic — it takes strings in and hands strings
out, and you wire it into whatever HTTP layer you already have. If your application uses
[Passport](https://www.passportjs.org/), reach for
[`@node-saml/passport-saml`](https://github.com/node-saml/passport-saml) instead; it wraps this
library in a Passport strategy.

- [Sponsors](#sponsors)
- [Installation](#installation)
- [Usage](#usage)
  - [Create a `SAML` instance](#create-a-saml-instance)
  - [Start a login](#start-a-login)
  - [Validate the response](#validate-the-response)
  - [The profile](#the-profile)
  - [Single logout (SLO)](#single-logout-slo)
  - [Service provider metadata](#service-provider-metadata)
- [Config parameter details](#config-parameter-details)
- [Security and signatures](#security-and-signatures)
- [Response validation timestamps](#response-validation-timestamps)
- [InResponseTo validation](#inresponseto-validation)
- [Cache provider](#cache-provider)
- [Node support policy](#node-support-policy)
- [Contributing](#contributing)
- [Changelog](#changelog)

## Sponsors

We gratefully acknowledge support from our sponsors:

<div align="center">
  <a href="https://stytch.com">
    <picture>
      <source width="200px" media="(prefers-color-scheme: dark)" srcset="./sponsor/stytch-light.svg">
      <source width="200px" media="(prefers-color-scheme: light)" srcset="./sponsor/stytch-dark.svg">
      <img width="200px" alt="Stytch" src="./sponsor/stytch-dark.svg" />
    </picture>
  </a>
   <p align="center">
      <a href="https://stytch.com/?utm_source=oss-sponsorship&utm_medium=paid_sponsorship&utm_campaign=nodesaml">
        <b>The identity platform for humans & AI agents</b><br/>
        One integration for authentication, authorization, and security
      </a>
   </p>
</div>

- [RideAmigos](https://rideamigos.com/)

If your company benefits from node-saml being secure and up-to-date, consider asking them to sponsor the project at $25/month. See the [Github Sponsors page](https://github.com/sponsors/cjbarth) for more sponsorship levels. It's easy to do, appearing as another line-item on the Github bill they already have.

## Installation

```shell
npm install @node-saml/node-saml
```

TypeScript type definitions ship with the package; there is no separate `@types` package to install.
See the [Node support policy](#node-support-policy) for supported runtimes.

## Usage

### Create a `SAML` instance

```javascript
const fs = require("node:fs");
const { SAML } = require("@node-saml/node-saml");

const saml = new SAML({
  // Required
  callbackUrl: "https://sp.example.com/login/callback",
  issuer: "https://sp.example.com/metadata",
  idpCert: fs.readFileSync("./idp-signing-cert.pem", "utf-8"),

  // Where to send the user to authenticate
  entryPoint: "https://idp.example.com/sso",

  // Sign our own requests. Set the algorithms explicitly; see "Security and signatures".
  privateKey: fs.readFileSync("./sp-private-key.pem", "utf-8"),
  publicCert: fs.readFileSync("./sp-public-cert.pem", "utf-8"),
  signatureAlgorithm: "sha256",
  digestAlgorithm: "sha256",
});
```

`callbackUrl`, `issuer`, and `idpCert` are required. Omitting one throws a `TypeError` naming the
option, and so does passing a non-boolean to an option that gates behavior — for example the string
`"false"`. All of this happens in the constructor, so a misconfiguration surfaces at startup rather
than in the middle of someone's login.

In TypeScript, the constructor takes a `SamlConfig` and `saml.options` is a `SamlOptions`; both are
exported from the package root, along with `Profile`, `CacheProvider`, `CacheItem`,
`ValidateInResponseTo`, `RacComparison`, `SignatureAlgorithm`, `SamlScopingConfig`,
`SamlIDPListConfig`, `SamlIDPEntryConfig`, `IdpCertCallback`, `AuthOptions`, `MandatorySamlOptions`,
and `SamlStatusError`.

### Start a login

All three of these require `entryPoint` to be set.

**HTTP-Redirect binding** — build a URL and redirect to it:

```javascript
const url = await saml.getAuthorizeUrlAsync(relayState, options);
res.redirect(url);
```

`relayState` is echoed back by the IdP and is omitted from the request when it is an empty string.
`options` is an `AuthOptions`, whose `additionalParams` override anything set by
`additionalParams`/`additionalAuthorizeParams` in the constructor.

All three of these methods also accept a deprecated `host` argument between `relayState` and
`options`. It has never been read, and it is removed in the next major version
([#367](https://github.com/node-saml/node-saml/pull/367)), so pass `options` directly:

```javascript
await saml.getAuthorizeUrlAsync(relayState, host, options); // deprecated
await saml.getAuthorizeUrlAsync(relayState, options); // use this
```

If you subclass `SAML` and override one of these, migrate the override at the same time: a
two-argument call reaches it directly, so an override written for the old signature receives
`options` as `host`.

**HTTP-POST binding** — return a self-submitting form:

```javascript
const html = await saml.getAuthorizeFormAsync(relayState, options);
res.send(html);
```

This returns a complete HTML document that posts to `entryPoint` on load, with a `<noscript>`
fallback button for browsers without JavaScript.

If you would rather build the form yourself, `getAuthorizeMessageAsync(relayState, options)`
returns the message as a plain object of form fields (`SAMLRequest` plus any additional parameters).

### Validate the response

The IdP posts the response back to your `callbackUrl` as a form-encoded `SAMLResponse` field, so the
route needs a body parser.

```javascript
app.post("/login/callback", express.urlencoded({ extended: false }), async (req, res, next) => {
  try {
    const { profile, loggedOut } = await saml.validatePostResponseAsync(req.body);
    // profile is the authenticated user; see "The profile" below
  } catch (err) {
    next(err);
  }
});
```

`validatePostResponseAsync` rejects with an `Error` on anything it cannot vouch for, and the message
says what failed — an invalid signature, a mismatched audience, an expired assertion, and a missing
decryption key are all distinguishable. Nothing is returned for a document that did not verify.

Two cases resolve without a `profile`:

- The IdP returned a `LogoutResponse` rather than an authentication response:
  `{ profile: null, loggedOut: true }`.
- A `passive` request could not be satisfied without user interaction (a `NoPassive` status on a
  validly signed response): `{ profile: null, loggedOut: false }`.

When the IdP reports a non-`Success` status, the rejection is a `SamlStatusError` whose `xmlStatus`
property carries the `Status` element as XML, so you can surface the IdP's own reason to the user.
Be aware that the signature requirement is applied first: many identity providers do not sign their
error responses, and under the default `wantAuthnResponseSigned: true` such a response is rejected
for the missing signature before its status is read.

### The profile

`profile` is a `Profile`: the fields the library understands, plus every `AttributeValue` in the
assertion keyed by its `Name`. What is populated depends on the message, so check for the fields you
rely on rather than assuming they are all present.

| Field                              | Description                                                                                                      |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `issuer`                           | The assertion's `Issuer`.                                                                                        |
| `nameID`, `nameIDFormat`           | The subject's name identifier and its format.                                                                    |
| `nameQualifier`, `spNameQualifier` | Name qualifiers, when the assertion carries them.                                                                |
| `sessionIndex`                     | The `AuthnStatement`'s `SessionIndex`; you need it to build a logout request.                                    |
| `inResponseTo`                     | The response's `InResponseTo`, when it carries one.                                                              |
| `mail`, `email`                    | Convenience aliases. `mail` falls back to `urn:oid:0.9.2342.19200300.100.1.3`, and `email` falls back to `mail`. |
| `attributes`                       | Every attribute as a `Name` → value map. Single-valued attributes are strings; repeated ones are arrays.         |
| `getAssertionXml()`                | The assertion XML **that the signature covers**. This is the trustworthy copy.                                   |
| `getAssertion()`                   | The same assertion, parsed into a JavaScript object.                                                             |
| `getSamlResponseXml()`             | The raw response XML, **unsigned and unverified**. See the warning below.                                        |

Attributes are also copied onto `profile` at the top level for convenience, but an attribute never
overwrites a field the library set itself.

The profile returned for a `LogoutRequest` by `validatePostRequestAsync` and `validateRedirectAsync`
is a smaller thing: `ID` (the logout request's own ID), `issuer`, `nameID`, `nameIDFormat`, and
`sessionIndex`. It carries no attributes and none of the getters, since there is no assertion.

> **Warning:** `getSamlResponseXml()` returns the response document as it arrived, including parts no
> signature covers. Never make a trust decision from it. Use `getAssertionXml()`, `getAssertion()`,
> or the profile fields, all of which come from the verified content. This method exists for
> backward compatibility and is a candidate for removal in a future major version.

### Single logout (SLO)

Node-SAML supports SP-initiated and IdP-initiated logout, over both the `Redirect` and `POST`
bindings, including signature validation and decryption of encrypted name identifiers.

**SP-initiated.** Build a `LogoutRequest` URL for a user you previously authenticated. The `profile`
you pass needs at least `nameID`, `nameIDFormat`, and — if the IdP expects it — `sessionIndex`:

```javascript
const url = await saml.getLogoutUrlAsync(profile, relayState, options);
res.redirect(url);
```

The request goes to `logoutUrl`, which defaults to `entryPoint`.

**IdP-initiated over POST.** Validate the incoming `LogoutRequest`, then answer it:

```javascript
const { profile } = await saml.validatePostRequestAsync(req.body);
const url = await saml.getLogoutResponseUrlAsync(profile, relayState, options, true);
res.redirect(url);
```

`getLogoutResponseUrl(profile, relayState, options, success, callback)` is the callback-style
equivalent of `getLogoutResponseUrlAsync`.

**Over the Redirect binding.** Redirect-binding signatures are computed over the exact bytes of the
query string, so you must hand the raw query string through unchanged — not a re-serialized copy of
the parsed object:

```javascript
const originalQuery = req.url.slice(req.url.indexOf("?") + 1);
const { profile, loggedOut } = await saml.validateRedirectAsync(req.query, originalQuery);
```

> **Note:** on the Redirect binding, a signature is only checked when the message carries a
> `Signature` query parameter, because the binding makes signing optional. A message arriving
> without one is accepted with none of its contents authenticated — the issuer and the timestamps
> are read from the same unsigned bytes, so `idpIssuer` does not constrain it either. Run with
> `NODE_DEBUG=node-saml` to be told when this happens. Configure your IdP to sign its logout
> messages; a future major version will reject unsigned ones
> ([#419](https://github.com/node-saml/node-saml/issues/419)). The POST binding is unaffected:
> `validatePostRequestAsync` always requires a valid signature.

### Service provider metadata

Most identity providers will take a metadata document instead of asking you to type the same values
into a form.

```javascript
const metadata = saml.generateServiceProviderMetadata(decryptionCert, publicCerts);
```

- `decryptionCert` — the public certificate matching `decryptionPvk`. Required if the instance was
  configured with `decryptionPvk`; pass `null` otherwise.
- `publicCerts` — the public certificate matching `privateKey`. Required if the instance was
  configured with `privateKey`. Pass an array to support certificate rotation: the first entry must
  match the current `privateKey`, and later entries publish upcoming certificates to the IdP before
  you switch over.

Both are read by the rules described under [`privateKey`](#configuration-option-privatekey), as PEM or
as Base64, and published as a single line of Base64. `decryptionCert`, and each entry of
`publicCerts`, must hold exactly one certificate; a value holding several, or holding a public key
rather than a certificate, is refused with an error naming it.

The underlying function is also exported directly, for generating metadata without constructing a
`SAML` instance:

```javascript
const { generateServiceProviderMetadata } = require("@node-saml/node-saml");

const metadata = generateServiceProviderMetadata({
  issuer: "https://sp.example.com/metadata",
  callbackUrl: "https://sp.example.com/login/callback",
});
```

It accepts `issuer` and `callbackUrl` plus the metadata-relevant options from the configuration tables below:
`logoutCallbackUrl`, `identifierFormat`, `wantAssertionsSigned`, `decryptionPvk`, `decryptionCert`,
`privateKey`, `publicCerts`, `signatureAlgorithm`, `digestAlgorithm`, `xmlSignatureTransforms`,
`signMetadata`, `metadataContactPerson`, `metadataOrganization`, and `generateUniqueId`.

## Config parameter details

### Required

| Option        | Type                                    | Description                                                                                                                                       |
| ------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `callbackUrl` | `string`                                | The SP endpoint the IdP posts the response back to; becomes the `AssertionConsumerServiceURL`.                                                    |
| `issuer`      | `string`                                | The issuer string identifying this service provider to the IdP.                                                                                   |
| `idpCert`     | `string \| string[] \| IdpCertCallback` | The IdP's signing certificate(s) or public key(s), used to validate incoming signatures. See [Security and signatures](#security-and-signatures). |

### Core

| Option                   | Default                        | Description                                                                                                                                                                       |
| ------------------------ | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `entryPoint`             | —                              | The IdP's SSO endpoint. Required to generate any authentication request, and required by the specification when the request is signed.                                            |
| `audience`               | `issuer`                       | Expected `Audience` in the response. Set to `false` to skip the check — which removes a security control; see the note under [Security and signatures](#security-and-signatures). |
| `privateKey`             | —                              | SP private key in PEM format, used to sign outgoing messages. See [Security and signatures](#security-and-signatures).                                                            |
| `publicCert`             | —                              | SP public signing certificate, embedded in the `AuthnRequest` so the IdP can verify it. Must match `privateKey`.                                                                  |
| `decryptionPvk`          | —                              | Private key used to decrypt encrypted assertions and encrypted name identifiers.                                                                                                  |
| `signatureAlgorithm`     | `"sha1"`                       | `"sha1"`, `"sha256"`, or `"sha512"`. **Set this explicitly**; see [Security and signatures](#security-and-signatures).                                                            |
| `digestAlgorithm`        | `"sha1"`                       | Digest algorithm for the signed data object: `"sha1"`, `"sha256"`, or `"sha512"`. Same advice as above.                                                                           |
| `xmlSignatureTransforms` | enveloped-signature + exc-c14n | Signature transforms used in HTTP-POST signatures. The default is `["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"]`.         |
| `generateUniqueId`       | built-in                       | Function returning the unique IDs used for outgoing SAML messages.                                                                                                                |

### Response validation

| Option                    | Default | Description                                                                                                                                                            |
| ------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `wantAssertionsSigned`    | `true`  | Require the assertion itself to be signed, and advertise `WantAssertionsSigned="true"` in the metadata.                                                                |
| `wantAuthnResponseSigned` | `true`  | Require the response to be signed at the top level, not only at the assertion.                                                                                         |
| `acceptedClockSkewMs`     | `0`     | Tolerance in milliseconds when checking `NotBefore` and `NotOnOrAfter`. `-1` disables those checks entirely.                                                           |
| `maxAssertionAgeMs`       | `0`     | Reject an assertion older than this, measured from its `IssueInstant`. `0` means no limit beyond `NotOnOrAfter`. When set and stricter than `NotOnOrAfter`, this wins. |
| `idpIssuer`               | —       | If set, the `Issuer` on incoming logout requests and responses must match it. For ADFS this looks like `https://acme_tools.windows.net/deadbeef`.                      |

Turning both `wantAssertionsSigned` and `wantAuthnResponseSigned` off does not turn signature
checking off: either the response or the assertion still has to carry a valid signature, or the
document is rejected.

### AuthnRequest content

| Option                           | Default                                                                 | Description                                                                                                                                                                                                         |
| -------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identifierFormat`               | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`                | `NameID` format to request. Set to `null` to leave the `Format` attribute off the `NameIDPolicy` and the `NameIDFormat` element out of the metadata.                                                                |
| `allowCreate`                    | `true`                                                                  | Let the IdP create a new subject identifier.                                                                                                                                                                        |
| `spNameQualifier`                | —                                                                       | Request that the subject identifier be returned or created in another SP's namespace, or in that of an affiliation of service providers.                                                                            |
| `authnContext`                   | `["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]` | Requested authentication context classes. Must be an array, even for a single value.                                                                                                                                |
| `racComparison`                  | `"exact"`                                                               | How the IdP should compare the requested context: `"exact"`, `"minimum"`, `"maximum"`, or `"better"`.                                                                                                               |
| `disableRequestedAuthnContext`   | `false`                                                                 | Omit `RequestedAuthnContext` entirely.                                                                                                                                                                              |
| `forceAuthn`                     | `false`                                                                 | Ask the IdP to re-authenticate the user even if they hold a valid session.                                                                                                                                          |
| `passive`                        | `false`                                                                 | Ask the IdP not to take visible control of the user interface. See the `NoPassive` case in [Validate the response](#validate-the-response).                                                                         |
| `providerName`                   | —                                                                       | Human-readable name of the requester, for the presenter's user agent or the IdP.                                                                                                                                    |
| `attributeConsumingServiceIndex` | —                                                                       | Tells the IdP which attribute set to attach to the response ([background](http://blog.aniljohn.com/2014/01/data-minimization-front-channel-saml-attribute-requests.html)).                                          |
| `disableRequestAcsUrl`           | `false`                                                                 | Omit the optional `AssertionConsumerServiceURL` from the request.                                                                                                                                                   |
| `skipRequestCompression`         | `false`                                                                 | Send the request uncompressed instead of DEFLATE-compressed.                                                                                                                                                        |
| `authnRequestBinding`            | `"HTTP-Redirect"`                                                       | Recorded on the instance for consumers such as `passport-saml` to act on. Within this library the binding follows from the method you call — `getAuthorizeUrlAsync` for Redirect, `getAuthorizeFormAsync` for POST. |
| `additionalParams`               | `{}`                                                                    | Query parameters added to every outgoing request.                                                                                                                                                                   |
| `additionalAuthorizeParams`      | `{}`                                                                    | Query parameters added to authorize requests only.                                                                                                                                                                  |
| `scoping`                        | —                                                                       | `Scoping` element contents; see below.                                                                                                                                                                              |

`scoping` implements [SAML core §3.4.1.2, `<Scoping>`](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf):

```javascript
scoping: {
  idpList: [ // optional
    {
      entries: [ // required
        {
          providerId: "yourProviderId", // required for each entry
          name: "yourName", // optional
          loc: "yourLoc", // optional
        },
      ],
      getComplete: "URI to your complete IDP list", // optional
    },
  ],
  proxyCount: 2, // optional
  requesterId: "requesterId", // optional; a string or an array of strings
}
```

### InResponseTo

| Option                        | Default         | Description                                                                                                                                                                                            |
| ----------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `validateInResponseTo`        | `"never"`       | `"always"` validates `InResponseTo` on every response, `"ifPresent"` validates it only when the response carries one, `"never"` skips the check. The `ValidateInResponseTo` enum is exported for this. |
| `requestIdExpirationPeriodMs` | `28800000` (8h) | How long a generated request ID stays valid for matching against an incoming `InResponseTo`.                                                                                                           |
| `cacheProvider`               | in-memory       | Where request IDs are stored. See [Cache provider](#cache-provider).                                                                                                                                   |

See [InResponseTo validation](#inresponseto-validation) below for what this protects against and how the IDs are consumed.

### Logout

| Option                   | Default      | Description                                                                                       |
| ------------------------ | ------------ | ------------------------------------------------------------------------------------------------- |
| `logoutUrl`              | `entryPoint` | Address to send logout requests to.                                                               |
| `additionalLogoutParams` | `{}`         | Query parameters added to logout requests only.                                                   |
| `logoutCallbackUrl`      | —            | The `Location` for the `SingleLogoutService` elements in the generated service provider metadata. |

### Metadata

| Option                  | Default | Description                                                                                               |
| ----------------------- | ------- | --------------------------------------------------------------------------------------------------------- |
| `signMetadata`          | `false` | Sign the generated service provider metadata. Requires `privateKey`.                                      |
| `metadataContactPerson` | —       | `ContactPerson` entries to include in the generated metadata. An array, since metadata may carry several. |
| `metadataOrganization`  | —       | `Organization` details to include in the generated metadata.                                              |

```javascript
metadataContactPerson: [
  {
    "@contactType": "support", // "technical" | "support" | "administrative" | "billing" | "other"
    GivenName: "test",
    EmailAddress: ["test@node-saml"], // note: an array
  },
],
metadataOrganization: {
  OrganizationName: [{ "@xml:lang": "en", "#text": "node-saml" }],
  OrganizationDisplayName: [{ "@xml:lang": "en", "#text": "node-saml" }],
  OrganizationURL: [{ "@xml:lang": "en", "#text": "https://github.com/node-saml/node-saml" }],
},
```

The full shapes are in the `SamlOptions` type definitions, which your editor will complete for you.

### Extensions

`samlAuthnRequestExtensions` and `samlLogoutRequestExtensions` add an `Extensions` element to the
generated `AuthnRequest` and `LogoutRequest`. They are useful for things like the
[requested attributes protocol extension](https://docs.oasis-open.org/security/saml-protoc-req-attr-req/v1.0/saml-protoc-req-attr-req-v1.0.html),
and accept any [xmlbuilder](https://www.npmjs.com/package/xmlbuilder) object, so any element is
expressible.

```javascript
samlAuthnRequestExtensions: {
  "md:RequestedAttribute": {
    "@isRequired": "true",
    "@Name": "LastName",
    "@xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
  },
  vetuma: {
    "@xmlns": "urn:vetuma:SAML:2.0:extensions",
    LG: { "#text": "sv" },
  },
},

samlLogoutRequestExtensions: {
  vetuma: {
    "@xmlns": "urn:vetuma:SAML:2.0:extensions",
    LG: { "#text": "sv" },
  },
},
```

## Security and signatures

Node-SAML uses the HTTP-Redirect binding for its `AuthnRequest`s (unless you call
`getAuthorizeFormAsync` for HTTP-POST) and expects the messages back over the HTTP-POST binding.

Three properties hold throughout response validation, and they are worth knowing because they
explain rejections that might otherwise look overly strict:

- **Only signed bytes are trusted.** Verification returns the content the signature actually covers,
  and that is the content the library goes on to process. The original document is never re-read
  after verification, because an attacker controls the difference between the two — that is the
  whole of an XML signature wrapping attack.
- **Ambiguity is rejected, not resolved.** A response with more than one assertion, more than one
  signature on an element, an `ID` resolving to more than one element, a reference pointing anywhere
  other than its own parent, or more than two transforms is refused. The library does not pick a
  reading, and it does not pick the reading that happens to verify.
- **Validation fails closed.** Decrypted content is not trusted content: an `EncryptedAssertion` is
  decrypted and then still has to have its signature verified. Timestamps, audience, issuer, and
  `InResponseTo` are security controls rather than conveniences — an option that switches one off
  (`audience: false`, `acceptedClockSkewMs: -1`) is removing a control, so make that choice
  deliberately.

### Configuration option `signatureAlgorithm`

Requests sent by Node-SAML can be signed using RSA with SHA-1, SHA-256, or SHA-512.

```javascript
signatureAlgorithm: "sha256"; // preferred — your IdP should support it; if not, consider upgrading the IdP
signatureAlgorithm: "sha512"; // strongest — check that your IdP supports it
signatureAlgorithm: "sha1"; // legacy; SHA-1 is no longer considered collision-resistant
```

`digestAlgorithm` takes the same three values and controls the digest over the signed data object.

> **Set both explicitly.** `signatureAlgorithm` and `digestAlgorithm` currently default to `"sha1"`,
> and an unrecognized value falls back to SHA-1 rather than throwing — so a typo silently downgrades
> you. Both behaviors are retained for backward compatibility, both are wrong, and both are slated
> for removal in a future major version, after which naming your algorithms will be required. Naming
> them now costs one line and makes that upgrade a no-op.

### Configuration option `privateKey`

To sign authentication requests, provide the private key in PEM format via `privateKey`. Node-SAML
reads it with xml-crypto's `toPem()`, and uses what that returns: canonical
[RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) PEM, with `\n` line endings, lines of 64
characters, and one message after another.

What it accepts is more liberal than RFC 7468's `stricttextualmsg`:

- whitespace surrounding the value, and a leading UTF-8 byte order mark, whether the value arrives
  as a string or a `Buffer`;
- any of the three line-ending conventions;
- encoded data wrapped at any width, or not wrapped at all, with spaces or tabs anywhere in it;
- a blank line after the `-----BEGIN ...-----` boundary;
- several PEM messages concatenated in one value, optionally separated by blank lines.

It rejects, with an error naming the option and giving the reason:

- encoded data that is not valid Base64 as [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)
  section 4 defines it — `=` padding away from the end, or a last group that is incomplete — rather
  than decoding as much of it as it can;
- a message whose `-----BEGIN` and `-----END` labels disagree;
- a `CERTIFICATE` whose data is not exactly one X.509 certificate;
- text before, after or between the messages, and a boundary sharing its line with other text.

xml-crypto documents the complete rules under
[What the parser accepts](https://github.com/node-saml/xml-crypto#what-the-parser-accepts). A
`Buffer` is read as the text of a PEM or Base64 file, just as a string is; DER is not accepted, so
convert it to PEM first as shown under [`idpCert`](#configuration-option-idpcert).

```javascript
privateKey: fs.readFileSync("./privateKey.pem", "latin1");
```

Accepted formats:

1. RFC 7468 PEM, with either label:

   ```text
   -----BEGIN PRIVATE KEY-----
   <private key contents here delimited at 64 characters per row>
   -----END PRIVATE KEY-----
   ```

   ```text
   -----BEGIN RSA PRIVATE KEY-----
   <private key contents here delimited at 64 characters per row>
   -----END RSA PRIVATE KEY-----
   ```

2. A single-line or multi-line private key in Base64, without the delimiter lines. See the
   [single-line private key](test/static/single_line_acme_tools_com.key) used in the tests.

### Configuration option `idpCert`

Validating the signatures on incoming responses is the point of this library, and `idpCert` is what
it validates them against. Provide the IdP's public X.509 signing certificate(s) or public key(s). The
same normalization, tolerances and rejections described under
[`privateKey`](#configuration-option-privatekey) apply here.

```javascript
idpCert: "MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==";
```

If the IdP has several valid signing certificates or public keys — during a rollover, for instance,
when responses signed with either key are valid — pass an array:

```javascript
idpCert: ["MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==", "MIIEOTCCAyGgAwIBAgIJAKZgJdKdCdL6M ... g="];
```

`idpCert` can also be a function taking a node-style callback, which lets you poll the IdP for its
current keys so a rotation is picked up without a restart. The result is not cached, so the function
is called on every validation:

```javascript
idpCert: (callback) => {
  callback(null, polledCertificates);
};
```

Accepted formats:

1. RFC 7468 PEM, as a certificate or a bare public key:

   ```text
   -----BEGIN CERTIFICATE-----
   <certificate contents here delimited at 64 characters per row>
   -----END CERTIFICATE-----
   ```

   ```text
   -----BEGIN PUBLIC KEY-----
   <public key contents here delimited at 64 characters per row>
   -----END PUBLIC KEY-----
   ```

2. A single-line or multi-line **certificate** in Base64, without the delimiter lines.

#### If the certificate is in the binary DER encoding

Convert it to PEM:

```shell
openssl x509 -inform der -in my_certificate.cer -out my_certificate.pem
```

### Configuration option `publicCert`

Some identity providers require the SP's public signing certificate to be embedded in the
`AuthnRequest`, so they can verify the request, match the subject DN, and confirm the certificate was
signed. Pass it as `publicCert`; it must match `privateKey`. The same two formats are accepted:

```text
-----BEGIN CERTIFICATE-----
<X.509 certificate contents here delimited at 64 characters per row>
-----END CERTIFICATE-----
```

or

```javascript
publicCert: "MIICizCCAfQCCQCY8tKaMc0BMjANBgkqh ... W==";
```

## Response validation timestamps

When a response carries `NotBefore` or `NotOnOrAfter`, Node-SAML validates them against the current
time plus or minus `acceptedClockSkewMs`, which accounts for drift between your server's clock and
the IdP's. The default skew is `0`.

Both attributes are honored on the `SubjectConfirmation` element and within
`Assertion/Conditions`. `maxAssertionAgeMs` adds an independent limit measured from the assertion's
`IssueInstant`, and applies when it is stricter than `NotOnOrAfter`.

## InResponseTo validation

`InResponseTo` ties a response back to a request you actually made, which is what stops a response
captured elsewhere from being replayed at your callback. Turn it on with
`validateInResponseTo: "always"`.

Node-SAML then records the ID of every request it generates, and a response validates only if its
`InResponseTo` matches one of them. It is checked both as an attribute of the top-level `Response`
element and within `SubjectConfirmation`.

Recorded IDs expire after `requestIdExpirationPeriodMs` (8 hours by default). A response arriving
with an expired — or unrecognized — `InResponseTo` is rejected. The ID is consumed on validation, so
the same response cannot be presented twice.

## Cache provider

With `InResponseTo` validation on, the generated request IDs have to be stored somewhere. That is
the `cacheProvider`'s job.

The default is a simple in-memory provider. It is not sufficient across multiple servers or
processes: the instance that generated the request ID may not be the one that handles the response,
and validation then fails for legitimate logins. For those deployments, back the cache with
something shared — Redis, a database, your session store — by implementing:

```typescript
interface CacheProvider {
  /** Store an item in the cache, using the specified key and value. */
  saveAsync(key: string, value: string): Promise<CacheItem | null>;
  /** Returns the value of the specified key in the cache. */
  getAsync(key: string): Promise<string | null>;
  /** Removes an item from the cache if the key exists. */
  removeAsync(key: string | null): Promise<string | null>;
}
```

`CacheProvider` and `CacheItem` are exported from the package root.

## Node support policy

We only support [Long-Term Support](https://github.com/nodejs/Release) versions of Node.

We specifically limit our support to LTS versions of Node, not because this package won't work on other versions, but because we have a limited amount of time, and supporting LTS offers the greatest return on that investment.

It's possible this package will work correctly on newer versions of Node. It may even be possible to use this package on older versions of Node, though that's more unlikely as we'll make every effort to take advantage of features available in the oldest LTS version we support.

The `engines` field in [`package.json`](package.json) is the authoritative statement of what we support. As each Node LTS version reaches its end-of-life we will remove that version from it. Removing a Node version is considered a breaking change and will entail the publishing of a new major version of this package. We will not accept any requests to support an end-of-life version of Node. Any merge requests or issues supporting an end-of-life version of Node will be closed.

We will accept code that allows this package to run on newer, non-LTS, versions of Node.

## Contributing

Issues and pull requests are welcome. A change that touches how a document is accepted, rejected, or
trusted needs a test that fails without it; [`AGENTS.md`](AGENTS.md) documents the standards this
repository holds itself to, and the [pull request template](.github/pull_request_template.md) lists
what a review looks for. For questions rather than bugs, start in
[Discussions](https://github.com/node-saml/node-saml/discussions).

When a change follows the SAML specification, link the relevant part. Start from the
[OASIS SAML 2.0 standards](https://www.oasis-open.org/standards#samlv2.0).

## Changelog

See [CHANGELOG.md](https://github.com/node-saml/node-saml/blob/master/CHANGELOG.md).
