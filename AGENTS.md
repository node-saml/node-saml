# AGENTS.md

## What this is

`@node-saml/node-saml` implements SAML 2.0 for Node.js. It generates `AuthnRequest`s and
logout messages, and — the part that matters — decides whether an incoming SAML response
is trustworthy. It is published to npm and is the engine underneath
`@node-saml/passport-saml`, so a bug here becomes an authentication bypass in every
application downstream. Treat every change as security-relevant.

## How to read this file

This describes the library we intend to have, not uniformly the library we have today.
The codebase carries years of contributions of varying quality, and some of it predates
the standards below.

So: **this file wins over precedent.** Finding an existing pattern that contradicts a rule
here is not permission to copy it — it is a debt, and the rules below name the ones we
already know about. When you touch code near a named debt, move it toward the target if
you can do so within the scope you were given. When you can't, leave it alone rather than
widening the change; don't let cleanup swallow the fix you were asked for.

## Layout

- `src/` — TypeScript source; the only code that ships.
- `src/index.ts` — the public barrel. Anything re-exported here is public API.
- `src/saml.ts` — the `SAML` class: option validation, request generation, and response
  validation. The security-critical path runs through `validatePostResponseAsync`.
- `src/xml.ts` — signature verification, decryption, XPath, and DOM/xml2js parsing.
- `src/crypto.ts` — PEM parsing and normalization (RFC 7468) and unique ID generation.
- `src/metadata.ts` — service provider metadata generation.
- `src/types.ts` — public types, including the whole `SamlOptions` surface.
- `test/*.spec.ts` — Mocha specs. `test/types.ts` is a shared fixture helper, not a spec.
- `test/static/` — fixtures, including `test/static/signatures/{valid,invalid}/`. See the
  warning below.
- `lib/` — build output. Generated and git-ignored; never edit.

## Commands

- `npm run build` — compile `src/` to `lib/`.
- `npm test` — runs `npm run build`, then `nyc mocha` over `test/**/*.spec.ts`.
- `npm run lint` — ESLint plus `prettier --check`.
- `npm run lint:fix` — ESLint `--fix` over `src` plus `prettier --write` over everything;
  rewrites files.

`npm test` builds first, so `npm test && npm run lint` covers everything. Run it before
calling work done.

Test order is randomized on every run (`choma`, wired up in `.mocharc.json`). A test that
depends on another test's leftover state fails intermittently rather than reproducibly, so
don't share mutable state between tests.

## Hard constraints

### Fixtures are byte-sensitive

`test/static/` contains signed SAML documents. XML canonicalization and digests depend on
the exact bytes, so re-indenting or reflowing one silently invalidates its signature, and
the resulting failure can look unrelated to what you touched.

`.prettierignore` excludes the whole directory. Keep it that way. Prettier has no XML
parser of its own today, so that entry looks redundant — it isn't. It is what makes "run
the formatter over everything" unconditionally safe, and it is what keeps an XML formatter
from silently invalidating every signature in the suite if one is ever added. That
combination is the pattern to follow: xml-crypto formats its XML with
`@prettier/plugin-xml` and keeps its signed fixtures ignored, so the plugin is welcome
here too — the ignore entry is what makes adding it safe rather than something to avoid.

When you need a new signed fixture, generate it (`docs/xml-signing-example.js` produces
the `DigestValue` and `SignatureValue`) rather than hand-editing an existing one.

Fixture names under `test/static/signatures/` encode what is signed —
`response.root-signed.assertion-unsigned.1advice-signed.xml` — and `valid/` versus
`invalid/` states the expected verdict. Follow the naming; the test names in
`test/test-signatures.spec.ts` read off it.

### The supported Node floor is real

`engines` in `package.json` is the contract, and the matrix in
`.github/workflows/workflow.yml` runs the suite on every supported version, oldest
included. Read both rather than assuming; they change. Only Node LTS versions are
supported, and `README.md` states that dropping one is a breaking change that entails a
new major. Development tooling has to install and run on the _oldest_ entry, not just the
newest.

`tsconfig.json` targets ES2018 with `lib: ["es2018"]`, and `@types/node` is pinned to the
v18 line. Anything newer than that is unavailable in `src/` even when it runs fine on your
local Node.

### The public API is semver-bound

Anything re-exported from `src/index.ts` is public. So is the option surface in
`src/types.ts`: `SamlOptions`, `SamlConfig`, and `Profile` are the configuration and
result contract that every consumer codes against. Adding a required option, renaming a
field, or tightening a default is breaking. Changes confined to `devDependencies`, tests,
CI, or tooling are not.

## Defense posture

The rules below are invariants, not aspirations, and the standard for each is the same:
**an invariant that no test can fail is not an invariant.** If you add or change one, add
the test that catches its violation, and watch that test fail before you make it pass. If
you find an invariant here with no test behind it, that gap is worth fixing on its own.

### Trust only the bytes that were signed

This is the defense against XML signature wrapping, and it is the single most important
rule in this repository. `getVerifiedXml()` in `src/xml.ts` returns the content the
signature actually covers. Process _that_ return value. Never verify a signature and then
go back and read the original DOM — an attacker controls the difference between the two.

A function that answers "did this verify?" with a boolean cannot uphold this rule, because
its caller still has to go find the content somewhere else. We are moving away from that
shape entirely: verification returns the verified bytes or it returns nothing.

_Known debts:_ `validateSignature()` is still exported and still returns a boolean.
`Profile.getSamlResponseXml()` hands callers the response as received, without indicating which
parts were authenticated, and `processValidlySignedAssertionAsync` takes that XML as a parameter
only to back it. The accessor is deprecated and goes in the next major, and the parameter with it.
See the deprecation section; don't build anything new on top of these.

### Reject ambiguity rather than resolving it

When a document admits two readings, the library refuses it. It does not pick one, and it
does not pick "the one that verifies." `src/xml.ts` and `validatePostResponseAsync`
already reject documents with more than one assertion, more than one signature on an
element, an `ID` that resolves to more than one element, a reference pointing somewhere
other than its own parent, and more than two transforms.

Each of those was a real attack, not a tidiness check. Do not relax one to make a document
parse. When you add a check of this kind, add its fixture to
`test/static/signatures/invalid/` so the rejection is pinned.

### Fail closed, and say why

- Never make a check more permissive to get a test green. If a document you believe is
  legitimate is rejected, the question is whether the check is wrong — answer that, don't
  route around it.
- Decrypted content is not trusted content. An `EncryptedAssertion` is decrypted and then
  still has to have its signature verified.
- Be careful with XPath. Expressions can incorporate values taken from the document under
  inspection; `getVerifiedXml()` rejects a reference URI containing `'` or `"` for exactly
  that reason. Don't interpolate document-derived text into an XPath without the same care.
- Timestamp, audience, issuer, and `InResponseTo` checks are part of the security surface,
  not conveniences. So are `wantAssertionsSigned` and `wantAuthnResponseSigned`.
- Prefer an explicit, specific error over silently accepting a malformed document, and over
  a generic one. The error message is how an integrator distinguishes a misconfiguration
  from an attack.

## Make the caller choose

Prefer removing footguns over adding convenience. A default that makes a security decision
on the caller's behalf is a footgun: the caller lives with the consequence without ever
having made the choice, and — worse — never learns the choice existed.

The target: **a security-relevant option has no default.** Its absence is a `TypeError`
naming the option, thrown at construction, the way `callbackUrl`, `issuer`, and `idpCert`
already are. An integrator who has to name their signature algorithm has thought about
their signature algorithm once; one who inherits a default has not thought about it ever,
and will not think about it when it becomes the wrong answer.

Rules that follow from that:

- Don't add a default for anything security-relevant. Throw instead.
- Where a default is genuinely unavoidable, it is the safe one and it is documented as a
  decision. `wantAssertionsSigned` and `wantAuthnResponseSigned` default to `true`; that is
  the shape to copy.
- Where guessing at an extension point would be dangerous, prefer an inert default over a
  working one. A default that trusts something the document supplied lets an attacker
  choose the key that verifies their own signature.
- Keep dangerous-but-legitimate behavior off until asked for, explicitly, by name.
- Validate options at construction, not at use. `assertRequired` and
  `assertBooleanIfPresent` exist because a JavaScript caller passing the string `"false"`
  would otherwise silently enable a security-relevant flag. New options that gate behavior
  get the same treatment in `initialize()`.
- A choice is only real if it is documented. When you require the implementer to decide,
  list the sensible options and their trade-offs under "Config parameter details" in
  `README.md` so they can choose knowingly. An option change that doesn't reach `README.md`
  isn't finished.

_Known debts:_ `signatureAlgorithm` defaults to `sha1` in `initialize()`, and
`getSigningAlgorithm`/`getDigestAlgorithm` in `src/algorithms.ts` fall through to SHA-1 for
an unrecognized value — so a typo silently downgrades the caller. Both are backward
compatibility, both are wrong by the standard above, and both are headed for removal
through the process below. Don't add a third.

## Deprecation strategy

We have things to deprecate — the debts named above are the list — and removing them is
part of the work, not a someday. What we don't have yet is the mechanism. Establish it the
first time it's needed:

1. **Mark it.** `@deprecated` JSDoc on the export, naming the replacement and the reason in
   one line. This surfaces in the consumer's editor, which is where the migration actually
   starts.
2. **Document it.** A note in `README.md` next to the thing it replaces, with the migration
   in code, not prose.
3. **Keep it working.** A deprecated API keeps its tests and keeps passing them. Deprecation
   is a message to consumers, not permission to let the code rot.
4. **Remove it in a major.** Not before. `CHANGELOG.md` and the release notes carry it.

Two cautions specific to this repository:

- A lint rule that errors on deprecated usage makes internal migration enforceable, and is
  worth adding when we have enough marked to justify it. Note that the `@deprecated` tag
  and that rule arrive together or the build breaks on our own call sites — which is why
  `validateSignature` carries a comment instead of a tag today. Deprecate the call sites
  first, then the API.
- Deprecating a **default** is not the same as deprecating an API and is harder: silence is
  the thing being removed, so there is no call site to warn at. The migration is to warn
  when the option is absent, then require it in the next major.

## Tests

Tests protect observable behavior, not implementation details. Favor tests that establish
what the library accepts, rejects, emits, or considers trustworthy. Security regressions
matter most: a test should ensure that malformed or adversarial XML cannot cause the
library to report untrusted data as valid.

- Test at a public boundary for the behavior being changed. For response handling, that
  means constructing a `SAML` with a config a real caller could write, feeding it a base64
  `SAMLResponse`, and asserting on the resulting profile or on the rejection message.
- Signature and wrapping regressions belong in `test/static/signatures/` with a case in
  `test/test-signatures.spec.ts`.
- That spec asserts how many signature checks were performed as well as the outcome. If
  your change alters the number, that is a behavior change: understand why before updating
  the expected count.
- Assert the specific rejection, not that something was rejected. `assert.rejects` with a
  message is the difference between a test that proves the defense works and one that
  passes because an unrelated line threw first.
- Test a utility directly only when it has an independently defined observable contract,
  such as PEM normalization in `src/crypto.ts` or the date parsing in `src/date-time.ts`.
  Assert its externally meaningful input/output behavior rather than its private
  implementation.
- Do not unit-test protected methods merely to increase coverage or mirror their
  implementation. Coverage is reported but not enforced (`check-coverage` is `false`).
  Uncovered code indicates either inadequately tested public behavior or code that may be
  unnecessary; determine which rather than adding protected-method tests merely to
  increase coverage.
- Add a test when a change alters what the library accepts, rejects, emits, or considers
  trustworthy.
- For a bug fix, observe the regression test failing for the reported reason before
  applying the fix. "For the reported reason" is the operative part — a test that fails for
  the wrong reason proves nothing and will keep passing after the bug returns.

## Style

- Strict TypeScript (`strict: true`), CommonJS, target ES2018.
- ESLint flat config lives in `eslint.config.mjs` and includes `typescript-eslint`'s
  `strict` preset. Rules that bite often:
  `@typescript-eslint/no-non-null-assertion` is an error, so no `!` assertions;
  `no-console` is an error — use the `util.debuglog("node-saml")` logger that `src/saml.ts`
  and `src/xml.ts` already set up.
- Use `as` for type assertions, never the angle-bracket form. The repository was converted
  away from `<T>value` to stay compatible with Node's strip-only TypeScript support, and
  there are none left.
- Prettier owns formatting for everything it can parse, and `.prettierignore` is the
  complete list of exceptions. Don't hand-format, don't argue with it in review, and don't
  add an exception without a reason as concrete as the fixture bytes.
- Line endings are LF, enforced by `.gitattributes` and by the `linebreak-style` lint rule.

## Comments

Code describes itself. Name things well and keep functions small enough that the _what_
and the _how_ are readable from the code, then don't restate them in prose that goes stale
the first time someone edits the line below it.

Comment only what the code cannot say: _why_ something is done, what would break if it
were done the obvious way, and which non-obvious constraint is being satisfied. The
comment explaining why multiple assertions are rejected earns its place because the code
alone reads like an arbitrary limit. Typically, well-written tests and code are
self-documenting.

Don't narrate history. A bug the code no longer has belongs in the commit message and the
PR, and `git blame` leads there.

If a comment is needed at all, keep it DRY. The `it()` name is usually the whole comment.
Link the SAML specification where the code implements it, but link an issue only for a
tricky edge case, where whoever breaks the test might otherwise decide the test is wrong.
Cite, don't quote: prefer a section number and a URL over the sentence they contain. Keep
it to a line or two.

A comment reading "parse the assertion" above a call that parses the assertion, or one
restating a field's name as a sentence, earns nothing and costs a review every time the
code beneath it changes. Delete those rather than update them.

JSDoc on exported API is a separate thing and is welcome: it documents the contract for
consumers and surfaces in their editor. Keep it about the contract — parameters, return
values, what throws, what is deprecated — not about the implementation. Reserve the
`/** */` form for that; on internal code and tests it advertises a contract that isn't
there.

## Conventions

- Keep changes minimal and focused; use modern semantic coding practices.
- Work in `src/` and `test/` unless asked otherwise.
- Never edit `node_modules/` or `lib/`.
- `CHANGELOG.md` is generated from merged pull requests by `npm run changelog`. Don't
  hand-edit it.
- When behavior follows the SAML specification, cite the relevant part. The pull request
  template asks for a link, and the maintainers use it to keep the library spec-compliant.
  Start from <https://www.oasis-open.org/standards#samlv2.0>.
- Before changing behavior, read the relevant implementation, tests, `README.md`, and
  public API. Do not infer behavior from names or issue descriptions when the repository
  can answer the question. Keep the change scoped to the requested problem; do not combine
  bug fixes with unrelated refactoring or cleanup.
