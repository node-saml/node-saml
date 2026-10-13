import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { expect } from "chai";
import {
  CacheProvider,
  InMemoryCacheProvider,
  SAML,
  SamlConfig,
  ValidateInResponseTo,
} from "../src";
import { signXml } from "../src/xml";

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const callbackUrl = "http://localhost/saml/consume";
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const success =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';
const audienceRestriction =
  "<saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction>";

function instant(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function sign(xml: string, element: string): string {
  const xpath = `//*[local-name(.)='${element}']`;
  return signXml(
    xml,
    xpath,
    { reference: xpath, action: "prepend" },
    { privateKey, signatureAlgorithm: "sha256", digestAlgorithm: "sha256" },
  );
}

function confirmation(notOnOrAfter: string): string {
  return (
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${callbackUrl}"/>` +
    "</saml:SubjectConfirmation>"
  );
}

// An unsolicited response, so nothing but the assertion's ID can tell a second copy from the first.
function response({
  issueInstant = instant(),
  assertionElement = "saml:Assertion",
  assertionAttributes = ` ID="_assertion" Version="2.0" IssueInstant="${issueInstant}"`,
  issuer = "<saml:Issuer>idp</saml:Issuer>",
  conditions = `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>`,
  confirmations = [confirmation(instant(300000))],
  subject = `<saml:Subject><saml:NameID>user</saml:NameID>${confirmations.join("")}</saml:Subject>`,
  signAssertion = true,
}: {
  issueInstant?: string;
  assertionElement?: string;
  assertionAttributes?: string;
  issuer?: string;
  conditions?: string;
  confirmations?: string[];
  subject?: string;
  signAssertion?: boolean;
} = {}): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    `<${assertionElement}${assertionAttributes}>${issuer}${subject}` +
    `${conditions}<saml:AuthnStatement AuthnInstant="${instant()}"/></${assertionElement}></samlp:Response>`;
  const signed = sign(signAssertion ? sign(xml, "Assertion") : xml, "Response");
  return { SAMLResponse: Buffer.from(signed).toString("base64") };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl,
    idpCert,
    issuer: "onesaml_login",
    validateInResponseTo: ValidateInResponseTo.never,
    rejectReplayedAssertions: true,
    ...config,
  });
}

async function outcome(validation: Promise<unknown>): Promise<string> {
  return validation.then(
    () => "accepted",
    (err: Error) => err.message,
  );
}

class RecordingCacheProvider extends InMemoryCacheProvider {
  expiries: number[] = [];

  async saveIfAbsentAsync(key: string, value: string, expiresAtMs: number): Promise<boolean> {
    this.expiries.push(expiresAtMs);
    return super.saveIfAbsentAsync(key, value, expiresAtMs);
  }
}

describe("rejectReplayedAssertions", function () {
  afterEach(function () {
    sinon.restore();
  });

  it("rejects a second copy of an accepted response", async () => {
    const saml = newSaml();
    const copy = response();

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("accepts a second copy when it is false", async () => {
    const saml = newSaml({ rejectReplayedAssertions: false });
    const copy = response();

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
  });

  it("accepts only one of two copies validated at the same moment", async () => {
    const saml = newSaml();
    const copy = response();

    const outcomes = await Promise.all([
      outcome(saml.validatePostResponseAsync(copy)),
      outcome(saml.validatePostResponseAsync(copy)),
    ]);

    expect(outcomes.sort()).to.deep.equal([
      "The assertion _assertion has already been received",
      "accepted",
    ]);
  });

  it("rejects a copy presented once valid, after it was rejected as not yet valid", async () => {
    const clock = sinon.useFakeTimers({ now: Date.now(), toFake: ["Date"] });
    const saml = newSaml();
    const early = response({
      conditions: `<saml:Conditions NotBefore="${instant(60000)}" NotOnOrAfter="${instant(300000)}">${audienceRestriction}</saml:Conditions>`,
    });

    expect(await outcome(saml.validatePostResponseAsync(early))).to.equal(
      "SAML assertion not yet valid",
    );
    clock.tick(120000);
    expect(await outcome(saml.validatePostResponseAsync(early))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("keeps an ID until the latest moment the assertion could be accepted", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider, acceptedClockSkewMs: 1000 });
    const conditionsEnd = instant(300000);
    const laterConfirmationEnd = instant(600000);

    await saml.validatePostResponseAsync(
      response({
        conditions: `<saml:Conditions NotOnOrAfter="${conditionsEnd}">${audienceRestriction}</saml:Conditions>`,
        confirmations: [confirmation(instant(120000)), confirmation(laterConfirmationEnd)],
      }),
    );

    // The later confirmation can be chosen next time, but Conditions still ends acceptance.
    expect(cacheProvider.expiries).to.deep.equal([Date.parse(conditionsEnd) + 1000]);
  });

  it("keeps an ID no longer than maxAssertionAgeMs allows the assertion", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider, maxAssertionAgeMs: 60000 });
    const issueInstant = instant();

    await saml.validatePostResponseAsync(response({ issueInstant }));

    expect(cacheProvider.expiries).to.deep.equal([Date.parse(issueInstant) + 60000]);
  });

  it("rejects an assertion whose acceptance nothing ends", async () => {
    const saml = newSaml({ audience: false });

    expect(
      await outcome(
        saml.validatePostResponseAsync(response({ conditions: "", confirmations: [] })),
      ),
    ).to.equal(
      "The assertion has no NotOnOrAfter, so it would be accepted for ever and cannot be checked for replay",
    );
  });

  it("does not record an assertion that has already expired", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider });
    const expired = response({
      conditions: `<saml:Conditions NotOnOrAfter="${instant(-1000)}">${audienceRestriction}</saml:Conditions>`,
    });

    expect(await outcome(saml.validatePostResponseAsync(expired))).to.equal(
      "SAML assertion expired: clocks skewed too much",
    );
    expect(cacheProvider.expiries).to.deep.equal([]);
  });

  it("rejects an assertion with no ID", async () => {
    const saml = newSaml({ wantAssertionsSigned: false });

    expect(
      await outcome(
        saml.validatePostResponseAsync(
          response({
            assertionElement: "Assertion",
            assertionAttributes: "",
            signAssertion: false,
          }),
        ),
      ),
    ).to.equal("The assertion has no ID, so it cannot be checked for replay");
  });

  it("rejects a second copy of an assertion with no Issuer", async () => {
    const saml = newSaml();
    const copy = response({ issuer: "" });

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("rejects a second copy of an assertion with no Subject", async () => {
    const saml = newSaml();
    const copy = response({ subject: "" });

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("passes over a confirmation whose data has no NotOnOrAfter", async () => {
    const cacheProvider = new RecordingCacheProvider();
    const saml = newSaml({ cacheProvider });
    const confirmationEnd = instant(120000);
    const bearer = 'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"';

    await saml.validatePostResponseAsync(
      response({
        confirmations: [
          `<saml:SubjectConfirmation ${bearer}/>`,
          `<saml:SubjectConfirmation ${bearer}><saml:SubjectConfirmationData/></saml:SubjectConfirmation>`,
          confirmation(confirmationEnd),
        ],
      }),
    );

    expect(cacheProvider.expiries).to.deep.equal([Date.parse(confirmationEnd)]);
  });

  it("keeps the IDs of different identity providers apart in a shared cache", async () => {
    const cacheProvider = new InMemoryCacheProvider();
    const saml = newSaml({ cacheProvider });

    expect(await outcome(saml.validatePostResponseAsync(response()))).to.equal("accepted");
    expect(
      await outcome(
        saml.validatePostResponseAsync(
          response({ issuer: "<saml:Issuer>other-idp</saml:Issuer>" }),
        ),
      ),
    ).to.equal("accepted");
  });

  it("rejects a second copy with a cache provider that has no saveIfAbsentAsync", async () => {
    const store = new Map<string, string>();
    const cacheProvider: CacheProvider = {
      saveAsync: async (key, value) => {
        store.set(key, value);
        return { value, createdAt: Date.now() };
      },
      getAsync: async (key) => store.get(key) ?? null,
      removeAsync: async (key) => (key != null && store.delete(key) ? key : null),
    };
    const saml = newSaml({ cacheProvider });
    const copy = response();

    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal("accepted");
    expect(await outcome(saml.validatePostResponseAsync(copy))).to.equal(
      "The assertion _assertion has already been received",
    );
  });

  it("cannot be combined with acceptedClockSkewMs: -1", () => {
    expect(() => newSaml({ acceptedClockSkewMs: -1 })).to.throw(
      TypeError,
      "rejectReplayedAssertions cannot be used with acceptedClockSkewMs: -1, under which an assertion never expires",
    );
  });
});
