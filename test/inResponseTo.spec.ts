import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";
import { expect } from "chai";
import { SAML } from "../src/saml";
import { CacheProvider, Profile, SamlConfig, ValidateInResponseTo } from "../src/types";
import { signXml } from "../src/xml";

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const requestId = "_4f1d2a9c7b3e8f60a5d1";
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const success =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';

function instant(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function sign(xml: string, element: string): string {
  const xpath = `//*[local-name(.)='${element}']`;
  return signXml(
    xml,
    xpath,
    { reference: `${xpath}/*[local-name(.)='Issuer']`, action: "after" },
    { privateKey, signatureAlgorithm: "sha256", digestAlgorithm: "sha256" },
  );
}

function loginResponse({ subjectConfirmationInResponseTo = true } = {}): Record<string, string> {
  const confirmationInResponseTo = subjectConfirmationInResponseTo
    ? ` InResponseTo="${requestId}"`
    : "";
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}" InResponseTo="${requestId}">` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    `<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="${instant()}"><saml:Issuer>idp</saml:Issuer>` +
    `<saml:Subject><saml:NameID>user</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="http://localhost/saml/consume"${confirmationInResponseTo}/>` +
    `</saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}"><saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion></samlp:Response>`;
  return { SAMLResponse: Buffer.from(sign(xml, "Assertion")).toString("base64") };
}

function logoutResponseXml(): string {
  return (
    `<samlp:LogoutResponse ${namespaces} ID="_logout_response" Version="2.0" IssueInstant="${instant()}" InResponseTo="${requestId}">` +
    `<saml:Issuer>idp</saml:Issuer>${success}</samlp:LogoutResponse>`
  );
}

function signedPostLogoutResponse(): Record<string, string> {
  return {
    SAMLResponse: Buffer.from(sign(logoutResponseXml(), "LogoutResponse")).toString("base64"),
  };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl: "http://localhost/saml/consume",
    entryPoint: "https://idp.example.com/sso",
    issuer: "onesaml_login",
    idpCert,
    validateInResponseTo: ValidateInResponseTo.always,
    wantAuthnResponseSigned: false,
    generateUniqueId: () => requestId,
    ...config,
  });
}

const user: Profile = {
  issuer: "idp",
  nameID: "user",
  nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
};

function outcome(validation: Promise<unknown>): Promise<string> {
  return validation.then(
    () => "accepted",
    (err: Error) => err.message,
  );
}

// Map-backed, like a Redis or database provider an integrator would write.
function mapCacheProvider(consumeAsync?: CacheProvider["consumeAsync"]): CacheProvider {
  const items = new Map<string, string>();
  return {
    saveAsync: async (key, value) => {
      items.set(key, value);
      return { value, createdAt: Date.now() };
    },
    getAsync: async (key) => items.get(key) ?? null,
    removeAsync: async (key) => (key != null && items.delete(key) ? key : null),
    ...(consumeAsync && { consumeAsync }),
  };
}

describe("InResponseTo request ID consumption", function () {
  describe("login responses", function () {
    let saml: SAML;

    beforeEach(async function () {
      saml = newSaml();
      await saml.getAuthorizeUrlAsync("", {});
    });

    it("accepts only one of two concurrent copies", async () => {
      const response = loginResponse();

      const outcomes = await Promise.all([
        outcome(saml.validatePostResponseAsync(response)),
        outcome(saml.validatePostResponseAsync(response)),
      ]);

      expect(outcomes).to.have.members(["accepted", "SubjectInResponseTo is not valid"]);
    });

    it("rejects one presented again when its SubjectConfirmationData omits InResponseTo", async () => {
      const response = loginResponse({ subjectConfirmationInResponseTo: false });

      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal("accepted");
      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
        "InResponseTo is not valid",
      );
    });
  });

  describe("logout responses", function () {
    let saml: SAML;

    beforeEach(async function () {
      saml = newSaml({ wantAuthnResponseSigned: true });
      await saml.getLogoutUrlAsync(user, "", {});
    });

    it("rejects one presented again on the Redirect binding", async () => {
      const container = {
        SAMLResponse: zlib.deflateRawSync(logoutResponseXml()).toString("base64"),
      };
      const query = new URLSearchParams(container).toString();

      expect(await outcome(saml.validateRedirectAsync(container, query))).to.equal("accepted");
      expect(await outcome(saml.validateRedirectAsync(container, query))).to.equal(
        "InResponseTo is not valid",
      );
    });

    it("accepts one over POST that answers a recorded request", async () => {
      expect(await saml.validatePostResponseAsync(signedPostLogoutResponse())).to.deep.equal({
        profile: null,
        loggedOut: true,
      });
    });

    it("rejects one presented again over POST", async () => {
      const response = signedPostLogoutResponse();

      await saml.validatePostResponseAsync(response);
      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
        "InResponseTo is not valid",
      );
    });
  });

  describe("custom cache providers", function () {
    it("rejects a response when consumeAsync reports the ID already taken", async () => {
      const saml = newSaml({ cacheProvider: mapCacheProvider(async () => null) });
      await saml.getAuthorizeUrlAsync("", {});

      expect(await outcome(saml.validatePostResponseAsync(loginResponse()))).to.equal(
        "SubjectInResponseTo is not valid",
      );
    });

    it("still consumes the ID without consumeAsync", async () => {
      const cacheProvider = mapCacheProvider();
      const saml = newSaml({ cacheProvider });
      await saml.getAuthorizeUrlAsync("", {});

      expect(await outcome(saml.validatePostResponseAsync(loginResponse()))).to.equal("accepted");
      expect(await cacheProvider.getAsync(requestId)).to.equal(null);
    });
  });
});
