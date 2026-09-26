import * as crypto from "crypto";
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
const requesterError =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>';

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

function loginResponse({
  responseInResponseTo = requestId,
  subjectInResponseTo = requestId,
  subjectConfirmations = [{ inResponseTo: true }],
  signResponse = false,
}: {
  responseInResponseTo?: string | null;
  subjectInResponseTo?: string;
  subjectConfirmations?: {
    inResponseTo?: boolean;
    data?: "full" | "empty" | "none";
    expired?: boolean;
  }[];
  signResponse?: boolean;
} = {}): Record<string, string> {
  const method = `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"`;
  const confirmations = subjectConfirmations
    .map(({ inResponseTo = false, data = "full", expired = false }) => {
      if (data === "none") {
        return `<saml:SubjectConfirmation ${method}/>`;
      }
      if (data === "empty") {
        return `<saml:SubjectConfirmation ${method}><saml:SubjectConfirmationData/></saml:SubjectConfirmation>`;
      }
      const inResponseToAttribute = inResponseTo ? ` InResponseTo="${subjectInResponseTo}"` : "";
      return (
        `<saml:SubjectConfirmation ${method}>` +
        `<saml:SubjectConfirmationData NotOnOrAfter="${instant(expired ? -300000 : 300000)}" Recipient="http://localhost/saml/consume"${inResponseToAttribute}/>` +
        `</saml:SubjectConfirmation>`
      );
    })
    .join("");
  const responseInResponseToAttribute =
    responseInResponseTo == null ? "" : ` InResponseTo="${responseInResponseTo}"`;
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}"${responseInResponseToAttribute}>` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    `<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="${instant()}"><saml:Issuer>idp</saml:Issuer>` +
    `<saml:Subject><saml:NameID>user</saml:NameID>${confirmations}</saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}"><saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion></samlp:Response>`;
  const signed = sign(xml, "Assertion");
  return {
    SAMLResponse: Buffer.from(signResponse ? sign(signed, "Response") : signed).toString("base64"),
  };
}

function logoutResponseXml({ inResponseTo = true, status = success } = {}): string {
  const inResponseToAttribute = inResponseTo ? ` InResponseTo="${requestId}"` : "";
  return (
    `<samlp:LogoutResponse ${namespaces} ID="_logout_response" Version="2.0" IssueInstant="${instant()}"${inResponseToAttribute}>` +
    `<saml:Issuer>idp</saml:Issuer>${status}</samlp:LogoutResponse>`
  );
}

function redirectLogoutResponse(xml: string): { container: Record<string, string>; query: string } {
  const container = { SAMLResponse: zlib.deflateRawSync(xml).toString("base64") };
  return { container, query: new URLSearchParams(container).toString() };
}

function signedRedirectLogoutResponse(xml: string): {
  container: Record<string, string>;
  query: string;
} {
  const signed = {
    SAMLResponse: zlib.deflateRawSync(xml).toString("base64"),
    SigAlg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  };
  const Signature = crypto
    .createSign("RSA-SHA256")
    .update(new URLSearchParams(signed).toString())
    .sign(privateKey, "base64");
  const container = { ...signed, Signature };
  return { container, query: new URLSearchParams(container).toString() };
}

function signedPostLogoutResponse(): Record<string, string> {
  return {
    SAMLResponse: Buffer.from(sign(logoutResponseXml(), "LogoutResponse")).toString("base64"),
  };
}

function newSaml(config: Partial<SamlConfig> = {}, Saml: typeof SAML = SAML): SAML {
  return new Saml({
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
      const response = loginResponse({
        subjectConfirmations: [{ inResponseTo: false }],
        signResponse: true,
      });

      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal("accepted");
      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
        "InResponseTo is not valid",
      );
    });

    // Otherwise a captured IdP-initiated assertion, wrapped in a new Response, answers a request the
    // sender started themselves: https://github.com/node-saml/node-saml/issues/433
    it("rejects an unsigned one whose SubjectConfirmationData omits InResponseTo", async () => {
      const response = loginResponse({ subjectConfirmations: [{ inResponseTo: false }] });

      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
        "SubjectInResponseTo is missing and the Response's InResponseTo is not signed",
      );
    });

    it("rejects an unsigned one whose assertion has no SubjectConfirmation", async () => {
      const response = loginResponse({ subjectConfirmations: [] });

      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
        "SubjectInResponseTo is missing and the Response's InResponseTo is not signed",
      );
    });

    (["none", "empty"] as const).forEach((data) => {
      const shape = data === "none" ? "no SubjectConfirmationData" : "an attribute-less one";

      it(`rejects an unsigned one whose SubjectConfirmation has ${shape}`, async () => {
        const response = loginResponse({ subjectConfirmations: [{ data }] });

        expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
          "No valid subject confirmation found among those available in the SAML assertion",
        );
      });
    });

    it("accepts an unsigned one when a later SubjectConfirmation carries InResponseTo", async () => {
      const response = loginResponse({
        subjectConfirmations: [{ inResponseTo: false }, { inResponseTo: true }],
      });

      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal("accepted");
    });

    // Defaulting to verified would leave an override written before the parameter open to #433.
    it("treats the Response as unsigned when an override passes only three arguments", async () => {
      class ThreeArgumentSaml extends SAML {
        protected async processValidlySignedAssertionAsync(
          xml: string,
          samlResponseXml: string,
          inResponseTo: string | null,
        ) {
          return super.processValidlySignedAssertionAsync(xml, samlResponseXml, inResponseTo);
        }
      }
      saml = newSaml({}, ThreeArgumentSaml);
      await saml.getAuthorizeUrlAsync("", {});
      const response = loginResponse({
        subjectConfirmations: [{ inResponseTo: false }],
        signResponse: true,
      });

      expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
        "SubjectInResponseTo is missing and the Response's InResponseTo is not signed",
      );
    });

    // Only a signature says the IdP answered the request, so nothing unsigned may retire it:
    // https://github.com/node-saml/node-saml/issues/438
    it("still accepts the IdP's response after an unsigned one naming its request fails", async () => {
      saml = newSaml({ wantAuthnResponseSigned: true });
      await saml.getAuthorizeUrlAsync("", {});
      const forged = {
        SAMLResponse: Buffer.from(
          `<samlp:Response ${namespaces} ID="_forged" Version="2.0" IssueInstant="${instant()}" InResponseTo="${requestId}">` +
            `<saml:Issuer>idp</saml:Issuer>${success}</samlp:Response>`,
        ).toString("base64"),
      };

      expect(await outcome(saml.validatePostResponseAsync(forged))).to.equal(
        "Invalid document signature",
      );
      expect(
        await outcome(saml.validatePostResponseAsync(loginResponse({ signResponse: true }))),
      ).to.equal("accepted");
    });

    it("still accepts the IdP's response after one whose unsigned Response disagrees with its assertion", async () => {
      const wrapped = loginResponse({ subjectInResponseTo: "_request_the_sender_started" });

      expect(await outcome(saml.validatePostResponseAsync(wrapped))).to.equal(
        "InResponseTo does not match subjectInResponseTo",
      );
      expect(await outcome(saml.validatePostResponseAsync(loginResponse()))).to.equal("accepted");
    });

    it("retires the request when a signed Response answering it fails", async () => {
      const expired = loginResponse({
        subjectConfirmations: [{ inResponseTo: false, expired: true }],
        signResponse: true,
      });

      expect(await outcome(saml.validatePostResponseAsync(expired))).to.equal(
        "No valid subject confirmation found among those available in the SAML assertion",
      );
      expect(
        await outcome(saml.validatePostResponseAsync(loginResponse({ signResponse: true }))),
      ).to.equal("InResponseTo is not valid");
    });

    it("retires the request when a signed assertion answering it fails in an unsigned Response", async () => {
      const expired = loginResponse({
        subjectConfirmations: [{ inResponseTo: true, expired: true }],
      });

      expect(await outcome(saml.validatePostResponseAsync(expired))).to.equal(
        "No valid subject confirmation found among those available in the SAML assertion",
      );
      expect(await outcome(saml.validatePostResponseAsync(loginResponse()))).to.equal(
        "InResponseTo is not valid",
      );
    });

    it("leaves the request pending when an unsigned Response names it under ifPresent", async () => {
      saml = newSaml({ validateInResponseTo: ValidateInResponseTo.ifPresent });
      await saml.getAuthorizeUrlAsync("", {});
      const wrapped = loginResponse({ subjectConfirmations: [{ inResponseTo: false }] });

      expect(await outcome(saml.validatePostResponseAsync(wrapped))).to.equal("accepted");
      expect(await outcome(saml.validatePostResponseAsync(loginResponse()))).to.equal("accepted");
    });
  });

  describe("logout responses", function () {
    let saml: SAML;

    beforeEach(async function () {
      saml = newSaml({ wantAuthnResponseSigned: true });
      await saml.getLogoutUrlAsync(user, "", {});
    });

    it("rejects a signed one presented again on the Redirect binding", async () => {
      const { container, query } = signedRedirectLogoutResponse(logoutResponseXml());

      expect(await outcome(saml.validateRedirectAsync(container, query))).to.equal("accepted");
      expect(await outcome(saml.validateRedirectAsync(container, query))).to.equal(
        "InResponseTo is not valid",
      );
    });

    it("retires the request when a signed one answering it fails on the Redirect binding", async () => {
      const failed = signedRedirectLogoutResponse(logoutResponseXml({ status: requesterError }));
      const signed = signedRedirectLogoutResponse(logoutResponseXml());

      expect(await outcome(saml.validateRedirectAsync(failed.container, failed.query))).to.equal(
        "Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester",
      );
      expect(await outcome(saml.validateRedirectAsync(signed.container, signed.query))).to.equal(
        "InResponseTo is not valid",
      );
    });

    it("leaves the request pending when an unsigned one naming it fails on the Redirect binding", async () => {
      const failed = redirectLogoutResponse(logoutResponseXml({ status: requesterError }));
      const signed = signedRedirectLogoutResponse(logoutResponseXml());

      expect(await outcome(saml.validateRedirectAsync(failed.container, failed.query))).to.equal(
        "Bad status code: urn:oasis:names:tc:SAML:2.0:status:Requester",
      );
      expect(await outcome(saml.validateRedirectAsync(signed.container, signed.query))).to.equal(
        "accepted",
      );
    });

    it("leaves the request pending when an unsigned one answers it on the Redirect binding", async () => {
      const unsigned = redirectLogoutResponse(logoutResponseXml());
      const signed = signedRedirectLogoutResponse(logoutResponseXml());

      expect(
        await outcome(saml.validateRedirectAsync(unsigned.container, unsigned.query)),
      ).to.equal("accepted");
      expect(await outcome(saml.validateRedirectAsync(signed.container, signed.query))).to.equal(
        "accepted",
      );
    });

    // Whether the message was signed must not travel through an overridable method, which an
    // override written against its two-argument signature would drop.
    describe("through an override of processValidlySignedSamlLogoutAsync", function () {
      class OverridingSaml extends SAML {
        protected async processValidlySignedSamlLogoutAsync(
          doc: Record<string, unknown>,
          dom: Document,
        ) {
          return super.processValidlySignedSamlLogoutAsync(doc, dom);
        }
      }

      beforeEach(async function () {
        saml = newSaml({ wantAuthnResponseSigned: true }, OverridingSaml);
        await saml.getLogoutUrlAsync(user, "", {});
      });

      it("rejects a signed one presented again on the Redirect binding", async () => {
        const { container, query } = signedRedirectLogoutResponse(logoutResponseXml());

        await saml.validateRedirectAsync(container, query);
        expect(await outcome(saml.validateRedirectAsync(container, query))).to.equal(
          "InResponseTo is not valid",
        );
      });

      it("leaves the request pending when an unsigned one answers it on the Redirect binding", async () => {
        const unsigned = redirectLogoutResponse(logoutResponseXml());
        const signed = signedRedirectLogoutResponse(logoutResponseXml());

        await saml.validateRedirectAsync(unsigned.container, unsigned.query);
        expect(await outcome(saml.validateRedirectAsync(signed.container, signed.query))).to.equal(
          "accepted",
        );
      });
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

  describe("Redirect-binding logout responses without InResponseTo", function () {
    let request: { container: Record<string, string>; query: string };

    beforeEach(function () {
      request = redirectLogoutResponse(logoutResponseXml({ inResponseTo: false }));
    });

    it("are rejected when validateInResponseTo is always", async () => {
      const saml = newSaml();

      expect(await outcome(saml.validateRedirectAsync(request.container, request.query))).to.equal(
        "InResponseTo is missing from response",
      );
    });

    [ValidateInResponseTo.ifPresent, ValidateInResponseTo.never].forEach((validateInResponseTo) => {
      it(`are accepted when validateInResponseTo is ${validateInResponseTo}`, async () => {
        const saml = newSaml({ validateInResponseTo });

        expect(
          await outcome(saml.validateRedirectAsync(request.container, request.query)),
        ).to.equal("accepted");
      });
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

    it("rejects a logout response when consumeAsync reports the ID already taken", async () => {
      const saml = newSaml({ cacheProvider: mapCacheProvider(async () => null) });
      await saml.getLogoutUrlAsync(user, "", {});

      expect(await outcome(saml.validatePostResponseAsync(signedPostLogoutResponse()))).to.equal(
        "InResponseTo is not valid",
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

  describe("profile.inResponseTo", function () {
    let saml: SAML;

    beforeEach(function () {
      saml = newSaml({ validateInResponseTo: ValidateInResponseTo.never });
    });

    it("is the Response's when the Response is signed", async () => {
      const response = loginResponse({
        subjectConfirmations: [{ inResponseTo: false }],
        signResponse: true,
      });

      const { profile } = await saml.validatePostResponseAsync(response);
      expect(profile).to.have.property("inResponseTo", requestId);
    });

    it("is the assertion's when the Response is unsigned", async () => {
      const response = loginResponse({ responseInResponseTo: "_unsigned" });

      const { profile } = await saml.validatePostResponseAsync(response);
      expect(profile).to.have.property("inResponseTo", requestId);
    });

    it("is a later SubjectConfirmation's when the first omits it", async () => {
      const response = loginResponse({
        responseInResponseTo: "_unsigned",
        subjectConfirmations: [{ inResponseTo: false }, { inResponseTo: true }],
      });

      const { profile } = await saml.validatePostResponseAsync(response);
      expect(profile).to.have.property("inResponseTo", requestId);
    });

    it("is absent when only an unsigned Response carries one", async () => {
      const response = loginResponse({
        responseInResponseTo: "_unsigned",
        subjectConfirmations: [{ inResponseTo: false }],
      });

      const { profile } = await saml.validatePostResponseAsync(response);
      expect(profile).to.not.have.property("inResponseTo");
    });
  });

  // The bearer confirmation window is a service provider MUST that does not depend on InResponseTo
  // (SAML profiles §4.1.4.3): https://github.com/node-saml/node-saml/issues/436
  describe("SubjectConfirmationData validity window", function () {
    [
      ValidateInResponseTo.always,
      ValidateInResponseTo.ifPresent,
      ValidateInResponseTo.never,
    ].forEach((validateInResponseTo) => {
      describe(`with validateInResponseTo set to ${validateInResponseTo}`, function () {
        let saml: SAML;

        beforeEach(async function () {
          saml = newSaml({ validateInResponseTo });
          await saml.getAuthorizeUrlAsync("", {});
        });

        // Under "always" a Response without InResponseTo is rejected before the assertion is
        // reached, so only the other modes have a confirmation window to check there.
        const responseInResponseTos =
          validateInResponseTo === ValidateInResponseTo.always ? [requestId] : [requestId, null];

        responseInResponseTos.forEach((responseInResponseTo) => {
          // An unsolicited response carries InResponseTo nowhere, neither on the Response nor on
          // the SubjectConfirmationData (SAML profiles §4.1.5).
          const inResponseTo = responseInResponseTo != null;
          const solicitation = inResponseTo ? "a solicited" : "an unsolicited";

          it(`rejects an expired confirmation on ${solicitation} response`, async () => {
            const response = loginResponse({
              responseInResponseTo,
              subjectConfirmations: [{ inResponseTo, expired: true }],
            });

            expect(await outcome(saml.validatePostResponseAsync(response))).to.equal(
              "No valid subject confirmation found among those available in the SAML assertion",
            );
          });

          it(`accepts one still within its window on ${solicitation} response`, async () => {
            const response = loginResponse({
              responseInResponseTo,
              subjectConfirmations: [{ inResponseTo }],
            });

            expect(await outcome(saml.validatePostResponseAsync(response))).to.equal("accepted");
          });
        });
      });
    });

    // An assertion carrying no SubjectConfirmation at all has no window to check; that it is
    // accepted at all is a separate gap: https://github.com/node-saml/node-saml/issues/435
    it("leaves an assertion without any SubjectConfirmation accepted", async () => {
      const saml = newSaml({ validateInResponseTo: ValidateInResponseTo.never });

      expect(
        await outcome(saml.validatePostResponseAsync(loginResponse({ subjectConfirmations: [] }))),
      ).to.equal("accepted");
    });
  });
});
