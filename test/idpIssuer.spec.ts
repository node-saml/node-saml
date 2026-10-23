import * as fs from "fs";
import * as path from "path";
import * as util from "util";
import * as xmlenc from "xml-encryption";
import { expect } from "chai";
import { SAML, SamlConfig, ValidateInResponseTo } from "../src";
import { signXml } from "../src/xml";

const encryptXml = util.promisify(xmlenc.encrypt);

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const callbackUrl = "http://localhost/saml/consume";
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const success =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';
const noPassive =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">' +
  '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive"/></samlp:StatusCode></samlp:Status>';

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

function issuerElements(issuers: string[]): string {
  return issuers.map((issuer) => `<saml:Issuer>${issuer}</saml:Issuer>`).join("");
}

function assertion(issuers: string[], { signed = true } = {}): string {
  const xml =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="${instant()}">` +
    issuerElements(issuers) +
    '<saml:Subject><saml:NameID>user</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
    "<saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction></saml:Conditions>" +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion>`;
  return signed ? sign(xml, "Assertion") : xml;
}

function message({
  element = "Response",
  issuers = ["idp"],
  status = success,
  content = assertion(["idp"]),
  signed = true,
}: {
  element?: string;
  issuers?: string[];
  status?: string;
  content?: string;
  signed?: boolean;
} = {}): Record<string, string> {
  const xml =
    `<samlp:${element} ${namespaces} ID="_message" Version="2.0" IssueInstant="${instant()}">` +
    `${issuerElements(issuers)}${status}${content}</samlp:${element}>`;
  const parameter = element.endsWith("Request") ? "SAMLRequest" : "SAMLResponse";
  return { [parameter]: Buffer.from(signed ? sign(xml, element) : xml).toString("base64") };
}

function newSaml(config: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl,
    idpCert,
    issuer: "onesaml_login",
    idpIssuer: "idp",
    validateInResponseTo: ValidateInResponseTo.never,
    ...config,
  });
}

async function outcome(validation: Promise<unknown>): Promise<string> {
  return validation.then(
    () => "accepted",
    (err: Error) => err.message,
  );
}

describe("idpIssuer on a login response", function () {
  it("accepts one whose Response and assertion are from idpIssuer", async () => {
    const { profile } = await newSaml().validatePostResponseAsync(message());

    expect(profile?.issuer).to.equal("idp");
  });

  it("rejects one whose assertion is from another issuer", async () => {
    const saml = newSaml({ wantAuthnResponseSigned: false });
    const received = message({ content: assertion(["another-idp"]), signed: false });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose unsigned assertion, in a signed Response, is from another issuer", async () => {
    const saml = newSaml({ wantAssertionsSigned: false });
    const received = message({ content: assertion(["another-idp"], { signed: false }) });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose encrypted assertion is from another issuer", async () => {
    const encryptedAssertion = await encryptXml(assertion(["another-idp"]), {
      rsa_pub: fs.readFileSync(path.join(__dirname, "static", "testshib encryption pub.pem")),
      pem: fs.readFileSync(path.join(__dirname, "static", "testshib encryption cert.pem")),
      encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    });
    const saml = newSaml({
      wantAuthnResponseSigned: false,
      decryptionPvk: fs.readFileSync(path.join(__dirname, "static", "testshib encryption pvk.pem")),
    });
    const received = message({
      content: `<saml:EncryptedAssertion>${encryptedAssertion}</saml:EncryptedAssertion>`,
      signed: false,
    });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose assertion names no issuer", async () => {
    const saml = newSaml({ wantAuthnResponseSigned: false });
    const received = message({ content: assertion([]), signed: false });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal("Missing SAML issuer");
  });

  it("rejects one whose signed Response is from another issuer", async () => {
    const received = message({ issuers: ["another-idp"] });

    expect(await outcome(newSaml().validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects a signed NoPassive response from another issuer", async () => {
    const received = message({ issuers: ["another-idp"], status: noPassive, content: "" });

    expect(await outcome(newSaml().validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("accepts a signed NoPassive response that names no issuer", async () => {
    const received = message({ issuers: [], status: noPassive, content: "" });

    expect(await newSaml().validatePostResponseAsync(received)).to.deep.equal({
      profile: null,
      loggedOut: false,
    });
  });
});

describe("a message that names more than one issuer", function () {
  const twoIssuers = "Expected one SAML issuer, received 2: idp, another-idp";

  it("is rejected as an assertion with no idpIssuer set", async () => {
    const saml = newSaml({ idpIssuer: undefined, wantAuthnResponseSigned: false });
    const received = message({ content: assertion(["idp", "another-idp"]), signed: false });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(twoIssuers);
  });

  it("is rejected as a signed LogoutRequest with no idpIssuer set", async () => {
    const received = message({
      element: "LogoutRequest",
      issuers: ["idp", "another-idp"],
      status: "",
      content: "<saml:NameID>user</saml:NameID>",
    });

    expect(
      await outcome(newSaml({ idpIssuer: undefined }).validatePostRequestAsync(received)),
    ).to.equal(twoIssuers);
  });

  it("is rejected as a signed LogoutResponse with no idpIssuer set", async () => {
    const received = message({
      element: "LogoutResponse",
      issuers: ["idp", "another-idp"],
      content: "",
    });

    expect(
      await outcome(newSaml({ idpIssuer: undefined }).validatePostResponseAsync(received)),
    ).to.equal(twoIssuers);
  });

  it("is rejected as a signed Response with no idpIssuer set", async () => {
    const received = message({ issuers: ["idp", "another-idp"] });

    expect(
      await outcome(newSaml({ idpIssuer: undefined }).validatePostResponseAsync(received)),
    ).to.equal(twoIssuers);
  });
});
