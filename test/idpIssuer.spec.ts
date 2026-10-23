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

function issuerElement(issuer: string | null): string {
  return issuer == null ? "" : `<saml:Issuer>${issuer}</saml:Issuer>`;
}

function assertion(issuer: string, { signed = true } = {}): string {
  const xml =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="${instant()}">` +
    issuerElement(issuer) +
    '<saml:Subject><saml:NameID>user</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
    "<saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction></saml:Conditions>" +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion>`;
  return signed ? sign(xml, "Assertion") : xml;
}

function response({
  issuer = "idp",
  status = success,
  content = assertion("idp"),
  signed = true,
}: {
  issuer?: string | null;
  status?: string;
  content?: string;
  signed?: boolean;
} = {}): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
    `${issuerElement(issuer)}${status}${content}</samlp:Response>`;
  return { SAMLResponse: Buffer.from(signed ? sign(xml, "Response") : xml).toString("base64") };
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
    const { profile } = await newSaml().validatePostResponseAsync(response());

    expect(profile?.issuer).to.equal("idp");
  });

  it("rejects one whose assertion is from another issuer", async () => {
    const saml = newSaml({ wantAuthnResponseSigned: false });
    const received = response({ content: assertion("another-idp"), signed: false });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose unsigned assertion, in a signed Response, is from another issuer", async () => {
    const saml = newSaml({ wantAssertionsSigned: false });
    const received = response({ content: assertion("another-idp", { signed: false }) });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose encrypted assertion is from another issuer", async () => {
    const encryptedAssertion = await encryptXml(assertion("another-idp"), {
      rsa_pub: fs.readFileSync(path.join(__dirname, "static", "testshib encryption pub.pem")),
      pem: fs.readFileSync(path.join(__dirname, "static", "testshib encryption cert.pem")),
      encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    });
    const saml = newSaml({
      wantAuthnResponseSigned: false,
      decryptionPvk: fs.readFileSync(path.join(__dirname, "static", "testshib encryption pvk.pem")),
    });
    const received = response({
      content: `<saml:EncryptedAssertion>${encryptedAssertion}</saml:EncryptedAssertion>`,
      signed: false,
    });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose signed Response is from another issuer", async () => {
    const received = response({ issuer: "another-idp" });

    expect(await outcome(newSaml().validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects a signed NoPassive response from another issuer", async () => {
    const received = response({ issuer: "another-idp", status: noPassive, content: "" });

    expect(await outcome(newSaml().validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("accepts a signed NoPassive response that names no issuer", async () => {
    const received = response({ issuer: null, status: noPassive, content: "" });

    expect(await newSaml().validatePostResponseAsync(received)).to.deep.equal({
      profile: null,
      loggedOut: false,
    });
  });
});
