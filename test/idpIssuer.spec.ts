import * as fs from "fs";
import * as path from "path";
import { expect } from "chai";
import { SAML, SamlConfig, ValidateInResponseTo } from "../src";
import { signXml } from "../src/xml";

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

function response({
  responseIssuer = "idp",
  assertionIssuer = "idp",
  signResponse = true,
}: {
  responseIssuer?: string | null;
  assertionIssuer?: string;
  signResponse?: boolean;
} = {}): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
    `${issuerElement(responseIssuer)}${success}` +
    `<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="${instant()}">${issuerElement(assertionIssuer)}` +
    '<saml:Subject><saml:NameID>user</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml:SubjectConfirmationData NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}">` +
    "<saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction></saml:Conditions>" +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion></samlp:Response>`;
  const signed = sign(xml, "Assertion");
  return {
    SAMLResponse: Buffer.from(signResponse ? sign(signed, "Response") : signed).toString("base64"),
  };
}

function noPassiveResponse(issuer: string): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}">` +
    `${issuerElement(issuer)}${noPassive}</samlp:Response>`;
  return { SAMLResponse: Buffer.from(sign(xml, "Response")).toString("base64") };
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
    const received = response({ assertionIssuer: "another-idp", signResponse: false });

    expect(await outcome(saml.validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose signed Response is from another issuer", async () => {
    const received = response({ responseIssuer: "another-idp" });

    expect(await outcome(newSaml().validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });

  it("rejects one whose signed Response names no issuer", async () => {
    const received = response({ responseIssuer: null });

    expect(await outcome(newSaml().validatePostResponseAsync(received))).to.equal(
      "Missing SAML issuer",
    );
  });

  it("rejects a NoPassive response from another issuer", async () => {
    const received = noPassiveResponse("another-idp");

    expect(await outcome(newSaml().validatePostResponseAsync(received))).to.equal(
      "Unknown SAML issuer. Expected: idp Received: another-idp",
    );
  });
});
