import * as fs from "fs";
import * as path from "path";
import { expect } from "chai";
import { SAML, ValidateInResponseTo } from "../src";
import { signXml } from "../src/xml";

const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
const idpCert = fs.readFileSync(path.join(__dirname, "static", "cert.pem"), "utf-8");
const callbackUrl = "http://localhost/saml/consume";
const namespaces =
  'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const success =
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';
const bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const holderOfKey = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

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

function confirmation(
  method: string,
  data = `NotOnOrAfter="${instant(300000)}" Recipient="${callbackUrl}"`,
): string {
  return `<saml:SubjectConfirmation Method="${method}"><saml:SubjectConfirmationData ${data}/></saml:SubjectConfirmation>`;
}

function signedResponse(confirmations: string[]): Record<string, string> {
  const xml =
    `<samlp:Response ${namespaces} ID="_response" Version="2.0" IssueInstant="${instant()}" Destination="${callbackUrl}">` +
    `<saml:Issuer>idp</saml:Issuer>${success}` +
    `<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="${instant()}"><saml:Issuer>idp</saml:Issuer>` +
    `<saml:Subject><saml:NameID>user</saml:NameID>${confirmations.join("")}</saml:Subject>` +
    `<saml:Conditions NotBefore="${instant(-60000)}" NotOnOrAfter="${instant(300000)}"><saml:AudienceRestriction><saml:Audience>onesaml_login</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant()}"/></saml:Assertion></samlp:Response>`;
  return { SAMLResponse: Buffer.from(sign(sign(xml, "Assertion"), "Response")).toString("base64") };
}

// The next major version rejects an assertion with no timely bearer confirmation (SAML profiles
// §4.1.4.2 and §4.1.4.3); until then it is accepted and only logged.
describe("responses that only the next major version rejects", function () {
  const saml = new SAML({
    callbackUrl,
    idpCert,
    issuer: "onesaml_login",
    validateInResponseTo: ValidateInResponseTo.never,
  });

  async function nameIdOf(response: Record<string, string>): Promise<string | undefined> {
    return (await saml.validatePostResponseAsync(response)).profile?.nameID;
  }

  it("accepts a confirmation chosen before a bearer one with a malformed NotOnOrAfter", async () => {
    const malformed = confirmation(bearer, `NotOnOrAfter="not a date" Recipient="${callbackUrl}"`);

    expect(await nameIdOf(signedResponse([confirmation(holderOfKey), malformed]))).to.equal("user");
  });
});
