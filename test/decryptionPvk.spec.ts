import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as util from "util";
import * as xmlenc from "xml-encryption";
import { expect } from "chai";
import { SAML } from "../src";
import { assertRequired, signXmlResponse } from "../src/utility";

const readStatic = (name: string) => fs.readFileSync(`${__dirname}/static/${name}`, "latin1");
const encryptXml = util.promisify(xmlenc.encrypt);

const withoutBoundaries = (pem: string) => pem.replace(/-----[^-]+-----/g, "").trim();
const singleLine = (pem: string) => withoutBoundaries(pem).replace(/\s/g, "");
const asPkcs8 = (pem: string) =>
  crypto.createPrivateKey(pem).export({ type: "pkcs8", format: "pem" }).toString();

// Every form a PKCS #1 PEM key can reasonably arrive in, as a string unless noted.
const keyFormats = (pkcs1Pem: string): Record<string, string | Buffer> => ({
  "PKCS #1 PEM": pkcs1Pem,
  "PKCS #8 PEM": asPkcs8(pkcs1Pem),
  "PKCS #1 as single-line Base64": singleLine(pkcs1Pem),
  "PKCS #8 as single-line Base64": singleLine(asPkcs8(pkcs1Pem)),
  "PKCS #1 as multi-line Base64": withoutBoundaries(pkcs1Pem),
  "PKCS #1 as single-line Base64 in a Buffer": Buffer.from(singleLine(pkcs1Pem), "latin1"),
  // What `openssl pkcs12 -nocerts` writes.
  "PKCS #8 PEM with explanatory text around it": `Bag Attributes\n    localKeyID: 01 00 00 00\nKey Attributes: <No Attributes>\n${asPkcs8(pkcs1Pem)}trailing text\n`,
});

const notPrivateKeys: Record<string, [unknown, RegExp]> = {
  "a PEM certificate": [readStatic("cert.pem"), /^decryptionPvk is not a private key: /],
  "a certificate as Base64": [
    singleLine(readStatic("cert.pem")),
    /^decryptionPvk is not a private key: /,
  ],
  "neither PEM nor Base64": [
    "not a key",
    /^decryptionPvk is not in PEM format or in base64 format: /,
  ],
  "a number": [42, /^decryptionPvk is not a string or a Buffer$/],
};

describe("decryptionPvk", function () {
  describe("an encrypted NameID in a LogoutRequest", function () {
    const validate = (decryptionPvk: string | Buffer) =>
      new SAML({
        callbackUrl: "http://localhost/saml/consume",
        idpCert: readStatic("cert.pem"),
        decryptionPvk,
        issuer: "onelogin_saml",
      }).validatePostRequestAsync({
        SAMLRequest: fs.readFileSync(
          `${__dirname}/static/logout_request_with_encrypted_name_id.xml`,
          "base64",
        ),
      });

    for (const [format, decryptionPvk] of Object.entries(keyFormats(readStatic("key.pem")))) {
      it(`is decrypted with a key given as ${format}`, async function () {
        const { profile } = await validate(decryptionPvk);
        expect(profile.nameID).to.equal("ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7");
      });
    }

    for (const [kind, [decryptionPvk, message]] of Object.entries(notPrivateKeys)) {
      it(`is refused, naming decryptionPvk, when it holds ${kind}`, async function () {
        await assert.rejects(validate(decryptionPvk as string), { message });
      });
    }
  });

  describe("an encrypted assertion in a signed Response", function () {
    const nameID = "encrypted@example.com";
    let samlResponse: string;

    before(async function () {
      const assertion =
        '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="assertion0">' +
        `<saml2:Subject><saml2:NameID>${nameID}</saml2:NameID></saml2:Subject>` +
        "</saml2:Assertion>";
      const encryptedAssertion = await encryptXml(assertion, {
        rsa_pub: readStatic("testshib encryption pub.pem"),
        pem: readStatic("testshib encryption cert.pem"),
        encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      });
      const response =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response0">' +
        '<saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">' +
        encryptedAssertion +
        "</saml2:EncryptedAssertion>" +
        "</samlp:Response>";
      const signed = signXmlResponse(response, {
        privateKey: readStatic("key.pem"),
        signatureAlgorithm: "sha256",
      });
      samlResponse = Buffer.from(signed).toString("base64");
    });

    const validate = (decryptionPvk: string | Buffer) =>
      new SAML({
        callbackUrl: "http://localhost/saml/consume",
        idpCert: readStatic("cert.pem"),
        decryptionPvk,
        issuer: "onesaml_login",
        audience: false,
        wantAssertionsSigned: false,
      }).validatePostResponseAsync({ SAMLResponse: samlResponse });

    for (const [format, decryptionPvk] of Object.entries(
      keyFormats(readStatic("testshib encryption pvk.pem")),
    )) {
      it(`is decrypted with a key given as ${format}`, async function () {
        const { profile } = await validate(decryptionPvk);
        assertRequired(profile, "profile must exist");
        expect(profile.nameID).to.equal(nameID);
      });
    }

    for (const [kind, [decryptionPvk, message]] of Object.entries(notPrivateKeys)) {
      it(`is refused, naming decryptionPvk, when it holds ${kind}`, async function () {
        await assert.rejects(validate(decryptionPvk as string), { message });
      });
    }
  });
});
