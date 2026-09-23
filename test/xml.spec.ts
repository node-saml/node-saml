"use strict";
import * as xmlenc from "xml-encryption";
import * as fs from "fs";
import * as util from "util";
import * as assert from "assert";
import { expect } from "chai";
import { parseDomFromString, parseSamlXmlFragment } from "../src/xml";

export const encryptXml = util.promisify(xmlenc.encrypt);
export const decryptXml = util.promisify(xmlenc.decrypt);

describe("xml /", async function () {
  const rsa_pub = fs.readFileSync(__dirname + "/static/testshib encryption pub.pem");
  const pem = fs.readFileSync(__dirname + "/static/testshib encryption cert.pem");
  const key = fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem");

  describe("decryption /", async function () {
    it("should decrypt aes128-cbc/rsa-oaep-mgf1p", async function () {
      const encryptOptions: xmlenc.EncryptOptions = {
        rsa_pub,
        pem,
        encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      };

      const decryptOptions: xmlenc.DecryptOptions = {
        key,
        disallowDecryptionWithInsecureAlgorithm: true,
      };

      const originalPayload = "XML payload";
      const encryptedPayload = await encryptXml(originalPayload, encryptOptions);
      const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

      expect(originalPayload).to.equal(decryptedPayload);
    });

    it("should decrypt aes256-cbc/rsa-oaep-mgf1p", async function () {
      const encryptOptions: xmlenc.EncryptOptions = {
        rsa_pub,
        pem,
        encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      };

      const decryptOptions: xmlenc.DecryptOptions = {
        key,
        disallowDecryptionWithInsecureAlgorithm: true,
      };

      const originalPayload = "XML payload";
      const encryptedPayload = await encryptXml(originalPayload, encryptOptions);
      const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

      expect(originalPayload).to.equal(decryptedPayload);
    });

    it("should decrypt aes128-gcm/rsa-oaep-mgf1p", async function () {
      const encryptOptions: xmlenc.EncryptOptions = {
        rsa_pub,
        pem,
        encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      };

      const decryptOptions: xmlenc.DecryptOptions = {
        key,
        disallowDecryptionWithInsecureAlgorithm: true,
      };

      const originalPayload = "XML payload";
      const encryptedPayload = await encryptXml(originalPayload, encryptOptions);
      const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

      expect(originalPayload).to.equal(decryptedPayload);
    });

    it("should decrypt aes256-gcm/rsa-oaep-mgf1p", async function () {
      const encryptOptions: xmlenc.EncryptOptions = {
        rsa_pub,
        pem,
        encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      };

      const decryptOptions: xmlenc.DecryptOptions = {
        key,
        disallowDecryptionWithInsecureAlgorithm: true,
      };

      const originalPayload = "XML payload";
      const encryptedPayload = await encryptXml(originalPayload, encryptOptions);
      const decryptedPayload = await decryptXml(encryptedPayload, decryptOptions);

      expect(originalPayload).to.equal(decryptedPayload);
    });

    it("should not decrypt tripledes-cbc/rsa-oaep-mgf1p", async function () {
      const encryptOptions: xmlenc.EncryptOptions = {
        rsa_pub,
        pem,
        encryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        warnInsecureAlgorithm: false,
      };

      const decryptOptions: xmlenc.DecryptOptions = {
        key,
        disallowDecryptionWithInsecureAlgorithm: true,
      };

      const originalPayload = "XML payload";
      const encryptedPayload = await encryptXml(originalPayload, encryptOptions);
      const decryptedPayload = await assert.rejects(decryptXml(encryptedPayload, decryptOptions));

      expect(decryptedPayload).to.be.undefined;
    });

    it("should not decrypt aes256-gcm/rsa-1_5", async function () {
      const encryptOptions: xmlenc.EncryptOptions = {
        rsa_pub,
        pem,
        encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
        warnInsecureAlgorithm: false,
      };

      const decryptOptions: xmlenc.DecryptOptions = {
        key,
        disallowDecryptionWithInsecureAlgorithm: true,
      };

      const originalPayload = "XML payload";
      const encryptedPayload = await encryptXml(originalPayload, encryptOptions);
      const decryptedPayload = await assert.rejects(decryptXml(encryptedPayload, decryptOptions));

      expect(decryptedPayload).to.be.undefined;
    });
  });

  describe("validation /", async function () {
    it("should parse a SAML response", async function () {
      const response =
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response">' +
        "<samlp:Status/>" +
        "</samlp:Response>";

      const responseDoc = await parseDomFromString(response);

      expect(responseDoc.documentElement.localName).to.equal("Response");
      expect(responseDoc.documentElement.namespaceURI).to.equal(
        "urn:oasis:names:tc:SAML:2.0:protocol",
      );
    });

    it("should preserve inherited namespaces when parsing a decrypted fragment", async function () {
      const responseDoc = await parseDomFromString(
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
          'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
          'xmlns:custom="urn:example:custom"><saml:EncryptedAssertion/></samlp:Response>',
      );
      const encryptedAssertion = responseDoc.getElementsByTagNameNS(
        "urn:oasis:names:tc:SAML:2.0:assertion",
        "EncryptedAssertion",
      )[0];

      const fragmentDoc = await parseSamlXmlFragment(
        "<saml:Assertion><custom:Extension/></saml:Assertion>",
        encryptedAssertion,
      );

      expect(fragmentDoc.getElementsByTagNameNS("urn:example:custom", "Extension")).to.have.length(
        1,
      );
    });

    /**
     * See https://github.com/node-saml/passport-saml/issues/266
     */
    it("Should parse XML with comments correctly", async function () {
      const evilComment =
        '<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">admin@mycompany.com<!---->.evil-domain</saml2:AttributeValue></saml2:Attribute>';
      const good =
        '<saml2:Attribute xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">admin@mycompany.com</saml2:AttributeValue></saml2:Attribute>';

      const evilCommentDoc = await parseDomFromString(evilComment);
      const goodDoc = await parseDomFromString(good);

      assert.ok(
        evilCommentDoc.documentElement.firstChild?.textContent ===
          "admin@mycompany.com.evil-domain",
        "Invalid XML comment parsing.",
      );
      assert.ok(
        goodDoc.documentElement.firstChild?.textContent === "admin@mycompany.com",
        "Invalid XML comment parsing.",
      );
    });
  });
});
