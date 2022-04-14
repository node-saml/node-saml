import { SAML } from "../src/saml";
import { FAKE_CERT } from "./types";
import * as zlib from "zlib";
import { expect } from "chai";
import { parseStringPromise } from "xml2js";
import { assertRequired } from "../src/utility";
import { SamlConfig } from "../src/types";
import * as assert from "assert";

describe("SAML request", function () {
  it("Config with Extensions", function () {
    const config: SamlConfig = {
      entryPoint: "https://wwwexampleIdp.com/saml",
      cert: FAKE_CERT,
      samlAuthnRequestExtensions: {
        "md:RequestedAttribute": {
          "@isRequired": "true",
          "@Name": "Lastname",
          "@xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
        },
        vetuma: {
          "@xmlns": "urn:vetuma:SAML:2.0:extensions",
          LG: {
            "#text": "sv",
          },
        },
      },
      issuer: "onesaml_login",
    };

    const result = {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost/saml/consume",
          Destination: "https://wwwexampleIdp.com/saml",
        },
        "saml:Issuer": [
          { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
        ],
        "samlp:Extensions": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
            "md:RequestedAttribute": [
              {
                $: {
                  isRequired: "true",
                  Name: "Lastname",
                  "xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
                },
              },
            ],
            vetuma: [
              {
                $: { xmlns: "urn:vetuma:SAML:2.0:extensions" },
                LG: ["sv"],
              },
            ],
          },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    };

    const oSAML = new SAML(config);
    oSAML
      .getAuthorizeFormAsync("http://localhost/saml/consume")
      .then((formBody) => {
        expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
        const samlRequestMatchValues = formBody.match(/<input.*name="SAMLRequest" value="([^"]*)"/);
        assertRequired(samlRequestMatchValues?.[1]);
        const encodedSamlRequest = samlRequestMatchValues?.[1];

        let buffer = Buffer.from(encodedSamlRequest, "base64");
        if (!config.skipRequestCompression) {
          buffer = zlib.inflateRawSync(buffer);
        }

        return parseStringPromise(buffer.toString());
      })
      .then((doc) => {
        delete doc["samlp:AuthnRequest"]["$"]["ID"];
        delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
        expect(doc).to.equal(result);
      });
  });

  it("AllowCreate defaults to true", function () {
    const config: SamlConfig = {
      entryPoint: "https://wwwexampleIdp.com/saml",
      cert: FAKE_CERT,
      issuer: "onesaml_login",
    };

    const result = {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost/saml/consume",
          Destination: "https://wwwexampleIdp.com/saml",
        },
        "saml:Issuer": [
          { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
              AllowCreate: "true",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    };

    const oSAML = new SAML(config);
    oSAML
      .getAuthorizeFormAsync("http://localhost/saml/consume")
      .then((formBody) => {
        expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
        const samlRequestMatchValues = formBody.match(/<input.*name="SAMLRequest" value="([^"]*)"/);
        assertRequired(samlRequestMatchValues?.[1]);
        const encodedSamlRequest = samlRequestMatchValues?.[1];

        let buffer = Buffer.from(encodedSamlRequest, "base64");
        if (!config.skipRequestCompression) {
          buffer = zlib.inflateRawSync(buffer);
        }

        return parseStringPromise(buffer.toString());
      })
      .then((doc) => {
        delete doc["samlp:AuthnRequest"]["$"]["ID"];
        delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
        expect(doc).to.equal(result);
      });
  });

  it("Config with NameIDPolicy options", function () {
    const config: SamlConfig = {
      entryPoint: "https://wwwexampleIdp.com/saml",
      cert: FAKE_CERT,
      issuer: "onesaml_login",
      identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
      allowCreate: false,
      spNameQualifier: "https://exampleaffiliation.com/saml",
    };

    const result = {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost/saml/consume",
          Destination: "https://wwwexampleIdp.com/saml",
        },
        "saml:Issuer": [
          { _: "onelogin_saml", $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" } },
        ],
        "samlp:NameIDPolicy": [
          {
            $: {
              "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
              Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
              AllowCreate: "false",
              SPNameQualifier: "https://exampleaffiliation.com/saml",
            },
          },
        ],
        "samlp:RequestedAuthnContext": [
          {
            $: { "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol", Comparison: "exact" },
            "saml:AuthnContextClassRef": [
              {
                _: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                $: { "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion" },
              },
            ],
          },
        ],
      },
    };

    const oSAML = new SAML(config);
    oSAML
      .getAuthorizeFormAsync("http://localhost/saml/consume")
      .then((formBody) => {
        expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
        const samlRequestMatchValues = formBody.match(/<input.*name="SAMLRequest" value="([^"]*)"/);
        assertRequired(samlRequestMatchValues?.[1]);
        const encodedSamlRequest = samlRequestMatchValues?.[1];

        let buffer = Buffer.from(encodedSamlRequest, "base64");
        if (!config.skipRequestCompression) {
          buffer = zlib.inflateRawSync(buffer);
        }

        return parseStringPromise(buffer.toString());
      })
      .then((doc) => {
        delete doc["samlp:AuthnRequest"]["$"]["ID"];
        delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
        expect(doc).to.equal(result);
      });
  });

  it("should throw error when samlAuthnRequestExtensions is not a object", async function () {
    const config: any = {
      entryPoint: "https://wwwexampleIdp.com/saml",
      cert: FAKE_CERT,
      samlAuthnRequestExtensions: "anyvalue",
      issuer: "onesaml_login",
    };

    const oSAML = new SAML(config);
    await assert.rejects(oSAML.getAuthorizeFormAsync("http://localhost/saml/consume"), {
      message: "samlAuthnRequestExtensions should be Object",
    });
  });
});
