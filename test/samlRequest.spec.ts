import * as fs from "fs";
import { SAML } from "../src/saml";
import { FAKE_CERT } from "./types";
import * as zlib from "zlib";
import { expect } from "chai";
import { parseStringPromise } from "xml2js";
import { assertRequired } from "../src/utility";
import { SamlConfig } from "../src/types";
import * as assert from "assert";
import { getVerifiedXml, parseDomFromString } from "../src/xml";

describe("SAML request", function () {
  describe("Config with Extensions", function () {
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      entryPoint: "https://wwwexampleIdp.com/saml",
      idpCert: FAKE_CERT,
      samlAuthnRequestExtensions: {
        "md:RequestedAttribute": {
          "@isRequired": "true",
          "@Name": "LastName",
          "@xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
        },
        vetuma: {
          "@xmlns": "urn:vetuma:SAML:2.0:extensions",
          LG: {
            "#text": "sv",
          },
        },
      },
      issuer: "onelogin_saml",
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
                  Name: "LastName",
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

    it("getAuthorizeMessageAsync", async function () {
      return oSAML
        .getAuthorizeMessageAsync("http://localhost/saml/consume")
        .then((samlMessage) => {
          assertRequired(samlMessage.SAMLRequest);
          const encodedSamlRequest = samlMessage.SAMLRequest as string;

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });

    it("getAuthorizeFormAsync", async function () {
      return oSAML
        .getAuthorizeFormAsync("http://localhost/saml/consume")
        .then((formBody) => {
          expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
          const samlRequestMatchValues = formBody.match(
            /<input.*name="SAMLRequest" value="([^"]*)"/,
          );
          assertRequired(samlRequestMatchValues?.[1]);
          const encodedSamlRequest = samlRequestMatchValues?.[1];

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });
  });

  describe("AllowCreate defaults to true", function () {
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      entryPoint: "https://wwwexampleIdp.com/saml",
      idpCert: FAKE_CERT,
      issuer: "onelogin_saml",
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

    it("getAuthorizeMessageAsync", async function () {
      return oSAML
        .getAuthorizeMessageAsync("http://localhost/saml/consume")
        .then((samlMessage) => {
          assertRequired(samlMessage.SAMLRequest);
          const encodedSamlRequest = samlMessage.SAMLRequest as string;

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });

    it("getAuthorizeFormAsync", async function () {
      return oSAML
        .getAuthorizeFormAsync("http://localhost/saml/consume")
        .then((formBody) => {
          expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
          const samlRequestMatchValues = formBody.match(
            /<input.*name="SAMLRequest" value="([^"]*)"/,
          );
          assertRequired(samlRequestMatchValues?.[1]);
          const encodedSamlRequest = samlRequestMatchValues?.[1];

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });
  });

  describe("Config with NameIDPolicy options", function () {
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      entryPoint: "https://wwwexampleIdp.com/saml",
      idpCert: FAKE_CERT,
      issuer: "onelogin_saml",
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

    it("getAuthorizeMessageAsync", async function () {
      return oSAML
        .getAuthorizeMessageAsync("http://localhost/saml/consume")
        .then((samlMessage) => {
          assertRequired(samlMessage.SAMLRequest);
          const encodedSamlRequest = samlMessage.SAMLRequest as string;

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });

    it("getAuthorizeFormAsync", async function () {
      return oSAML
        .getAuthorizeFormAsync("http://localhost/saml/consume")
        .then((formBody) => {
          expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
          const samlRequestMatchValues = formBody.match(
            /<input.*name="SAMLRequest" value="([^"]*)"/,
          );
          assertRequired(samlRequestMatchValues?.[1]);
          const encodedSamlRequest = samlRequestMatchValues?.[1];

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });
  });

  describe("Config with forceAuthn and passive", function () {
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      entryPoint: "https://wwwexampleIdp.com/saml",
      idpCert: FAKE_CERT,
      issuer: "onelogin_saml",
      forceAuthn: true,
      passive: true,
    };

    const result = {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          AssertionConsumerServiceURL: "http://localhost/saml/consume",
          Destination: "https://wwwexampleIdp.com/saml",
          ForceAuthn: "true",
          IsPassive: "true",
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

    it("getAuthorizeMessageAsync", async function () {
      return oSAML
        .getAuthorizeMessageAsync("http://localhost/saml/consume")
        .then((samlMessage) => {
          assertRequired(samlMessage.SAMLRequest);
          const encodedSamlRequest = samlMessage.SAMLRequest as string;

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });

    it("getAuthorizeFormAsync", async function () {
      return oSAML
        .getAuthorizeFormAsync("http://localhost/saml/consume")
        .then((formBody) => {
          expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
          const samlRequestMatchValues = formBody.match(
            /<input.*name="SAMLRequest" value="([^"]*)"/,
          );
          assertRequired(samlRequestMatchValues?.[1]);
          const encodedSamlRequest = samlRequestMatchValues?.[1];

          const decoded = Buffer.from(encodedSamlRequest, "base64");
          const inflated = zlib.inflateRawSync(decoded);

          return parseStringPromise(inflated.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });
  });

  describe("With additional run-time parameters", function () {
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      entryPoint: "https://wwwexampleIdp.com/saml",
      idpCert: FAKE_CERT,
      issuer: "onelogin_saml",
    };

    const oSAML = new SAML(config);

    it("getAuthorizeMessageAsync", async function () {
      const samlMessage = await oSAML.getAuthorizeMessageAsync(
        "http://localhost/saml/consume",
        undefined,
        { additionalParams: { foo: "bar" } },
      );

      assertRequired(samlMessage.SAMLRequest);
      expect(samlMessage.foo).to.equal("bar");
    });

    it("getAuthorizeFormAsync", async function () {
      const formBody = await oSAML.getAuthorizeFormAsync(
        "http://localhost/saml/consume",
        undefined,
        { additionalParams: { foo: "bar" } },
      );

      expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
      expect(formBody).to.match(/<input.*name="foo" value="bar"/);
    });

    it("getAuthorizeFormAsync with empty options", async function () {
      const formBody = await oSAML.getAuthorizeFormAsync(
        "http://localhost/saml/consume",
        undefined,
        {},
      );

      expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
      expect(formBody).to.not.match(/<input.*name="foo" value="bar"/);
    });
  });

  describe("Config with disableRequestedAuthnContext, skipRequestCompression, disableRequestAcsUrl", function () {
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      entryPoint: "https://wwwexampleIdp.com/saml",
      idpCert: FAKE_CERT,
      issuer: "onelogin_saml",
      disableRequestedAuthnContext: true,
      skipRequestCompression: true,
      disableRequestAcsUrl: true,
    };

    const result = {
      "samlp:AuthnRequest": {
        $: {
          "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          Version: "2.0",
          ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
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
      },
    };

    const oSAML = new SAML(config);

    it("getAuthorizeMessageAsync", async function () {
      return oSAML
        .getAuthorizeMessageAsync("http://localhost/saml/consume")
        .then((samlMessage) => {
          assertRequired(samlMessage.SAMLRequest);
          const encodedSamlRequest = samlMessage.SAMLRequest as string;
          const buffer = Buffer.from(encodedSamlRequest, "base64");

          return parseStringPromise(buffer.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });

    it("getAuthorizeFormAsync", async function () {
      return oSAML
        .getAuthorizeFormAsync("http://localhost/saml/consume")
        .then((formBody) => {
          expect(formBody).to.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
          const samlRequestMatchValues = formBody.match(
            /<input.*name="SAMLRequest" value="([^"]*)"/,
          );
          assertRequired(samlRequestMatchValues?.[1]);
          const encodedSamlRequest = samlRequestMatchValues?.[1];
          const buffer = Buffer.from(encodedSamlRequest, "base64");

          return parseStringPromise(buffer.toString("utf8"));
        })
        .then((doc) => {
          delete doc["samlp:AuthnRequest"]["$"]["ID"];
          delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
          expect(doc).to.deep.equal(result);
        });
    });
  });

  describe("should throw error when samlAuthnRequestExtensions is not a object", function () {
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      entryPoint: "https://wwwexampleIdp.com/saml",
      idpCert: FAKE_CERT,
      samlAuthnRequestExtensions: "anyValue" as unknown as Record<string, unknown>,
      issuer: "onesaml_login",
    };

    const oSAML = new SAML(config);

    it("getAuthorizeMessageAsync", async function () {
      await assert.rejects(oSAML.getAuthorizeMessageAsync("http://localhost/saml/consume"), {
        message: "samlAuthnRequestExtensions should be Object",
      });
    });

    it("getAuthorizeFormAsync", async function () {
      await assert.rejects(oSAML.getAuthorizeFormAsync("http://localhost/saml/consume"), {
        message: "samlAuthnRequestExtensions should be Object",
      });
    });
  });

  describe("signing with the HTTP-POST binding", function () {
    const readStatic = (name: string) => fs.readFileSync(`${__dirname}/static/${name}`, "utf-8");
    const privateKey = readStatic("acme_tools_com.key");
    const certificate = readStatic("acme_tools_com.cert");

    const signedRequest = async (signing: Pick<SamlConfig, "privateKey" | "publicCert">) => {
      const saml = new SAML({
        callbackUrl: "http://localhost/saml/consume",
        entryPoint: "https://idp.example.com/saml",
        issuer: "http://sp.example.com",
        idpCert: FAKE_CERT,
        authnRequestBinding: "HTTP-POST",
        skipRequestCompression: true,
        signatureAlgorithm: "sha256",
        digestAlgorithm: "sha256",
        ...signing,
      });
      const form = await saml.getAuthorizeFormAsync("");
      const encoded = form.match(/<input.*name="SAMLRequest" value="([^"]*)"/)?.[1];
      assertRequired(encoded);
      return Buffer.from(encoded, "base64").toString("utf8");
    };

    it("signs with a private key given as Base64", async function () {
      const request = await signedRequest({
        privateKey: readStatic("single_line_acme_tools_com.key"),
      });
      const dom = await parseDomFromString(request);
      assert.ok(getVerifiedXml(request, dom.documentElement, [certificate]));
    });

    it("publishes a certificate given as Base64 in KeyInfo", async function () {
      const base64 = readStatic("acme_tools_com_without_header_and_footer.cert").replace(/\s/g, "");
      const request = await signedRequest({ privateKey, publicCert: base64 });
      expect(request).to.contain(`<X509Certificate>${base64}</X509Certificate>`);
    });

    it("should throw if publicCert is neither PEM nor Base64, naming it", async function () {
      await assert.rejects(signedRequest({ privateKey, publicCert: "not a certificate" }), {
        message: /^publicCert is not in PEM format or in base64 format: /,
      });
    });

    it("should throw if publicCert is a public key rather than omit KeyInfo", async function () {
      await assert.rejects(signedRequest({ privateKey, publicCert: readStatic("pub.pem") }), {
        message: "publicCert must hold at least one certificate",
      });
    });
  });
});
