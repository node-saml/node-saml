import { SAML } from "../src/saml";
import { FAKE_CERT, SamlCheck } from "./types";
import * as zlib from "zlib";
import * as should from "should";
import { parseString } from "xml2js";

const capturedSamlRequestChecks: SamlCheck[] = [
  {
    name: "Config with Extensions",
    config: {
      entryPoint: "https://wwwexampleIdp.com/saml",
      cert: FAKE_CERT,
      samlExtensions: {
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
    },
    result: {
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
    },
  },
];

describe("SAML request", function () {
  function testForCheck(check: SamlCheck) {
    return function (done: Mocha.Done) {
      function helper(err: Error | null, samlRequest: Buffer) {
        try {
          should.not.exist(err);
          parseString(samlRequest.toString(), function (err, doc) {
            try {
              should.not.exist(err);
              delete doc["samlp:AuthnRequest"]["$"]["ID"];
              delete doc["samlp:AuthnRequest"]["$"]["IssueInstant"];
              doc.should.eql(check.result);
              done();
            } catch (err2) {
              done(err2);
            }
          });
        } catch (err3) {
          done(err3);
        }
      }
      const oSAML = new SAML(check.config);
      oSAML.getAuthorizeFormAsync("http://localhost/saml/consume").then((formBody) => {
        formBody.should.match(/<!DOCTYPE html>[^]*<input.*name="SAMLRequest"[^]*<\/html>/);
        const samlRequestMatchValues = formBody.match(/<input.*name="SAMLRequest" value="([^"]*)"/);
        const encodedSamlRequest = samlRequestMatchValues && samlRequestMatchValues[1];

        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const buffer = Buffer.from(encodedSamlRequest!, "base64");
        if (check.config.skipRequestCompression) {
          return helper(null, buffer);
        } else {
          return zlib.inflateRaw(buffer, helper);
        }
      });
    };
  }

  capturedSamlRequestChecks.forEach(function (check) {
    it(check.name, testForCheck(check));
  });
});
