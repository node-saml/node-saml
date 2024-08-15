import * as fs from "fs";
import { signSamlPost, signAuthnRequestPost } from "../src/saml-post-signing.js";
import { SamlSigningOptions } from "../src/types.js";
import { parseXml2JsFromString } from "../src/xml.js";
import { expect } from "chai";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const signingKey = fs.readFileSync(__dirname + "/static/key.pem");

describe("SAML POST Signing", function () {
  it("should sign a simple saml request", async function () {
    const xml =
      '<SAMLRequest><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></SAMLRequest>';
    const result = signSamlPost(xml, "/SAMLRequest", {
      privateKey: signingKey,
      signatureAlgorithm: "sha1",
    });
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      SAMLRequest: {
        $: { Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1" } }],
                    DigestValue: [{ _: "1yis05FW/NgGxi12sn/bW3GP9co=" }],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "Oa5ST39rynnUH6XN4tnjoK2luRlKGOq4VHPAKqSgEjzEymTFQRhMwqwQTuFI+AwHSn0qd4wc7GGLIHn0BmUsk/CBZ51nvgjiyTQo+Gkc2/24QlCAwpOM35hgOEaMMvJXgzkFwxvnV/3TGA2J+jrrcQ0q2l6nSuDe27JnCCzbo1vFiHIuWG91pZnS0ZQKnJ593jG5ozo2m2a7l/KvCXIWCGs91KR43IKgmQmOIkVk4i170Ep2trlyj5651LFlT4LShDkkrf4tvWAmeC7rZgf97j58m9vTYXY7zZt5URIvmlE9SZH6NmUdrryZjfZin4Xf7FqpfK/sLzVfBCSLvCse8A==",
              },
            ],
          },
        ],
      },
    });
  });

  it("should place the Signature element after the Issuer element", async function () {
    const xml =
      '<SAMLRequest><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer><SomeOtherElement /></SAMLRequest>';
    const result = signSamlPost(xml, "/SAMLRequest", {
      privateKey: signingKey,
      signatureAlgorithm: "sha1",
    });
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      SAMLRequest: {
        $: { Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1" } }],
                    DigestValue: [{ _: "5z/cj0WrzI7UGvPSu543FzezwE4=" }],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "ggJj62O7r2KwAFyiRtQmWOGu2q1MtLFNcGGCYaeKi5/lmSwhjOqgrLLQlZnQWRIoxhkKw0OLgtT9dIeZC3+TMZtolLQ9OM0pQARz8svJuYQUd4ti71hoIRTRzgzEXbOvpyDoqXaJMeZeveidAg/DHIIATpCUwqy1soUPxiHXdweXJ8BYrNoWjFBKLULbBNmTlYEdeQqYOE3TcCuvCDYOdbQlTKRPJlC5eVz+SIRb8q6c9sHTzmFuiquFezQsroY3MEvHjO5jPQ1L3L1drVwWBeF8TNoNsHcJ8aMMMJqHzjiSDeAJZnq6G3VOisZrJVcSJWipAd383EyuhDy3Zo5PJw==",
              },
            ],
          },
        ],
        SomeOtherElement: [""],
      },
    });
  });

  it("should sign and digest with SHA256 when specified", async function () {
    const xml =
      '<SAMLRequest><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></SAMLRequest>';
    const options: SamlSigningOptions = {
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
      privateKey: signingKey,
    };
    const result = signSamlPost(xml, "/SAMLRequest", options);
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      SAMLRequest: {
        $: { Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256" } }],
                    DigestValue: [{ _: "DeVk/na+V3reUnB3kJPBXoeA12QBCaPNSr/J/1+g8X0=" }],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "N1vamg3kKL4lvk+i/ZPltfZRIvFPO4J+CpNslFCKcuOpVTtgxhbvaHEnmU1gTpfEmFHw2js8isKWbEWepsP+aOfQMFDTnlZM2X7HtuB6uKntpS6bOUnG4mx+P2stbRyhLzJIsDwHTvzZM5+L63O551afjZxYCJBwD2bsvUk1A/1N6dG9+AB6QP/x/Fl6OjZE9J/kQWVZbRyty48p3sIBkO1L0rVk7ekHj5f83JGRtyKt9nlK7ke8dX+BItPQ/CU353RRumQ6rSkv+MZVzqfGWcg6wIc4x5+euS9zA80eBrYOvIU9vjzK8Bd+Lv9ltAAtISMRrVCVWW0XgnKJ4fzZGg==",
              },
            ],
          },
        ],
      },
    });
  });

  it("should sign and digest with SHA512 when specified", async function () {
    const xml =
      '<SAMLRequest><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></SAMLRequest>';
    const options: SamlSigningOptions = {
      signatureAlgorithm: "sha512",
      digestAlgorithm: "sha512",
      privateKey: signingKey,
    };
    const result = signSamlPost(xml, "/SAMLRequest", options);
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      SAMLRequest: {
        $: { Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2001/04/xmlenc#sha512" } }],
                    DigestValue: [
                      {
                        _: "yn+OO5/n06jYFfFMCoxNBymzzuCmVjPFMjUPbc0yH6ey61fO9V7rC1U2BSwRIB1v469KidoTixmO2z38ujYmZA==",
                      },
                    ],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "wtwJoAQRa2cBE8JPBbTystBw6zArZIuhyX9HwKH6dKgWVLHE8AhTcTOeJl6EXtNneQVYRT1i7XZcWnbaTdtcEuKFEhbWod9uN4ItMswFPJTooUnl8a6AjVO6II8iN/X1+5Tkhd8L4r6oEPufd/jWnoR4TDuvkbkOm5ur0uAPlJC37B7GM6gQNwUXikHMoGp73lMJ4hi8H5gnFjrjjVPUHiT2y3S7Bf6Hw7X4u6bfbAwqMTcBbA5aiOWSfDbnwgrvwmcmYPRVQKMIZ/4UTeDs4qWLeZjr3djRzmUbkmPQh6/a+YgUsJmqTBnotdWMe1q0HxZNi3Qh9QRoqnoGiaKXpg==",
              },
            ],
          },
        ],
      },
    });
  });

  it("should sign and digest with SHA256 when specified and using privateKey", async function () {
    const xml =
      '<SAMLRequest><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></SAMLRequest>';
    const options: SamlSigningOptions = {
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
      privateKey: signingKey,
    };
    const result = signSamlPost(xml, "/SAMLRequest", options);
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      SAMLRequest: {
        $: { Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256" } }],
                    DigestValue: [{ _: "DeVk/na+V3reUnB3kJPBXoeA12QBCaPNSr/J/1+g8X0=" }],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "N1vamg3kKL4lvk+i/ZPltfZRIvFPO4J+CpNslFCKcuOpVTtgxhbvaHEnmU1gTpfEmFHw2js8isKWbEWepsP+aOfQMFDTnlZM2X7HtuB6uKntpS6bOUnG4mx+P2stbRyhLzJIsDwHTvzZM5+L63O551afjZxYCJBwD2bsvUk1A/1N6dG9+AB6QP/x/Fl6OjZE9J/kQWVZbRyty48p3sIBkO1L0rVk7ekHj5f83JGRtyKt9nlK7ke8dX+BItPQ/CU353RRumQ6rSkv+MZVzqfGWcg6wIc4x5+euS9zA80eBrYOvIU9vjzK8Bd+Lv9ltAAtISMRrVCVWW0XgnKJ4fzZGg==",
              },
            ],
          },
        ],
      },
    });
  });

  it("should sign and digest with SHA512 when specified and using privateKey", async function () {
    const xml =
      '<SAMLRequest><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></SAMLRequest>';
    const options: SamlSigningOptions = {
      signatureAlgorithm: "sha512",
      digestAlgorithm: "sha512",
      privateKey: signingKey,
    };
    const result = signSamlPost(xml, "/SAMLRequest", options);
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      SAMLRequest: {
        $: { Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2001/04/xmlenc#sha512" } }],
                    DigestValue: [
                      {
                        _: "yn+OO5/n06jYFfFMCoxNBymzzuCmVjPFMjUPbc0yH6ey61fO9V7rC1U2BSwRIB1v469KidoTixmO2z38ujYmZA==",
                      },
                    ],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "wtwJoAQRa2cBE8JPBbTystBw6zArZIuhyX9HwKH6dKgWVLHE8AhTcTOeJl6EXtNneQVYRT1i7XZcWnbaTdtcEuKFEhbWod9uN4ItMswFPJTooUnl8a6AjVO6II8iN/X1+5Tkhd8L4r6oEPufd/jWnoR4TDuvkbkOm5ur0uAPlJC37B7GM6gQNwUXikHMoGp73lMJ4hi8H5gnFjrjjVPUHiT2y3S7Bf6Hw7X4u6bfbAwqMTcBbA5aiOWSfDbnwgrvwmcmYPRVQKMIZ/4UTeDs4qWLeZjr3djRzmUbkmPQh6/a+YgUsJmqTBnotdWMe1q0HxZNi3Qh9QRoqnoGiaKXpg==",
              },
            ],
          },
        ],
      },
    });
  });

  it("should sign an AuthnRequest", async function () {
    const xml =
      '<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></AuthnRequest>';
    const result = signAuthnRequestPost(xml, {
      privateKey: signingKey,
      signatureAlgorithm: "sha1",
    });
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      AuthnRequest: {
        $: { xmlns: "urn:oasis:names:tc:SAML:2.0:protocol", Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1" } }],
                    DigestValue: [{ _: "wHDDyV7rEQ/AQLYeLgsEUXX+Zxw=" }],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "t6Vg5DrOQiwfVv1IBzhPXMwoRGdNY1lIKbvcZOXr9EeFEEaI8I8qPs9Ibl+Hj3eCC0aDVLg/Uhg9/NCygfYuQuJjFdji0/rEFve/DEgGDscCS42+0J5fM55wNyVLglly9D+hJdZChmHg5IQltFcvOsNHYxbUiPywbOSLSHHFqOfdL4bqYNO/nwhhHMRuA6VQGRSC8EGJkjF9kwuFVjF7XvXyV2aTRJgZYmUB3fzIlokUfBNg2PpvexLipOb1K14ZV0nORewOCPjulJWnd+WSJkHBY1jA/OGiJNCeokOw7XTOLrAZ9+d4/JJ7T3XthWwHrfP3gEljoNTUdQV/gBNNqA==",
              },
            ],
          },
        ],
      },
    });
  });

  it("should sign an AuthnRequest and include Signature KeyInfo", async function () {
    const xml =
      '<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></AuthnRequest>';
    const publicCert = fs.readFileSync(__dirname + "/static/cert.pem").toString();
    const result = signAuthnRequestPost(xml, {
      privateKey: signingKey,
      publicCert,
      signatureAlgorithm: "sha1",
    });
    const doc = await parseXml2JsFromString(result);
    expect(doc).to.deep.equal({
      AuthnRequest: {
        $: { xmlns: "urn:oasis:names:tc:SAML:2.0:protocol", Id: "_0" },
        Issuer: [
          {
            _: "http://example.com",
            $: { "xmlns:saml2": "urn:oasis:names:tc:SAML:2.0:assertion" },
          },
        ],
        Signature: [
          {
            $: { xmlns: "http://www.w3.org/2000/09/xmldsig#" },
            SignedInfo: [
              {
                CanonicalizationMethod: [
                  { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                ],
                SignatureMethod: [
                  { $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1" } },
                ],
                Reference: [
                  {
                    $: { URI: "#_0" },
                    Transforms: [
                      {
                        Transform: [
                          {
                            $: {
                              Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                            },
                          },
                          { $: { Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" } },
                        ],
                      },
                    ],
                    DigestMethod: [{ $: { Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1" } }],
                    DigestValue: [{ _: "wHDDyV7rEQ/AQLYeLgsEUXX+Zxw=" }],
                  },
                ],
              },
            ],
            KeyInfo: [
              {
                X509Data: [
                  {
                    X509Certificate: [
                      {
                        _: "MIIDtTCCAp2gAwIBAgIJAKg4VeVcIDz1MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTUwODEzMDE1NDIwWhcNMTUwOTEyMDE1NDIwWjBFMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG3ouM7U+fXbJt69X1H6d4UNg/uRr06pFuU9RkfIwNC+yaXyptqB3ynXKsL7BFt4DCd0fflRvJAx3feJIDp16wN9GDVHcufWMYPhh2j5HcTW/j9JoIJzGhJyvO00YKBt+hHy83iN1SdChKv5y0iSyiPP5GnqFw+ayyHoM6hSO0PqBou1Xb0ZSIE+DHosBnvVna5w2AiPY4xrJl9yZHZ4Q7DfMiYTgstjETio4bX+6oLiBnYktn7DjdEslqhffVme4PuBxNojI+uCeg/sn4QVLd/iogMJfDWNuLD8326Mi/FE9cCRvFlvAiMSaebMI3zPaySsxTK7Zgj5TpEbmbHI9wIDAQABo4GnMIGkMB0GA1UdDgQWBBSVGgvoW4MhMuzBGce29PY8vSzHFzB1BgNVHSMEbjBsgBSVGgvoW4MhMuzBGce29PY8vSzHF6FJpEcwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAKg4VeVcIDz1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJu1rqs+anD74dbdwgd3CnqnQsQDJiEXmBhG2leaGt3ve9b/9gKaJg2pyb2NyppDe1uLqh6nNXDuzg1oNZrPz5pJL/eCXPl7FhxhMUi04TtLf8LeNTCIWYZiFuO4pmhohHcv8kRvYR1+6SkLTC8j/TZerm7qvesSiTQFNapa1eNdVQ8nFwVkEtWl+JzKEM1BlRcn42sjJkijeFp7DpI7pU+PnYeiaXpRv5pJo8ogM1iFxN+SnfEs0EuQ7fhKIG9aHKi7bKZ7L6SyX7MDIGLeulEU6lf5D9BfXNmcMambiS0pXhL2QXajt96UBq8FT2KNXY8XNtR4y6MyyCzhaiZZcc8=",
                      },
                    ],
                  },
                ],
              },
            ],
            SignatureValue: [
              {
                _: "t6Vg5DrOQiwfVv1IBzhPXMwoRGdNY1lIKbvcZOXr9EeFEEaI8I8qPs9Ibl+Hj3eCC0aDVLg/Uhg9/NCygfYuQuJjFdji0/rEFve/DEgGDscCS42+0J5fM55wNyVLglly9D+hJdZChmHg5IQltFcvOsNHYxbUiPywbOSLSHHFqOfdL4bqYNO/nwhhHMRuA6VQGRSC8EGJkjF9kwuFVjF7XvXyV2aTRJgZYmUB3fzIlokUfBNg2PpvexLipOb1K14ZV0nORewOCPjulJWnd+WSJkHBY1jA/OGiJNCeokOw7XTOLrAZ9+d4/JJ7T3XthWwHrfP3gEljoNTUdQV/gBNNqA==",
              },
            ],
          },
        ],
      },
    });
  });
});
