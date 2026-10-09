import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import { URL } from "url";
import * as zlib from "zlib";
import { expect } from "chai";
import { generateServiceProviderMetadata, SAML, SignatureAlgorithm } from "../src";
import { TEST_CERT } from "./types";

const privateKey = fs.readFileSync(__dirname + "/static/key.pem", "utf-8");
const publicCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");

const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
// RSASSA-PSS, RFC 9231 2.3.10: https://www.rfc-editor.org/rfc/rfc9231#section-2.3.10
const RSA_SHA256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
const pss = {
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
};
const SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

// An omitted option (#422) or an unrecognized name such as "SHA256" or "sha-256" (#423) falls back
// to SHA-1 instead of throwing. Making either an error is breaking, so the rows that use one should
// change only in a major.
const UNRECOGNIZED = "SHA256" as SignatureAlgorithm;

const label = (value: string | undefined) => (value === undefined ? "omitted" : `"${value}"`);

const algorithmsIn = (signedXml: string) => ({
  signature: /SignatureMethod Algorithm="([^"]+)"/.exec(signedXml)?.[1],
  digest: /DigestMethod Algorithm="([^"]+)"/.exec(signedXml)?.[1],
});

const xmlSigningCases: Array<{
  signatureAlgorithm: SignatureAlgorithm;
  digestAlgorithm?: string;
  expected: { signature: string; digest: string };
}> = [
  {
    signatureAlgorithm: "sha1",
    digestAlgorithm: "sha1",
    expected: { signature: RSA_SHA1, digest: SHA1 },
  },
  {
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha256",
    expected: { signature: RSA_SHA256, digest: SHA256 },
  },
  {
    signatureAlgorithm: "sha512",
    digestAlgorithm: "sha512",
    expected: { signature: RSA_SHA512, digest: SHA512 },
  },
  {
    signatureAlgorithm: "sha256-mgf1",
    digestAlgorithm: "sha256",
    expected: { signature: RSA_SHA256_MGF1, digest: SHA256 },
  },
  {
    signatureAlgorithm: UNRECOGNIZED,
    digestAlgorithm: "sha256",
    expected: { signature: RSA_SHA1, digest: SHA256 },
  },
  {
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha-256",
    expected: { signature: RSA_SHA256, digest: SHA1 },
  },
  {
    signatureAlgorithm: "sha256",
    digestAlgorithm: undefined,
    expected: { signature: RSA_SHA256, digest: SHA1 },
  },
];

// "sha256-mgf1" has no caller to break, so it does not get the SHA-1 fallback the rows above pin.
const pssDigestErrors: Array<{ digestAlgorithm?: string; message: string }> = [
  {
    digestAlgorithm: undefined,
    message: 'digestAlgorithm is required when signatureAlgorithm is "sha256-mgf1"',
  },
  {
    digestAlgorithm: "sha-256",
    message: 'digestAlgorithm "sha-256" is not recognized; use one of sha1, sha256, sha512',
  },
];

describe("Signing algorithms /", function () {
  const config = {
    callbackUrl: "http://localhost/saml/consume",
    entryPoint: "https://idp.example.com/saml/sso",
    idpCert: TEST_CERT,
    issuer: "onesaml_login",
    privateKey,
  };

  describe("HTTP-Redirect: SigAlg, and the hash the Signature verifies under", function () {
    const cases: Array<{
      signatureAlgorithm?: SignatureAlgorithm;
      digestAlgorithm?: string;
      sigAlg: string;
      hash: string;
      padding?: typeof pss;
    }> = [
      { signatureAlgorithm: undefined, sigAlg: RSA_SHA1, hash: "sha1" },
      { signatureAlgorithm: "sha1", sigAlg: RSA_SHA1, hash: "sha1" },
      { signatureAlgorithm: "sha256", sigAlg: RSA_SHA256, hash: "sha256" },
      {
        signatureAlgorithm: "sha256-mgf1",
        digestAlgorithm: "sha256",
        sigAlg: RSA_SHA256_MGF1,
        hash: "sha256",
        padding: pss,
      },
      { signatureAlgorithm: "sha512", sigAlg: RSA_SHA512, hash: "sha512" },
      { signatureAlgorithm: UNRECOGNIZED, sigAlg: RSA_SHA1, hash: "sha1" },
    ];

    for (const { signatureAlgorithm, digestAlgorithm, sigAlg, hash, padding } of cases) {
      it(`signatureAlgorithm ${label(signatureAlgorithm)} => ${hash}${padding ? " under RSASSA-PSS" : ""}`, async () => {
        const url = new URL(
          await new SAML({ ...config, signatureAlgorithm, digestAlgorithm }).getAuthorizeUrlAsync(
            "",
            undefined,
            {},
          ),
        );
        // SAML bindings 3.4.4.1: the signature covers the other parameters as they appear in the URL.
        const signedOctets = url.search
          .slice(1)
          .split("&")
          .filter((param) => !param.startsWith("Signature="))
          .join("&");

        expect(url.searchParams.get("SigAlg")).to.equal(sigAlg);
        expect(
          crypto.verify(
            hash,
            Buffer.from(signedOctets),
            { key: publicCert, ...padding },
            Buffer.from(url.searchParams.get("Signature") ?? "", "base64"),
          ),
        ).to.equal(true);
      });
    }

    it('signatureAlgorithm "sha256-mgf1" signs with a private key given as Base64', async () => {
      const readStatic = (name: string) => fs.readFileSync(`${__dirname}/static/${name}`, "utf-8");
      const url = new URL(
        await new SAML({
          ...config,
          privateKey: readStatic("single_line_acme_tools_com.key"),
          signatureAlgorithm: "sha256-mgf1",
          digestAlgorithm: "sha256",
        }).getAuthorizeUrlAsync("", undefined, {}),
      );
      const signedOctets = url.search
        .slice(1)
        .split("&")
        .filter((param) => !param.startsWith("Signature="))
        .join("&");

      expect(
        crypto.verify(
          "sha256",
          Buffer.from(signedOctets),
          { key: readStatic("acme_tools_com.cert"), ...pss },
          Buffer.from(url.searchParams.get("Signature") ?? "", "base64"),
        ),
      ).to.equal(true);
    });
  });

  describe("HTTP-Redirect: a receiver verifies the Signature over the query string as sent", function () {
    const signing = {
      ...config,
      logoutUrl: "https://idp.example.com/saml/slo",
      signatureAlgorithm: "sha256" as const,
    };
    const user = {
      issuer: "idp",
      nameID: "user",
      nameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    };
    // Every printable ASCII character that `querystring` and a URL's `searchParams` encode
    // differently.
    const relayState = "a b!'()~";

    // SAML bindings 3.4.4.1: the signature covers these parameters, URL-encoded as they arrived.
    const verifiesAsSent = (redirectUrl: string): boolean => {
      const url = new URL(redirectUrl);
      const sent = url.search.slice(1).split("&");
      const signedOctets = ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg"]
        .map((name) => sent.find((parameter) => parameter.startsWith(`${name}=`)))
        .filter((parameter) => parameter !== undefined)
        .join("&");
      return crypto.verify(
        "sha256",
        Buffer.from(signedOctets),
        publicCert,
        Buffer.from(url.searchParams.get("Signature") ?? "", "base64"),
      );
    };

    const messages: Array<[string, (saml: SAML) => Promise<string>]> = [
      ["a login request", (saml) => saml.getAuthorizeUrlAsync(relayState, {})],
      ["a logout request", (saml) => saml.getLogoutUrlAsync(user, relayState, {})],
      [
        "a logout response",
        (saml) => saml.getLogoutResponseUrlAsync({ ...user, ID: "_request" }, relayState, {}, true),
      ],
    ];

    for (const [message, getUrl] of messages) {
      it(`${message} whose RelayState is ${JSON.stringify(relayState)}`, async () => {
        const url = await getUrl(new SAML(signing));

        expect(new URL(url).searchParams.get("RelayState")).to.equal(relayState);
        expect(verifiesAsSent(url)).to.equal(true);
      });
    }

    for (const inAdditionalParams of ["", ["a", "b"]]) {
      it(`a RelayState given as ${JSON.stringify(inAdditionalParams)} in additionalParams`, async () => {
        const url = await new SAML(signing).getAuthorizeUrlAsync("", {
          additionalParams: { RelayState: inAdditionalParams },
        });

        expect(new URL(url).searchParams.has("RelayState")).to.equal(true);
        expect(verifiesAsSent(url)).to.equal(true);
      });
    }

    it("a RelayState that the entryPoint carries", async () => {
      const url = await new SAML({
        ...signing,
        entryPoint: `${config.entryPoint}?RelayState=fixed`,
      }).getAuthorizeUrlAsync("", {});

      expect(new URL(url).searchParams.getAll("RelayState")).to.deep.equal(["fixed"]);
      expect(verifiesAsSent(url)).to.equal(true);
    });
  });

  describe("HTTP-Redirect: verifying a message the IdP signed", function () {
    const logoutRequest =
      '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
      `ID="_logout_request" Version="2.0" IssueInstant="${new Date().toISOString()}">` +
      "<saml:Issuer>idp</saml:Issuer><saml:NameID>user</saml:NameID></samlp:LogoutRequest>";

    const redirectMessage = (sigAlg: string, sign: (octets: Buffer) => Buffer) => {
      const signed = {
        SAMLRequest: zlib.deflateRawSync(logoutRequest).toString("base64"),
        SigAlg: sigAlg,
      };
      const Signature = sign(Buffer.from(new URLSearchParams(signed).toString())).toString(
        "base64",
      );
      const container = { ...signed, Signature };
      return { container, query: new URLSearchParams(container).toString() };
    };
    const validate = ({ query }: ReturnType<typeof redirectMessage>) =>
      new SAML({ ...config, idpCert: publicCert }).validateRedirectAsync(query);

    it("accepts a signature made with RSASSA-PSS", async () => {
      const message = redirectMessage(RSA_SHA256_MGF1, (octets) =>
        crypto.sign("sha256", octets, { key: privateKey, ...pss }),
      );

      const { profile } = await validate(message);
      expect(profile?.nameID).to.equal("user");
    });

    it("rejects a PKCS #1 v1.5 signature presented under the PSS identifier", async () => {
      const message = redirectMessage(RSA_SHA256_MGF1, (octets) =>
        crypto.sign("sha256", octets, privateKey),
      );

      await assert.rejects(validate(message), { message: "Invalid query signature" });
    });

    it("rejects a PSS signature presented under the PKCS #1 v1.5 identifier", async () => {
      const message = redirectMessage(RSA_SHA256, (octets) =>
        crypto.sign("sha256", octets, { key: privateKey, ...pss }),
      );

      await assert.rejects(validate(message), { message: "Invalid query signature" });
    });

    it("rejects a PSS signature over other octets", async () => {
      const { container, query } = redirectMessage(RSA_SHA256_MGF1, (octets) =>
        crypto.sign("sha256", Buffer.concat([octets, Buffer.from("x")]), {
          key: privateKey,
          ...pss,
        }),
      );

      await assert.rejects(validate({ container, query }), { message: "Invalid query signature" });
    });

    it("accepts a PKCS #1 v1.5 signature under rsa-sha384", async () => {
      const message = redirectMessage(RSA_SHA384, (octets) =>
        crypto.sign("sha384", octets, privateKey),
      );

      const { profile } = await validate(message);
      expect(profile?.nameID).to.equal("user");
    });

    it("rejects an HMAC keyed with the IdP's certificate", async () => {
      const message = redirectMessage(HMAC_SHA1, (octets) =>
        crypto.createHmac("sha1", publicCert).update(octets).digest(),
      );

      await assert.rejects(validate(message), { message: `${HMAC_SHA1} is not supported` });
    });
  });

  describe('constructing a SAML with signatureAlgorithm "sha256-mgf1"', function () {
    for (const { digestAlgorithm, message } of pssDigestErrors) {
      it(`digestAlgorithm ${label(digestAlgorithm)} => error rather than SHA-1`, function () {
        assert.throws(
          () => new SAML({ ...config, signatureAlgorithm: "sha256-mgf1", digestAlgorithm }),
          { name: "TypeError", message },
        );
      });
    }

    it("digestAlgorithm omitted, and no privateKey to sign with => no error", function () {
      assert.doesNotThrow(
        () => new SAML({ ...config, privateKey: undefined, signatureAlgorithm: "sha256-mgf1" }),
      );
    });
  });

  describe("HTTP-POST AuthnRequest: SignatureMethod and DigestMethod", function () {
    const signedRequest = async (options: {
      signatureAlgorithm?: SignatureAlgorithm;
      digestAlgorithm?: string;
    }) => {
      const form = await new SAML({
        ...config,
        authnRequestBinding: "HTTP-POST",
        // Without it the form carries a DEFLATE-compressed request, which HTTP-POST doesn't allow (#463).
        skipRequestCompression: true,
        ...options,
      }).getAuthorizeFormAsync("", {});
      const samlRequest = /name="SAMLRequest" value="([^"]+)"/.exec(form)?.[1] ?? "";
      return Buffer.from(samlRequest, "base64").toString("utf-8");
    };

    it("both omitted => rsa-sha1 and sha1", async () => {
      expect(algorithmsIn(await signedRequest({}))).to.deep.equal({
        signature: RSA_SHA1,
        digest: SHA1,
      });
    });

    for (const { signatureAlgorithm, digestAlgorithm, expected } of xmlSigningCases) {
      it(`signatureAlgorithm ${label(signatureAlgorithm)}, digestAlgorithm ${label(digestAlgorithm)}`, async () => {
        expect(
          algorithmsIn(await signedRequest({ signatureAlgorithm, digestAlgorithm })),
        ).to.deep.equal(expected);
      });
    }
  });

  describe("signed SP metadata: SignatureMethod and DigestMethod", function () {
    const signedMetadata = (options: {
      signatureAlgorithm?: SignatureAlgorithm;
      digestAlgorithm?: string;
    }) =>
      generateServiceProviderMetadata({
        issuer: "onesaml_login",
        callbackUrl: "http://localhost/saml/consume",
        signMetadata: true,
        privateKey,
        publicCerts: publicCert,
        ...options,
      });

    it("signatureAlgorithm omitted => error rather than a default", function () {
      expect(() => signedMetadata({ digestAlgorithm: "sha256" })).to.throw(
        "signatureAlgorithm is required",
      );
    });

    for (const { digestAlgorithm, message } of pssDigestErrors) {
      it(`signatureAlgorithm "sha256-mgf1", digestAlgorithm ${label(digestAlgorithm)} => error rather than SHA-1`, function () {
        assert.throws(
          () => signedMetadata({ signatureAlgorithm: "sha256-mgf1", digestAlgorithm }),
          {
            name: "TypeError",
            message,
          },
        );
      });
    }

    for (const { signatureAlgorithm, digestAlgorithm, expected } of xmlSigningCases) {
      it(`signatureAlgorithm ${label(signatureAlgorithm)}, digestAlgorithm ${label(digestAlgorithm)}`, function () {
        expect(algorithmsIn(signedMetadata({ signatureAlgorithm, digestAlgorithm }))).to.deep.equal(
          expected,
        );
      });
    }
  });
});
