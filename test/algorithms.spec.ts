import * as crypto from "crypto";
import * as fs from "fs";
import { URL } from "url";
import { expect } from "chai";
import { generateServiceProviderMetadata, SAML, SignatureAlgorithm } from "../src";
import { FAKE_CERT } from "./types";

const privateKey = fs.readFileSync(__dirname + "/static/key.pem", "utf-8");
const publicCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");

const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

// An unrecognized name ("SHA256", "sha-256") signs with SHA-1 instead of throwing. Making it throw
// is breaking, so the rows that use one should change only in a major.
const UNRECOGNIZED = "SHA256" as SignatureAlgorithm;

const label = (value: string | undefined) => (value === undefined ? "omitted" : `"${value}"`);

const algorithmsIn = (signedXml: string) => ({
  signature: /SignatureMethod Algorithm="([^"]+)"/.exec(signedXml)?.[1],
  digest: /DigestMethod Algorithm="([^"]+)"/.exec(signedXml)?.[1],
});

const xmlSigningCases: Array<{
  signatureAlgorithm: SignatureAlgorithm;
  digestAlgorithm: string;
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
    signatureAlgorithm: UNRECOGNIZED,
    digestAlgorithm: "sha256",
    expected: { signature: RSA_SHA1, digest: SHA256 },
  },
  {
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha-256",
    expected: { signature: RSA_SHA256, digest: SHA1 },
  },
];

describe("Signing algorithms /", function () {
  const config = {
    callbackUrl: "http://localhost/saml/consume",
    entryPoint: "https://idp.example.com/saml/sso",
    idpCert: FAKE_CERT,
    issuer: "onesaml_login",
    privateKey,
  };

  describe("HTTP-Redirect: SigAlg, and the hash the Signature verifies under", function () {
    const cases: Array<{ signatureAlgorithm?: SignatureAlgorithm; sigAlg: string; hash: string }> =
      [
        { signatureAlgorithm: undefined, sigAlg: RSA_SHA1, hash: "sha1" },
        { signatureAlgorithm: "sha1", sigAlg: RSA_SHA1, hash: "sha1" },
        { signatureAlgorithm: "sha256", sigAlg: RSA_SHA256, hash: "sha256" },
        { signatureAlgorithm: "sha512", sigAlg: RSA_SHA512, hash: "sha512" },
        { signatureAlgorithm: UNRECOGNIZED, sigAlg: RSA_SHA1, hash: "sha1" },
      ];

    for (const { signatureAlgorithm, sigAlg, hash } of cases) {
      it(`signatureAlgorithm ${label(signatureAlgorithm)} => ${hash}`, async () => {
        const url = new URL(
          await new SAML({ ...config, signatureAlgorithm }).getAuthorizeUrlAsync("", undefined, {}),
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
            publicCert,
            Buffer.from(url.searchParams.get("Signature") ?? "", "base64"),
          ),
        ).to.equal(true);
      });
    }
  });

  describe("HTTP-POST AuthnRequest: SignatureMethod and DigestMethod", function () {
    const signedRequest = async (options: {
      signatureAlgorithm?: SignatureAlgorithm;
      digestAlgorithm?: string;
    }) => {
      const { SAMLRequest } = await new SAML({
        ...config,
        skipRequestCompression: true,
        ...options,
      }).getAuthorizeMessageAsync("", undefined, {});
      return Buffer.from(SAMLRequest as string, "base64").toString("utf-8");
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

    for (const { signatureAlgorithm, digestAlgorithm, expected } of xmlSigningCases) {
      it(`signatureAlgorithm ${label(signatureAlgorithm)}, digestAlgorithm ${label(digestAlgorithm)}`, function () {
        expect(algorithmsIn(signedMetadata({ signatureAlgorithm, digestAlgorithm }))).to.deep.equal(
          expected,
        );
      });
    }
  });
});
