import { spawnSync } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { URL } from "url";
import { expect } from "chai";
import { generateServiceProviderMetadata, SAML, SignatureAlgorithm } from "../src";
import { TEST_CERT } from "./types";

const privateKey = fs.readFileSync(__dirname + "/static/key.pem", "utf-8");
const publicCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");

const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
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

describe("Signing algorithms /", function () {
  const config = {
    callbackUrl: "http://localhost/saml/consume",
    entryPoint: "https://idp.example.com/saml/sso",
    idpCert: TEST_CERT,
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

    for (const { signatureAlgorithm, digestAlgorithm, expected } of xmlSigningCases) {
      it(`signatureAlgorithm ${label(signatureAlgorithm)}, digestAlgorithm ${label(digestAlgorithm)}`, function () {
        expect(algorithmsIn(signedMetadata({ signatureAlgorithm, digestAlgorithm }))).to.deep.equal(
          expected,
        );
      });
    }
  });

  // `util.debuglog` reads NODE_DEBUG once per process and the suite order is randomized, so
  // these run in one child rather than mutating the shared environment.
  describe("signed SP metadata: warnings from the root generateServiceProviderMetadata", function () {
    let stderr: string;

    before(function () {
      this.timeout(20000);
      const script = `
        const { generateServiceProviderMetadata, SAML } = require(${JSON.stringify(path.join(__dirname, "..", "src"))});
        const base = {
          issuer: "onesaml_login",
          callbackUrl: "http://localhost/saml/consume",
          privateKey: ${JSON.stringify(privateKey)},
          publicCerts: ${JSON.stringify(publicCert)},
        };
        const signed = { ...base, signMetadata: true };
        console.error("<<digest-omitted>>");
        generateServiceProviderMetadata({ ...signed, signatureAlgorithm: "sha256" });
        console.error("<<casing-slip>>");
        generateServiceProviderMetadata({ ...signed, signatureAlgorithm: "SHA256", digestAlgorithm: "sha256" });
        console.error("<<digest-typo>>");
        generateServiceProviderMetadata({ ...signed, signatureAlgorithm: "sha256", digestAlgorithm: "sha-256" });
        console.error("<<everything-chosen>>");
        generateServiceProviderMetadata({ ...signed, signatureAlgorithm: "sha256", digestAlgorithm: "sha256" });
        console.error("<<not-signing>>");
        generateServiceProviderMetadata({ ...base, signatureAlgorithm: "SHA256" });
        console.error("<<no-private-key>>");
        generateServiceProviderMetadata({ ...signed, privateKey: undefined, publicCerts: undefined });
        console.error("<<saml-constructor>>");
        const samlObj = new SAML({
          ...signed,
          publicCerts: undefined,
          idpCert: ${JSON.stringify(TEST_CERT)},
          validateInResponseTo: "always",
          signatureAlgorithm: "SHA256",
        });
        console.error("<<saml-method>>");
        samlObj.generateServiceProviderMetadata(null, base.publicCerts);
        console.error("<<end>>");
      `;
      const child = spawnSync(
        process.execPath,
        ["--require", "ts-node/register/transpile-only", "--eval", script],
        { env: { ...process.env, NODE_DEBUG: "node-saml" }, encoding: "utf8" },
      );
      expect(child.status, `child failed:\n${child.stderr}`).to.equal(0);
      stderr = child.stderr;
    });

    // Returns only what was logged for the case named by `marker`, so one case staying silent
    // cannot be masked by another case warning.
    function warningsFor(marker: string): string {
      const section = stderr.split(`<<${marker}>>`)[1] ?? "";
      return section.split("<<")[0].trim();
    }

    it("warns that an omitted `digestAlgorithm` defaults to sha1", function () {
      const warnings = warningsFor("digest-omitted");
      expect(warnings).to.contain("`digestAlgorithm` is not set, so it defaults to `sha1`");
      expect(warnings).to.contain("requires it whenever `privateKey` is set");
      expect(warnings).not.to.contain("`signatureAlgorithm`");
    });

    it("warns that an unrecognized `signatureAlgorithm` downgrades to SHA-1", function () {
      const warnings = warningsFor("casing-slip");
      expect(warnings).to.contain('`signatureAlgorithm` is set to "SHA256"');
      expect(warnings).to.contain("SHA-1 is used instead");
      expect(warnings).not.to.contain("`digestAlgorithm`");
    });

    it("warns that an unrecognized `digestAlgorithm` downgrades to SHA-1", function () {
      const warnings = warningsFor("digest-typo");
      expect(warnings).to.contain('`digestAlgorithm` is set to "sha-256"');
      expect(warnings).not.to.contain("`signatureAlgorithm`");
    });

    it("says nothing when both are chosen explicitly", function () {
      expect(warningsFor("everything-chosen")).to.equal("");
    });

    it("says nothing when the metadata is not signed", function () {
      expect(warningsFor("not-signing")).to.equal("");
      expect(warningsFor("no-private-key")).to.equal("");
    });

    it("adds nothing through `SAML`'s method to what its constructor logged", function () {
      const fromConstructor = warningsFor("saml-constructor");
      expect(fromConstructor).to.contain('`signatureAlgorithm` is set to "SHA256"');
      expect(fromConstructor).to.contain("`digestAlgorithm` is not set");
      expect(warningsFor("saml-method")).to.equal("");
    });
  });
});
