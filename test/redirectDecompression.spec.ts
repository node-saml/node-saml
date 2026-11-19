import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import * as zlib from "zlib";
import { SAML } from "../src/saml";
import { SamlConfig } from "../src/types";

const cert = fs.readFileSync(path.join(__dirname, "static/acme_tools_com.cert"), "utf8");
const testCert = fs.readFileSync(path.join(__dirname, "static/cert.pem"), "utf8");
const testKey = fs.readFileSync(path.join(__dirname, "static/key.pem"), "utf8");
const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "static/idp_slo_redirect.json"), "utf8"),
) as { SAMLRequest: string; originalQuery: string };
const inflatedFixture = zlib.inflateRawSync(Buffer.from(fixture.SAMLRequest, "base64"));

function makeSaml(options: Partial<SamlConfig> = {}): SAML {
  return new SAML({
    callbackUrl: "http://localhost/saml/consume",
    issuer: "onesaml_login",
    idpCert: cert,
    idpIssuer: "http://localhost:20000/saml2/idp/metadata.php",
    ...options,
  });
}

function unsignedQuery(data: Buffer): { encoded: string; query: string } {
  const encoded = zlib.deflateRawSync(data).toString("base64");
  return { encoded, query: `SAMLRequest=${encodeURIComponent(encoded)}` };
}

function signedQuery(data: Buffer): string {
  const { query } = unsignedQuery(data);
  const algorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const sigAlg = `SigAlg=${encodeURIComponent(algorithm)}`;
  const signed = `${query}&${sigAlg}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signed), testKey).toString("base64");
  return `${signed}&Signature=${encodeURIComponent(signature)}`;
}

describe("HTTP-Redirect decompression limits", function () {
  it("sets a configurable 5 MiB default and validates overrides", function () {
    assert.strictEqual(makeSaml().options.maxRedirectMessageBytes, 5 * 1024 * 1024);
    assert.strictEqual(
      makeSaml({ maxRedirectMessageBytes: 4 * 1024 * 1024 }).options.maxRedirectMessageBytes,
      4 * 1024 * 1024,
    );
    for (const maxRedirectMessageBytes of [0, -1, 1.5, Infinity, NaN]) {
      assert.throws(() => makeSaml({ maxRedirectMessageBytes }), {
        name: "TypeError",
        message: "maxRedirectMessageBytes must be a positive safe integer",
      });
    }
  });

  it("rejects invalid signatures before decoding invalid DEFLATE data", async function () {
    const query =
      "SAMLRequest=" +
      encodeURIComponent(Buffer.from("invalid DEFLATE").toString("base64")) +
      "&SigAlg=" +
      encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") +
      "&Signature=not-valid";
    await assert.rejects(makeSaml().validateRedirectAsync(query), {
      message: "Invalid query signature",
    });
  });

  it("rejects unsigned compressed messages before decompression", async function () {
    const { query } = unsignedQuery(Buffer.alloc(128 * 1024, 0x41));
    await assert.rejects(makeSaml().validateRedirectAsync(query), {
      message: "The query string has no Signature parameter",
    });
  });

  it("rejects a signed message larger than the default inflated size limit", async function () {
    const originalQuery = signedQuery(Buffer.alloc(5 * 1024 * 1024 + 1, 0x41));
    const saml = makeSaml({ idpCert: testCert });
    const errorMessage = "SAML Redirect message exceeds maxRedirectMessageBytes (5242880 bytes)";
    await assert.rejects(saml.validateRedirectAsync(originalQuery), { message: errorMessage });
  });

  it("accepts a signed message exactly at the configured inflated byte limit", async function () {
    const clock = sinon.useFakeTimers({
      now: Date.parse("2018-04-11T14:08:00Z"),
      toFake: ["Date"],
    });
    try {
      const result = await makeSaml({
        maxRedirectMessageBytes: inflatedFixture.length,
      }).validateRedirectAsync(fixture.originalQuery);
      assert.strictEqual(result.profile?.ID, "_8f0effde308adfb6ae7f1e29b414957fc320f5636f");
    } finally {
      clock.restore();
    }
  });

  it("rejects the same signed message one byte below its inflated size", async function () {
    const limit = inflatedFixture.length - 1;
    await assert.rejects(
      makeSaml({ maxRedirectMessageBytes: limit }).validateRedirectAsync(fixture.originalQuery),
      { message: `SAML Redirect message exceeds maxRedirectMessageBytes (${limit} bytes)` },
    );
  });

  it("retains the one-argument API's existing required-signature policy", async function () {
    const { query } = unsignedQuery(Buffer.from("<LogoutRequest />"));
    await assert.rejects(makeSaml().validateRedirectAsync(query), {
      message: "The query string has no Signature parameter",
    });
  });
});
