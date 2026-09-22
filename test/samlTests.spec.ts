"use strict";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { URL } from "url";
import { expect } from "chai";
import * as assert from "assert";
import { SAML } from "../src/saml";
import { AuthOptions, IdpCertCallback } from "../src/types";
import { assertRequired } from "../src/utility";
import { FAKE_CERT, RequestWithUser, TEST_CERT_MULTILINE } from "./types";
import { parseDomFromString, parseXml2JsFromString, validateSignature } from "../src/xml";
import type * as querystring from "querystring";

const noop = (): void => undefined;

describe("saml.ts", function () {
  it("should throw when instantiating a SAML object with a string instead of a boolean", function () {
    expect(
      () =>
        new SAML({
          passive: "false" as unknown as boolean,
          idpCert: FAKE_CERT,
          issuer: "issuer",
          callbackUrl: "callback",
        }),
    ).to.throw("value is set but not boolean");
  });

  // `util.debuglog` reads NODE_DEBUG once per process and the suite order is randomized, so
  // these run in one child rather than mutating the shared environment.
  describe("warnings on defaults the next major requires choosing", function () {
    let stderr: string;

    before(function () {
      this.timeout(20000);
      const privateKey = fs.readFileSync(path.join(__dirname, "static", "key.pem"), "utf-8");
      const script = `
        const { SAML } = require(${JSON.stringify(path.join(__dirname, "..", "src"))});
        const base = {
          issuer: "onesaml_login",
          idpCert: ${JSON.stringify(FAKE_CERT)},
          callbackUrl: "http://localhost/saml/consume",
        };
        const privateKey = ${JSON.stringify(privateKey)};
        console.error("<<says-nothing>>");
        new SAML({ ...base });
        console.error("<<signs-says-nothing>>");
        new SAML({ ...base, privateKey, validateInResponseTo: "always" });
        console.error("<<signs-digest-omitted>>");
        new SAML({ ...base, privateKey, validateInResponseTo: "always", signatureAlgorithm: "sha256" });
        console.error("<<casing-slip>>");
        new SAML({ ...base, validateInResponseTo: "always", signatureAlgorithm: "SHA256" });
        console.error("<<digest-typo>>");
        new SAML({
          ...base,
          validateInResponseTo: "always",
          signatureAlgorithm: "sha256",
          digestAlgorithm: "sha-256",
        });
        console.error("<<everything-chosen>>");
        new SAML({
          ...base,
          privateKey,
          validateInResponseTo: "always",
          signatureAlgorithm: "sha256",
          digestAlgorithm: "sha256",
        });
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

    // Returns only what was logged while constructing the case named by `marker`, so one case
    // staying silent cannot be masked by another case warning.
    function warningsFor(marker: string): string {
      const section = stderr.split(`<<${marker}>>`)[1] ?? "";
      return section.split("<<")[0].trim();
    }

    it("warns that `validateInResponseTo` defaults to never validating", function () {
      const warnings = warningsFor("says-nothing");
      expect(warnings).to.contain("`validateInResponseTo` is not set");
      expect(warnings).to.contain("replayed");
      expect(warnings).to.contain("The next major version requires it");
    });

    it("does not warn about signing algorithms when nothing is signed", function () {
      const warnings = warningsFor("says-nothing");
      expect(warnings).not.to.contain("`signatureAlgorithm` is not set");
      expect(warnings).not.to.contain("`digestAlgorithm` is not set");
    });

    it("warns that `signatureAlgorithm` and `digestAlgorithm` default to sha1 when signing", function () {
      const warnings = warningsFor("signs-says-nothing");
      expect(warnings).to.contain("`signatureAlgorithm` is not set, so it defaults to `sha1`");
      expect(warnings).to.contain("`digestAlgorithm` is not set, so it defaults to `sha1`");
      expect(warnings).to.contain("requires it whenever `privateKey` is set");
    });

    it("warns about an omitted `digestAlgorithm` when only `signatureAlgorithm` is chosen", function () {
      const warnings = warningsFor("signs-digest-omitted");
      expect(warnings).to.contain("`digestAlgorithm` is not set");
      expect(warnings).not.to.contain("`signatureAlgorithm`");
    });

    // "SHA256" is accepted today and signs with SHA-1, which is the whole reason this warns.
    it("warns that an unrecognized `signatureAlgorithm` downgrades to SHA-1", function () {
      const warnings = warningsFor("casing-slip");
      expect(warnings).to.contain('`signatureAlgorithm` is set to "SHA256"');
      expect(warnings).to.contain("SHA-1 is used instead");
      expect(warnings).to.contain("sha1, sha256, sha512");
    });

    it("warns that an unrecognized `digestAlgorithm` downgrades to SHA-1", function () {
      expect(warningsFor("digest-typo")).to.contain('`digestAlgorithm` is set to "sha-256"');
    });

    it("says nothing when every one of them is chosen explicitly", function () {
      expect(warningsFor("everything-chosen")).to.equal("");
    });
  });

  describe("resolveAndParseKeyInfosToPem", function () {
    let getKeyInfosAsPemSpy: sinon.SinonSpy;

    beforeEach(function () {
      getKeyInfosAsPemSpy = sinon.spy(SAML.prototype, "getKeyInfosAsPem" as never);
      sinon
        .stub(SAML.prototype, "processValidlySignedPostRequestAsync" as unknown as keyof SAML)
        .resolves(null);
    });

    afterEach(function () {
      sinon.restore();
    });

    async function testResolveAndParseKeyInfosPemAsync(
      idpCert: string | string[] | IdpCertCallback,
    ): Promise<string[]> {
      const samlObj = new SAML({
        callbackUrl: "http://localhost/saml/consume",
        idpCert,
        issuer: "onesaml_login",
        audience: false,
      });

      await samlObj.validatePostRequestAsync(
        { SAMLRequest: "" },
        {
          _parseDomFromString: (() => {
            return { documentElement: null };
          }) as unknown as typeof parseDomFromString,
          _parseXml2JsFromString: noop as unknown as typeof parseXml2JsFromString,
          _validateSignature: (() => true) as unknown as typeof validateSignature,
        },
      );

      const pendingResult = getKeyInfosAsPemSpy.returnValues[0];
      const result = await pendingResult;

      return result as string[];
    }

    it("returns PEM files correctly if 'cert' is PEM formatted certificate", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();
      const pemFiles = await testResolveAndParseKeyInfosPemAsync(certificate);

      expect(pemFiles.length).to.equal(1);
      expect(pemFiles[0]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is Base64 formatted certificate", async () => {
      const pemFiles = await testResolveAndParseKeyInfosPemAsync(TEST_CERT_MULTILINE);

      expect(pemFiles.length).to.equal(1);
      expect(pemFiles[0]).to.equal(
        `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`,
      );
    });

    it("returns PEM files correctly if 'cert' is Array of PEM formatted certificates", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();
      const pemFiles = await testResolveAndParseKeyInfosPemAsync([certificate, certificate]);

      expect(pemFiles.length).to.equal(2);
      expect(pemFiles[0]).to.equal(certificate);
      expect(pemFiles[1]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is Array of PEM formatted certificate and public key", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();
      const publicKey = fs.readFileSync("./test/static/pub.pem").toString();
      const pemFiles = await testResolveAndParseKeyInfosPemAsync([publicKey, certificate]);

      expect(pemFiles.length).to.equal(2);
      expect(pemFiles[0]).to.equal(publicKey);
      expect(pemFiles[1]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is a callback which returns a PEM formatted certificate", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();

      const cert: IdpCertCallback = (cb) => {
        setTimeout(() => {
          cb(null, certificate);
        }, 0);
      };
      const pemFiles = await testResolveAndParseKeyInfosPemAsync(cert);

      expect(pemFiles.length).to.equal(1);
      expect(pemFiles[0]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is a callback which returns Array of PEM formatted certificates", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();

      const cert: IdpCertCallback = (cb) => {
        setTimeout(() => {
          cb(null, [certificate, certificate]);
        }, 0);
      };
      const pemFiles = await testResolveAndParseKeyInfosPemAsync(cert);

      expect(pemFiles.length).to.equal(2);
      expect(pemFiles[0]).to.equal(certificate);
      expect(pemFiles[1]).to.equal(certificate);
    });

    it("will fail if 'cert' is a callback which returns invalid value", async () => {
      const cert: IdpCertCallback = (cb) => {
        setTimeout(() => {
          cb(null, null as never);
        }, 0);
      };

      assert.rejects(testResolveAndParseKeyInfosPemAsync(cert), "callback didn't return cert");
    });
  });

  describe("SAML protected getKeyInfosAsPem", function () {
    const publicKey = fs.readFileSync(__dirname + "/static/pub.pem", "ascii");
    const samlResponseBody = {
      SAMLResponse: fs.readFileSync(
        __dirname + "/static/signatures/valid/response.root-signed.assertion-signed.xml",
        "base64",
      ),
    };
    let fakeClock: sinon.SinonFakeTimers;

    const triggerGetKeyInfosAsPemFunctionCall = async (samlObj: SAML): Promise<void> =>
      assert.doesNotReject(samlObj.validatePostResponseAsync(samlResponseBody));

    beforeEach(() => {
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(() => {
      fakeClock.restore();
    });

    it("calls 'resolveAndParseKeyInfosToPem()' to get key infos if 'cert' is not a function", async () => {
      const samlObj = new SAML({
        callbackUrl: "http://localhost/saml/consume",
        idpCert: publicKey,
        issuer: "onesaml_login",
        audience: false,
      });

      await triggerGetKeyInfosAsPemFunctionCall(samlObj);
      expect(samlObj.pemFiles.length).to.equal(1);
    });

    it("returns cached key infos", async () => {
      const samlObj = new SAML({
        callbackUrl: "http://localhost/saml/consume",
        idpCert: publicKey,
        issuer: "onesaml_login",
        audience: false,
      });

      await triggerGetKeyInfosAsPemFunctionCall(samlObj);
      const oldPems = samlObj.pemFiles;
      await triggerGetKeyInfosAsPemFunctionCall(samlObj);

      expect(samlObj.pemFiles.length).to.equal(1);
      expect(oldPems).to.equal(samlObj.pemFiles, "pemFiles Array has different reference");
    });

    it("does not cache key infos if 'cert' is a function", async () => {
      const idpCert: IdpCertCallback = (cb) => {
        cb(null, [publicKey]);
      };
      const samlObj = new SAML({
        callbackUrl: "http://localhost/saml/consume",
        idpCert,
        issuer: "onesaml_login",
        audience: false,
      });

      const oldPems = samlObj.pemFiles;
      await triggerGetKeyInfosAsPemFunctionCall(samlObj);
      await triggerGetKeyInfosAsPemFunctionCall(samlObj);

      expect(samlObj.pemFiles.length).to.equal(0);
      expect(oldPems).to.equal(samlObj.pemFiles, "pemFiles Array has different reference");
    });
  });

  describe("get Urls", function () {
    let saml: SAML;
    let req: RequestWithUser;
    let options: AuthOptions;

    beforeEach(function () {
      saml = new SAML({
        callbackUrl: "http://localhost/saml/consume",
        entryPoint: "https://exampleidp.com/path?key=value",
        logoutUrl: "https://exampleidp.com/path?key=value",
        idpCert: FAKE_CERT,
        issuer: "onesaml_login",
        generateUniqueId: () => "uniqueId",
      });
      req = {
        protocol: "https",
        headers: {
          host: "exampleSp.com",
        },
        user: {
          nameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
          nameID: "nameID",
        },
        samlLogoutRequest: {
          ID: 123,
        },
      } as unknown as RequestWithUser;
      options = {
        additionalParams: {
          additionalKey: "additionalValue",
        },
      };
    });

    describe("getAuthorizeUrl", function () {
      it("calls callback with right host", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(new URL(target).host).to.equal("exampleidp.com");
      });

      it("calls callback with right protocol", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(new URL(target).protocol).to.equal("https:");
      });

      it("calls callback with right path", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(new URL(target).pathname).to.equal("/path");
      });

      it("calls callback with original query string", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(new URL(target).searchParams.get("key")).to.equal("value");
      });

      it("calls callback with additional run-time params in query string", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, options);
        const urlSearchParams = new URL(target).searchParams;
        expect(Array.from(urlSearchParams)).to.have.lengthOf(3);
        expect(urlSearchParams.get("key")).to.equal("value");
        expect(urlSearchParams.get("SAMLRequest")).to.not.be.empty;
        expect(urlSearchParams.get("additionalKey")).to.equal("additionalValue");
      });

      // NOTE: This test only tests existence of the assertion, not the correctness
      it("calls callback with saml request object", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(new URL(target).searchParams.get("SAMLRequest")).to.not.be.empty;
      });
    });

    // Both shapes are accepted until `host` is removed, so both are exercised here.
    describe("deprecated `host` argument", function () {
      it("applies additionalParams whether or not `host` is passed", async () => {
        const withHost = await saml.getAuthorizeUrlAsync("", req.headers.host, options);
        const withoutHost = await saml.getAuthorizeUrlAsync("", options);

        for (const target of [withHost, withoutHost]) {
          expect(new URL(target).searchParams.get("additionalKey")).to.equal("additionalValue");
        }
      });

      it("applies additionalParams when `host` is passed as undefined", async () => {
        const target = await saml.getAuthorizeUrlAsync("", undefined, options);
        expect(new URL(target).searchParams.get("additionalKey")).to.equal("additionalValue");
      });

      it("treats a lone options argument as options on getAuthorizeMessageAsync", async () => {
        const message = await saml.getAuthorizeMessageAsync("", options);
        expect(message.additionalKey).to.equal("additionalValue");
      });

      it("treats a lone options argument as options on getAuthorizeFormAsync", async () => {
        const form = await saml.getAuthorizeFormAsync("", options);
        expect(form).to.contain('name="additionalKey"');
        expect(form).to.contain('value="additionalValue"');
      });

      // Dispatch is the half the emitted-type test cannot see.
      it("calls a subclass override with the arguments it received, not normalized ones", async () => {
        const received: Array<[string, string | undefined, AuthOptions | undefined]> = [];

        class RecordingSaml extends SAML {
          async getAuthorizeMessageAsync(
            RelayState: string,
            host?: string,
            options?: AuthOptions,
          ): Promise<querystring.ParsedUrlQueryInput> {
            received.push([RelayState, host, options]);
            return super.getAuthorizeMessageAsync(RelayState, host, options);
          }
        }

        const subclass = new RecordingSaml({
          callbackUrl: "http://localhost/saml/consume",
          entryPoint: "https://exampleidp.com/path?key=value",
          idpCert: FAKE_CERT,
          issuer: "onesaml_login",
        });

        const form = await subclass.getAuthorizeFormAsync("rs", "host.example", options);

        expect(received).to.have.lengthOf(1);
        expect(received[0][0]).to.equal("rs");
        expect(received[0][1]).to.equal("host.example");
        expect(received[0][2]).to.equal(options);
        expect(form).to.contain('name="additionalKey"');
      });

      // The other direction: a migrated caller against an override that has not migrated.
      it("hands a two-argument call straight to an unmigrated override", async () => {
        const received: Array<[string, unknown, unknown]> = [];

        class RecordingSaml extends SAML {
          async getAuthorizeMessageAsync(
            RelayState: string,
            host?: string,
            options?: AuthOptions,
          ): Promise<querystring.ParsedUrlQueryInput> {
            received.push([RelayState, host, options]);
            return super.getAuthorizeMessageAsync(RelayState, host, options);
          }
        }

        const subclass = new RecordingSaml({
          callbackUrl: "http://localhost/saml/consume",
          entryPoint: "https://exampleidp.com/path?key=value",
          idpCert: FAKE_CERT,
          issuer: "onesaml_login",
        });

        const form = await subclass.getAuthorizeFormAsync("rs", options);

        expect(received).to.have.lengthOf(1);
        // The base class resolves by shape afterwards, so the form is still correct.
        expect(received[0][1]).to.equal(options);
        expect(received[0][2]).to.be.undefined;
        expect(form).to.contain('name="additionalKey"');
      });

      // `util.debuglog` reads NODE_DEBUG once per process and the suite order is randomized,
      // so this runs in a child rather than mutating the shared environment.
      it("warns for the calls that pass `host`, and not at all otherwise", function () {
        this.timeout(20000);
        const script = `
          const { SAML } = require(${JSON.stringify(path.join(__dirname, "..", "src"))});
          const saml = new SAML({
            callbackUrl: "http://localhost/saml/consume",
            issuer: "onesaml_login",
            idpCert: ${JSON.stringify(FAKE_CERT)},
            entryPoint: "https://exampleidp.com/path?key=value",
          });
          (async () => {
            await saml.getAuthorizeUrlAsync("", "a.example.com", {});
            await saml.getAuthorizeFormAsync("", "a.example.com", {});
            await saml.getAuthorizeUrlAsync("", {});
            await saml.getAuthorizeFormAsync("", {});
          })();
        `;
        const { stderr } = spawnSync(
          process.execPath,
          ["--require", "ts-node/register/transpile-only", "--eval", script],
          { env: { ...process.env, NODE_DEBUG: "node-saml" }, encoding: "utf8" },
        );

        expect(stderr).to.contain("getAuthorizeUrlAsync was called with a `host` argument");
        expect(stderr).to.contain("getAuthorizeFormAsync was called with a `host` argument");
        // `getAuthorizeFormAsync` forwards unchanged, so a call passing `host` warns twice.
        expect(stderr).to.contain("getAuthorizeMessageAsync was called with a `host` argument");
        // Three in total, so neither of the two-argument calls warned.
        expect(stderr.match(/was called with a `host` argument/g)).to.have.lengthOf(3);
      });
    });

    describe("getLogoutUrl", function () {
      it("calls callback with right host", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(new URL(target).host).to.equal("exampleidp.com");
      });

      it("calls callback with right protocol", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(new URL(target).protocol).to.equal("https:");
        expect(new URL(target).protocol).to.equal("https:");
      });

      it("calls callback with right path", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(new URL(target).pathname).to.equal("/path");
      });

      it("calls callback with original query string", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(new URL(target).searchParams.get("key")).to.equal("value");
      });

      it("calls callback with additional run-time params in query string", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", options);
        const urlSearchParams = new URL(target).searchParams;
        expect(Array.from(urlSearchParams)).to.have.lengthOf(3);
        expect(urlSearchParams.get("key")).to.equal("value");
        expect(urlSearchParams.get("SAMLRequest")).to.not.be.empty;
        expect(urlSearchParams.get("additionalKey")).to.equal("additionalValue");
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it("calls callback with saml request object", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(new URL(target).searchParams.get("SAMLRequest")).to.not.be.empty;
      });
    });

    describe("getLogoutResponseUrl", function () {
      it("calls callback with right host", function (done) {
        saml.getLogoutResponseUrl(req.samlLogoutRequest, "", {}, true, function (err, target) {
          expect(err).to.not.exist;
          try {
            assertRequired(target);
            const parsed = new URL(target);
            expect(parsed.host).to.equal("exampleidp.com");
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });

      it("calls callback with right protocol", function (done) {
        saml.getLogoutResponseUrl(req.samlLogoutRequest, "", {}, true, function (err, target) {
          expect(err).to.not.exist;
          try {
            assertRequired(target);
            const parsed = new URL(target);
            expect(parsed.protocol).to.equal("https:");
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });

      it("calls callback with right path", function (done) {
        saml.getLogoutResponseUrl(req.samlLogoutRequest, "", {}, true, function (err, target) {
          expect(err).to.not.exist;
          try {
            assertRequired(target);
            const parsed = new URL(target);
            expect(parsed.pathname).to.equal("/path");
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });

      it("calls callback with original query string", function (done) {
        saml.getLogoutResponseUrl(req.samlLogoutRequest, "", {}, true, function (err, target) {
          expect(err).to.not.exist;
          try {
            assertRequired(target);
            const parsed = new URL(target);
            expect(parsed.searchParams.get("key")).to.equal("value");
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });

      it("calls callback with additional run-time params in query string", function (done) {
        saml.getLogoutResponseUrl(req.samlLogoutRequest, "", options, true, function (err, target) {
          expect(err).to.not.exist;
          try {
            assertRequired(target);
            const parsed = new URL(target);
            expect(parsed.searchParams.get("key")).to.equal("value");
            expect(parsed.searchParams.get("SAMLResponse")).to.exist;
            expect(parsed.searchParams.get("additionalKey")).to.equal("additionalValue");
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });

      // NOTE: This test only tests existence of the assertion, not the correctness
      it("calls callback with saml response object", function (done) {
        saml.getLogoutResponseUrl(req.samlLogoutRequest, "", {}, true, function (err, target) {
          expect(err).to.not.exist;
          try {
            assertRequired(target);
            const parsed = new URL(target);
            expect(parsed.searchParams.get("SAMLResponse")).to.not.be.empty;
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });

    describe("getLogoutResponseUrlAsync", function () {
      let fakeClock: sinon.SinonFakeTimers;

      beforeEach(function () {
        fakeClock = sinon.useFakeTimers({
          now: Date.parse("2020-09-25T16:59:00Z"),
          toFake: ["Date"],
        });
      });

      afterEach(function () {
        fakeClock.restore();
      });

      it("resolves with the same target as getLogoutResponseUrl", function (done) {
        saml.getLogoutResponseUrl(
          req.samlLogoutRequest,
          "",
          {},
          true,
          async function (err, cbTarget) {
            try {
              const asyncTarget = await saml.getLogoutResponseUrlAsync(
                req.samlLogoutRequest,
                "",
                {},
                true,
              );
              assertRequired(cbTarget);
              assertRequired(asyncTarget);
              expect(asyncTarget).to.equal(cbTarget);
              done();
            } catch (err2) {
              done(err2);
            }
          },
        );
      });
    });
    describe("initialize", function () {
      it("should throw a error when SamlOptions is not set", function () {
        expect(() => {
          const samlObj = new SAML({
            callbackUrl: "http://localhost/saml/consume",
            idpCert: FAKE_CERT,
            issuer: "onesaml_login",
            audience: false,
          });
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          samlObj.initialize(undefined as any);
        }).to.throw("SamlOptions required on construction");
      });
    });
  });
});
