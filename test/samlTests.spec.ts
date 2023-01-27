"use strict";
import * as fs from "fs";
import * as sinon from "sinon";
import { URL } from "url";
import { expect } from "chai";
import * as assert from "assert";
import { SAML, resolveAndParseKeyInfosToPem } from "../src/saml";
import { CertCallback } from "../src/types";
import { AuthenticateOptions, AuthorizeOptions } from "../src/passport-saml-types";
import { assertRequired } from "../src/utility";
import { FAKE_CERT, RequestWithUser, TEST_CERT_MULTILINE } from "./types";

describe("saml.ts", function () {
  describe("resolveAndParseKeyInfosToPem", function () {
    it("returns PEM files correctly if 'cert' is PEM formated certificate", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();
      const pemFiles = await resolveAndParseKeyInfosToPem({ cert: certificate });

      expect(pemFiles.length).to.equal(1);
      expect(pemFiles[0]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is Base64 formated certificate", async () => {
      const pemFiles = await resolveAndParseKeyInfosToPem({ cert: TEST_CERT_MULTILINE });

      expect(pemFiles.length).to.equal(1);
      expect(pemFiles[0]).to.equal(
        `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`
      );
    });

    it("returns PEM files correctly if 'cert' is Array of PEM formated certificates", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();
      const pemFiles = await resolveAndParseKeyInfosToPem({ cert: [certificate, certificate] });

      expect(pemFiles.length).to.equal(2);
      expect(pemFiles[0]).to.equal(certificate);
      expect(pemFiles[1]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is Array of PEM formated certificate and public key", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();
      const publicKey = fs.readFileSync("./test/static/pub.pem").toString();
      const pemFiles = await resolveAndParseKeyInfosToPem({ cert: [publicKey, certificate] });

      expect(pemFiles.length).to.equal(2);
      expect(pemFiles[0]).to.equal(publicKey);
      expect(pemFiles[1]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is a callback which returns a PEM formated certificate", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();

      const cert: CertCallback = (cb) => {
        setTimeout(() => {
          cb(null, certificate);
        }, 50);
      };
      const pemFiles = await resolveAndParseKeyInfosToPem({ cert });

      expect(pemFiles.length).to.equal(1);
      expect(pemFiles[0]).to.equal(certificate);
    });

    it("returns PEM files correctly if 'cert' is a callback which returns Array of PEM formated certificates", async () => {
      const certificate = fs.readFileSync("./test/static/acme_tools_com.cert").toString();

      const cert: CertCallback = (cb) => {
        setTimeout(() => {
          cb(null, [certificate, certificate]);
        }, 50);
      };
      const pemFiles = await resolveAndParseKeyInfosToPem({ cert });

      expect(pemFiles.length).to.equal(2);
      expect(pemFiles[0]).to.equal(certificate);
      expect(pemFiles[1]).to.equal(certificate);
    });

    it("will fail if 'cert' is a callback which returns invalid value", async () => {
      const cert: CertCallback = (cb) => {
        setTimeout(() => {
          cb(null, null as any);
        }, 50);
      };

      assert.rejects(resolveAndParseKeyInfosToPem({ cert }), "callback didn't return cert");
    });
  });

  describe("SAML protected getKeyInfosAsPem", function () {
    const publicKey = fs.readFileSync(__dirname + "/static/pub.pem", "ascii");
    const samlResponseBody = {
      SAMLResponse: fs.readFileSync(
        __dirname + "/static/signatures/valid/response.root-signed.assertion-signed.xml",
        "base64"
      ),
    };
    let fakeClock: sinon.SinonFakeTimers;

    const triggerGetKeyInfosAsPemFunctionCall = async (samlObj: SAML): Promise<void> =>
      assert.doesNotReject(samlObj.validatePostResponseAsync(samlResponseBody));

    beforeEach(() => {
      fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
    });

    afterEach(() => {
      fakeClock.restore();
    });

    it("calls 'resolveAndParseKeyInfosToPem()' to get key infos if 'cert' is not a function", async () => {
      const samlObj = new SAML({
        cert: publicKey,
        issuer: "onesaml_login",
        audience: false,
      });

      await triggerGetKeyInfosAsPemFunctionCall(samlObj);
      expect(samlObj.pemFiles.length).to.equal(1);
    });

    it("returns cached key infos", async () => {
      const samlObj = new SAML({
        cert: publicKey,
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
      const cert: CertCallback = (cb) => {
        cb(null, [publicKey]);
      };
      const samlObj = new SAML({
        cert,
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
    let options: AuthenticateOptions & AuthorizeOptions;

    beforeEach(function () {
      saml = new SAML({
        entryPoint: "https://exampleidp.com/path?key=value",
        logoutUrl: "https://exampleidp.com/path?key=value",
        cert: FAKE_CERT,
        issuer: "onesaml_login",
        generateUniqueId: () => "uniqueId",
      });
      req = {
        protocol: "https",
        headers: {
          host: "examplesp.com",
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
            assert.strictEqual(parsed.host, "exampleidp.com");
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
            assert.strictEqual(parsed.protocol, "https:");
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
            assert.strictEqual(parsed.pathname, "/path");
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
            assert.strictEqual(parsed.searchParams.get("key"), "value");
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
            assert.strictEqual(parsed.searchParams.get("key"), "value");
            expect(parsed.searchParams.get("SAMLResponse")).to.exist;
            assert.strictEqual(parsed.searchParams.get("additionalKey"), "additionalValue");
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
        fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
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
                true
              );
              assertRequired(cbTarget);
              assertRequired(asyncTarget);
              assert.strictEqual(asyncTarget, cbTarget);
              done();
            } catch (err2) {
              done(err2);
            }
          }
        );
      });
    });
  });
});
