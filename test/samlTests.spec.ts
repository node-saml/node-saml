"use strict";
import * as sinon from "sinon";
import { URL } from "url";
import { expect } from "chai";
import * as assert from "assert";
import { SAML } from "../src/saml";
import { AuthenticateOptions, AuthorizeOptions } from "../src/passport-saml-types";
import { assertRequired } from "../src/utility";
import { FAKE_CERT, RequestWithUser } from "./types";

describe("SAML.js", function () {
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
