"use strict";
import * as fs from "fs";
import * as url from "url";
import { expect } from "chai";
import assert = require("assert");
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
        expect(url.parse(target).host).to.equal("exampleidp.com");
      });
      it("calls callback with right protocol", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(url.parse(target).protocol).to.equal("https:");
      });
      it("calls callback with right path", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(url.parse(target).pathname).to.equal("/path");
      });
      it("calls callback with original query string", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(url.parse(target, true).query["key"]).to.equal("value");
      });
      it("calls callback with additional run-time params in query string", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, options);
        expect(Object.keys(url.parse(target, true).query)).to.have.lengthOf(3);
        expect(url.parse(target, true).query["key"]).to.equal("value");
        expect(url.parse(target, true).query["SAMLRequest"]).to.not.be.empty;
        expect(url.parse(target, true).query["additionalKey"]).to.equal("additionalValue");
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it("calls callback with saml request object", async () => {
        const target = await saml.getAuthorizeUrlAsync("", req.headers.host, {});
        expect(url.parse(target, true).query).have.property("SAMLRequest");
      });
    });

    describe("getLogoutUrl", function () {
      it("calls callback with right host", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(url.parse(target).host).to.equal("exampleidp.com");
      });
      it("calls callback with right protocol", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(url.parse(target).protocol).to.equal("https:");
        expect(url.parse(target).protocol).to.equal("https:");
      });
      it("calls callback with right path", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(url.parse(target).pathname).to.equal("/path");
      });
      it("calls callback with original query string", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(url.parse(target, true).query["key"]).to.equal("value");
      });
      it("calls callback with additional run-time params in query string", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", options);
        expect(Object.keys(url.parse(target, true).query)).to.have.lengthOf(3);
        expect(url.parse(target, true).query["key"]).to.equal("value");
        expect(url.parse(target, true).query["SAMLRequest"]).to.not.be.empty;
        expect(url.parse(target, true).query["additionalKey"]).to.equal("additionalValue");
      });
      // NOTE: This test only tests existence of the assertion, not the correctness
      it("calls callback with saml request object", async () => {
        assertRequired(req.user);
        const target = await saml.getLogoutUrlAsync(req.user, "", {});
        expect(url.parse(target, true).query).have.property("SAMLRequest");
      });
    });

    describe("getLogoutResponseUrl", function () {
      it("calls callback with right host", function (done) {
        saml.getLogoutResponseUrl(req.samlLogoutRequest, "", {}, true, function (err, target) {
          expect(err).to.not.exist;
          try {
            assertRequired(target);
            const parsed = url.parse(target);
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
            const parsed = url.parse(target);
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
            const parsed = url.parse(target);
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
            const parsed = url.parse(target, true);
            assert.strictEqual(parsed.query["key"], "value");
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
            const parsed = url.parse(target, true);
            assert.strictEqual(parsed.query["key"], "value");
            expect(parsed.query["SAMLResponse"]).to.exist;
            assert.strictEqual(parsed.query["additionalKey"], "additionalValue");
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
            const parsed = url.parse(target, true);
            expect(parsed.query).have.property("SAMLResponse");
            done();
          } catch (err2) {
            done(err2);
          }
        });
      });
    });
  });
});
