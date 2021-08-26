import * as fs from "fs";
import * as should from "should";
import assert = require("assert");
import { certToPEM, generateUniqueId, keyToPEM } from "../src/crypto";
import { TEST_CERT } from "./types";

describe("crypto.ts", function () {
  describe("keyToPEM", function () {
    const [regular, singleline] = ["acme_tools_com.key", "singleline_acme_tools_com.key"].map(
      keyFromFile
    );

    it("should format singleline keys properly", function () {
      const result = keyToPEM(singleline);
      result.should.equal(regular);
    });

    it("should pass all other multiline keys", function () {
      const result = keyToPEM(regular);
      result.should.equal(regular);
    });

    it("should fail with falsy", function () {
      assert.throws(() => keyToPEM(null as any));
    });

    it("should do nothing to non strings", function () {
      const result = keyToPEM(1 as any);
      should.equal(result, 1);
    });
  });

  describe("generateUniqueID", function () {
    it("should generate 21 char IDs", function () {
      for (let i = 0; i < 200; i++) {
        generateUniqueId().length.should.eql(21);
      }
    });
  });

  describe("certToPEM", function () {
    it("should generate valid certificate", function () {
      const samlConfig = {
        entryPoint: "https://app.onelogin.com/trust/saml2/http-post/sso/371755",
        cert: "-----BEGIN CERTIFICATE-----" + TEST_CERT + "-----END CERTIFICATE-----",
        acceptedClockSkewMs: -1,
      };
      const certificate = certToPEM(samlConfig.cert);

      if (!(certificate.match(/BEGIN/g)!.length == 1 && certificate.match(/END/g)!.length == 1)) {
        throw Error("Certificate should have only 1 BEGIN and 1 END block");
      }
    });
  });
});

function keyFromFile(file: string) {
  return fs.readFileSync(`./test/static/${file}`).toString();
}
