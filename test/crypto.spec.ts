import * as fs from "fs";
import { expect } from "chai";
import * as assert from "assert";
import { certToPEM, generateUniqueId, keyToPEM } from "../src/crypto";
import { TEST_CERT } from "./types";
import { assertRequired } from "../src/utility";

describe("crypto.ts", function () {
  describe("keyToPEM", function () {
    const [regular, singleline] = ["acme_tools_com.key", "singleline_acme_tools_com.key"].map(
      keyFromFile
    );

    it("should format singleline keys properly", function () {
      const result = keyToPEM(singleline);
      expect(result).to.equal(regular);
    });

    it("should pass all other multiline keys", function () {
      const result = keyToPEM(regular);
      expect(result).to.equal(regular);
    });

    it("should fail with falsy", function () {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      assert.throws(() => keyToPEM(null as any));
    });

    it("should do nothing to non strings", function () {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = keyToPEM(1 as any);
      expect(result).to.equal(1);
    });
  });

  describe("generateUniqueID", function () {
    it("should generate 21 char IDs", function () {
      for (let i = 0; i < 200; i++) {
        expect(generateUniqueId().length).to.equal(21);
      }
    });
  });

  describe("certToPEM", function () {
    it("should generate valid certificate", function () {
      const cert = "-----BEGIN CERTIFICATE-----" + TEST_CERT + "-----END CERTIFICATE-----";
      const certificate = certToPEM(cert.toString());
      const certificateBegin = certificate.match(/BEGIN/g);
      const certificateEnd = certificate.match(/END/g);
      assertRequired(certificateBegin, "certificate does not have a BEGIN block");
      assertRequired(certificateEnd, "certificate does not have an END block");

      if (!(certificateBegin.length == 1 && certificateEnd.length == 1)) {
        throw Error("Certificate should have only 1 BEGIN and 1 END block");
      }
    });
  });
});

function keyFromFile(file: string) {
  return fs.readFileSync(`./test/static/${file}`).toString();
}
