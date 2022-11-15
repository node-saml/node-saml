import * as fs from "fs";
import { expect } from "chai";
import * as assert from "assert";
import {
  keyInfoToPem,
  generateUniqueId,
  keyToPEM,
  stripPemHeaderAndFooter,
  normalizeBase64Data,
  normalizePemFile,
} from "../src/crypto";
import {
  TEST_CERT_SINGLELINE,
  TEST_CERT_MULTILINE,
  TEST_PUBLIC_KEY_SINGLELINE,
  TEST_PUBLIC_KEY_MULTILINE,
} from "./types";

describe("crypto.ts", function () {
  const expectedCert = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`;
  const expectedPublicKey = `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----\n`;

  describe("normalizeBase64Data", function () {
    it("normalizes singleline base64 data properly", function () {
      const normalizedData = normalizeBase64Data(TEST_CERT_SINGLELINE);
      expect(normalizedData).to.equal(TEST_CERT_MULTILINE);
    });

    it("normalizes multiline base64 data properly", function () {
      const normalizedData = normalizeBase64Data(TEST_CERT_MULTILINE);
      expect(normalizedData).to.equal(TEST_CERT_MULTILINE);
    });
  });

  describe("normalizePemFile", function () {
    it("normalizes certificate PEM which has base64 data formatted into singleline", function () {
      const certificate = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`;
      const normalizedPem = normalizePemFile(certificate);
      expect(normalizedPem).to.equal(expectedCert);
    });

    it("normalizes certificate PEM which has base64 data formatted into multiline", function () {
      const certificate = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`;
      const normalizedPem = normalizePemFile(certificate);
      expect(normalizedPem).to.equal(expectedCert);
    });

    it("normalizes public key PEM which has base64 data formatted into singleline", function () {
      const publicKey = `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_SINGLELINE}\n-----END PUBLIC KEY-----`;
      const normalizedPem = normalizePemFile(publicKey);
      expect(normalizedPem).to.equal(expectedPublicKey);
    });

    it("normalizes public key PEM which has base64 data formatted into multiline", function () {
      const publicKey = `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----`;
      const normalizedPem = normalizePemFile(publicKey);
      expect(normalizedPem).to.equal(expectedPublicKey);
    });
  });

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
    it("should generate 41 char IDs, 160 bits of entropy plus leading _", function () {
      for (let i = 0; i < 200; i++) {
        const id = generateUniqueId();
        expect(id.startsWith("_"));
        expect(id.length).to.equal(41);
      }
    });
  });

  describe("keyInfoToPem", function () {
    describe("when key info is provided in PEM format", function () {
      it("should return certificate in PEM format for multiline certificate", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for singleline certificate", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return public key in PEM format for multiline pubic key", function () {
        const publicKey = keyInfoToPem(
          `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----`,
          "PUBLIC KEY"
        );
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("should return public key in PEM format for singleline public", function () {
        const publicKey = keyInfoToPem(
          `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_SINGLELINE}\n-----END PUBLIC KEY-----`,
          "PUBLIC KEY"
        );
        expect(publicKey).to.equal(expectedPublicKey);
      });
    });

    describe("when key info is provided in Base64 format", function () {
      it("should return certificate in PEM format for multiline Base64 certificate", function () {
        const certificate = keyInfoToPem(TEST_CERT_MULTILINE);
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for singleline Base64 certificate", function () {
        const certificate = keyInfoToPem(TEST_CERT_SINGLELINE);
        expect(certificate).to.equal(expectedCert);
      });

      it("should return public key in PEM format for multiline Base64 public key", function () {
        const publicKey = keyInfoToPem(TEST_PUBLIC_KEY_MULTILINE, "PUBLIC KEY");
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("should return public key in PEM format for singleline Base64 public key", function () {
        const publicKey = keyInfoToPem(TEST_PUBLIC_KEY_SINGLELINE, "PUBLIC KEY");
        expect(publicKey).to.equal(expectedPublicKey);
      });
    });
  });

  describe("stripPemHeaderAndFooter", function () {
    it("removes PEM header and footer from singleline certificate", function () {
      const certificate = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`;
      const plainBase64Data = stripPemHeaderAndFooter(certificate);

      expect(plainBase64Data.trimEnd()).to.equal(TEST_CERT_SINGLELINE);
    });

    it("removes PEM header and footer from multiline certificate", function () {
      const certificate = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`;
      const plainBase64Data = stripPemHeaderAndFooter(certificate);

      expect(plainBase64Data.trimEnd()).to.equal(TEST_CERT_MULTILINE);
    });

    it("removes PEM header and footer from singleline public key", function () {
      const publicKey = `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_SINGLELINE}\n-----END PUBLIC KEY-----`;
      const plainBase64Data = stripPemHeaderAndFooter(publicKey);

      expect(plainBase64Data.trimEnd()).to.equal(TEST_PUBLIC_KEY_SINGLELINE);
    });

    it("removes PEM header and footer from multiline public key", function () {
      const publicKey = `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----`;
      const plainBase64Data = stripPemHeaderAndFooter(publicKey);

      expect(plainBase64Data.trimEnd()).to.equal(TEST_PUBLIC_KEY_MULTILINE);
    });
  });
});

function keyFromFile(file: string) {
  return fs.readFileSync(`./test/static/${file}`).toString();
}
