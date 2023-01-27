import * as fs from "fs";
import { expect } from "chai";
import * as assert from "assert";
import {
  keyInfoToPem,
  generateUniqueId,
  stripPemHeaderAndFooter,
  normalizePemFile,
} from "../src/crypto";
import { PemLabel } from "../src/types";
import {
  TEST_CERT_SINGLELINE,
  TEST_CERT_MULTILINE,
  TEST_PUBLIC_KEY_SINGLELINE,
  TEST_PUBLIC_KEY_MULTILINE,
} from "./types";

describe("crypto.ts", function () {
  const expectedCert = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`;
  const expectedPublicKey = `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----\n`;
  const expectedPrivateKey = fs.readFileSync(`./test/static/acme_tools_com.key`).toString();

  describe("normalizePemFile", function () {
    describe("invalid values", function () {
      it("should throw with empty string", function () {
        assert.throws(() => normalizePemFile(""));
      });

      it("should throw if string clearly is not a pem file", function () {
        assert.throws(() => normalizePemFile("I'm not pem file"));
      });

      it("should throw if string is not a RFC7468 pem file", function () {
        // NOTE, no new lines
        assert.throws(() =>
          normalizePemFile(
            `-----BEGIN CERTIFICATE-----${TEST_CERT_MULTILINE}-----END CERTIFICATE-----`
          )
        );
      });
    });

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

    it("normalizes PEM which has multiple certificates", function () {
      const multipleCertificates = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`;
      const expectedMultipleCerts = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`;
      const normalizedPem = normalizePemFile(multipleCertificates);
      expect(normalizedPem).to.equal(expectedMultipleCerts);
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

    it("normalizes private key PEM which has base64 data formatted into singleline", function () {
      const privateKeyBase64Data = fs
        .readFileSync(`./test/static/singleline_acme_tools_com.key`)
        .toString();
      const privateKey = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64Data}\n-----END PRIVATE KEY-----`;
      const normalizedPem = normalizePemFile(privateKey);
      expect(normalizedPem).to.equal(expectedPrivateKey);
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
    describe("invalid values", function () {
      it("should throw with null", function () {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        assert.throws(() => keyInfoToPem(null as any));
      });

      it("should throw with false", function () {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        assert.throws(() => keyInfoToPem(false as any));
      });

      it("should throw with empty string", function () {
        assert.throws(() => keyInfoToPem(""));
      });

      it("should throw with empty Buffer", function () {
        assert.throws(() => keyInfoToPem(Buffer.from("")));
      });

      it("should throw if string is not in PEM format or not in Base64 format", function () {
        assert.throws(() => keyInfoToPem("MI"));
      });
    });

    describe("when key info is provided in PEM format", function () {
      it("should return certificate in PEM format for multiline certificate", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`,
          PemLabel.CERTIFICATE
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for singleline certificate", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`,
          PemLabel.CERTIFICATE
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return public key in PEM format for multiline pubic key", function () {
        const publicKey = keyInfoToPem(
          `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----`,
          PemLabel.PUBLIC_KEY
        );
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("should return public key in PEM format for singleline public key", function () {
        const publicKey = keyInfoToPem(
          `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_SINGLELINE}\n-----END PUBLIC KEY-----`,
          PemLabel.PUBLIC_KEY
        );
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("should return private key in PEM format for multiline private key", function () {
        const privateKeyData = fs.readFileSync(`./test/static/acme_tools_com.key`).toString();
        const privateKey = keyInfoToPem(privateKeyData, PemLabel.PRIVATE_KEY);
        expect(privateKey).to.equal(expectedPrivateKey);
      });

      it("should return private key in PEM format for singleline private key", function () {
        const privateKeyBase64Data = fs
          .readFileSync(`./test/static/singleline_acme_tools_com.key`)
          .toString();
        const privateKey = keyInfoToPem(
          `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64Data}\n-----END PRIVATE KEY-----`,
          PemLabel.PRIVATE_KEY
        );
        expect(privateKey).to.equal(expectedPrivateKey);
      });

      it("handles key info as Buffer properly", function () {
        const certificateBuffer = Buffer.from(expectedCert);
        const certificate = keyInfoToPem(certificateBuffer, PemLabel.CERTIFICATE);
        expect(certificate).to.equal(expectedCert);
      });
    });

    describe("when key info is provided in Base64 format", function () {
      it("should return certificate in PEM format for multiline Base64 certificate", function () {
        const certificate = keyInfoToPem(TEST_CERT_MULTILINE, PemLabel.CERTIFICATE);
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for singleline Base64 certificate", function () {
        const certificate = keyInfoToPem(TEST_CERT_SINGLELINE, PemLabel.CERTIFICATE);
        expect(certificate).to.equal(expectedCert);
      });

      it("should return public key in PEM format for multiline Base64 public key", function () {
        const publicKey = keyInfoToPem(TEST_PUBLIC_KEY_MULTILINE, PemLabel.PUBLIC_KEY);
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("should return public key in PEM format for singleline Base64 public key", function () {
        const publicKey = keyInfoToPem(TEST_PUBLIC_KEY_SINGLELINE, PemLabel.PUBLIC_KEY);
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("handles key info as Buffer properly", function () {
        const base64CertificateBuffer = Buffer.from(TEST_CERT_SINGLELINE);
        const certificate = keyInfoToPem(base64CertificateBuffer, PemLabel.CERTIFICATE);
        expect(certificate).to.equal(expectedCert);
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
