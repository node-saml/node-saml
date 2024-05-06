import * as fs from "fs";
import { expect } from "chai";
import { keyInfoToPem, generateUniqueId, stripPemHeaderAndFooter } from "../src/crypto";
import {
  TEST_CERT_SINGLELINE,
  TEST_CERT_MULTILINE,
  TEST_PUBLIC_KEY_SINGLELINE,
  TEST_PUBLIC_KEY_MULTILINE,
} from "./types";

describe("crypto.ts", function () {
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
    const expectedCert = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`;
    const expectedPublicKey = `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----\n`;
    const expectedPrivateKey = fs.readFileSync(`./test/static/acme_tools_com.key`).toString();

    describe("invalid values", function () {
      it("should throw with null", function () {
        expect(() => keyInfoToPem(null as never, "CERTIFICATE")).to.throw();
      });

      it("should throw with null with optionName in message", function () {
        expect(() => keyInfoToPem(null as never, "CERTIFICATE", "optionName")).to.throw(
          /optionName/,
        );
      });

      it("should throw with false", function () {
        expect(() => keyInfoToPem(false as never, "CERTIFICATE")).to.throw();
      });

      it("should throw with empty string", function () {
        expect(() => keyInfoToPem("", "CERTIFICATE")).to.throw();
      });

      it("should throw with empty Buffer", function () {
        expect(() => keyInfoToPem(Buffer.from(""), "CERTIFICATE")).to.throw();
      });

      it("should throw if string is not in PEM format or not in Base64 format", function () {
        expect(() => keyInfoToPem("I'm not pem file", "CERTIFICATE")).to.throw();
      });

      it("should throw if string is not in PEM format or not in Base64 format with optionName in message", function () {
        expect(() => keyInfoToPem("I'm not pem file", "CERTIFICATE", "optionName")).to.throw(
          /optionName/,
        );
      });

      it("should throw if cert is missing newlines after header and before footer", function () {
        expect(() =>
          keyInfoToPem(
            `-----BEGIN CERTIFICATE-----${TEST_CERT_MULTILINE.trim()}-----END CERTIFICATE-----`,
            "CERTIFICATE",
          ),
        ).to.throw();
      });

      it("should throw if cert is missing newline after header ", function () {
        expect(() =>
          keyInfoToPem(
            `-----BEGIN CERTIFICATE-----${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`,
            "CERTIFICATE",
          ),
        ).to.throw();
      });

      it("should throw if cert is missing newline before footer ", function () {
        expect(() =>
          keyInfoToPem(
            `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}-----END CERTIFICATE-----`,
            "CERTIFICATE",
          ),
        ).to.throw();
      });
    });

    describe("when key info is provided in PEM format", function () {
      it("should return certificate in PEM format for multiline certificate", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`,
          "CERTIFICATE",
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for singleline certificate", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`,
          "CERTIFICATE",
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return public key in PEM format for multiline pubic key", function () {
        const publicKey = keyInfoToPem(
          `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_MULTILINE}\n-----END PUBLIC KEY-----`,
          "PUBLIC KEY",
        );
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("should return public key in PEM format for singleline public key", function () {
        const publicKey = keyInfoToPem(
          `-----BEGIN PUBLIC KEY-----\n${TEST_PUBLIC_KEY_SINGLELINE}\n-----END PUBLIC KEY-----`,
          "PUBLIC KEY",
        );
        expect(publicKey).to.equal(expectedPublicKey);
      });

      it("normalizes PEM which has multiple certificates", function () {
        const multipleCertificates = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`;
        const expectedMultipleCerts = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`;
        const normalizedPem = keyInfoToPem(multipleCertificates, "CERTIFICATE");
        expect(normalizedPem).to.equal(expectedMultipleCerts);
      });

      it("should return private key in PEM format for multiline private key", function () {
        const privateKeyData = fs.readFileSync(`./test/static/acme_tools_com.key`).toString();
        const privateKey = keyInfoToPem(privateKeyData, "PRIVATE KEY");
        expect(privateKey).to.equal(expectedPrivateKey);
      });

      it("should return private key in PEM format for singleline private key", function () {
        const privateKeyBase64Data = fs
          .readFileSync(`./test/static/single_line_acme_tools_com.key`)
          .toString();
        const privateKey = keyInfoToPem(
          `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64Data}\n-----END PRIVATE KEY-----`,
          "PRIVATE KEY",
        );
        expect(privateKey).to.equal(expectedPrivateKey);
      });

      it("handles key info as Buffer properly", function () {
        const certificateBuffer = Buffer.from(expectedCert);
        const certificate = keyInfoToPem(certificateBuffer, "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });
    });

    describe("when key info is provided in Base64 format", function () {
      it("should return certificate in PEM format for multiline Base64 certificate", function () {
        const certificate = keyInfoToPem(TEST_CERT_MULTILINE, "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for singleline Base64 certificate", function () {
        const certificate = keyInfoToPem(TEST_CERT_SINGLELINE, "CERTIFICATE");
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

      it("handles key info as Buffer properly", function () {
        const base64CertificateBuffer = Buffer.from(TEST_CERT_SINGLELINE);
        const certificate = keyInfoToPem(base64CertificateBuffer, "CERTIFICATE");
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
