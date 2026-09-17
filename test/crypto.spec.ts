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
        expect(() => keyInfoToPem(false as never, "CERTIFICATE")).to.throw(
          /is not a string or a Buffer/,
        );
      });

      it("should throw with a number that looks like Base64", function () {
        expect(() => keyInfoToPem(1234 as never, "CERTIFICATE")).to.throw(
          /is not a string or a Buffer/,
        );
      });

      it("should throw with true, which spells four Base64 characters", function () {
        expect(() => keyInfoToPem(true as never, "CERTIFICATE")).to.throw(
          /is not a string or a Buffer/,
        );
      });

      it("should throw with an array, naming the option", function () {
        expect(() => keyInfoToPem([] as never, "CERTIFICATE", "idpCert")).to.throw(/idpCert/);
      });

      it("should throw with empty string", function () {
        expect(() => keyInfoToPem("", "CERTIFICATE")).to.throw();
      });

      it("should throw with empty Buffer", function () {
        expect(() => keyInfoToPem(Buffer.from(""), "CERTIFICATE")).to.throw();
      });

      it("should throw if Base64 lines are separated by blanks", function () {
        const [firstLine, ...rest] = TEST_CERT_MULTILINE.split("\n");
        const spaced = [`${firstLine} `, ...rest].join("");
        expect(() => keyInfoToPem(spaced, "CERTIFICATE")).to.throw(
          /not in PEM format or in base64 format/,
        );
      });

      it("should throw with only whitespace", function () {
        expect(() => keyInfoToPem(" \t\r\n ", "CERTIFICATE")).to.throw(/is not provided/);
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

      it("should throw when the value is larger than the cap", function () {
        const oversized = "A".repeat(1024 * 1024 + 1);
        expect(() => keyInfoToPem(oversized, "CERTIFICATE")).to.throw(/is larger than/);
      });

      it("should throw when an oversized value would otherwise be valid", function () {
        const padding = `\n${TEST_CERT_MULTILINE}`.repeat(16000);
        expect(() => keyInfoToPem(`${TEST_CERT_MULTILINE}${padding}`, "CERTIFICATE")).to.throw(
          /is larger than/,
        );
      });

      it("should name the option when the value is larger than the cap", function () {
        expect(() => keyInfoToPem("A".repeat(1024 * 1024 + 1), "CERTIFICATE", "idpCert")).to.throw(
          /idpCert/,
        );
      });

      it("should reject a malformed CRLF certificate rather than accept it", function () {
        const malformed = `-----BEGIN CERTIFICATE-----\r\n${"AAAA\r\n".repeat(26)}!`;
        expect(() => keyInfoToPem(malformed, "CERTIFICATE")).to.throw(
          /not in PEM format or in base64 format/,
        );
      });

      // The shape that makes '[ \t]+$' quadratic. Asserts only the rejection:
      // linearity is settled by an analyzer, not by timing one machine.
      it("should reject a body that is one long run of blanks", function () {
        const blanks = `-----BEGIN CERTIFICATE-----\n${" ".repeat(1024 * 1024 - 100)}x\n-----END CERTIFICATE-----`;
        expect(() => keyInfoToPem(blanks, "CERTIFICATE")).to.throw(
          /not in PEM format or in base64 format/,
        );
      });

      // Unpadded so the blank line is the only thing wrong with it; mid-body
      // padding would mask a regression in the behaviour under test.
      it("should throw if the encapsulated text has a blank line between body lines", function () {
        expect(() =>
          keyInfoToPem(
            "-----BEGIN CERTIFICATE-----\nQUJD\n\nREVG\n-----END CERTIFICATE-----",
            "CERTIFICATE",
          ),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      it("should throw if the encapsulated text is empty", function () {
        expect(() =>
          keyInfoToPem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----", "CERTIFICATE"),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      it("should throw if the encapsulated text contains a space", function () {
        const spaced = TEST_CERT_MULTILINE.replace("M", "M ");
        expect(() =>
          keyInfoToPem(
            `-----BEGIN CERTIFICATE-----\n${spaced}\n-----END CERTIFICATE-----`,
            "CERTIFICATE",
          ),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      // RFC7468 section 2 ignores blanks only at the ends of lines.
      it("should throw if a line of the encapsulated text starts with a blank", function () {
        const [firstLine, ...rest] = TEST_CERT_MULTILINE.split("\n");
        const indented = [` ${firstLine}`, ...rest].join("\n");
        expect(() =>
          keyInfoToPem(
            `-----BEGIN CERTIFICATE-----\n${indented}\n-----END CERTIFICATE-----`,
            "CERTIFICATE",
          ),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      it("should throw if the encapsulated text is padded before its end", function () {
        expect(() =>
          keyInfoToPem(
            "-----BEGIN CERTIFICATE-----\nQUJD=REVG\n-----END CERTIFICATE-----",
            "CERTIFICATE",
          ),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      it("should throw if a body line other than the last one is padded", function () {
        expect(() =>
          keyInfoToPem(
            "-----BEGIN CERTIFICATE-----\nQUJDCg==\nQUJD\n-----END CERTIFICATE-----",
            "CERTIFICATE",
          ),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      it("should throw if the encapsulated text is nothing but padding", function () {
        expect(() =>
          keyInfoToPem("-----BEGIN CERTIFICATE-----\n==\n-----END CERTIFICATE-----", "CERTIFICATE"),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      // RFC4648 section 4: a multiple of four characters, two then '==', or
      // three then '='. https://www.rfc-editor.org/rfc/rfc4648#section-4
      const partialQuanta = ["A", "A=", "AA", "AAA", "AAAA=", "AAA==", "AAAAA", "AAAA=="];

      partialQuanta.forEach(function (body) {
        it(`should throw if the encapsulated text ends in the partial quantum ${body}`, function () {
          expect(() =>
            keyInfoToPem(
              `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`,
              "CERTIFICATE",
            ),
          ).to.throw(/not in PEM format or in base64 format/);
        });
      });

      // The two forms differ only in whether boundaries are present, never in
      // what data they accept between them.
      [
        ...partialQuanta,
        "QUJD=REVG",
        "AAAA=BBB=",
        "=",
        "==",
        "QUJD\n\nREVG",
        "AAAA",
        "AA==",
        "AAA=",
        "QUJDCg==",
        "AAAA\nBBBB",
        "QUJD\nRE\nVG",
        "QU\nJD",
        "QUJDCg=\n=",
      ].forEach(function (body) {
        it(`should judge ${JSON.stringify(body)} the same with and without boundaries`, function () {
          const asPem = () =>
            keyInfoToPem(
              `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`,
              "CERTIFICATE",
            );
          const asBare = () => keyInfoToPem(body, "CERTIFICATE");
          // A rejection has to be the format rejection, so that agreeing for
          // two unrelated reasons cannot pass for equivalence.
          const accepted = (run: () => string) => {
            try {
              run();
              return true;
            } catch (error) {
              expect((error as Error).message).to.match(/not in PEM format or in base64 format/);
              return false;
            }
          };
          expect(accepted(asPem)).to.equal(accepted(asBare));
        });
      });

      it("should throw if the encapsulated text is not base64", function () {
        expect(() =>
          keyInfoToPem(
            "-----BEGIN CERTIFICATE-----\nI'm not base64\n-----END CERTIFICATE-----",
            "CERTIFICATE",
          ),
        ).to.throw(/not in PEM format or in base64 format/);
      });

      it("should throw if concatenated certificates are separated by other text", function () {
        const certificate = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`;
        expect(() =>
          keyInfoToPem(`${certificate}\nBag Attributes\n${certificate}`, "CERTIFICATE"),
        ).to.throw(/not in PEM format or in base64 format/);
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

      it("normalizes PEM which has multiple certificates separated by blank lines", function () {
        const multipleCertificates = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\n${TEST_CERT_SINGLELINE}\n-----END CERTIFICATE-----`;
        const expectedMultipleCerts = `-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\n`;
        const normalizedPem = keyInfoToPem(multipleCertificates, "CERTIFICATE");
        expect(normalizedPem).to.equal(expectedMultipleCerts);
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

      it("should return certificate in PEM format for certificate with CRLF line endings", function () {
        const certificate = keyInfoToPem(expectedCert.replace(/\n/g, "\r\n"), "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for certificate with CR line endings", function () {
        const certificate = keyInfoToPem(expectedCert.replace(/\n/g, "\r"), "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for certificate read from a file with a BOM", function () {
        const certificate = keyInfoToPem(`\uFEFF${expectedCert}`, "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for certificate with an empty line after the header", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n\n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`,
          "CERTIFICATE",
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for certificate with surrounding whitespace", function () {
        const certificate = keyInfoToPem(`\n${expectedCert}\n`, "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      // RFC7468 section 3 Figure 1 permits '*WSP' before every 'eol'. Stripped
      // rather than carried through, so normalizePemFile() cannot rewrap on one.
      it("should return certificate in PEM format for certificate with trailing blanks on a body line", function () {
        const [firstLine, ...rest] = TEST_CERT_MULTILINE.split("\n");
        const padded = [`${firstLine} \t`, ...rest].join("\n");
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n${padded}\n-----END CERTIFICATE-----`,
          "CERTIFICATE",
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for certificate with blanks after the boundaries", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE----- \n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----\t `,
          "CERTIFICATE",
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for certificate with a blank line after the header", function () {
        const certificate = keyInfoToPem(
          `-----BEGIN CERTIFICATE-----\n \t \n${TEST_CERT_MULTILINE}\n-----END CERTIFICATE-----`,
          "CERTIFICATE",
        );
        expect(certificate).to.equal(expectedCert);
      });

      it("handles key info as Buffer properly", function () {
        const certificateBuffer = Buffer.from(expectedCert);
        const certificate = keyInfoToPem(certificateBuffer, "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });
    });

    describe("when key info is provided in Base64 format", function () {
      it("should return certificate in PEM format for Base64 certificate with a trailing newline", function () {
        const certificate = keyInfoToPem(`${TEST_CERT_MULTILINE}\n`, "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for Base64 certificate with CRLF line endings", function () {
        const certificate = keyInfoToPem(TEST_CERT_MULTILINE.replace(/\n/g, "\r\n"), "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for Base64 certificate with CR line endings", function () {
        const certificate = keyInfoToPem(TEST_CERT_MULTILINE.replace(/\n/g, "\r"), "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should return certificate in PEM format for Base64 certificate with surrounding whitespace", function () {
        const certificate = keyInfoToPem(` \n${TEST_CERT_SINGLELINE} \t\r\n`, "CERTIFICATE");
        expect(certificate).to.equal(expectedCert);
      });

      it("should discard whitespace around Base64 without padding", function () {
        const certificate = keyInfoToPem("QUIK \n", "CERTIFICATE");
        expect(certificate).to.equal(
          "-----BEGIN CERTIFICATE-----\nQUIK\n-----END CERTIFICATE-----\n",
        );
      });

      it("should discard whitespace around Base64 with one pad", function () {
        const certificate = keyInfoToPem("QQo= \n", "CERTIFICATE");
        expect(certificate).to.equal(
          "-----BEGIN CERTIFICATE-----\nQQo=\n-----END CERTIFICATE-----\n",
        );
      });

      it("should discard whitespace around Base64 with two pads", function () {
        const certificate = keyInfoToPem("QUJDCg== \n", "CERTIFICATE");
        expect(certificate).to.equal(
          "-----BEGIN CERTIFICATE-----\nQUJDCg==\n-----END CERTIFICATE-----\n",
        );
      });

      it("should return certificate in PEM format for Base64 wrapped off the quantum", function () {
        const wrapped = TEST_CERT_SINGLELINE.replace(/(.{30})/g, "$1\n");
        const certificate = keyInfoToPem(wrapped, "CERTIFICATE");
        // normalizePemFile() splits long lines but never joins short ones, so
        // the 30-character wrapping survives; compare data, not layout.
        expect(stripPemHeaderAndFooter(certificate).replace(/\n/g, "")).to.equal(
          TEST_CERT_SINGLELINE,
        );
      });

      // 'base64finl' in RFC7468 Figure 1 permits a pad, an 'eol', then a pad.
      it("should accept padding split across a line ending", function () {
        const certificate = keyInfoToPem("QUJDCg=\n=", "CERTIFICATE");
        expect(certificate).to.equal(
          "-----BEGIN CERTIFICATE-----\nQUJDCg=\n=\n-----END CERTIFICATE-----\n",
        );
      });

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

      it("handles key info as Buffer with a trailing newline properly", function () {
        const base64CertificateBuffer = Buffer.from(`${TEST_CERT_SINGLELINE}\n`);
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
