import { SAML } from "../src";
import * as fs from "fs";
import * as sinon from "sinon";
import { SamlConfig } from "../src/types";
import * as xml from "../src/xml";
import * as assert from "assert";
import { expect } from "chai";

const cert = fs.readFileSync(__dirname + "/static/cert.pem", "ascii");

describe("Signatures", function () {
  const INVALID_SIGNATURE = "Invalid signature";
  const INVALID_DOCUMENT_SIGNATURE = "Invalid document signature";
  const INVALID_ENCRYPTED_SIGNATURE = "Invalid signature from encrypted assertion";
  const INVALID_TOO_MANY_TRANSFORMS = "Invalid signature, too many transforms";
  const XMLDOM_ERROR =
    "[xmldom error]\telement parse error: Error: Hierarchy request error: Only one element can be added and only after doctype\n@#[line:57,col:1]";

  const createBody = (pathToXml: string) => ({
    SAMLResponse: fs.readFileSync(__dirname + "/static/signatures" + pathToXml, "base64"),
  });

  const testOneResponseBody = async (
    samlResponseBody: Record<string, string>,
    shouldErrorWith: string | false | undefined,
    amountOfSignatureChecks = 1,
    options: Partial<SamlConfig> = {}
  ) => {
    //== Instantiate new instance before every test
    const samlObj = new SAML({
      cert,
      issuer: options.issuer ?? "onesaml_login",
      audience: false,
      ...options,
    });

    //== Spy on `validateSignature` to be able to count how many times it has been called
    const validateSignatureSpy = sinon.spy(xml, "validateSignature");

    try {
      //== Run the test in `func`
      if (shouldErrorWith === false) {
        await assert.doesNotReject(samlObj.validatePostResponseAsync(samlResponseBody));
      } else {
        await assert.rejects(samlObj.validatePostResponseAsync(samlResponseBody), {
          message: shouldErrorWith,
        });
      }
      //== Assert times `validateSignature` was called
      expect(validateSignatureSpy.callCount).to.equal(amountOfSignatureChecks);
    } finally {
      validateSignatureSpy.restore();
    }
  };

  const testOneResponse = (
    pathToXml: string,
    shouldErrorWith: string | false,
    amountOfSignaturesChecks: number | undefined,
    options?: Partial<SamlConfig>
  ) => {
    //== Create a body based on an XML and run the test
    return async () =>
      await testOneResponseBody(
        createBody(pathToXml),
        shouldErrorWith,
        amountOfSignaturesChecks,
        options
      );
  };

  describe("Signatures - multiple roots are considered invalid", () => {
    it(
      "multiple roots => invalid",
      testOneResponse("/invalid/response.root-signed.multiple-root-elements.xml", XMLDOM_ERROR, 0)
    );
  });

  describe("Signatures on saml:Response - Only 1 saml:Assertion", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
    });

    afterEach(function () {
      fakeClock.restore();
    });

    //== VALID
    it(
      "R1A - both signed => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.xml", false, 2)
    );
    const publicKey = fs.readFileSync(__dirname + "/static/pub.pem", "ascii");
    it(
      "R1A - both signed, verify using public key => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.xml", false, 2, {
        cert: publicKey,
      })
    );
    it(
      "R1A - root signed => valid",
      testOneResponse("/valid/response.root-signed.assertion-unsigned.xml", false, 1, {
        wantAssertionsSigned: false,
      })
    );
    it(
      "R1A - asrt signed => valid",
      testOneResponse("/valid/response.root-unsigned.assertion-signed.xml", false, 2, {
        wantAuthnResponseSigned: false,
      })
    );
    it(
      "R1A - asrt signed, neither wanted => valid",
      testOneResponse("/valid/response.root-unsigned.assertion-signed.xml", false, 2, {
        wantAuthnResponseSigned: false,
        wantAssertionsSigned: false,
      })
    );

    //== INVALID
    it(
      "R1A - root not signed, but required, asrt signed => error",
      testOneResponse(
        "/valid/response.root-unsigned.assertion-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A - none signed => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A - none signed, none wanted => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.xml",
        INVALID_SIGNATURE,
        2,
        {
          wantAuthnResponseSigned: false,
          wantAssertionsSigned: false,
        }
      )
    );
    it(
      "R1A - both signed => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A - root signed => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A - asrt signed => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A - root signed - wantAssertionsSigned=true => error",
      testOneResponse("/valid/response.root-signed.assertion-unsigned.xml", INVALID_SIGNATURE, 2)
    );
    it(
      "R1A - root signed - asrt unsigned encrypted -wantAssertionsSigned=true => error",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned-encrypted.xml",
        INVALID_ENCRYPTED_SIGNATURE,
        2,
        {
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
        }
      )
    );
    it(
      "R1A - root signed - asrt invalidly signed wantAssertionsSigned=true => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-invalidly-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A - root signed - asrt invalidly signed encrypted wantAssertionsSigned=true => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-invalidly-signed-encrypted.xml",
        INVALID_ENCRYPTED_SIGNATURE,
        2,
        {
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
        }
      )
    );
    it(
      "R1A - root signed but with too many transforms => early error",
      testOneResponse(
        "/invalid/response.root-signed-transforms.assertion-unsigned.xml",
        INVALID_TOO_MANY_TRANSFORMS,
        1
      )
    );
    it(
      "R1A - root unsigned, asrt signed but with too many transforms => early error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed-transforms.xml",
        INVALID_TOO_MANY_TRANSFORMS,
        2,
        {
          wantAuthnResponseSigned: false,
        }
      )
    );
  });

  describe("Signatures on saml:Response - 1 saml:Assertion + 1 saml:Advice containing 1 saml:Assertion", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
    });

    afterEach(function () {
      fakeClock.restore();
    });

    //== VALID
    it(
      "R1A1Ad - signed root+asrt+advi => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.1advice-signed.xml", false, 2)
    );
    it(
      "R1A1Ad - signed root+asrt => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.1advice-unsigned.xml", false, 2)
    );
    it(
      "R1A1Ad - signed asrt+advi => valid",
      testOneResponse(
        "/valid/response.root-unsigned.assertion-signed.1advice-signed.xml",
        false,
        2,
        { wantAuthnResponseSigned: false }
      )
    );
    it(
      "R1A1Ad - signed root => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned.1advice-unsigned.xml",
        false,
        1,
        {
          wantAssertionsSigned: false,
        }
      )
    );
    it(
      "R1A1Ad - signed asrt => valid",
      testOneResponse(
        "/valid/response.root-unsigned.assertion-signed.1advice-unsigned.xml",
        false,
        2,
        { wantAuthnResponseSigned: false }
      )
    );

    //== INVALID
    it(
      "R1A1Ad - signed none => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.1advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A1Ad - signed root+asrt+advi => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.1advice-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A1Ad - signed root+asrt => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.1advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A1Ad - signed asrt+advi => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.1advice-signed.xml",
        INVALID_SIGNATURE,
        2,
        { wantAuthnResponseSigned: false }
      )
    );
    it(
      "R1A1Ad - signed root => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.1advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A1Ad - signed asrt => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.1advice-unsigned.xml",
        INVALID_SIGNATURE,
        2,
        { wantAuthnResponseSigned: false }
      )
    );
  });

  describe("Signatures on saml:Response - 1 saml:Assertion + 1 saml:Advice containing 2 saml:Assertion", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
    });

    afterEach(function () {
      fakeClock.restore();
    });

    //== VALID
    it(
      "R1A2Ad - signed root+asrt+advi => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.2advice-signed.xml", false, 2)
    );
    it(
      "R1A2Ad - signed root+asrt => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.2advice-unsigned.xml", false, 2)
    );
    it(
      "R1A2Ad - signed root => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned.2advice-unsigned.xml",
        false,
        1,
        { wantAssertionsSigned: false }
      )
    );

    //== INVALID
    it(
      "R1A2Ad - signed none => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.2advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A2Ad - signed root+asrt+advi => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.2advice-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A2Ad - signed root+asrt => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.2advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
    it(
      "R1A2Ad - signed root => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.2advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1
      )
    );
  });

  describe("Signature on saml:Response with non-LF line endings", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
    });

    afterEach(function () {
      fakeClock.restore();
    });

    const samlResponseXml = fs
      .readFileSync(
        __dirname + "/static/signatures/valid/response.root-signed.assertion-signed.xml"
      )
      .toString();
    const makeBody = (str: string) => ({ SAMLResponse: Buffer.from(str).toString("base64") });

    it("CRLF line endings", async () => {
      const body = makeBody(samlResponseXml.replace(/\n/g, "\r\n"));
      await testOneResponseBody(body, false, 2);
    });

    it("CR line endings", async () => {
      const body = makeBody(samlResponseXml.replace(/\n/g, "\r"));
      await testOneResponseBody(body, false, 2);
    });
  });

  describe("Signature on saml:Response with XML-encoded carriage returns", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
    });

    afterEach(function () {
      fakeClock.restore();
    });

    it(
      "Attribute with &#13;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-13.xml", false, 1, {
        wantAssertionsSigned: false,
      })
    );

    it(
      "Attribute with &#xd;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-xd.xml", false, 1, {
        wantAssertionsSigned: false,
      })
    );
  });

  describe("Signature on saml:Response with XML-encoded carriage returns in signature value and certificate", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers(Date.parse("2020-09-25T16:59:00Z"));
    });

    afterEach(function () {
      fakeClock.restore();
    });

    it(
      "Signature attributes with &#13;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-13-signature.xml", false, 1, {
        wantAssertionsSigned: false,
      })
    );

    it(
      "Signature attributes with &#xd;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-xd-signature.xml", false, 1, {
        wantAssertionsSigned: false,
      })
    );
  });
});
