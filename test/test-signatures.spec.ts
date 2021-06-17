import { SAML } from "../src";
import * as fs from "fs";
import * as sinon from "sinon";
import { SamlConfig } from "../src/types";
import assert = require("assert");

const cert = fs.readFileSync(__dirname + "/static/cert.pem", "ascii");

describe("Signatures", function () {
  const INVALID_SIGNATURE = "Invalid signature",
    INVALID_ENCRYPTED_SIGNATURE = "Invalid signature from encrypted assertion",
    INVALID_TOO_MANY_TRANSFORMS = "Invalid signature, too many transforms",
    createBody = (pathToXml: string) => ({
      SAMLResponse: fs.readFileSync(__dirname + "/static/signatures" + pathToXml, "base64"),
    }),
    testOneResponseBody = async (
      samlResponseBody: Record<string, string>,
      shouldErrorWith: string | false | undefined,
      amountOfSignatureChecks = 1,
      options: Partial<SamlConfig> = {}
    ) => {
      //== Instantiate new instance before every test
      const samlObj = new SAML({ cert, ...options });
      //== Spy on `validateSignature` to be able to count how many times it has been called
      const validateSignatureSpy = sinon.spy(samlObj, "validateSignature");

      //== Run the test in `func`
      await assert.rejects(samlObj.validatePostResponseAsync(samlResponseBody), {
        message: shouldErrorWith || "SAML assertion expired: clocks skewed too much",
      });
      //== Assert times `validateSignature` was called
      validateSignatureSpy.callCount.should.eql(amountOfSignatureChecks);
    },
    testOneResponse = (
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

  describe("Signatures on saml:Response - Only 1 saml:Assertion", () => {
    //== VALID
    it(
      "R1A - both signed => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.xml", false, 1)
    );
    it(
      "R1A - root signed => valid",
      testOneResponse("/valid/response.root-signed.assertion-unsigned.xml", false, 1)
    );
    it(
      "R1A - asrt signed => valid",
      testOneResponse("/valid/response.root-unsigned.assertion-signed.xml", false, 2)
    );

    //== INVALID
    it(
      "R1A - none signed => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A - both signed => error",
      testOneResponse("/invalid/response.root-signed.assertion-signed.xml", INVALID_SIGNATURE, 2)
    );
    it(
      "R1A - root signed => error",
      testOneResponse("/invalid/response.root-signed.assertion-unsigned.xml", INVALID_SIGNATURE, 2)
    );
    it(
      "R1A - asrt signed => error",
      testOneResponse("/invalid/response.root-unsigned.assertion-signed.xml", INVALID_SIGNATURE, 2)
    );
    it(
      "R1A - root signed - wantAssertionsSigned=true => error",
      testOneResponse("/valid/response.root-signed.assertion-unsigned.xml", INVALID_SIGNATURE, 2, {
        wantAssertionsSigned: true,
      })
    );
    it(
      "R1A - root signed - asrt unsigned encrypted -wantAssertionsSigned=true => error",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned-encrypted.xml",
        INVALID_ENCRYPTED_SIGNATURE,
        2,
        {
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
          wantAssertionsSigned: true,
        }
      )
    );
    it(
      "R1A - root signed - asrt invalidly signed wantAssertionsSigned=true => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-invalidly-signed.xml",
        INVALID_SIGNATURE,
        2,
        {
          wantAssertionsSigned: true,
        }
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
          wantAssertionsSigned: true,
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
        2
      )
    );
  });

  describe("Signatures on saml:Response - 1 saml:Assertion + 1 saml:Advice containing 1 saml:Assertion", () => {
    //== VALID
    it(
      "R1A1Ad - signed root+asrt+advi => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.1advice-signed.xml", false, 1)
    );
    it(
      "R1A1Ad - signed root+asrt => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.1advice-unsigned.xml", false, 1)
    );
    it(
      "R1A1Ad - signed asrt+advi => valid",
      testOneResponse("/valid/response.root-unsigned.assertion-signed.1advice-signed.xml", false, 2)
    );
    it(
      "R1A1Ad - signed root => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned.1advice-unsigned.xml",
        false,
        1
      )
    );
    it(
      "R1A1Ad - signed asrt => valid",
      testOneResponse(
        "/valid/response.root-unsigned.assertion-signed.1advice-unsigned.xml",
        false,
        2
      )
    );

    //== INVALID
    it(
      "R1A1Ad - signed none => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.1advice-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A1Ad - signed root+asrt+advi => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.1advice-signed.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A1Ad - signed root+asrt => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.1advice-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A1Ad - signed asrt+advi => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.1advice-signed.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A1Ad - signed root => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.1advice-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A1Ad - signed asrt => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.1advice-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
  });

  describe("Signatures on saml:Response - 1 saml:Assertion + 1 saml:Advice containing 2 saml:Assertion", () => {
    //== VALID
    it(
      "R1A2Ad - signed root+asrt+advi => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.2advice-signed.xml", false, 1)
    );
    it(
      "R1A2Ad - signed root+asrt => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.2advice-unsigned.xml", false, 1)
    );
    it(
      "R1A2Ad - signed root => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned.2advice-unsigned.xml",
        false,
        1
      )
    );

    //== INVALID
    it(
      "R1A2Ad - signed none => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.2advice-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A2Ad - signed root+asrt+advi => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.2advice-signed.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A2Ad - signed root+asrt => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.2advice-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
    it(
      "R1A2Ad - signed root => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.2advice-unsigned.xml",
        INVALID_SIGNATURE,
        2
      )
    );
  });

  describe("Signature on saml:Response with non-LF line endings", () => {
    const samlResponseXml = fs
      .readFileSync(
        __dirname + "/static/signatures/valid/response.root-signed.assertion-signed.xml"
      )
      .toString();
    const makeBody = (str: string) => ({ SAMLResponse: Buffer.from(str).toString("base64") });

    it("CRLF line endings", async () => {
      const body = makeBody(samlResponseXml.replace(/\n/g, "\r\n"));
      await testOneResponseBody(body, false, 1);
    });

    it("CR line endings", async () => {
      const body = makeBody(samlResponseXml.replace(/\n/g, "\r"));
      await testOneResponseBody(body, false, 1);
    });
  });

  describe("Signature on saml:Response with XML-encoded carriage returns", () => {
    const samlResponseXml = fs
      .readFileSync(
        __dirname + "/static/signatures/valid/response.root-unsigned.assertion-signed.xml"
      )
      .toString();
    const makeBody = (str: string) => ({ SAMLResponse: Buffer.from(str).toString("base64") });

    const insertChars = (str: string, where: string, chars: string) =>
      str.replace(new RegExp(`(<ds:${where}>)(.{10})(.{10})`), `$1$2${chars}$3`);

    it("SignatureValue with &#13;", async () => {
      const body = makeBody(insertChars(samlResponseXml, "SignatureValue", "&#13;"));
      await testOneResponseBody(body, false, 2);
    });

    it("SignatureValue with &#xd;", async () => {
      const body = makeBody(insertChars(samlResponseXml, "SignatureValue", "&#xd;"));
      await testOneResponseBody(body, false, 2);
    });
  });
});
