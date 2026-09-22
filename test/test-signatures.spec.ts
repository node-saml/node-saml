import { SAML } from "../src";
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { SamlConfig } from "../src/types";
import * as xml from "../src/xml";
import * as assert from "assert";
import { expect } from "chai";

const idpCert = fs.readFileSync(__dirname + "/static/cert.pem", "ascii");

describe("Signatures", function () {
  const INVALID_SIGNATURE = "Invalid signature";
  const INVALID_DOCUMENT_SIGNATURE = "Invalid document signature";
  const INVALID_ENCRYPTED_SIGNATURE = "Invalid signature from encrypted assertion";
  const INVALID_TOO_MANY_TRANSFORMS = "Invalid signature, too many transforms";
  const INVALID_DOCUMENT_ELEMENT_SIGNATURE = "Invalid signature on documentElement";
  const INVALID_AMBIGUOUS_ID = "Invalid signature: ID cannot refer to more than one element";
  const XMLDOM_ERROR =
    "[xmldom error]\telement parse error: Error: Hierarchy request error: Only one element can be added and only after doctype\n@#[line:57,col:1]";

  const createBody = (pathToXml: string) => ({
    SAMLResponse: fs.readFileSync(__dirname + "/static/signatures" + pathToXml, "base64"),
  });

  let validateSignatureSpy: sinon.SinonSpy;

  beforeEach(() => {
    validateSignatureSpy = sinon.spy(xml, "getVerifiedXml");
  });

  afterEach(() => {
    sinon.restore();
  });

  const testOneResponseBody = async (
    samlResponseBody: Record<string, string>,
    shouldErrorWith: string | false,
    amountOfSignatureChecks = 1,
    options: Partial<SamlConfig> = {},
  ) => {
    //== Instantiate new instance before every test
    const samlObj = new SAML({
      callbackUrl: "http://localhost/saml/consume",
      idpCert,
      issuer: options.issuer ?? "onesaml_login",
      audience: false,
      ...options,
    });

    //== Run the test in `func`
    if (shouldErrorWith === false) {
      await assert.doesNotReject(samlObj.validatePostResponseAsync(samlResponseBody));
    } else {
      await assert.rejects(samlObj.validatePostResponseAsync(samlResponseBody), {
        message: shouldErrorWith,
      });
    }

    expect(validateSignatureSpy.callCount).to.equal(amountOfSignatureChecks);
  };

  const testOneResponse = (
    pathToXml: string,
    shouldErrorWith: string | false,
    amountOfSignaturesChecks: number | undefined,
    options?: Partial<SamlConfig>,
  ) => {
    //== Create a body based on an XML and run the test
    return async () =>
      await testOneResponseBody(
        createBody(pathToXml),
        shouldErrorWith,
        amountOfSignaturesChecks,
        options,
      );
  };

  describe("Signatures - Profile.getSamlResponseXml returns the response as received", () => {
    const validResponse = "/valid/response.root-unsigned.assertion-signed.xml";
    // The fixture's assertion is long expired in real time, like every other valid one here.
    const fixtureNow = "2020-09-25T16:59:00Z";
    const config: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      idpCert,
      issuer: "onesaml_login",
      audience: false,
      wantAuthnResponseSigned: false,
    };
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({ now: Date.parse(fixtureNow), toFake: ["Date"] });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    it("returns response-level material that no signature covered", async () => {
      const received = fs
        .readFileSync(__dirname + "/static/signatures" + validResponse, "utf8")
        // The first Issuer is the response's own; the assertion's sits inside the signed element.
        .replace(
          "<saml:Issuer>https://evil-corp.com</saml:Issuer>",
          "<saml:Issuer>https://attacker.example</saml:Issuer>",
        );

      const { profile } = await new SAML(config).validatePostResponseAsync({
        SAMLResponse: Buffer.from(received).toString("base64"),
      });
      assert.ok(profile != null);

      expect(profile.issuer).to.equal("https://evil-corp.com");
      expect(profile.getAssertionXml?.()).to.not.contain("https://attacker.example");
      expect(profile.getSamlResponseXml?.()).to.contain("https://attacker.example");
    });

    it("warns when it is called, and stays quiet for the verified accessors", function () {
      this.timeout(20000);
      const script = `
        const { SAML } = require(${JSON.stringify(path.join(__dirname, "..", "src"))});
        const fs = require("fs");
        require("sinon").useFakeTimers({
          now: Date.parse(${JSON.stringify(fixtureNow)}),
          toFake: ["Date"],
        });
        const samlObj = new SAML(${JSON.stringify(config)});
        const body = {
          SAMLResponse: fs.readFileSync(
            ${JSON.stringify(path.join(__dirname, "static", "signatures" + validResponse))},
            "base64",
          ),
        };
        (async () => {
          const { profile } = await samlObj.validatePostResponseAsync(body);
          console.error("<<verified-accessors>>");
          profile.getAssertionXml();
          profile.getAssertion();
          console.error("<<unverified-accessor>>");
          profile.getSamlResponseXml();
          console.error("<<end>>");
        })().catch((err) => {
          console.error("FAILED", err);
          process.exit(1);
        });
      `;
      const child = spawnSync(
        process.execPath,
        ["--require", "ts-node/register/transpile-only", "--eval", script],
        { env: { ...process.env, NODE_DEBUG: "node-saml" }, encoding: "utf8" },
      );
      expect(child.status, `child failed:\n${child.stderr}`).to.equal(0);

      const section = (marker: string) =>
        (child.stderr.split(`<<${marker}>>`)[1] ?? "").split("<<")[0].trim();

      expect(section("verified-accessors")).to.equal("");
      expect(section("unverified-accessor")).to.contain("getSamlResponseXml");
      expect(section("unverified-accessor")).to.contain(
        "Don't treat what it returns as authenticated",
      );
    });
  });

  describe("Signatures - multiple roots are considered invalid", () => {
    it(
      "multiple roots => invalid",
      testOneResponse("/invalid/response.root-signed.multiple-root-elements.xml", XMLDOM_ERROR, 0),
    );
  });

  describe("Signatures on saml:Response - Only 1 saml:Assertion", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    //== VALID
    it(
      "R1A - both signed => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.xml", false, 2),
    );
    const publicKey = fs.readFileSync(__dirname + "/static/pub.pem", "ascii");
    it(
      "R1A - both signed, verify using public key => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.xml", false, 2, {
        idpCert: publicKey,
      }),
    );
    it(
      "R1A - root signed => valid",
      testOneResponse("/valid/response.root-signed.assertion-unsigned.xml", false, 1, {
        wantAssertionsSigned: false,
      }),
    );
    it(
      "R1A - assertion signed => valid",
      testOneResponse("/valid/response.root-unsigned.assertion-signed.xml", false, 2, {
        wantAuthnResponseSigned: false,
      }),
    );
    it(
      "R1A - assertion signed, neither wanted => valid",
      testOneResponse("/valid/response.root-unsigned.assertion-signed.xml", false, 2, {
        wantAuthnResponseSigned: false,
        wantAssertionsSigned: false,
      }),
    );

    //== INVALID
    it(
      "R1A - root not signed, but required, assertion signed => error",
      testOneResponse(
        "/valid/response.root-unsigned.assertion-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A - none signed => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
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
        },
      ),
    );
    it(
      "R1A - both signed => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A - root signed => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A - assertion signed => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A - root signed - wantAssertionsSigned=true => error",
      testOneResponse("/valid/response.root-signed.assertion-unsigned.xml", INVALID_SIGNATURE, 2),
    );
    it(
      "R1A - root signed - assertion unsigned encrypted -wantAssertionsSigned=true => error",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned-encrypted.xml",
        INVALID_ENCRYPTED_SIGNATURE,
        2,
        {
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
        },
      ),
    );
    it(
      "R1A - root signed - assertion invalidly signed wantAssertionsSigned=true => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-invalidly-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A - root signed - assertion invalidly signed encrypted wantAssertionsSigned=true => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-invalidly-signed-encrypted.xml",
        INVALID_ENCRYPTED_SIGNATURE,
        2,
        {
          decryptionPvk: fs.readFileSync(__dirname + "/static/testshib encryption pvk.pem"),
        },
      ),
    );
    it(
      "R1A - root signed but with too many transforms => early error",
      testOneResponse(
        "/invalid/response.root-signed-transforms.assertion-unsigned.xml",
        INVALID_TOO_MANY_TRANSFORMS,
        1,
      ),
    );
    it(
      "R1A - root unsigned, assertion signed but with too many transforms => early error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed-transforms.xml",
        INVALID_TOO_MANY_TRANSFORMS,
        2,
        {
          wantAuthnResponseSigned: false,
        },
      ),
    );
    it(
      "R1A - root re-signed by attackers own private key and attacker's certificate placed to keyinfo",
      testOneResponse(
        "/invalid/response.root-resigned-by-attacker-assertion-unsigned-attackers-cert-at-keyinfo.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
        {
          wantAssertionsSigned: false,
        },
      ),
    );
  });

  describe("Signatures on saml:Response - 1 saml:Assertion + 1 saml:Advice containing 1 saml:Assertion", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    //== VALID
    it(
      "R1A1Ad - signed root + assertion + advice => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.1advice-signed.xml", false, 2),
    );
    it(
      "R1A1Ad - signed root + assertion => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-signed.1advice-unsigned.xml",
        false,
        2,
      ),
    );
    it(
      "R1A1Ad - signed assertion + advice => valid",
      testOneResponse(
        "/valid/response.root-unsigned.assertion-signed.1advice-signed.xml",
        false,
        2,
        { wantAuthnResponseSigned: false },
      ),
    );
    it(
      "R1A1Ad - signed root => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned.1advice-unsigned.xml",
        false,
        1,
        {
          wantAssertionsSigned: false,
        },
      ),
    );
    it(
      "R1A1Ad - signed assertion => valid",
      testOneResponse(
        "/valid/response.root-unsigned.assertion-signed.1advice-unsigned.xml",
        false,
        2,
        { wantAuthnResponseSigned: false },
      ),
    );

    //== INVALID
    it(
      "R1A1Ad - signed none => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.1advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A1Ad - signed root + assertion + advice => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.1advice-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A1Ad - signed root + assertion => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.1advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A1Ad - signed assertion + advice => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.1advice-signed.xml",
        INVALID_SIGNATURE,
        2,
        { wantAuthnResponseSigned: false },
      ),
    );
    it(
      "R1A1Ad - signed root => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.1advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A1Ad - signed assertion => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-signed.1advice-unsigned.xml",
        INVALID_SIGNATURE,
        2,
        { wantAuthnResponseSigned: false },
      ),
    );
  });

  describe("Signatures on saml:Response - 1 saml:Assertion + 1 saml:Advice containing 2 saml:Assertion", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    //== VALID
    it(
      "R1A2Ad - signed root + assertion + advice => valid",
      testOneResponse("/valid/response.root-signed.assertion-signed.2advice-signed.xml", false, 2),
    );
    it(
      "R1A2Ad - signed root + assertion => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-signed.2advice-unsigned.xml",
        false,
        2,
      ),
    );
    it(
      "R1A2Ad - signed root => valid",
      testOneResponse(
        "/valid/response.root-signed.assertion-unsigned.2advice-unsigned.xml",
        false,
        1,
        { wantAssertionsSigned: false },
      ),
    );

    //== INVALID
    it(
      "R1A2Ad - signed none => error",
      testOneResponse(
        "/invalid/response.root-unsigned.assertion-unsigned.2advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A2Ad - signed root + assertion + advice => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.2advice-signed.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A2Ad - signed root + assertion => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-signed.2advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
    it(
      "R1A2Ad - signed root => error",
      testOneResponse(
        "/invalid/response.root-signed.assertion-unsigned.2advice-unsigned.xml",
        INVALID_DOCUMENT_SIGNATURE,
        1,
      ),
    );
  });

  describe("Signature on saml:Response with non-LF line endings", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    const samlResponseXml = fs
      .readFileSync(
        __dirname + "/static/signatures/valid/response.root-signed.assertion-signed.xml",
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
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    it(
      "Attribute with &#13;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-13.xml", false, 1, {
        wantAssertionsSigned: false,
      }),
    );

    it(
      "Attribute with &#xd;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-xd.xml", false, 1, {
        wantAssertionsSigned: false,
      }),
    );
  });

  describe("Signature on saml:Response with XML-encoded carriage returns in signature value and certificate", () => {
    let fakeClock: sinon.SinonFakeTimers;

    beforeEach(function () {
      fakeClock = sinon.useFakeTimers({
        now: Date.parse("2020-09-25T16:59:00Z"),
        toFake: ["Date"],
      });
    });

    afterEach(function () {
      fakeClock.restore();
    });

    it(
      "Signature attributes with &#13;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-13-signature.xml", false, 1, {
        wantAssertionsSigned: false,
      }),
    );

    it(
      "Signature attributes with &#xd;",
      testOneResponse("/valid/response.root-signed.assertion-unsigned-xd-signature.xml", false, 1, {
        wantAssertionsSigned: false,
      }),
    );
  });

  describe("Signatures on samlp:LogoutRequest", () => {
    const createRequestBody = (pathToXml: string) => ({
      SAMLRequest: fs.readFileSync(__dirname + "/static" + pathToXml, "base64"),
    });

    const samlObj = () =>
      new SAML({
        callbackUrl: "http://localhost/saml/consume",
        idpCert,
        issuer: "onesaml_login",
      });

    const testOneRequest =
      (pathToXml: string, shouldErrorWith: string, amountOfSignatureChecks = 1) =>
      async () => {
        await assert.rejects(samlObj().validatePostRequestAsync(createRequestBody(pathToXml)), {
          message: shouldErrorWith,
        });

        expect(validateSignatureSpy.callCount).to.equal(amountOfSignatureChecks);
      };

    it("root signed => the profile is read from the signed bytes", async () => {
      const { profile } = await samlObj().validatePostRequestAsync(
        createRequestBody("/logout_request_with_good_signature.xml"),
      );

      expect(profile.nameID).to.equal("ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7");
      expect(validateSignatureSpy.callCount).to.equal(1);
    });

    it(
      "signature displaced into samlp:Extensions => error",
      testOneRequest(
        "/signatures/invalid/logoutrequest.root-signed.signature-in-extensions.xml",
        INVALID_DOCUMENT_ELEMENT_SIGNATURE,
      ),
    );

    it(
      "a second element carries the root ID => error",
      testOneRequest(
        "/signatures/invalid/logoutrequest.root-signed.duplicate-root-id.xml",
        INVALID_AMBIGUOUS_ID,
      ),
    );
  });
});
