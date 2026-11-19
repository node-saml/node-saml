import * as assert from "assert";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";
import { SAML } from "../src/saml";
import { XmlParserLimits } from "../src/types";
import { parseDomFromString, parseXml2JsFromString } from "../src/xml";
import { DEFAULT_XML_PARSER_LIMITS } from "../src/xml-limits";

const idpCert = fs.readFileSync(path.join(__dirname, "static/cert.pem"), "utf8");
const privateKey = fs.readFileSync(path.join(__dirname, "static/key.pem"), "utf8");

function makeSaml(xmlParserLimits?: Partial<XmlParserLimits>): SAML {
  return new SAML({
    callbackUrl: "http://localhost/saml/consume",
    issuer: "onesaml_login",
    idpCert,
    xmlParserLimits,
  });
}

function signedRedirectQuery(xml: string): string {
  const message = zlib.deflateRawSync(xml).toString("base64");
  const algorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const params = `SAMLRequest=${encodeURIComponent(message)}`;
  const signed = `${params}&SigAlg=${encodeURIComponent(algorithm)}`;
  const signature = crypto.createSign("RSA-SHA256").update(signed).sign(privateKey, "base64");
  return `${signed}&Signature=${encodeURIComponent(signature)}`;
}

describe("XML parser resource budgets", function () {
  it("defaults to 5 MiB and 50,000 estimated tokens with configurable overrides", function () {
    assert.deepStrictEqual(makeSaml().options.xmlParserLimits, DEFAULT_XML_PARSER_LIMITS);
    assert.deepStrictEqual(makeSaml({ maxTokens: 100_000 }).options.xmlParserLimits, {
      ...DEFAULT_XML_PARSER_LIMITS,
      maxTokens: 100_000,
    });
  });

  it("rejects unknown or invalid settings at construction", function () {
    for (const value of [0, -1, 1.5, Infinity, NaN, "64"]) {
      assert.throws(() => makeSaml({ maxTokens: value as number }), {
        name: "TypeError",
        message: "xmlParserLimits.maxTokens must be a positive safe integer",
      });
    }
    assert.throws(() => makeSaml("wrong" as unknown as Partial<XmlParserLimits>), {
      message: "xmlParserLimits must be an object",
    });
    assert.throws(() => makeSaml({ hidden: 4 } as unknown as Partial<XmlParserLimits>), {
      message: "Unknown xmlParserLimits option: hidden",
    });
  });

  it("rejects XML above the default byte limit", async function () {
    const xml = "<Root>" + "x".repeat(DEFAULT_XML_PARSER_LIMITS.maxBytes) + "</Root>";
    await assert.rejects(parseDomFromString(xml), {
      message: "SAML XML exceeds xmlParserLimits.maxBytes (5242880)",
    });
  });

  it("measures XML bytes in UTF-8 before building either representation", async function () {
    const xml = "<Root>" + "é".repeat(32) + "</Root>";
    const limit = Buffer.byteLength(xml) - 1;
    const limits = { maxBytes: limit };
    const message = `SAML XML exceeds xmlParserLimits.maxBytes (${limit})`;
    await assert.rejects(parseDomFromString(xml, limits), { message });
    await assert.rejects(parseXml2JsFromString(Buffer.from(xml), limits), { message });
  });

  it("uses the gosaml2 token estimate", async function () {
    const xml = "<Root><Child/></Root>";
    const doc = await parseDomFromString(xml, { maxTokens: 10 });
    assert.strictEqual(doc.documentElement.tagName, "Root");
    assert.ok((await parseXml2JsFromString(xml, { maxTokens: 10 })).Root);
    const tooMany = "<Root><Child/><Child/></Root>";
    const message = "SAML XML exceeds xmlParserLimits.maxTokens (10)";
    await assert.rejects(parseDomFromString(tooMany, { maxTokens: 10 }), { message });
    await assert.rejects(parseXml2JsFromString(tooMany, { maxTokens: 10 }), { message });
  });

  it("enforces the default token budget", async function () {
    const xml = "<Root>" + "<N/>".repeat(16_666) + "</Root>";
    await assert.rejects(parseDomFromString(xml), {
      message: "SAML XML exceeds xmlParserLimits.maxTokens (50000)",
    });
  });

  it("does not count literal markup characters inside CDATA or comments", async function () {
    const xml = `<Root><!--${"<".repeat(20_000)}--><![CDATA[${"<".repeat(20_000)}]]></Root>`;
    const doc = await parseDomFromString(xml, { maxTokens: 13 });
    assert.strictEqual(doc.documentElement.tagName, "Root");
    assert.ok((await parseXml2JsFromString(xml, { maxTokens: 13 })).Root);
  });

  it("counts CDATA sections and comments as markup", async function () {
    const xml = "<Root>" + "<![CDATA[x]]>".repeat(4) + "</Root>";
    await assert.rejects(parseDomFromString(xml, { maxTokens: 10 }), {
      message: "SAML XML exceeds xmlParserLimits.maxTokens (10)",
    });
    const comments = "<Root>" + "<!--x-->".repeat(4) + "</Root>";
    await assert.rejects(parseXml2JsFromString(comments, { maxTokens: 10 }), {
      message: "SAML XML exceeds xmlParserLimits.maxTokens (10)",
    });
  });

  it("does not let a CDATA opener inside a comment conceal real elements", async function () {
    const xml = "<Root><!-- <![CDATA[ --><Child/><Child/><![CDATA[<x>]]></Root>";
    await assert.rejects(parseDomFromString(xml, { maxTokens: 10 }), {
      message: "SAML XML exceeds xmlParserLimits.maxTokens (10)",
    });
  });

  it("counts markup after a fake CDATA opener in a processing instruction", async function () {
    const xml = "<Root><?example <![CDATA[ ?><Child/><Child/><![CDATA[<x>]]></Root>";
    await assert.rejects(parseDomFromString(xml, { maxTokens: 10 }), {
      message: "SAML XML exceeds xmlParserLimits.maxTokens (10)",
    });
  });

  it("rejects actual DTDs, but not the text DOCTYPE inside CDATA", async function () {
    const dtd = '<!DOCTYPE Root [<!ENTITY foo "expanded">]><Root>&foo;</Root>';
    const message = "SAML XML must not contain a DOCTYPE declaration";
    await assert.rejects(parseDomFromString(dtd), { message });
    await assert.rejects(parseXml2JsFromString(dtd), { message });
    const literal = "<Root><![CDATA[<!DOCTYPE Root>]]></Root>";
    assert.ok((await parseXml2JsFromString(literal)).Root);
  });

  it("checks markup on POST before signature validation", async function () {
    const saml = makeSaml({ maxTokens: 10 });
    const xml = "<Response><N/><N/></Response>";
    await assert.rejects(
      saml.validatePostResponseAsync({ SAMLResponse: Buffer.from(xml).toString("base64") }),
      { message: "SAML XML exceeds xmlParserLimits.maxTokens (10)" },
    );
  });

  it("checks markup after HTTP-Redirect signature validation", async function () {
    const saml = makeSaml({ maxTokens: 10 });
    const query = signedRedirectQuery("<LogoutRequest><N/><N/></LogoutRequest>");
    await assert.rejects(saml.validateRedirectAsync(query), {
      message: "SAML XML exceeds xmlParserLimits.maxTokens (10)",
    });
  });
});
