import { XmlParserLimits } from "./types";

// The 5 MiB input bound and 50,000-token estimate follow gosaml2's resource budgets.
// The token estimate is conservative; this is not an XML parser.
export const DEFAULT_XML_PARSER_LIMITS: XmlParserLimits = {
  maxBytes: 5 * 1024 * 1024,
  maxTokens: 50_000,
};

const LIMIT_NAMES = Object.keys(DEFAULT_XML_PARSER_LIMITS);

export function resolveXmlParserLimits(overrides?: Partial<XmlParserLimits>): XmlParserLimits {
  if (overrides === undefined) {
    return { ...DEFAULT_XML_PARSER_LIMITS };
  }
  if (overrides === null || typeof overrides !== "object" || Array.isArray(overrides)) {
    throw new TypeError("xmlParserLimits must be an object");
  }
  for (const [name, value] of Object.entries(overrides)) {
    if (!LIMIT_NAMES.includes(name)) {
      throw new TypeError(`Unknown xmlParserLimits option: ${name}`);
    }
    if (!Number.isSafeInteger(value) || (value as number) <= 0) {
      throw new TypeError(`xmlParserLimits.${name} must be a positive safe integer`);
    }
  }
  return { ...DEFAULT_XML_PARSER_LIMITS, ...overrides };
}

/**
 * Apply a conservative markup-token bound before XML tree allocation.
 * Count one opener for each markup construct, but skip literal '<' within
 * comments, CDATA, and processing instructions. Using a raw CDATA split
 * could hide actual elements when a CDATA opener occurs inside a comment.
 */
export function checkXmlComplexity(
  input: string | Buffer,
  overrides?: Partial<XmlParserLimits>,
): void {
  const limits = resolveXmlParserLimits(overrides);
  const inputBytes = typeof input === "string" ? Buffer.byteLength(input) : input.byteLength;
  if (inputBytes > limits.maxBytes) {
    throw new Error(`SAML XML exceeds xmlParserLimits.maxBytes (${limits.maxBytes})`);
  }

  const xml = typeof input === "string" ? input : input.toString("utf8");
  let count = 0;
  let offset = 0;
  while (true) {
    const start = xml.indexOf("<", offset);
    if (start === -1) return;

    // gosaml2's upper-bound estimate is 3 tokens per markup opener, plus one.
    count += 1;
    if (3 * count + 1 > limits.maxTokens) {
      throw new Error(`SAML XML exceeds xmlParserLimits.maxTokens (${limits.maxTokens})`);
    }

    if (xml.startsWith("<!DOCTYPE", start)) {
      throw new Error("SAML XML must not contain a DOCTYPE declaration");
    }

    let closing: string | undefined;
    let openingLength = 0;
    if (xml.startsWith("<!--", start)) {
      closing = "-->";
      openingLength = 4;
    } else if (xml.startsWith("<![CDATA[", start)) {
      closing = "]]>";
      openingLength = 9;
    } else if (xml.startsWith("<?", start)) {
      closing = "?>";
      openingLength = 2;
    }

    if (closing === undefined) {
      offset = start + 1;
    } else {
      const end = xml.indexOf(closing, start + openingLength);
      if (end === -1) {
        throw new Error("Unterminated XML comment, CDATA, or processing instruction");
      }
      offset = end + closing.length;
    }
  }
}
