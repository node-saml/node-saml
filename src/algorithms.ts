import * as crypto from "crypto";
import * as util from "util";
import { SignatureAlgorithm, SignedXml } from "xml-crypto";

const debugLog = util.debuglog("node-saml");

type AlgorithmOption = "signatureAlgorithm" | "digestAlgorithm";

// The Redirect binding signs octets, not XML, but names the algorithm with an XML Signature
// identifier (SAML bindings 3.4.4.1), so what an identifier means is xml-crypto's to say. Its
// default set leaves out HMAC, which would let anyone holding the IdP's certificate sign.
export function findSignatureAlgorithm(identifier: string): SignatureAlgorithm | undefined {
  const registered = new SignedXml().SignatureAlgorithms;
  return Object.prototype.hasOwnProperty.call(registered, identifier)
    ? new registered[identifier]()
    : undefined;
}

// The short names the switches below recognize. Anything else falls through to SHA-1, so every
// caller that signs warns against these lists rather than let a typo downgrade signing silently.
const SUPPORTED_ALGORITHMS: Record<AlgorithmOption, string[]> = {
  signatureAlgorithm: ["sha1", "sha256", "sha256-mgf1", "sha512"],
  digestAlgorithm: ["sha1", "sha256", "sha512"],
};

// The values that came before "sha256-mgf1" get a SHA-1 digest when `digestAlgorithm` is omitted or
// misspelled, and rejecting that is breaking for them. This one has no caller to break.
export function assertDigestAlgorithmChosen(
  signatureAlgorithm: string | undefined,
  digestAlgorithm: string | undefined,
): void {
  if (signatureAlgorithm !== "sha256-mgf1") {
    return;
  }
  if (digestAlgorithm == null) {
    throw new TypeError('digestAlgorithm is required when signatureAlgorithm is "sha256-mgf1"');
  }
  if (!SUPPORTED_ALGORITHMS.digestAlgorithm.includes(digestAlgorithm)) {
    throw new TypeError(
      `digestAlgorithm "${digestAlgorithm}" is not recognized; use one of ${SUPPORTED_ALGORITHMS.digestAlgorithm.join(", ")}`,
    );
  }
}

export function warnAlgorithmNotSet(option: AlgorithmOption): void {
  debugLog(
    "`%s` is not set, so it defaults to `sha1`, which is no longer considered safe for signatures. The next major version requires it whenever `privateKey` is set; set it now.",
    option,
  );
}

// An unrecognized value is not an error today: it falls through to SHA-1, so a casing slip
// like "SHA256" silently downgrades the signature the caller asked for.
export function warnIfAlgorithmNotRecognized(
  option: AlgorithmOption,
  value: string | undefined,
): void {
  if (value !== undefined && !SUPPORTED_ALGORITHMS[option].includes(value)) {
    debugLog(
      '`%s` is set to "%s", which is not recognized, so SHA-1 is used instead. Use one of %s. The next major version rejects an unrecognized value rather than downgrading.',
      option,
      value,
      SUPPORTED_ALGORITHMS[option].join(", "),
    );
  }
}

export function getSigningAlgorithm(shortName?: string): string {
  switch (shortName) {
    case "sha256":
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    case "sha256-mgf1":
      // RSASSA-PSS, RFC 9231 2.3.10: https://www.rfc-editor.org/rfc/rfc9231#section-2.3.10
      return "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
    case "sha512":
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    case "sha1":
    default:
      return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  }
}

export function getDigestAlgorithm(shortName?: string): string {
  switch (shortName) {
    case "sha256":
      return "http://www.w3.org/2001/04/xmlenc#sha256";
    case "sha512":
      return "http://www.w3.org/2001/04/xmlenc#sha512";
    case "sha1":
    default:
      return "http://www.w3.org/2000/09/xmldsig#sha1";
  }
}

/**
 * @deprecated No longer used: xml-crypto signs Redirect-binding messages. Removed in the next
 *   major version; call `crypto.createSign()` yourself.
 */
export function getSigner(shortName?: string) {
  // The return type of `crypto.createSign` is `crypto.Sign`, but in Node@14, it fails compilation if specified; it is correct inferred if not specified
  switch (shortName) {
    case "sha256":
      return crypto.createSign("RSA-SHA256");
    case "sha512":
      return crypto.createSign("RSA-SHA512");
    case "sha1":
    default:
      return crypto.createSign("RSA-SHA1");
  }
}
