import * as crypto from "crypto";
import * as util from "util";

const debugLog = util.debuglog("node-saml");

type AlgorithmOption = "signatureAlgorithm" | "digestAlgorithm";

<<<<<<< HEAD
// RSASSA-PSS, RFC 6931 2.3.10: https://www.rfc-editor.org/rfc/rfc6931#section-2.3.10
export const RSA_SHA256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
=======
// The short names the switches below recognize. Anything else falls through to SHA-1, so every
// caller that signs warns against this list rather than let a typo downgrade signing silently.
export const SUPPORTED_ALGORITHMS = ["sha1", "sha256", "sha512"];
>>>>>>> warn-metadata-signing-algorithms

// That section fixes the salt at the length of the hash, which is also what xml-crypto signs and
// verifies this algorithm with.
export const PSS_OPTIONS = {
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
};

// The short names the switches below recognize. Anything else falls through to SHA-1, so
// every caller that signs warns against these lists rather than let a typo downgrade signing silently.
const SUPPORTED_ALGORITHMS: Record<AlgorithmOption, string[]> = {
  signatureAlgorithm: ["sha1", "sha256", "sha256-mgf1", "sha512"],
  digestAlgorithm: ["sha1", "sha256", "sha512"],
};

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
      return RSA_SHA256_MGF1;
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

export function getSigner(shortName?: string) {
  // The return type of `crypto.createSign` is `crypto.Sign`, but in Node@14, it fails compilation if specified; it is correct inferred if not specified
  switch (shortName) {
    case "sha256":
    case "sha256-mgf1":
      return crypto.createSign("RSA-SHA256");
    case "sha512":
      return crypto.createSign("RSA-SHA512");
    case "sha1":
    default:
      return crypto.createSign("RSA-SHA1");
  }
}
