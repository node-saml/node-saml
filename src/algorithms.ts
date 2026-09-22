import * as crypto from "crypto";

// The short names the switches below recognize. Anything else falls through to SHA-1, so
// `initialize()` warns against this list rather than let a typo downgrade signing silently.
export const SUPPORTED_ALGORITHMS = ["sha1", "sha256", "sha512"];

export function isSupportedAlgorithm(shortName: string): boolean {
  return SUPPORTED_ALGORITHMS.includes(shortName);
}

export function getSigningAlgorithm(shortName?: string): string {
  switch (shortName) {
    case "sha256":
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
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
      return crypto.createSign("RSA-SHA256");
    case "sha512":
      return crypto.createSign("RSA-SHA512");
    case "sha1":
    default:
      return crypto.createSign("RSA-SHA1");
  }
}
