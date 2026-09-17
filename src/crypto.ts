import * as crypto from "crypto";
import { assertRequired } from "./utility";
import { PemLabel } from "./types";
/**
 * PEM format has wide range of usages, but this library
 * is enforcing RFC7468 which focuses on PKIX, PKCS and CMS.
 *
 * https://www.rfc-editor.org/rfc/rfc7468
 *
 * PEM_FORMAT_REGEX is validating given PEM file against RFC7468 'stricttextualmsg' definition.
 *
 * With few exceptions;
 *  - 'posteb' MAY have 'eol', but it is not mandatory.
 *  - 'preeb' and 'posteb' lines are limited to 64 characters, but
 *     should not cause any issues in context of PKIX, PKCS and CMS.
 *  - whitespace around the message is discarded before validation. This is the
 *     leading and trailing '*W' of 'laxtextualmsg' (Section 3, Figure 2) and
 *     nothing else from it, so whitespace inside the message is still rejected.
 *     String.trim() is wider than 'W' — it also takes U+FEFF, so a file saved
 *     with a BOM is accepted, which Section 2 invites outside of US-ASCII.
 *  - the encapsulated text is only checked for base64 characters; neither line
 *     length nor the position of the padding is enforced, since Section 2 lets
 *     parsers handle line sizes other than 64. normalizePemFile() rewraps them.
 *  - several messages MAY be concatenated in one value, optionally separated by
 *     blank lines, as Section 2 allows for files holding several certificates.
 *  - 'eol' is normalized to '\n' before either pattern runs, so both match only
 *     '\n'. See the note in keyInfoToPem(); this is not cosmetic.
 *
 * BASE64_REGEX validates the bare base64 form, which this library accepts as a
 * convenience. RFC7468 does not define it — a textual message always carries
 * encapsulation boundaries — so the notes above do not apply to it.
 *
 * Its '{4}' must stay fixed-width. Relaxing it to '{1,4}', the obvious way to
 * accept a line length that is not a multiple of four, makes the group
 * ambiguous and the match exponential: ~14x per added character, which is a
 * denial of service on any input an attacker can influence.
 *
 * normalizePemFile() -function is returning PEM files conforming
 * RFC7468 'stricttextualmsg' definition.
 *
 * With couple of notes:
 *  - 'eol' is normalized to '\n'
 */
const PEM_FORMAT_REGEX =
  /^(?:-----BEGIN [A-Z\x20]{1,48}-----\n(?:[A-Za-z0-9+/=]*\n)+-----END [A-Z\x20]{1,48}-----\n*)+$/;
const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4}\n?)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * -----BEGIN [LABEL]-----
 * base64([DATA])
 * -----END [LABEL]-----
 *
 * Above is shown what PEM file looks like. As can be seen, base64 data
 * can be in single line or multiple lines.
 *
 * This function normalizes PEM presentation to;
 *  - contain PEM header and footer as they are given
 *  - normalize line endings to '\n'
 *  - normalize line length to maximum of 64 characters
 *  - ensure that 'preeb' has line ending '\n'
 */
const normalizePemFile = (pem: string): string => {
  return `${(
    pem
      .trim()
      .replace(/(\r\n|\r)/g, "\n")
      .match(/.{1,64}/g) ?? []
  ).join("\n")}\n`;
};

// latin1 keeps every byte of a Buffer intact; utf8 would fold anything outside
// the ASCII that PEM and Base64 use into U+FFFD and lose the evidence. String()
// is for JavaScript callers who reach here with neither a string nor a Buffer,
// so they get the message naming the option rather than a TypeError from trim().
const keyInfoToString = (keyInfo: string | Buffer): string => {
  return Buffer.isBuffer(keyInfo) ? keyInfo.toString("latin1") : String(keyInfo ?? "");
};

/**
 * This function currently expects to get data in PEM format or in base64 format.
 */
export const keyInfoToPem = (
  keyInfo: string | Buffer,
  pemLabel: PemLabel,
  optionName = "keyInfo",
): string => {
  // Line endings are normalized here rather than matched in the patterns. An
  // alternation like '(?:\r\n|\r|\n)' inside a repeated group lets CRLF parse
  // two ways — one eol, or CR followed by an empty line — so a value that fails
  // to match backtracks exponentially, and a malformed certificate stalls the
  // event loop. Section 2 asks parsers to handle every convention; doing it
  // once here keeps both patterns unambiguous.
  const keyData = keyInfoToString(keyInfo)
    .trim()
    .replace(/\r\n|\r/g, "\n");
  assertRequired(keyData, `${optionName} is not provided`);

  if (PEM_FORMAT_REGEX.test(keyData)) {
    return normalizePemFile(keyData);
  }

  const isBase64 = BASE64_REGEX.test(keyData);
  assertRequired(isBase64 || undefined, `${optionName} is not in PEM format or in base64 format`);

  const pem = `-----BEGIN ${pemLabel}-----\n${keyData}\n-----END ${pemLabel}-----`;

  return normalizePemFile(pem);
};

export const generateUniqueId = (): string => {
  return "_" + crypto.randomBytes(20).toString("hex");
};

export const stripPemHeaderAndFooter = (certificate: string): string => {
  return certificate
    .replace(/(\r\n|\r)/g, "\n")
    .replace(/-----BEGIN [A-Z\x20]{1,48}-----\n?/, "")
    .replace(/-----END [A-Z\x20]{1,48}-----\n?/, "");
};
