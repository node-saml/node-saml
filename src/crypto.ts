import * as crypto from "crypto";
import { assertRequired } from "./utility";
import { PemLabel } from "./types";
/**
 * PEM format has wide range of usages, but this library
 * is enforcing RFC7468 which focuses on PKIX, PKCS and CMS.
 *
 * https://www.rfc-editor.org/rfc/rfc7468
 *
 * PEM_FORMAT_REGEX validates structure against 'textualmsg': boundaries and
 * line structure, not the data. BASE64_REGEX validates the data, of a PEM
 * message and of the bare base64 form alike, with the line breaks removed, so
 * neither pattern has to describe a quantum that spans one.
 *
 * With few exceptions;
 *  - 'posteb' MAY have 'eol', but it is not mandatory.
 *  - 'preeb' and 'posteb' lines are limited to 64 characters, but
 *     should not cause any issues in context of PKIX, PKCS and CMS.
 *  - whitespace surrounding the message is discarded, the '*W' of
 *     'laxtextualmsg' in section 3 Figure 2. String.trim() also takes U+FEFF,
 *     so a BOM is accepted, which section 2 invites outside US-ASCII.
 *  - blanks at the ends of lines are discarded, which Figure 1 permits after
 *     'preeb', 'base64line' and 'posteb'. Leading and interior blanks are
 *     rejected; section 2 treats those as far less compatible.
 *  - a whitespace-only line MAY follow 'preeb', the '*eolWSP' of Figure 1.
 *  - line length is not enforced; section 2 permits sizes other than 64.
 *  - the data is base64 of RFC4648 section 4, so padding sits at its end and
 *     the final quantum is whole. Checking it de-lined also admits the split
 *     pad of 'base64finl'. https://www.rfc-editor.org/rfc/rfc4648#section-4
 *  - several messages MAY be concatenated, as section 2 allows.
 *  - the labels of 'preeb' and 'posteb' need not match each other or pemLabel.
 *  - 'eol' is normalized to '\n' before either pattern runs.
 *
 * The bare base64 form is not an RFC7468 textual message, so only the notes
 * above about boundaries and line structure fail to apply to it.
 * BASE64_LINES_REGEX carries what is left: no line of it may be empty.
 *
 * normalizePemFile() -function is returning PEM files conforming
 * RFC7468 'stricttextualmsg' definition.
 *
 * With couple of notes:
 *  - 'eol' is normalized to '\n'
 *  - lines longer than 64 characters are split, but shorter ones are not
 *     reflowed, so output is not literally 'stricttextualmsg'.
 */
const PEM_FORMAT_REGEX =
  /^(?:-----BEGIN [A-Z\x20]{1,48}-----\n+(?:[A-Za-z0-9+/=]+\n)+-----END [A-Z\x20]{1,48}-----\n*)+$/;
const PEM_BODY_REGEX =
  /-----BEGIN [A-Z\x20]{1,48}-----\n+((?:[A-Za-z0-9+/=]+\n)+)-----END [A-Z\x20]{1,48}-----/g;
const BASE64_LINES_REGEX = /^(?:[A-Za-z0-9+/=]+\n)*[A-Za-z0-9+/=]+$/;
const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Bounds the linear passes below; a 200-certificate bundle is 289KiB. It does
// NOT bound backtracking, so it is no substitute for unambiguous patterns.
const MAX_KEY_INFO_LENGTH = 1024 * 1024;

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
// the ASCII that PEM and Base64 use into U+FFFD and lose the evidence.
const keyInfoToString = (keyInfo: string | Buffer): string => {
  return Buffer.isBuffer(keyInfo) ? keyInfo.toString("latin1") : keyInfo;
};

// Stripped rather than matched: '[ \t]+' against an anchor is quadratic in the
// length of the run, which at MAX_KEY_INFO_LENGTH is minutes.
const stripTrailingBlanks = (text: string): string => {
  return text
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n");
};

// PEM_BODY_REGEX is global; the loop runs to exhaustion so lastIndex returns to 0.
const pemBodies = (pem: string): string[] => {
  const bodies: string[] = [];
  PEM_BODY_REGEX.lastIndex = 0;
  let message = PEM_BODY_REGEX.exec(pem);
  while (message !== null) {
    bodies.push(message[1]);
    message = PEM_BODY_REGEX.exec(pem);
  }
  return bodies;
};

// Line breaks are removed first, so where a line ends is a question of
// structure and never of the data.
const isBase64Data = (text: string): boolean => {
  return BASE64_REGEX.test(text.replace(/\n/g, ""));
};

const isBareBase64 = (text: string): boolean => {
  return BASE64_LINES_REGEX.test(text) && isBase64Data(text);
};

/**
 * This function currently expects to get data in PEM format or in base64 format.
 */
export const keyInfoToPem = (
  keyInfo: string | Buffer,
  pemLabel: PemLabel,
  optionName = "keyInfo",
): string => {
  // 'true' and '1234' coerce to four base64 characters, so a wrong type would
  // come back as a valid-looking PEM instead of an error naming the option.
  assertRequired(keyInfo, `${optionName} is not provided`);
  assertRequired(
    typeof keyInfo === "string" || Buffer.isBuffer(keyInfo) || undefined,
    `${optionName} is not a string or a Buffer`,
  );
  assertRequired(
    keyInfo.length <= MAX_KEY_INFO_LENGTH || undefined,
    `${optionName} is larger than ${MAX_KEY_INFO_LENGTH} characters`,
  );

  // Normalized here rather than matched: an 'eol' alternation inside a repeated
  // group is ambiguous and backtracks exponentially. Both patterns must stay
  // provably linear — check a change with `npx recheck@4 check '<source>' ''`,
  // which no timing test can establish.
  const keyData = stripTrailingBlanks(keyInfoToString(keyInfo).replace(/\r\n|\r/g, "\n")).trim();
  assertRequired(keyData, `${optionName} is not provided`);

  if (PEM_FORMAT_REGEX.test(keyData)) {
    assertRequired(
      pemBodies(keyData).every(isBase64Data) || undefined,
      `${optionName} is not in PEM format or in base64 format`,
    );

    return normalizePemFile(keyData);
  }

  assertRequired(
    isBareBase64(keyData) || undefined,
    `${optionName} is not in PEM format or in base64 format`,
  );

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
