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
 *  - whitespace surrounding the message is discarded before validation. That is
 *     the leading and trailing '*W' of 'laxtextualmsg' (Section 3, Figure 2)
 *     and nothing else from that figure. String.trim() is wider than 'W' — it
 *     also takes U+FEFF, so a file saved with a BOM is accepted, which Section
 *     2 invites outside of US-ASCII.
 *  - blanks at the end of a line are discarded before validation as well. These
 *     are not a 'laxtextualmsg' concession: plain 'textualmsg' (Figure 1)
 *     already permits them at every position this accepts them — 'preeb *WSP
 *     eol', 'base64line = 1*base64char *WSP eol' and 'posteb *WSP'. Section 2
 *     singles them out as the one stray whitespace parsers agree on: "Most
 *     extant parsers ignore blanks at the ends of lines; blanks at the
 *     beginnings of lines or in the middle of the base64-encoded data are far
 *     less compatible." Leading and interior blanks are therefore still
 *     rejected. String.trimEnd() is wider than 'WSP' in the same way trim() is.
 *  - a line holding nothing but whitespace MAY follow 'preeb', which is the
 *     '*eolWSP' of Figure 1. It is emptied by the step above and matched by
 *     the '\n+' below.
 *  - line length is not enforced, since Section 2 lets parsers handle line
 *     sizes other than 64. normalizePemFile() rewraps anything longer. Every
 *     body line still carries at least one base64 character, as 'base64line'
 *     requires, so a blank line may not appear between two of them.
 *  - padding is confined to the end of the encapsulated text, where all three
 *     figures of Section 3 put it. The one padded form Figure 1 allows and this
 *     rejects is a pad split across an 'eol' ('base64pad *WSP eol base64pad');
 *     no generator emits it. BASE64_REGEX has always confined padding this way,
 *     so a value is now judged the same with and without its boundaries.
 *  - several messages MAY be concatenated in one value, optionally separated by
 *     blank lines, as Section 2 allows for files holding several certificates.
 *  - the 'label' of 'preeb' and of 'posteb' are not required to match each
 *     other, nor to match pemLabel. That gap predates this pattern.
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
 *  - lines longer than 64 characters are split, but shorter lines are left as
 *     they are rather than reflowed, so a body that arrives wrapped at some
 *     other width keeps that width. The result is a well-formed PEM message
 *     that every parser accepts; it is not literally 'stricttextualmsg', whose
 *     'base64fullline' is exactly 64 characters.
 */
const PEM_FORMAT_REGEX =
  /^(?:-----BEGIN [A-Z\x20]{1,48}-----\n+(?:[A-Za-z0-9+/]+\n)*[A-Za-z0-9+/]+={0,2}\n-----END [A-Z\x20]{1,48}-----\n*)+$/;
const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4}\n?)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * A certificate, key, or bundle of them is kilobytes. This cap bounds the
 * linear passes below — the copy, the trim, the replace, the blank stripping,
 * the match — so a hostile value cannot turn them into real work, and it fails
 * at construction with a message naming the option rather than somewhere
 * further in.
 *
 * It does NOT bound backtracking, and must not be mistaken for a control that
 * does: at this size an ambiguous pattern still has more paths than atoms. The
 * defense against that is keeping the patterns unambiguous, above.
 */
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

// Blanks at the ends of lines are removed here rather than matched, for the
// same reason line endings are: '[ \t]+' against an anchor is quadratic, since
// the engine retries the run from every position inside it. A mebibyte of
// blanks — permitted by MAX_KEY_INFO_LENGTH — takes minutes that way, which
// would reintroduce as a parser the denial of service the patterns avoid.
// split/trimEnd/join is linear, and runs in single-digit milliseconds at the
// cap. Only the ends of lines are touched; blanks anywhere else survive to be
// rejected by the patterns.
const stripTrailingBlanks = (text: string): string => {
  return text
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n");
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
  //
  // Both patterns must stay provably non-backtracking; no test can establish
  // that, because a test can only time one input on one machine. Check a change
  // to either of them with an analyzer, e.g.
  //   npx recheck@4 check '<source>' ''
  // which reports 'linear' or 'safe' for both as they stand, and reported
  // 'exponential' for the two forms this file has already had to fix.
  // A JavaScript caller reaching here with something else gets it coerced by the
  // template literal below, and 'true' or '1234' happen to be four base64
  // characters — so the wrong type would come back as a valid-looking PEM
  // instead of an error naming the option. Refuse the type outright.
  assertRequired(keyInfo, `${optionName} is not provided`);
  assertRequired(
    typeof keyInfo === "string" || Buffer.isBuffer(keyInfo) || undefined,
    `${optionName} is not a string or a Buffer`,
  );
  assertRequired(
    keyInfo.length <= MAX_KEY_INFO_LENGTH || undefined,
    `${optionName} is larger than ${MAX_KEY_INFO_LENGTH} characters`,
  );

  const keyData = stripTrailingBlanks(keyInfoToString(keyInfo).replace(/\r\n|\r/g, "\n")).trim();
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
