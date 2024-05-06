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
 *
 * normalizePemFile() -function is returning PEM files conforming
 * RFC7468 'stricttextualmsg' definition.
 *
 * With couple of notes:
 *  - 'eol' is normalized to '\n'
 */
const PEM_FORMAT_REGEX =
  /^(-----BEGIN [A-Z\x20]{1,48}-----(\r\n|\r|\n){1}.*(\r\n|\r|\n){1}-----END [A-Z\x20]{1,48}-----(\r\n|\r|\n){0,1})$/s;
const BASE64_REGEX =
  /^(?:[A-Za-z0-9\+\/]{4}\n{0,1})*(?:[A-Za-z0-9\+\/]{2}==|[A-Za-z0-9\+\/]{3}=)?$/s; // eslint-disable-line no-useless-escape

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

/**
 * This function currently expects to get data in PEM format or in base64 format.
 */
export const keyInfoToPem = (
  keyInfo: string | Buffer,
  pemLabel: PemLabel,
  optionName = "keyInfo",
): string => {
  const keyData = Buffer.isBuffer(keyInfo) ? keyInfo.toString("latin1") : keyInfo;
  assertRequired(keyData, `${optionName} is not provided`);

  if (PEM_FORMAT_REGEX.test(keyData)) {
    return normalizePemFile(keyData);
  }

  const isBase64 = BASE64_REGEX.test(keyData);
  assertRequired(isBase64 || undefined, `${optionName} is not in PEM format or in base64 format`);

  const pem = `-----BEGIN ${pemLabel}-----\n${keyInfo}\n-----END ${pemLabel}-----`;

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
