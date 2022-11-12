import * as crypto from "crypto";
import { assertRequired } from "./utility";

const PEM_FORMAT_REGEX = /(-----BEGIN .*-----\s+.*\s+-----END .*-----)/s;
const BASE64_REGEX =
  /^(?:[A-Za-z0-9\+\/]{4})*(?:[A-Za-z0-9\+\/]{2}==|[A-Za-z0-9\+\/]{3}=|[A-Za-z0-9\+\/]{4})$/m; // eslint-disable-line no-useless-escape

export const keyToPEM = (
  key: string | Buffer
): typeof key extends string | Buffer ? string | Buffer : Error => {
  assertRequired(key, "key is required");

  if (typeof key !== "string") return key;
  if (key.split(/\r?\n/).length !== 1) return key;

  const matchedKey = key.match(/.{1,64}/g);

  if (matchedKey) {
    const wrappedKey = [
      "-----BEGIN PRIVATE KEY-----",
      ...matchedKey,
      "-----END PRIVATE KEY-----",
      "",
    ].join("\n");
    return wrappedKey;
  }

  throw new Error("Invalid key");
};

/**
 * Base64 data may be formated into 64 character line length
 * or it may be in a single line.
 *
 * Return Base64 data formated into 64 character line length.
 */
export const normalizeBase64Data = (base64Data: string): string => {
  return (base64Data.trim().match(/.{1,64}/g) || []).join("\n");
};

/**
 *
 * -----BEGIN [LABEL]-----
 * base64([DATA])
 * -----END [LABEL]-----
 *
 * Above is shown what PEM file looks like. As can be seen, base64 data
 * can be in single line or multiple lines.
 *
 * This function normalizes PEM presentation to contain PEM header and footer
 * as they are given and formats base64 data into 64 character line length
 * and normalizes file end to contain only single new line after PEM footer.
 */
export const normalizePemFile = (pem: string): string => {
  const isPemFormat = PEM_FORMAT_REGEX.test(pem);
  assertRequired(isPemFormat || undefined, "pem file has invalid headers");

  const parts = pem.match(/-----BEGIN .*-----\s?(.*)\s?----END .*-----/s) || []; // empty array satisfies TypeScript
  const base64Data = parts[1];

  const isBase64 = BASE64_REGEX.test(base64Data);
  assertRequired(isBase64 || undefined, "pem content is not base64");

  return pem.replace(base64Data, normalizeBase64Data(base64Data)).replace(/\s?$/, "\n");
};

/**
 * This function currently expects to get data in PEM format or in base64 format.
 */
export const keyInfoToPem = (keyInfo: string, pemHeaderLabel = "CERTIFICATE"): string => {
  if (PEM_FORMAT_REGEX.test(keyInfo)) {
    return normalizePemFile(keyInfo);
  }

  const isBase64 = BASE64_REGEX.test(keyInfo);
  assertRequired(isBase64 || undefined, "keyInfo is not in base64 format");

  const pem = `-----BEGIN ${pemHeaderLabel}-----\n${keyInfo}\n-----END ${pemHeaderLabel}-----`;

  return normalizePemFile(pem);
};

export const generateUniqueId = (): string => {
  return "_" + crypto.randomBytes(20).toString("hex");
};

export const stripPemHeaderAndFooter = (certificate: string): string => {
  return certificate
    .replace(/\r\n/g, "\n")
    .replace(/-----BEGIN.*-----(\n?|)/, "")
    .replace(/-----END.*-----(\n?|)/, "");
};
