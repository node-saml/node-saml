import * as crypto from "crypto";
import { assertRequired } from "./utility";

const PEM_FORMAT_REGEX = /(-----BEGIN .*-----\s+.*\s+-----END .*-----)/s;
const BASE64_REGEX =
  /^(?:[A-Za-z0-9\+\/]{4})*(?:[A-Za-z0-9\+\/]{2}==|[A-Za-z0-9\+\/]{3}=|[A-Za-z0-9\+\/]{4})$/m; // eslint-disable-line no-useless-escape

export const PemLabel = {
  CERTIFICATE: "CERTIFICATE" as const,
  PUBLIC_KEY: "PUBLIC KEY" as const,
  PRIVATE_KEY: "PRIVATE KEY" as const,
};

type PemLabelId = typeof PemLabel[keyof typeof PemLabel];

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
export const keyInfoToPem = (
  keyInfo: string | Buffer,
  pemLabel = PemLabel.CERTIFICATE as PemLabelId
): string => {
  const keyData = Buffer.isBuffer(keyInfo) ? keyInfo.toString("latin1") : keyInfo;
  assertRequired(keyData, "keyInfo is not provided");

  if (PEM_FORMAT_REGEX.test(keyData)) {
    return normalizePemFile(keyData);
  }

  const isBase64 = BASE64_REGEX.test(keyData);
  assertRequired(isBase64 || undefined, "keyInfo is not in base64 format");

  const pem = `-----BEGIN ${pemLabel}-----\n${keyInfo}\n-----END ${pemLabel}-----`;

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
