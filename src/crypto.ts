import * as crypto from "crypto";
import { assertRequired } from "./utility";

const PEM_FORMAT_REGEX =
  /(-----BEGIN .*-----(\n|\r|\r\n)([0-9a-zA-Z\+\/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+\/=]{1,63}(\n|\r|\r\n))?-----END .*-----)/m; // eslint-disable-line no-useless-escape
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

/*
 Base64 data may be formated into 64 character line length
 or it may be in single line.

 Return Base64 data formated into 64 character line length.
*/
export const normalizeBase64Data = (base64Data: string): string => {
  return (base64Data.match(/.{1,64}/g) || []).join("\n");
};

export const certToPEM = (keyInfo: string, pemHeaderLabel = "CERTIFICATE"): string => {
  if (PEM_FORMAT_REGEX.test(keyInfo)) {
    return keyInfo;
  }

  const isBase64 = BASE64_REGEX.test(keyInfo);
  assertRequired(isBase64 || undefined, "cert is invalid");

  const pem = `-----BEGIN ${pemHeaderLabel}-----\n${normalizeBase64Data(
    keyInfo
  )}\n-----END ${pemHeaderLabel}-----\n`;

  return pem;
};

export const generateUniqueId = (): string => {
  return "_" + crypto.randomBytes(20).toString("hex");
};

export const stripPEMHeaderAndFooter = (certificate: string): string => {
  return certificate
    .replace(/\r\n/g, "\n")
    .replace(/-----BEGIN.*-----(\n?|)/, "")
    .replace(/-----END.*-----(\n?|)/, "");
};
