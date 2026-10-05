import * as crypto from "crypto";
import { pemCertificates, toPem } from "xml-crypto";
import { assertRequired } from "./utility";
import { PemLabel } from "./types";

export const keyInfoToPem = (
  keyInfo: string | Buffer,
  pemLabel: PemLabel,
  optionName = "keyInfo",
): string => {
  assertRequired(keyInfo, `${optionName} is not provided`);
  assertRequired(
    typeof keyInfo === "string" || Buffer.isBuffer(keyInfo) || undefined,
    `${optionName} is not a string or a Buffer`,
  );

  // toPem() reads a Buffer that does not open with a boundary as DER, but a
  // Buffer here has always been the bytes of a PEM or base64 file.
  const keyData = Buffer.isBuffer(keyInfo) ? keyInfo.toString("latin1") : keyInfo;
  assertRequired(keyData.trim(), `${optionName} is not provided`);

  try {
    return toPem(keyData, pemLabel);
  } catch (error) {
    throw new TypeError(
      `${optionName} is not in PEM format or in base64 format: ${(error as Error).message}`,
    );
  }
};

export const keyInfoToBase64Certificate = (
  keyInfo: string | Buffer,
  optionName: string,
): string => {
  const certificates = pemCertificates(keyInfoToPem(keyInfo, "CERTIFICATE", optionName));
  assertRequired(
    certificates.length === 1 || undefined,
    `${optionName} must hold exactly one certificate, but holds ${certificates.length}`,
  );

  return certificates[0];
};

export const generateUniqueId = (): string => {
  return "_" + crypto.randomBytes(20).toString("hex");
};
