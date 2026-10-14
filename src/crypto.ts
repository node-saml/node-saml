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

// Base64 carries no label, so it may be PKCS #8 or PKCS #1. Some Node versions read PKCS #8 under
// either label, so trying PKCS #8 first keeps each key under its own label on every version.
export const privateKeyToPem = (keyInfo: string | Buffer, optionName: string): string => {
  try {
    return keyInfoToPem(keyInfo, "PRIVATE KEY", optionName);
  } catch {
    return keyInfoToPem(keyInfo, "RSA PRIVATE KEY", optionName);
  }
};

// Node's crypto has always read a PEM decryptionPvk as given, and it passes over text around the
// message that toPem() refuses, so only base64, which Node cannot read, is converted. The base64
// alphabet has no "-", so a value holding a boundary is PEM.
export const decryptionPvkToPem = (decryptionPvk: string | Buffer): string | Buffer => {
  const text = Buffer.isBuffer(decryptionPvk) ? decryptionPvk.toString("latin1") : decryptionPvk;
  if (typeof text === "string" && text.includes("-----BEGIN")) {
    return decryptionPvk;
  }

  return privateKeyToPem(decryptionPvk, "decryptionPvk");
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
