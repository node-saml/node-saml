import * as crypto from "crypto";
import { assertRequired } from "./utility";

export const keyToPEM = (
  key: string | Buffer
): typeof key extends string | Buffer ? string | Buffer : Error => {
  key = assertRequired(key, "key is required");

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

export const certToPEM = (cert: string): string => {
  cert = cert.match(/.{1,64}/g)!.join("\n");

  if (cert.indexOf("-BEGIN CERTIFICATE-") === -1) cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  if (cert.indexOf("-END CERTIFICATE-") === -1) cert = cert + "\n-----END CERTIFICATE-----\n";

  return cert;
};

export const generateUniqueId = (): string => {
  return "_" + crypto.randomBytes(10).toString("hex");
};

export const removeCertPEMHeaderAndFooter = (certificate: string): string => {
  certificate = certificate.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, "");
  certificate = certificate.replace(/-+END CERTIFICATE-+\r?\n?/, "");
  certificate = certificate.replace(/\r\n/g, "\n");
  return certificate;
};
