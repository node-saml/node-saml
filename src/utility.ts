import { SamlSigningOptions } from "./types";
import { signXml } from "./xml";

export function assertRequired<T>(value: T | null | undefined, error?: string): asserts value {
  if (value === undefined || value === null || (typeof value === "string" && value.length === 0)) {
    throw new TypeError(error ?? "value does not exist");
  }
}

export function assertBooleanIfPresent<T>(
  value: T | null | undefined,
  error?: string,
): asserts value {
  if (value != null && typeof value != "boolean") {
    throw new TypeError(error ?? "value is set but not boolean");
  }
}

export function assertObject(
  value: unknown,
  name: string,
  supportedKeys: string[],
): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  const unsupportedKey = Object.keys(value).find((key) => !supportedKeys.includes(key));
  if (unsupportedKey !== undefined) {
    throw new TypeError(`${name} has an unsupported key "${unsupportedKey}"`);
  }
}

export function assertNonEmptyString(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
}

export function assertNonEmptyArray(value: unknown, name: string): asserts value is unknown[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty array`);
  }
}

export function signXmlResponse(samlMessage: string, options: SamlSigningOptions): string {
  const responseXpath =
    '//*[local-name(.)="Response" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';

  return signXml(
    samlMessage,
    responseXpath,
    { reference: responseXpath, action: "append" },
    options,
  );
}

export function signXmlMetadata(metadataXml: string, options: SamlSigningOptions): string {
  const metadataXpath =
    '//*[local-name(.)="EntityDescriptor" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:metadata"]';

  return signXml(
    metadataXml,
    metadataXpath,
    { reference: metadataXpath, action: "prepend" },
    options,
  );
}
