import { SamlSigningOptions } from "./types.js";
import { signXml } from "./xml.js";

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
