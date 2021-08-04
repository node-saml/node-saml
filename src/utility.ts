import { SamlSigningOptions } from "./types";
import { signXml } from "./xml";
import { JSONXMLSchemaError } from "./types";

export function assertRequired<T>(value: T | null | undefined, error?: string): T {
  if (value === undefined || value === null || (typeof value === "string" && value.length === 0)) {
    throw new TypeError(error ?? "value does not exist");
  } else {
    return value;
  }
}

export function signXmlResponse(samlMessage: string, options: SamlSigningOptions): string {
  const responseXpath =
    '//*[local-name(.)="Response" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';

  return signXml(
    samlMessage,
    responseXpath,
    { reference: responseXpath, action: "append" },
    options
  );
}

export function assertObjectAndNotEmpty(value: any, error?: string): any {
  if (typeof value !== "object" || JSON.stringify(value) === JSON.stringify({})) {
    throw new TypeError(error ?? "value does not exist");
  } else {
    return value;
  }
}

export function validateSAMLExtensionsElement(jsonSAMLExtensionsElement: any): boolean {
  jsonSAMLExtensionsElement = assertObjectAndNotEmpty(
    jsonSAMLExtensionsElement,
    `samlExtensions Element value should be object and not empty`
  );
  let result = true;
  for (const subElementKey in jsonSAMLExtensionsElement) {
    if (!validateXMLNamespace(subElementKey, jsonSAMLExtensionsElement[subElementKey])) {
      result = false;
      break;
    }
  }
  return result;
}

/**
 * Validate the XMLBuilder input JSON, wether it has proper namespece or not
 * @param jsonXMLElementKey - Key of the element, need key to understand its namespace
 * @param jsonXMLElement - Just JSON which we want to pass to xmlbuilder to make xml
 * @returns boolean | JSONXMLSchemaError
 */
export function validateXMLNamespace(
  jsonXMLElementKey: string,
  jsonXMLElementValue: any
): boolean | JSONXMLSchemaError {
  jsonXMLElementKey = assertRequired(jsonXMLElementKey, `key should be define`);

  jsonXMLElementValue = assertObjectAndNotEmpty(
    jsonXMLElementValue,
    `${jsonXMLElementKey} XML Element value should be object and not empty`
  );

  // check namespace attribute
  const elementKeyParts = jsonXMLElementKey.split(":");
  let namespaceKey;
  if (elementKeyParts && elementKeyParts.length > 1) {
    const elementKeyPrefix = elementKeyParts[0];
    namespaceKey = `@xmlns:${elementKeyPrefix}`;
  } else {
    namespaceKey = "@xmlns";
  }
  const namespaceValue = jsonXMLElementValue[namespaceKey];
  if (!namespaceValue) {
    throw new JSONXMLSchemaError(
      `Namespace ${namespaceKey} is not defined for element ${jsonXMLElementKey}`
    );
  }
  return true;
}
