import * as util from "util";
import * as algorithms from "./algorithms";
import {
  isValidSamlSigningOptions,
  ServiceMetadataXML,
  XMLObject,
  GenerateServiceProviderMetadataParams,
} from "./types";
import { assertRequired, signXmlMetadata } from "./utility";
import { buildXmlBuilderObject } from "./xml";
import { generateUniqueId as generateUniqueIdDefault, keyInfoToBase64Certificate } from "./crypto";
import { DEFAULT_IDENTIFIER_FORMAT, DEFAULT_WANT_ASSERTIONS_SIGNED } from "./constants";

const debugLog = util.debuglog("node-saml");

const CONTACT_TYPES = ["technical", "support", "administrative", "billing", "other"];

function assertObject(
  value: unknown,
  path: string,
  supportedKeys: string[],
): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  const unsupportedKey = Object.keys(value).find((key) => !supportedKeys.includes(key));
  if (unsupportedKey !== undefined) {
    throw new TypeError(`${path} has an unsupported key "${unsupportedKey}"`);
  }
}

function assertNonEmptyString(value: unknown, path: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
}

function assertLocalizedNames(value: unknown, path: string): void {
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array`);
  }
  value.forEach((name: unknown, i) => {
    assertObject(name, `${path}[${i}]`, ["@xml:lang", "#text"]);
    assertNonEmptyString(name["@xml:lang"], `${path}[${i}]["@xml:lang"]`);
    assertNonEmptyString(name["#text"], `${path}[${i}]["#text"]`);
  });
}

function assertNonEmptyArray(value: unknown, path: string): asserts value is unknown[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${path} must be a non-empty array`);
  }
}

function assertValidContactPersons(contacts: unknown): void {
  if (contacts == null) {
    return;
  }
  if (!Array.isArray(contacts)) {
    throw new TypeError("metadataContactPerson must be an array");
  }

  contacts.forEach((contact: unknown, i) => {
    const path = `metadataContactPerson[${i}]`;
    assertObject(contact, path, [
      "@contactType",
      "Extensions",
      "Company",
      "GivenName",
      "SurName",
      "EmailAddress",
      "TelephoneNumber",
    ]);

    const contactType = contact["@contactType"];
    if (typeof contactType !== "string" || !CONTACT_TYPES.includes(contactType)) {
      throw new TypeError(`${path}["@contactType"] must be one of ${CONTACT_TYPES.join(", ")}`);
    }
    // `md:Extensions` holds elements and no text: SAML 2.0 Metadata, section 2.3.1.
    const extensions = contact.Extensions;
    if (extensions != null && (typeof extensions !== "object" || Array.isArray(extensions))) {
      throw new TypeError(`${path}.Extensions must be an object of namespace-qualified elements`);
    }
    for (const key of ["Company", "GivenName", "SurName"]) {
      if (contact[key] != null) {
        assertNonEmptyString(contact[key], `${path}.${key}`);
      }
    }
    for (const key of ["EmailAddress", "TelephoneNumber"]) {
      const values = contact[key];
      if (values == null) {
        continue;
      }
      if (!Array.isArray(values)) {
        throw new TypeError(`${path}.${key} must be an array`);
      }
      values.forEach((value: unknown, j) => assertNonEmptyString(value, `${path}.${key}[${j}]`));
    }
  });
}

function assertValidOrganization(organization: unknown): void {
  if (organization == null) {
    return;
  }
  const names = ["OrganizationName", "OrganizationDisplayName", "OrganizationURL"];
  assertObject(organization, "metadataOrganization", names);
  for (const name of names) {
    assertNonEmptyArray(organization[name], `metadataOrganization.${name}`);
    assertLocalizedNames(organization[name], `metadataOrganization.${name}`);
  }
}

// Both options are still written into the metadata as given, so what the checks find is logged and
// not thrown. The next major version throws it.
export const warnIfContactOrOrganizationInvalid = (
  params: Pick<
    GenerateServiceProviderMetadataParams,
    "metadataContactPerson" | "metadataOrganization"
  >,
): void => {
  const checks = [
    () => assertValidContactPersons(params.metadataContactPerson),
    () => assertValidOrganization(params.metadataOrganization),
  ];
  for (const check of checks) {
    try {
      check();
    } catch (error) {
      debugLog(
        "%s. The metadata is still generated from the option as given, and may not follow the SAML metadata schema. The next major version rejects this instead.",
        (error as Error).message,
      );
    }
  }
};

// `SAML`'s constructor has already reported its options, so its method builds the metadata
// without warning again.
export const buildServiceProviderMetadata = (
  params: GenerateServiceProviderMetadataParams,
): string => {
  const {
    issuer,
    callbackUrl,
    logoutCallbackUrl,
    decryptionPvk,
    privateKey,
    metadataContactPerson,
    metadataOrganization,
    identifierFormat = DEFAULT_IDENTIFIER_FORMAT,
    wantAssertionsSigned = DEFAULT_WANT_ASSERTIONS_SIGNED,
    // This matches the default used in the `SAML` class.
    generateUniqueId = generateUniqueIdDefault,
  } = params;

  let { publicCerts, decryptionCert } = params;

  if (decryptionPvk != null) {
    if (!decryptionCert) {
      throw new Error(
        "Missing decryptionCert while generating metadata for decrypting service provider",
      );
    }
  } else {
    decryptionCert = null;
  }

  if (privateKey != null) {
    if (!publicCerts) {
      throw new Error(
        "Missing publicCert while generating metadata for signing service provider messages",
      );
    }
  } else {
    publicCerts = null;
  }

  const metadata: ServiceMetadataXML = {
    EntityDescriptor: {
      "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
      "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
      "@entityID": issuer,
      "@ID": generateUniqueId(),
      SPSSODescriptor: {
        "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@AuthnRequestsSigned": "false",
      },
      ...(metadataOrganization ? { Organization: metadataOrganization } : {}),
      ...(metadataContactPerson ? { ContactPerson: metadataContactPerson } : {}),
    },
  };

  if (decryptionCert != null || publicCerts != null) {
    metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = [];
    if (isValidSamlSigningOptions(params)) {
      assertRequired(
        publicCerts,
        "Missing publicCert while generating metadata for signing service provider messages",
      );

      metadata.EntityDescriptor.SPSSODescriptor["@AuthnRequestsSigned"] = true;

      const certArray = Array.isArray(publicCerts) ? publicCerts : [publicCerts];
      const signingKeyDescriptors = certArray.map((cert, index) => ({
        "@use": "signing",
        "ds:KeyInfo": {
          "ds:X509Data": {
            "ds:X509Certificate": {
              "#text": keyInfoToBase64Certificate(
                cert,
                Array.isArray(publicCerts) ? `publicCerts[${index}]` : "publicCerts",
              ),
            },
          },
        },
      }));
      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push(signingKeyDescriptors);
    }

    if (decryptionPvk != null) {
      assertRequired(
        decryptionCert,
        "Missing decryptionCert while generating metadata for decrypting service provider",
      );

      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
        "@use": "encryption",
        "ds:KeyInfo": {
          "ds:X509Data": {
            "ds:X509Certificate": {
              "#text": keyInfoToBase64Certificate(decryptionCert, "decryptionCert"),
            },
          },
        },
        EncryptionMethod: [
          // this should be the set that the xmlenc library supports
          { "@Algorithm": "http://www.w3.org/2009/xmlenc11#aes256-gcm" },
          { "@Algorithm": "http://www.w3.org/2009/xmlenc11#aes128-gcm" },
          { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes256-cbc" },
          { "@Algorithm": "http://www.w3.org/2001/04/xmlenc#aes128-cbc" },
        ],
      });
    }
  }

  if (logoutCallbackUrl != null) {
    metadata.EntityDescriptor.SPSSODescriptor.SingleLogoutService = {
      "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "@Location": logoutCallbackUrl,
    };
  }

  if (identifierFormat != null) {
    metadata.EntityDescriptor.SPSSODescriptor.NameIDFormat = identifierFormat;
  }

  if (wantAssertionsSigned) {
    metadata.EntityDescriptor.SPSSODescriptor["@WantAssertionsSigned"] = true;
  }

  metadata.EntityDescriptor.SPSSODescriptor.AssertionConsumerService = {
    "@index": "1",
    "@isDefault": "true",
    "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "@Location": callbackUrl,
  } as XMLObject;

  let metadataXml = buildXmlBuilderObject(metadata, true);
  if (params.signMetadata === true && isValidSamlSigningOptions(params)) {
    metadataXml = signXmlMetadata(metadataXml, {
      privateKey: params.privateKey,
      signatureAlgorithm: params.signatureAlgorithm,
      xmlSignatureTransforms: params.xmlSignatureTransforms,
      digestAlgorithm: params.digestAlgorithm,
    });
  }
  return metadataXml;
};

export const generateServiceProviderMetadata = (
  params: GenerateServiceProviderMetadataParams,
): string => {
  if (params.signMetadata === true && isValidSamlSigningOptions(params)) {
    // An omitted `signatureAlgorithm` needs no notice here: signing fails without one.
    if (params.digestAlgorithm === undefined) {
      algorithms.warnAlgorithmNotSet("digestAlgorithm");
    }
    for (const option of ["signatureAlgorithm", "digestAlgorithm"] as const) {
      algorithms.warnIfAlgorithmNotRecognized(option, params[option]);
    }
  }
  warnIfContactOrOrganizationInvalid(params);

  return buildServiceProviderMetadata(params);
};
