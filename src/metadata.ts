import * as algorithms from "./algorithms";
import {
  isValidSamlSigningOptions,
  ServiceMetadataXML,
  XMLObject,
  XMLValue,
  GenerateServiceProviderMetadataParams,
} from "./types";
import { assertRequired, signXmlMetadata } from "./utility";
import { buildXmlBuilderObject } from "./xml";
import { generateUniqueId as generateUniqueIdDefault, keyInfoToBase64Certificate } from "./crypto";
import { DEFAULT_IDENTIFIER_FORMAT, DEFAULT_WANT_ASSERTIONS_SIGNED } from "./constants";

// The order in which `ContactType` and `OrganizationType` sequence their children: SAML 2.0
// Metadata, sections 2.3.2.2 and 2.3.2.1.
// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
const CONTACT_PERSON_CHILDREN = [
  "Extensions",
  "Company",
  "GivenName",
  "SurName",
  "EmailAddress",
  "TelephoneNumber",
];
const ORGANIZATION_CHILDREN = [
  "Extensions",
  "OrganizationName",
  "OrganizationDisplayName",
  "OrganizationURL",
];

// The builder emits keys in the order they were written, and the order a caller writes an
// object's keys in is not a choice the schema should depend on. Any other key, such as an
// attribute, is kept ahead of the children.
function inSchemaOrder(element: XMLValue, children: string[]): XMLValue {
  if (Array.isArray(element)) {
    return element.map((entry) => inSchemaOrder(entry, children));
  }
  if (typeof element !== "object" || element === null) {
    return element;
  }
  const keys = Object.keys(element);
  const ordered: XMLObject = {};
  for (const key of [
    ...keys.filter((key) => !children.includes(key)),
    ...children.filter((key) => keys.includes(key)),
  ]) {
    ordered[key] = element[key];
  }
  return ordered;
}

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
      ...(metadataOrganization
        ? { Organization: inSchemaOrder(metadataOrganization, ORGANIZATION_CHILDREN) }
        : {}),
      // `Extensions` is xmlbuilder content the caller built, which its type does not describe.
      ...(metadataContactPerson
        ? {
            ContactPerson: inSchemaOrder(
              metadataContactPerson as XMLValue,
              CONTACT_PERSON_CHILDREN,
            ),
          }
        : {}),
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

  return buildServiceProviderMetadata(params);
};
