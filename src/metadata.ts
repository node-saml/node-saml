import { stripPemHeaderAndFooter } from "./crypto";
import {
  isValidSamlSigningOptions,
  ServiceMetadataXML,
  XMLObject,
  GenerateServiceProviderMetadataParams,
} from "./types";
import { assertRequired, signXmlMetadata } from "./utility";
import { buildXmlBuilderObject } from "./xml";
import { generateUniqueId as generateUniqueIdDefault } from "./crypto";
import { DEFAULT_IDENTIFIER_FORMAT, DEFAULT_WANT_ASSERTIONS_SIGNED } from "./constants";

export const generateServiceProviderMetadata = (
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
    publicCerts = !Array.isArray(publicCerts) ? [publicCerts] : publicCerts;
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
      const signingKeyDescriptors = certArray.map((cert) => ({
        "@use": "signing",
        "ds:KeyInfo": {
          "ds:X509Data": {
            "ds:X509Certificate": {
              "#text": stripPemHeaderAndFooter(cert),
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

      decryptionCert = stripPemHeaderAndFooter(decryptionCert);

      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
        "@use": "encryption",
        "ds:KeyInfo": {
          "ds:X509Data": {
            "ds:X509Certificate": {
              "#text": decryptionCert,
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
