import { removeCertPEMHeaderAndFooter } from "../crypto";
import { ServiceMetadataXML } from "../types";
import { buildXmlBuilderObject } from "../xml";

export const generateServiceProviderMetadata = (params: {
  issuer: string;
  callbackUrl: string;
  logoutCallbackUrl?: string;
  identifierFormat?: string | null;
  wantAssertionsSigned: boolean;
  decryptionCert: string | null;
  signingCerts?: string[] | null;
}): string => {
  const {
    issuer,
    callbackUrl,
    logoutCallbackUrl,
    identifierFormat,
    wantAssertionsSigned,
    decryptionCert,
    signingCerts,
  } = params;

  const metadata: ServiceMetadataXML = {
    EntityDescriptor: {
      "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
      "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
      "@entityID": issuer,
      "@ID": issuer.replace(/\W/g, "_"),
      SPSSODescriptor: {
        "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
      },
    },
  };

  if (decryptionCert != null || signingCerts != null) {
    metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor = [];
    if (signingCerts != null) {
      metadata.EntityDescriptor.SPSSODescriptor["@AuthnRequestsSigned"] = true;
      const signingKeyDescriptors = signingCerts.map((signingCert) => ({
        "@use": "signing",
        "ds:KeyInfo": {
          "ds:X509Data": {
            "ds:X509Certificate": {
              "#text": removeCertPEMHeaderAndFooter(signingCert),
            },
          },
        },
      }));
      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push(signingKeyDescriptors);
    }

    if (decryptionCert != null) {
      metadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor.push({
        "@use": "encryption",
        "ds:KeyInfo": {
          "ds:X509Data": {
            "ds:X509Certificate": {
              "#text": removeCertPEMHeaderAndFooter(decryptionCert),
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
  };

  return buildXmlBuilderObject(metadata, true);
};
