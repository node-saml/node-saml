export type SignatureAlgorithm = "sha1" | "sha256" | "sha256-mgf1" | "sha512";

export type PemLabel = "CERTIFICATE" | "PUBLIC KEY" | "PRIVATE KEY";

export interface SamlSigningOptions {
  privateKey: string | Buffer;
  publicCert?: string;
  signatureAlgorithm?: SignatureAlgorithm;
  xmlSignatureTransforms?: string[];
  digestAlgorithm?: string;
}

export interface AuthOptions {
  samlFallback?: "login-request" | "logout-request";
  additionalParams?: Record<string, string | string[]>;
}

export const isValidSamlSigningOptions = (
  options: Partial<SamlSigningOptions>,
): options is SamlSigningOptions => {
  return options.privateKey != null;
};

export interface AudienceRestrictionXML {
  Audience?: XMLObject[];
}
export interface CacheItem {
  value: string;
  createdAt: number;
}

export interface CacheProvider {
  saveAsync(key: string, value: string): Promise<CacheItem | null>;
  getAsync(key: string): Promise<string | null>;
  removeAsync(key: string | null): Promise<string | null>;
}

export type XMLValue = string | number | boolean | null | XMLObject | XMLValue[];

export type XMLObject = {
  [key: string]: XMLValue;
};

export type XMLInput = XMLObject;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type XMLOutput = Record<string, any>;

export type AuthorizeRequestXML = {
  "samlp:AuthnRequest": XMLInput;
};

export type XmlJsObject = {
  [key: string]: string | XmlJsObject | XmlJsObject[] | undefined;
  $?: { Value: string };
  _?: string;
};

export type SamlResponseXmlJs = XmlJsObject & {
  Response?: SamlAssertionXmlJs | SamlStatusXmlJs;
  LogoutResponse?: unknown;
};

export type SamlRequestXmlJs = {
  Request: unknown;
};

export type SamlAssertionXmlJs = {
  Assertion: unknown;
};

export type SamlStatusXmlJs = {
  Status: [
    { StatusCode: [XmlJsObject & { StatusCode: [XmlJsObject] }]; StatusMessage: [XmlJsObject] },
  ];
};

export type IdpCertCallback = (
  callback: (err: Error | null, publicCert?: string | string[]) => void,
) => void;

/**
 * These are SAML options that must be provided to construct a new SAML Strategy
 */
export interface MandatorySamlOptions {
  idpCert: string | string[] | IdpCertCallback;
  issuer: string;
  callbackUrl: string;
}

export interface SamlIDPListConfig {
  entries: SamlIDPEntryConfig[];
  getComplete?: string;
}

export interface SamlIDPEntryConfig {
  providerId: string;
  name?: string;
  loc?: string;
}

export type LogoutRequestXML = {
  "samlp:LogoutRequest": {
    "saml:NameID": XMLInput;
    [key: string]: XMLValue;
  };
};

export type ServiceMetadataXML = {
  EntityDescriptor: {
    [key: string]: XMLValue;
    SPSSODescriptor: XMLObject;
  };
};

export interface NameID {
  value: string | null;
  format: string | null;
}

export interface XmlSignatureLocation {
  reference: string;
  action: "append" | "prepend" | "before" | "after";
}

export type RacComparison = "exact" | "minimum" | "maximum" | "better";

export interface SamlScopingConfig {
  idpList?: SamlIDPListConfig[];
  proxyCount?: number;
  requesterId?: string[] | string;
}

export enum ValidateInResponseTo {
  never = "never",
  ifPresent = "ifPresent",
  always = "always",
}

/**
 * The options required to use a SAML strategy
 * These may be provided by means of defaults specified in the constructor
 */
export interface SamlOptions extends Partial<SamlSigningOptions>, MandatorySamlOptions {
  // Core
  entryPoint?: string;
  decryptionPvk?: string | Buffer;

  // Additional SAML behaviors
  additionalParams: Record<string, string>;
  additionalAuthorizeParams: Record<string, string>;
  identifierFormat: string | null;
  allowCreate: boolean;
  spNameQualifier?: string | null;
  acceptedClockSkewMs: number;
  attributeConsumingServiceIndex?: string;
  disableRequestedAuthnContext: boolean;
  authnContext: string[];
  forceAuthn: boolean;
  skipRequestCompression: boolean;
  authnRequestBinding?: string;
  racComparison: RacComparison;
  providerName?: string;
  passive: boolean;
  idpIssuer?: string;
  audience: string | false;
  scoping?: SamlScopingConfig;
  wantAssertionsSigned: boolean;
  wantAuthnResponseSigned: boolean;
  maxAssertionAgeMs: number;
  generateUniqueId: () => string;
  signMetadata: boolean;

  // InResponseTo Validation
  validateInResponseTo: ValidateInResponseTo;
  requestIdExpirationPeriodMs: number;
  cacheProvider: CacheProvider;

  // Logout
  logoutUrl: string;
  additionalLogoutParams: Record<string, string>;
  logoutCallbackUrl?: string;

  // extras
  disableRequestAcsUrl: boolean;
  samlAuthnRequestExtensions?: Record<string, unknown>;
  samlLogoutRequestExtensions?: Record<string, unknown>;
  metadataContactPerson?: {
    "@contactType": "technical" | "support" | "administrative" | "billing" | "other";
    Extensions?: string;
    Company?: string;
    GivenName?: string;
    SurName?: string;
    EmailAddress?: [string];
    TelephoneNumber?: [string];
  }[];
  metadataOrganization?: {
    OrganizationName: {
      "@xml:lang": string;
      "#text": string;
    }[];
    OrganizationDisplayName: {
      "@xml:lang": string;
      "#text": string;
    }[];
    OrganizationURL: {
      "@xml:lang": string;
      "#text": string;
    }[];
  };
}

export interface GenerateServiceProviderMetadataParams {
  decryptionCert?: string | null;
  publicCerts?: string | string[] | null;
  issuer: SamlOptions["issuer"];
  callbackUrl: SamlOptions["callbackUrl"];
  logoutCallbackUrl?: SamlOptions["logoutCallbackUrl"];
  identifierFormat?: SamlOptions["identifierFormat"];
  wantAssertionsSigned?: SamlOptions["wantAssertionsSigned"];
  decryptionPvk?: SamlOptions["decryptionPvk"];
  privateKey?: SamlOptions["privateKey"];
  signatureAlgorithm?: SamlOptions["signatureAlgorithm"];
  xmlSignatureTransforms?: SamlOptions["xmlSignatureTransforms"];
  digestAlgorithm?: SamlOptions["digestAlgorithm"];
  signMetadata?: SamlOptions["signMetadata"];
  metadataContactPerson?: SamlOptions["metadataContactPerson"];
  metadataOrganization?: SamlOptions["metadataOrganization"];
  generateUniqueId?: SamlOptions["generateUniqueId"];
}

export type SamlConfig = Partial<SamlOptions> & MandatorySamlOptions;

export interface Profile {
  issuer: string;
  sessionIndex?: string;
  nameID: string;
  nameIDFormat: string;
  nameQualifier?: string;
  spNameQualifier?: string;
  ID?: string;
  mail?: string; // InCommon Attribute urn:oid:0.9.2342.19200300.100.1.3
  email?: string; // `mail` if not present in the assertion
  ["urn:oid:0.9.2342.19200300.100.1.3"]?: string;
  getAssertionXml?(): string; // get the raw assertion XML
  getAssertion?(): Record<string, unknown>; // get the assertion XML parsed as a JavaScript object
  getSamlResponseXml?(): string; // get the raw SAML response XML
  [attributeName: string]: unknown; // arbitrary `AttributeValue`s
}

export class SamlStatusError extends Error {
  constructor(
    message: string,
    public readonly xmlStatus: string,
  ) {
    super(message);
  }
}
