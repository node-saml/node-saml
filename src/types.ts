export type SignatureAlgorithm = "sha1" | "sha256" | "sha512";

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
 * Describes an AttributeConsumingService element in the SAML metadata.
 * Used by service providers to specify required attributes.
 * 
 * @see {@link https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf SAML 2.0 Metadata Specification, Section 2.4.4}
 * 
 * @example
 * ```typescript
 * const attributeConsumingService: AttributeConsumingService = {
 *   "@index": "0",
 *   "@isDefault": true,
 *   ServiceName: [{
 *     "@xml:lang": "en",
 *     "#text": "Employee Portal"
 *   }],
 *   ServiceDescription: [{
 *     "@xml:lang": "en",
 *     "#text": "Authentication service for employee portal access"
 *   }],
 *   RequestedAttribute: [
 *     {
 *       "@Name": "urn:oid:2.5.4.42",
 *       "@FriendlyName": "givenName",
 *       "@isRequired": true
 *     },
 *     {
 *       "@Name": "urn:oid:2.5.4.4",
 *       "@FriendlyName": "sn",
 *       "@isRequired": true
 *     },
 *     {
 *       "@Name": "urn:oid:1.2.840.113549.1.9.1",
 *       "@FriendlyName": "emailAddress",
 *       "@isRequired": false
 *     }
 *   ]
 * };
 * ```
 */
export interface AttributeConsumingService {
  /** 
   * Unique index for the service within the SP metadata.
   * Must be unique across all AttributeConsumingService elements.
   * @example "0", "1", "2"
   */
  "@index": string;

  /**
   * Indicates if this service is the default for the SP
   * @default false
   */
  "@isDefault"?: boolean;

  /**
   * Names of the service in multiple languages.
   * At least one ServiceName is required.
   */
  ServiceName: {
    /** 
     * Language code (e.g., "en", "es", "fr") 
     * @example "en", "es", "fr", "de"
     */
    "@xml:lang": string;
    
    /** 
     * The actual service name text
     * @example "My Authentication Service", "Employee Portal"
     */
    "#text": string;
  }[];

  /**
   * Descriptions of the service in multiple languages.
   * Optional but recommended for better user experience.
   */
  ServiceDescription?: {
    /** 
     * Language code (e.g., "en", "es", "fr") 
     * @example "en", "es", "fr", "de"
     */
    "@xml:lang": string;
    
    /** 
     * The actual service description text
     * @example "This service provides authentication for the employee portal"
     */
    "#text": string;
  }[];

  /**
   * Attributes requested by the service, with specifications
   */
  RequestedAttribute: {
    /** 
     * Name of the requested attribute, typically an OID.
     * Common values:
     * - `urn:oid:2.5.4.42` (givenName)
     * - `urn:oid:2.5.4.4` (sn/surname)
     * - `urn:oid:1.2.840.113549.1.9.1` (emailAddress)
     * - `urn:oid:2.5.4.3` (cn/commonName)
     * - `urn:oid:0.9.2342.19200300.100.1.3` (mail)
     */
    "@Name": string;

    /**
     * Format of the attribute name
     * @default "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
     */
    "@NameFormat"?: string;

    /** 
     * Human-readable name of the attribute
     * @example "givenName", "sn", "emailAddress", "mail"
     */
    "@FriendlyName"?: string;

    /** 
     * Indicates if the attribute is required for the service to function
     * @default false
     */
    "@isRequired"?: boolean;

    /**
     * Specific values the attribute can take (optional constraint)
     */
    AttributeValue?: {
      "#text": string;
    }[];
  }[];
}

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
  
  /**
   * Attribute consuming services to include in the metadata.
   * These describe the attributes that the service provider wishes to receive.
   * 
   * @example
   * ```typescript
   * metadataAttributeConsumingServices: [{
   *   "@index": "0",
   *   "@isDefault": true,
   *   ServiceName: [{
   *     "@xml:lang": "en",
   *     "#text": "My Service"
   *   }],
   *   RequestedAttribute: [{
   *     "@Name": "urn:oid:2.5.4.42",
   *     "@FriendlyName": "givenName",
   *     "@isRequired": true
   *   }]
   * }]
   * ```
   */
  metadataAttributeConsumingServices?: AttributeConsumingService[];
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
  metadataAttributeConsumingServices?: SamlOptions["metadataAttributeConsumingServices"];
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
