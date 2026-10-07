import * as xmldom from "@xmldom/xmldom";
import * as util from "util";
import * as algorithms from "./algorithms";
import {
  isValidSamlSigningOptions,
  ServiceMetadataXML,
  XMLObject,
  XMLValue,
  GenerateServiceProviderMetadataParams,
} from "./types";
import {
  assertBooleanIfPresent,
  assertNonEmptyArray,
  assertNonEmptyString,
  assertObject,
  assertRequired,
  signXmlMetadata,
} from "./utility";
import { buildXmlBuilderObject } from "./xml";
import { generateUniqueId as generateUniqueIdDefault, keyInfoToBase64Certificate } from "./crypto";
import { DEFAULT_IDENTIFIER_FORMAT, DEFAULT_WANT_ASSERTIONS_SIGNED } from "./constants";

const debugLog = util.debuglog("node-saml");

const METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata";
const XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE = "http://www.w3.org/2000/xmlns/";
const XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance";
// Declared on `EntityDescriptor`, and so in scope on every element of the metadata.
const INHERITED_NAMESPACES = {
  "@xmlns": METADATA_NAMESPACE,
  "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
};
const CONTACT_TYPES = ["technical", "support", "administrative", "billing", "other"];
const SERVICES_OPTION = "metadataAttributeConsumingServices";
const MAX_UNSIGNED_SHORT = 65535;
// The lexical space of `xs:language`, the type the schema gives `xml:lang`:
// https://www.w3.org/TR/xmlschema-2/#language
const LANGUAGE_TAG = /^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$/;
// SAML 2.0 Core, section 1.3.2, requires a URI value to be absolute in the sense of RFC 2396,
// whose grammar comes to a scheme, a colon and one or more URI characters, then an optional
// fragment: https://www.rfc-editor.org/rfc/rfc2396#section-3
const URI_CHARACTER = "(?:[;/?:@&=+$,a-zA-Z0-9_.!~*'()-]|%[0-9a-fA-F]{2})";
const ABSOLUTE_URI = new RegExp(
  `^[a-zA-Z][a-zA-Z0-9+.-]*:${URI_CHARACTER}+(?:#${URI_CHARACTER}*)?$`,
);

function assertLocalizedNames(value: unknown, path: string): void {
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array`);
  }
  value.forEach((name: unknown, i) => {
    assertObject(name, `${path}[${i}]`, ["@xml:lang", "#text"]);
    const language = name["@xml:lang"];
    if (typeof language !== "string" || !LANGUAGE_TAG.test(language)) {
      throw new TypeError(
        `${path}[${i}]["@xml:lang"] must be a language tag, such as "en" or "en-GB"`,
      );
    }
    assertNonEmptyString(name["#text"], `${path}[${i}]["#text"]`);
  });
}

// SAML 2.0 Metadata, sections 2.4.4 and 2.4.4.1, and its schema. The schema alone would not do: a
// repeated `index` and a second default both validate against it.
// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
export const assertValidAttributeConsumingServices = (services: unknown): void => {
  if (services == null) {
    return;
  }
  if (!Array.isArray(services)) {
    throw new TypeError(`${SERVICES_OPTION} must be an array`);
  }

  const entryByIndex = new Map<number, number>();
  let defaultEntry: number | undefined;

  services.forEach((service: unknown, i) => {
    const path = `${SERVICES_OPTION}[${i}]`;
    assertObject(service, path, [
      "@index",
      "@isDefault",
      "ServiceName",
      "ServiceDescription",
      "RequestedAttribute",
    ]);

    const index = service["@index"];
    if (
      typeof index !== "string" ||
      !/^[0-9]+$/.test(index) ||
      Number(index) > MAX_UNSIGNED_SHORT
    ) {
      throw new TypeError(
        `${path}["@index"] must be a string of digits from "0" to "${MAX_UNSIGNED_SHORT}"`,
      );
    }
    // Compared as numbers, because "1" and "01" are the same `xs:unsignedShort`.
    const entryWithIndex = entryByIndex.get(Number(index));
    if (entryWithIndex !== undefined) {
      throw new TypeError(
        `${path}["@index"] is "${index}", but ${SERVICES_OPTION}[${entryWithIndex}] already uses that index`,
      );
    }
    entryByIndex.set(Number(index), i);

    assertBooleanIfPresent(service["@isDefault"], `${path}["@isDefault"] must be a boolean`);
    if (service["@isDefault"] === true) {
      if (defaultEntry !== undefined) {
        throw new TypeError(
          `${path}["@isDefault"] is true, but ${SERVICES_OPTION}[${defaultEntry}] is already the default`,
        );
      }
      defaultEntry = i;
    }

    assertNonEmptyArray(service.ServiceName, `${path}.ServiceName`);
    assertLocalizedNames(service.ServiceName, `${path}.ServiceName`);
    if (service.ServiceDescription != null) {
      assertLocalizedNames(service.ServiceDescription, `${path}.ServiceDescription`);
    }

    assertNonEmptyArray(service.RequestedAttribute, `${path}.RequestedAttribute`);
    service.RequestedAttribute.forEach((attribute, j) => {
      const attributePath = `${path}.RequestedAttribute[${j}]`;
      assertObject(attribute, attributePath, [
        "@Name",
        "@NameFormat",
        "@FriendlyName",
        "@isRequired",
      ]);
      assertNonEmptyString(attribute["@Name"], `${attributePath}["@Name"]`);
      const nameFormat = attribute["@NameFormat"];
      if (
        nameFormat != null &&
        (typeof nameFormat !== "string" || !ABSOLUTE_URI.test(nameFormat))
      ) {
        throw new TypeError(
          `${attributePath}["@NameFormat"] must be an absolute URI, such as "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"`,
        );
      }
      if (attribute["@FriendlyName"] != null) {
        assertNonEmptyString(attribute["@FriendlyName"], `${attributePath}["@FriendlyName"]`);
      }
      assertBooleanIfPresent(
        attribute["@isRequired"],
        `${attributePath}["@isRequired"] must be a boolean`,
      );
    });
  });
};

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
const LOCALIZED_ORGANIZATION_CHILDREN = [
  "OrganizationName",
  "OrganizationDisplayName",
  "OrganizationURL",
];
const ORGANIZATION_CHILDREN = ["Extensions", ...LOCALIZED_ORGANIZATION_CHILDREN];
// Both types end in `anyAttribute namespace="##other"`, which is how a REFEDS security contact is
// marked: a prefixed attribute, next to the `xmlns:` declaration of its prefix. The prefix and the
// name are each an `NCName`: https://www.w3.org/TR/xml-names/#NT-NCName
const NAME_START_CHARACTER =
  "A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF" +
  "\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD" +
  "\\u{10000}-\\u{EFFFF}";
const NAME_CHARACTER = `\\u0300-\\u036F${NAME_START_CHARACTER}.0-9\\u00B7\\u203F-\\u2040\\-`;
const NCNAME = `[${NAME_START_CHARACTER}][${NAME_CHARACTER}]*`;
const QUALIFIED_ATTRIBUTE = new RegExp(`^@(${NCNAME}):(${NCNAME})$`, "u");

// The grammar of a URI reference: https://www.rfc-editor.org/rfc/rfc3986#appendix-A
const REG_NAME_CHARACTER = "[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2}";
const PCHAR = `(?:${REG_NAME_CHARACTER}|[:@])`;
const SEGMENTS = `(?:/${PCHAR}*)*`;
const AUTHORITY =
  `//(?:(?:${REG_NAME_CHARACTER}|:)*@)?` +
  `(?:\\[(?:${REG_NAME_CHARACTER}|:)+\\]|(?:${REG_NAME_CHARACTER})*)(?::[0-9]*)?`;
const hierarchy = (firstSegment: string) =>
  `(?:${AUTHORITY}${SEGMENTS}|/(?:${PCHAR}+${SEGMENTS})?|${firstSegment}${SEGMENTS})?`;
const QUERY_OR_FRAGMENT = `(?:${PCHAR}|[/?])*`;
const URI_REFERENCE = new RegExp(
  `^(?:[A-Za-z][A-Za-z0-9+.-]*:${hierarchy(`${PCHAR}+`)}|${hierarchy(`(?:${REG_NAME_CHARACTER}|@)+`)})` +
    `(?:\\?${QUERY_OR_FRAGMENT})?(?:#${QUERY_OR_FRAGMENT})?$`,
);

// A namespace name is a URI reference, and the `xml` and `xmlns` prefixes and their namespaces
// are reserved: https://www.w3.org/TR/xml-names/#ns-decl
function assertNamespaceName(prefix: string, namespace: string, path: string): void {
  if (!URI_REFERENCE.test(namespace) || (prefix && !namespace)) {
    throw new TypeError(`${path} must be a URI`);
  }
  if (
    prefix === "xmlns" ||
    namespace === XMLNS_NAMESPACE ||
    (prefix === "xml") !== (namespace === XML_NAMESPACE)
  ) {
    throw new TypeError(
      `${path} must leave the "xml" and "xmlns" prefixes and their namespaces as XML defines them`,
    );
  }
}

// xmldom parses an element whose namespaces are not well formed without reporting it:
// https://www.w3.org/TR/xml-names/#Conformance
function assertNamespaces(element: Element, path: string): void {
  const attributes = Array.from(element.attributes);
  const qualified: Attr[] = [];
  for (const attribute of attributes) {
    const { prefix, localName, nodeName, value } = attribute;
    if (prefix === "xmlns" || nodeName === "xmlns") {
      assertNamespaceName(prefix ? localName : "", value, `${path}["@${nodeName}"]`);
    } else if (prefix) {
      qualified.push(attribute);
    }
  }
  const undeclared = [element, ...qualified].find((node) => node.prefix && !node.namespaceURI);
  if (undeclared) {
    throw new TypeError(
      `${path}["${undeclared === element ? "" : "@"}${undeclared.nodeName}"] uses the prefix "${undeclared.prefix}", which is not declared`,
    );
  }
  qualified.forEach((attribute, i) => {
    const earlier = qualified
      .slice(0, i)
      .find(
        (other) =>
          other.namespaceURI === attribute.namespaceURI && other.localName === attribute.localName,
      );
    if (earlier) {
      throw new TypeError(
        `${path}["@${attribute.nodeName}"] repeats "@${earlier.nodeName}": both prefixes name one namespace`,
      );
    }
  });
  for (const child of Array.from(element.childNodes)) {
    if (child.nodeType === child.ELEMENT_NODE) {
      assertNamespaces(child as Element, path);
    }
  }
}

// A key shows neither its namespace nor whether its prefix is declared, since both come from the
// declarations in scope. So what the caller wrote is built as it will be emitted, and read back.
// xmldom does not parse a name outside the Basic Multilingual Plane, so one is reported here:
// signing the metadata parses it the same way.
function build(content: Record<string, unknown>, path: string): Element {
  // Without a handler, xmldom writes what it finds to the console.
  let wellFormed = true;
  const notWellFormed = () => {
    wellFormed = false;
  };
  const built = new xmldom.DOMParser({
    errorHandler: { warning: notWellFormed, error: notWellFormed, fatalError: notWellFormed },
  }).parseFromString(
    buildXmlBuilderObject({ Element: { ...INHERITED_NAMESPACES, ...content } }, false),
    "text/xml",
  ).documentElement;
  if (!wellFormed || built == null) {
    throw new TypeError(`${path} must be well-formed XML`);
  }
  assertNamespaces(built, path);
  return built;
}

// The attributes that https://www.w3.org/2001/xml.xsd, which the metadata schema imports, gives a
// type narrower than a URI.
const XML_ATTRIBUTES: [string, RegExp, string][] = [
  ["lang", new RegExp(`${LANGUAGE_TAG.source}|^$`), 'a language tag, such as "en" or "en-GB"'],
  ["space", /^(?:default|preserve)$/, '"default" or "preserve"'],
  ["id", new RegExp(`^${NCNAME}$`, "u"), "an XML name without a colon"],
];

// The wildcard that admits an attribute from another namespace does not free one that XML Schema
// or the XML namespace defines from its own rule: https://www.w3.org/TR/xmlschema-1/#xsi_type
function assertElement(
  value: unknown,
  path: string,
  keys: string[],
  type: string,
): asserts value is Record<string, unknown> {
  const attributes =
    typeof value === "object" && value !== null
      ? Object.keys(value).filter((key) => QUALIFIED_ATTRIBUTE.test(key))
      : [];
  assertObject(value, path, [...keys, ...attributes]);
  if (attributes.length === 0) {
    return;
  }
  const qualified: Record<string, unknown> = {};
  for (const attribute of attributes) {
    if (typeof value[attribute] !== "string") {
      throw new TypeError(`${path}["${attribute}"] must be a string`);
    }
    qualified[attribute] = value[attribute];
  }
  const built = build(qualified, path);
  for (const { prefix, namespaceURI, localName, nodeName, value: content } of Array.from(
    built.attributes,
  )) {
    if (!prefix || prefix === "xmlns") {
      continue;
    }
    const attributePath = `${path}["@${nodeName}"]`;
    if (namespaceURI === METADATA_NAMESPACE) {
      throw new TypeError(
        `${attributePath} must be in a namespace other than the metadata namespace`,
      );
    }
    if (namespaceURI === XSI_NAMESPACE && localName === "nil") {
      throw new TypeError(`${attributePath} must be left out: the element cannot be nil`);
    }
    if (namespaceURI === XSI_NAMESPACE && localName === "type") {
      const [, typePrefix, typeName] = /^(?:([^:]*):)?(.*)$/.exec(content) as RegExpExecArray;
      const declaration = typePrefix === undefined ? "xmlns" : `xmlns:${typePrefix}`;
      if (built.getAttribute(declaration) !== METADATA_NAMESPACE || typeName !== type) {
        throw new TypeError(`${attributePath} must name the element's own type, ${type}`);
      }
    }
    const rule = XML_ATTRIBUTES.find(
      ([name]) => namespaceURI === XML_NAMESPACE && name === localName,
    );
    if (rule && !rule[1].test(content)) {
      throw new TypeError(`${attributePath} must be ${rule[2]}`);
    }
  }
}

// `ExtensionsType` is one or more elements from a namespace other than the metadata one, and no
// text: SAML 2.0 Metadata, section 2.3.1.
function assertExtensions(parent: Record<string, unknown>, path: string): void {
  const extensions = parent.Extensions;
  if (extensions == null) {
    return;
  }
  if (typeof extensions !== "object" || Array.isArray(extensions)) {
    throw new TypeError(`${path} must be an object of namespace-qualified elements`);
  }
  const declarations: Record<string, unknown> = {};
  for (const key of Object.keys(parent).filter((key) => key.startsWith("@xmlns:"))) {
    declarations[key] = parent[key];
  }
  const built = build({ ...declarations, ...extensions }, path);
  const children = Array.from(built.childNodes);
  const elements = children.filter((node): node is Element => node.nodeType === node.ELEMENT_NODE);

  if (built.namespaceURI !== METADATA_NAMESPACE) {
    throw new TypeError(`${path} must not declare a default namespace of its own`);
  }
  const isText = (node: Node) =>
    node.nodeType === node.TEXT_NODE || node.nodeType === node.CDATA_SECTION_NODE;
  if (children.some((node) => isText(node) && /\S/.test(node.nodeValue ?? ""))) {
    throw new TypeError(`${path} must not hold text`);
  }
  if (elements.length === 0) {
    throw new TypeError(`${path} must hold at least one element`);
  }
  for (const element of elements) {
    if (!element.namespaceURI || element.namespaceURI === METADATA_NAMESPACE) {
      throw new TypeError(
        `${path}["${element.nodeName}"] must be in a namespace other than the metadata namespace`,
      );
    }
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
    assertElement(contact, path, ["@contactType", ...CONTACT_PERSON_CHILDREN], "ContactType");

    const contactType = contact["@contactType"];
    if (typeof contactType !== "string" || !CONTACT_TYPES.includes(contactType)) {
      throw new TypeError(`${path}["@contactType"] must be one of ${CONTACT_TYPES.join(", ")}`);
    }
    assertExtensions(contact, `${path}.Extensions`);
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
  assertElement(organization, "metadataOrganization", ORGANIZATION_CHILDREN, "OrganizationType");
  assertExtensions(organization, "metadataOrganization.Extensions");
  for (const name of LOCALIZED_ORGANIZATION_CHILDREN) {
    assertNonEmptyArray(organization[name], `metadataOrganization.${name}`);
    assertLocalizedNames(organization[name], `metadataOrganization.${name}`);
  }
  (organization.OrganizationURL as { "#text": string }[]).forEach((url, i) => {
    if (!ABSOLUTE_URI.test(url["#text"])) {
      throw new TypeError(
        `metadataOrganization.OrganizationURL[${i}]["#text"] must be an absolute URI, such as "https://example.com"`,
      );
    }
  });
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
      ...INHERITED_NAMESPACES,
      "@entityID": issuer,
      "@ID": generateUniqueId(),
      SPSSODescriptor: {
        "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
        "@AuthnRequestsSigned": "false",
      },
      // `Extensions` is xmlbuilder content the caller built, which its type does not describe.
      ...(metadataOrganization
        ? { Organization: inSchemaOrder(metadataOrganization as XMLValue, ORGANIZATION_CHILDREN) }
        : {}),
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

  assertValidAttributeConsumingServices(params.metadataAttributeConsumingServices);

  // This must be assigned after `AssertionConsumerService` above, because
  // `SPSSODescriptorType` sequences `AssertionConsumerService` before
  // `AttributeConsumingService`. Likewise, the fields below are copied one by
  // one rather than spread, so that the children are emitted in the order
  // `AttributeConsumingServiceType` sequences them, whatever order the caller
  // happened to write them in.
  if (params.metadataAttributeConsumingServices?.length) {
    metadata.EntityDescriptor.SPSSODescriptor.AttributeConsumingService =
      params.metadataAttributeConsumingServices.map((service) => ({
        "@index": service["@index"],
        ...(service["@isDefault"] != null ? { "@isDefault": service["@isDefault"] } : {}),
        ServiceName: service.ServiceName,
        ...(service.ServiceDescription ? { ServiceDescription: service.ServiceDescription } : {}),
        RequestedAttribute: service.RequestedAttribute,
      }));
  }

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
