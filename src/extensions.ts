import * as xmldom from "@xmldom/xmldom";
import * as util from "util";
import { SamlOptions } from "./types";
import { buildXmlBuilderObject } from "./xml";

const debugLog = util.debuglog("node-saml");

export const METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata";
const ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
const PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";
// The namespaces that SAML 2.0 Metadata, section 1.1, lists as SAML's. An extension element or
// attribute must come from any other: SAML 2.0 Core, section 3.2.1, and SAML 2.0 Metadata,
// sections 2.3.2.1 and 2.3.2.2. That is narrower than the schemas' `##other`, and leaves room for
// later OASIS extensions such as `mdui`.
// https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
export const SAML_NAMESPACES = [METADATA_NAMESPACE, ASSERTION_NAMESPACE, PROTOCOL_NAMESPACE];
export const XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE = "http://www.w3.org/2000/xmlns/";

// An `NCName`, which a prefix and a local name each are: https://www.w3.org/TR/xml-names/#NT-NCName
const NAME_START_CHARACTER =
  "A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF" +
  "\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD" +
  "\\u{10000}-\\u{EFFFF}";
const NAME_CHARACTER = `\\u0300-\\u036F${NAME_START_CHARACTER}.0-9\\u00B7\\u203F-\\u2040\\-`;
export const NCNAME = `[${NAME_START_CHARACTER}][${NAME_CHARACTER}]*`;

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
// signing parses the document the same way.
export function build(name: string, content: Record<string, unknown>, path: string): Element {
  // Without a handler, xmldom writes what it finds to the console.
  let wellFormed = true;
  const notWellFormed = () => {
    wellFormed = false;
  };
  const built = new xmldom.DOMParser({
    errorHandler: { warning: notWellFormed, error: notWellFormed, fatalError: notWellFormed },
  }).parseFromString(buildXmlBuilderObject({ [name]: content }, false), "text/xml").documentElement;
  if (!wellFormed || built == null) {
    throw new TypeError(`${path} must be well-formed XML`);
  }
  assertNamespaces(built, path);
  return built;
}

// An `ExtensionsType`, in the metadata schema and in the protocol one, is one or more elements and
// no text. Each element is from a namespace that SAML does not define. `declarations` are the
// ones in scope where the element named `name` is emitted.
export function assertExtensions(
  extensions: unknown,
  path: string,
  name: string,
  declarations: Record<string, unknown>,
): void {
  if (typeof extensions !== "object" || extensions === null || Array.isArray(extensions)) {
    throw new TypeError(`${path} must be an object of namespace-qualified elements`);
  }
  const built = build(name, { ...declarations, ...extensions }, path);
  const children = Array.from(built.childNodes);
  const elements = children.filter((node): node is Element => node.nodeType === node.ELEMENT_NODE);

  const [prefix] = name.includes(":") ? name.split(":") : [""];
  if (built.namespaceURI !== declarations[prefix ? `@xmlns:${prefix}` : "@xmlns"]) {
    throw new TypeError(`${path} must not redeclare the namespace that ${name} itself is in`);
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
    if (!element.namespaceURI || SAML_NAMESPACES.includes(element.namespaceURI)) {
      throw new TypeError(
        `${path}["${element.nodeName}"] must be in a namespace that SAML does not define`,
      );
    }
  }
}

// Declared on the request that each option's `samlp:Extensions` is written into.
const REQUEST_EXTENSIONS = {
  samlAuthnRequestExtensions: { "@xmlns:samlp": PROTOCOL_NAMESPACE },
  samlLogoutRequestExtensions: {
    "@xmlns:samlp": PROTOCOL_NAMESPACE,
    "@xmlns:saml": ASSERTION_NAMESPACE,
  },
};

// Both options are still written into the request as given, so what the check finds is logged and
// not thrown. The next major version throws it.
export const warnIfRequestExtensionsInvalid = (
  options: Pick<SamlOptions, keyof typeof REQUEST_EXTENSIONS>,
): void => {
  for (const option of Object.keys(REQUEST_EXTENSIONS) as (keyof typeof REQUEST_EXTENSIONS)[]) {
    try {
      if (options[option] != null) {
        assertExtensions(options[option], option, "samlp:Extensions", REQUEST_EXTENSIONS[option]);
      }
    } catch (error) {
      debugLog(
        "%s. The request is still built from the option as given, and may not follow SAML. The next major version rejects this instead.",
        (error as Error).message,
      );
    }
  }
};
