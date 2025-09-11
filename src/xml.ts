import * as isDomNode from "@xmldom/is-dom-node";
import * as xmldom from "@xmldom/xmldom";
import * as util from "util";
import * as xmlCrypto from "xml-crypto";
import * as xmlenc from "xml-encryption";
import * as xml2js from "xml2js";
import * as xmlbuilder from "xmlbuilder";
import { select, SelectReturnType } from "xpath";
import * as algorithms from "./algorithms";
import {
  isValidSamlSigningOptions,
  NameID,
  SamlSigningOptions,
  XmlJsObject,
  XMLOutput,
  XmlSignatureLocation,
} from "./types";
import { assertRequired } from "./utility";

const debugLog = util.debuglog("node-saml");

const selectXPath = <T extends Node>(
  guard: (values: SelectReturnType) => values is Array<T>,
  node: Node,
  xpath: string,
): Array<T> => {
  const result = select(xpath, node);
  if (!guard(result)) {
    throw new Error("Invalid xpath return type");
  }
  return result;
};

const attributesXPathTypeGuard = (values: unknown): values is Array<Attr> =>
  isDomNode.isArrayOfNodes(values) && values.every(isDomNode.isAttributeNode);

const elementsXPathTypeGuard = (values: unknown): values is Array<Element> =>
  isDomNode.isArrayOfNodes(values) && values.every(isDomNode.isElementNode);

export const xpath = {
  selectAttributes: (node: Node, xpath: string): Array<Attr> =>
    selectXPath(attributesXPathTypeGuard, node, xpath),
  selectElements: (node: Node, xpath: string): Array<Element> =>
    selectXPath(elementsXPathTypeGuard, node, xpath),
};

export const decryptXml = async (xml: string, decryptionKey: string | Buffer) =>
  util.promisify(xmlenc.decrypt).bind(xmlenc)(xml, { key: decryptionKey });

/**
 * we can use this utility before passing XML to `xml-crypto`
 * we are considered the XML processor and are responsible for newline normalization
 * https://github.com/node-saml/passport-saml/issues/431#issuecomment-718132752
 */
const normalizeNewlines = (xml: string): string => {
  return xml.replace(/\r\n?/g, "\n");
};

/**
 * // modeled after the current validateSignature method, to maintain consistency for unit tests
 * Input: fullXml, the document for SignedXML context
 * Input: currentNode, this node must have a Signature
 * Input: pemFiles: a list of pem encoded certificates that are trusted. User is responsible for ensuring trust
 * Find's a signature for the currentNode
 * Return the verified contents if verified?
 * Otherwise returns null
 * */
export const getVerifiedXml = (
  fullXml: string,
  currentNode: Element,
  pemFiles: string[],
): string | null => {
  fullXml = normalizeNewlines(fullXml);

  // find any signature
  const signatures = xpath.selectElements(
    currentNode,
    "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
  );
  if (signatures.length < 1) {
    return null;
  }

  if (signatures.length > 1) {
    throw new Error("Too many signatures found for this element");
  }

  const signature = signatures[0];

  const xpathTransformQuery =
    ".//*[local-name(.)='Transform' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
  const transforms = xpath.selectElements(signature, xpathTransformQuery);
  // Reject also XMLDSIG with more than 2 Transform
  if (transforms.length > 2) {
    // do not return false, throw an error so that it can be caught by tests differently
    throw new Error("Invalid signature, too many transforms");
  }

  for (const pemFile of pemFiles) {
    const sig = new xmlCrypto.SignedXml();
    sig.publicCert = pemFile; // public certificate to verify
    sig.loadSignature(signature);

    // here are the sanity checks
    // They do not affect the actual security of the program
    // more so to check conformance with the SAML spec
    const refs = sig.getReferences();

    if (refs.length !== 1) return null;
    if (!signature.parentNode) {
      return null;
    }

    const ref = refs[0];

    // only allow enveloped signature
    const refUri = ref.uri;

    const refId = refUri[0] === "#" ? refUri.substring(1) : refUri;

    assertRequired(refId, "signature reference uri not found");
    // prevent XPath injection
    if (refId.includes("'") || refId.includes('"')) {
      throw new Error("ref URI included quote character ' or \". Not a valid ID, and not allowed");
    }

    const totalReferencedNodes = xpath.selectElements(
      signature.ownerDocument,
      `//*[@ID="${refId}"]`,
    );

    if (totalReferencedNodes.length !== 1) {
      throw new Error("Invalid signature: ID cannot refer to more than one element");
    }

    if (totalReferencedNodes[0] !== signature.parentNode) {
      throw new Error("Invalid signature: Referenced node does not refer to its parent element");
    }

    // actual cryptographic verification
    // after verification, the referenced XML will be in `sig.signedReferences`
    // do not trust any other xml (including referencedNode)

    try {
      if (!sig.checkSignature(fullXml)) {
        continue; // no signatures verified
      }

      if (sig.getSignedReferences().length !== 1) {
        throw new Error("Only 1 signed references should be present in signature");
      }

      return sig.getSignedReferences()[0];
    } catch {
      // return null; // we don't return null, since we have to verify with another key
    }
  }

  return null;
};

/**
 * Internally deprecated Do not only return boolean value, instead return the actual signed content. SAML Libraries must only use the referenced bytes from the signature
 * This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
 *   signature of the |currentNode|.
 *
 * See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
 *   vectors against SAML signature verification.
 */

const _validateSignature = (fullXml: string, currentNode: Element, pemFiles: string[]): boolean => {
  const xpathSigQuery = `.//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and descendant::*[local-name(.)='Reference' and @URI='#${currentNode.getAttribute("ID")}']]`;
  const signatures = xpath.selectElements(currentNode, xpathSigQuery);
  // This function is expecting to validate exactly one signature, so if we find more or fewer
  //   than that, reject.
  if (signatures.length !== 1) {
    return false;
  }
  const xpathTransformQuery =
    ".//*[" +
    "local-name(.)='Transform' and " +
    "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
    "ancestor::*[local-name(.)='Reference' and @URI='#" +
    currentNode.getAttribute("ID") +
    "']" +
    "]";
  const transforms = xpath.selectElements(currentNode, xpathTransformQuery);
  // Reject also XMLDSIG with more than 2 Transform
  if (transforms.length > 2) {
    // do not return false, throw an error so that it can be caught by tests differently
    throw new Error("Invalid signature, too many transforms");
  }

  const signature = signatures[0];
  return pemFiles.some((pemFile) => {
    return validateXmlSignatureWithPemFile(signature, pemFile, fullXml, currentNode);
  });
};

// validateSignature is deprecated, should be using getVerifiedXml
// Existing non-sensitive callers can still use validateSignature
// but new callers should use getVerifiedXml
// this allows us to deprecate it without raising a warning
export const validateSignature = _validateSignature;

/**
 * This function checks that the |signature| is signed with a given |pemFile|.
 * Internally deprecated, users should not be using this for anything new
 */
const validateXmlSignatureWithPemFile = (
  signature: Node,
  pemFile: string,
  fullXml: string,
  currentNode: Element,
): boolean => {
  const sig = new xmlCrypto.SignedXml();
  sig.publicCert = pemFile;
  sig.loadSignature(signature);
  // We expect each signature to contain exactly one reference to the top level of the xml we
  //   are validating, so if we see anything else, reject.
  if (sig.getReferences().length !== 1) return false;
  const t = sig.getReferences();
  const refUri = t[0].uri;
  assertRequired(refUri, "signature reference uri not found");
  const refId = refUri[0] === "#" ? refUri.substring(1) : refUri;
  // If we can't find the reference at the top level, reject
  const idAttribute = currentNode.getAttribute("ID") ? "ID" : "Id";
  if (currentNode.getAttribute(idAttribute) != refId) return false;
  // If we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
  //   multiple candidate references is bad news)
  const totalReferencedNodes = xpath.selectElements(
    currentNode.ownerDocument,
    "//*[@" + idAttribute + "='" + refId + "']",
  );

  if (totalReferencedNodes.length > 1) {
    return false;
  }
  fullXml = normalizeNewlines(fullXml);

  try {
    return sig.checkSignature(fullXml);
  } catch (err) {
    debugLog.enabled && debugLog("signature check resulted in an error: %s", err);
    return false;
  }
};

export const signXml = (
  xml: string,
  xpath: string,
  location: XmlSignatureLocation,
  options: SamlSigningOptions,
): string => {
  const defaultTransforms = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
  ];

  if (!xml) throw new Error("samlMessage is required");
  if (!location) throw new Error("location is required");
  if (!options) throw new Error("options is required");
  if (!isValidSamlSigningOptions(options)) throw new Error("options.privateKey is required");

  const transforms = options.xmlSignatureTransforms ?? defaultTransforms;
  const sig = new xmlCrypto.SignedXml();
  if (options.signatureAlgorithm != null) {
    sig.signatureAlgorithm = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  }
  sig.addReference({
    xpath,
    transforms,
    digestAlgorithm: algorithms.getDigestAlgorithm(options.digestAlgorithm),
  });
  sig.privateKey = options.privateKey;
  sig.publicCert = options.publicCert;
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.computeSignature(xml, { location });

  return sig.getSignedXml();
};

export const parseDomFromString = (xml: string): Promise<Document> => {
  return new Promise(function (resolve, reject) {
    function errHandler(msg: string) {
      return reject(new Error(msg));
    }

    const dom = new xmldom.DOMParser({
      /**
       * locator is always need for error position info
       */
      locator: {},
      /**
       * you can override the errorHandler for xml parser
       * @link http://www.saxproject.org/apidoc/org/xml/sax/ErrorHandler.html
       */
      errorHandler: { error: errHandler, fatalError: errHandler },
    }).parseFromString(xml, "text/xml");

    if (!Object.prototype.hasOwnProperty.call(dom, "documentElement")) {
      return reject(new Error("Not a valid XML document"));
    }

    return resolve(dom);
  });
};

export const parseXml2JsFromString = async (xml: string | Buffer): Promise<XmlJsObject> => {
  const parserConfig = {
    explicitRoot: true,
    explicitCharkey: true,
    tagNameProcessors: [xml2js.processors.stripPrefix],
  };
  const parser = new xml2js.Parser(parserConfig);
  return parser.parseStringPromise(xml);
};

export const buildXml2JsObject = (rootName: string, xml: XmlJsObject): string => {
  const builderOpts = { rootName, headless: true };
  return new xml2js.Builder(builderOpts).buildObject(xml);
};

export const buildXmlBuilderObject = (xml: XMLOutput, pretty: boolean): string => {
  const options = pretty ? { pretty: true, indent: "  ", newline: "\n" } : {};
  return xmlbuilder.create(xml).end(options);
};

export const promiseWithNameId = async (nameid: Node): Promise<NameID> => {
  const format = xpath.selectAttributes(nameid, "@Format");
  return { value: nameid.textContent, format: format && format[0] && format[0].nodeValue };
};

export const getNameIdAsync = async (
  doc: Node,
  decryptionPvk: string | Buffer | null,
): Promise<NameID> => {
  const nameIds = xpath.selectElements(
    doc,
    "/*[local-name()='LogoutRequest']/*[local-name()='NameID']",
  );
  const encryptedIds = xpath.selectElements(
    doc,
    "/*[local-name()='LogoutRequest']/*[local-name()='EncryptedID']",
  );

  if (nameIds.length + encryptedIds.length > 1) {
    throw new Error("Invalid LogoutRequest: multiple ID elements");
  }
  if (nameIds.length === 1) {
    return promiseWithNameId(nameIds[0]);
  }
  if (encryptedIds.length === 1) {
    assertRequired(
      decryptionPvk,
      "No decryption key found getting name ID for encrypted SAML response",
    );

    const encryptedData = xpath.selectElements(
      encryptedIds[0],
      "./*[local-name()='EncryptedData']",
    );

    if (encryptedData.length !== 1) {
      throw new Error("Invalid LogoutRequest: no EncryptedData element found");
    }
    const encryptedDataXml = encryptedData[0].toString();

    const decryptedXml = await decryptXml(encryptedDataXml, decryptionPvk);
    const decryptedDoc = await parseDomFromString(decryptedXml);
    const decryptedIds = xpath.selectElements(decryptedDoc, "/*[local-name()='NameID']");
    if (decryptedIds.length !== 1) {
      throw new Error("Invalid EncryptedData content");
    }
    return await promiseWithNameId(decryptedIds[0]);
  }
  throw new Error("Missing SAML NameID");
};
