import * as util from "util";
import * as xmlCrypto from "xml-crypto";
import * as xmlenc from "xml-encryption";
import * as xmldom from "@xmldom/xmldom";
import * as xml2js from "xml2js";
import * as xmlbuilder from "xmlbuilder";
import {
  isValidSamlSigningOptions,
  NameID,
  SamlSigningOptions,
  XmlJsObject,
  XMLOutput,
  XmlSignatureLocation,
} from "./types";
import * as algorithms from "./algorithms";
import { assertRequired } from "./utility";

type SelectedValue = string | number | boolean | Node;

const selectXPath = <T extends SelectedValue>(
  guard: (values: SelectedValue[]) => values is T[],
  node: Node,
  xpath: string
): T[] => {
  const result = xmlCrypto.xpath(node, xpath);
  if (!guard(result)) {
    throw new Error("invalid xpath return type");
  }
  return result;
};

const attributesXPathTypeGuard = (values: SelectedValue[]): values is Attr[] => {
  return values.every((value) => {
    if (typeof value != "object") {
      return false;
    }
    return typeof value.nodeType === "number" && value.nodeType === value.ATTRIBUTE_NODE;
  });
};

const elementsXPathTypeGuard = (values: SelectedValue[]): values is Element[] => {
  return values.every((value) => {
    if (typeof value != "object") {
      return false;
    }
    return typeof value.nodeType === "number" && value.nodeType === value.ELEMENT_NODE;
  });
};

export const xpath = {
  selectAttributes: (node: Node, xpath: string): Attr[] =>
    selectXPath(attributesXPathTypeGuard, node, xpath),
  selectElements: (node: Node, xpath: string): Element[] =>
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
 * This function checks that the |currentNode| in the |fullXml| document contains exactly 1 valid
 *   signature of the |currentNode|.
 *
 * See https://github.com/bergie/passport-saml/issues/19 for references to some of the attack
 *   vectors against SAML signature verification.
 */
export const validateSignature = (
  fullXml: string,
  currentNode: Element,
  pemFiles: string[]
): boolean => {
  const xpathSigQuery =
    ".//*[" +
    "local-name(.)='Signature' and " +
    "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
    "descendant::*[local-name(.)='Reference' and @URI='#" +
    currentNode.getAttribute("ID") +
    "']" +
    "]";
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

/**
 * This function checks that the |signature| is signed with a given |pemFile|.
 */
const validateXmlSignatureWithPemFile = (
  signature: Node,
  pemFile: string,
  fullXml: string,
  currentNode: Element
): boolean => {
  const sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: () => "<X509Data></X509Data>",
    getKey: () => Buffer.from(pemFile),
  };
  sig.loadSignature(signature);
  // We expect each signature to contain exactly one reference to the top level of the xml we
  //   are validating, so if we see anything else, reject.
  if (sig.references.length != 1) return false;
  const refUri = sig.references[0].uri;
  assertRequired(refUri, "signature reference uri not found");
  const refId = refUri[0] === "#" ? refUri.substring(1) : refUri;
  // If we can't find the reference at the top level, reject
  const idAttribute = currentNode.getAttribute("ID") ? "ID" : "Id";
  if (currentNode.getAttribute(idAttribute) != refId) return false;
  // If we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
  //   multiple candidate references is bad news)
  const totalReferencedNodes = xpath.selectElements(
    currentNode.ownerDocument,
    "//*[@" + idAttribute + "='" + refId + "']"
  );

  if (totalReferencedNodes.length > 1) {
    return false;
  }
  fullXml = normalizeNewlines(fullXml);
  return sig.checkSignature(fullXml);
};

export const signXml = (
  xml: string,
  xpath: string,
  location: XmlSignatureLocation,
  options: SamlSigningOptions
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
  sig.addReference(xpath, transforms, algorithms.getDigestAlgorithm(options.digestAlgorithm));
  sig.signingKey = options.privateKey;
  sig.computeSignature(xml, {
    location,
  });

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
      errorHandler: {
        error: errHandler,
        fatalError: errHandler,
      },
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
  const builderOpts = {
    rootName,
    headless: true,
  };
  return new xml2js.Builder(builderOpts).buildObject(xml);
};

export const buildXmlBuilderObject = (xml: XMLOutput, pretty: boolean): string => {
  const options = pretty ? { pretty: true, indent: "  ", newline: "\n" } : {};
  return xmlbuilder.create(xml).end(options);
};

export const promiseWithNameId = async (nameid: Node): Promise<NameID> => {
  const format = xpath.selectAttributes(nameid, "@Format");
  return {
    value: nameid.textContent,
    format: format && format[0] && format[0].nodeValue,
  };
};

export const getNameIdAsync = async (
  doc: Node,
  decryptionPvk: string | Buffer | null
): Promise<NameID> => {
  const nameIds = xpath.selectElements(
    doc,
    "/*[local-name()='LogoutRequest']/*[local-name()='NameID']"
  );
  const encryptedIds = xpath.selectElements(
    doc,
    "/*[local-name()='LogoutRequest']/*[local-name()='EncryptedID']"
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
      "No decryption key found getting name ID for encrypted SAML response"
    );

    const encryptedData = xpath.selectElements(
      encryptedIds[0],
      "./*[local-name()='EncryptedData']"
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
