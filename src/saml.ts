import Debug from "debug";
const debug = Debug("node-saml");
import * as zlib from "zlib";
import * as crypto from "crypto";
import { URL } from "url";
import * as querystring from "querystring";
import * as util from "util";
import { InMemoryCacheProvider } from "./inmemory-cache-provider";
import * as algorithms from "./algorithms";
import { ParsedQs } from "qs";
import {
  isValidSamlSigningOptions,
  AudienceRestrictionXML,
  CacheProvider,
  CertCallback,
  ErrorWithXmlStatus,
  Profile,
  SamlOptions,
  SamlConfig,
  XMLOutput,
  ValidateInResponseTo,
} from "./types";
import { AuthenticateOptions, AuthorizeOptions } from "./passport-saml-types";
import { assertBooleanIfPresent, assertRequired } from "./utility";
import {
  buildXml2JsObject,
  decryptXml,
  parseDomFromString,
  parseXml2JsFromString,
  validateSignature,
  xpath,
} from "./xml";
import { certToPEM, generateUniqueId, keyToPEM } from "./crypto";
import { dateStringToTimestamp } from "./datetime";
import {
  generateAuthorizeRequestAsync,
  generateServiceProviderMetadata,
  _generateLogoutRequest,
  _generateLogoutResponse,
} from "./saml/generate";
import {
  processValidlySignedAssertionAsync,
  processValidlySignedPostRequestAsync,
  processValidlySignedSamlLogoutAsync,
} from "./saml/process";

const inflateRawAsync = util.promisify(zlib.inflateRaw);
const deflateRawAsync = util.promisify(zlib.deflateRaw);

class SAML {
  /**
   * Note that some methods in SAML are not yet marked as protected as they are used in testing.
   * Those methods start with an underscore, e.g. _generateLogoutRequest
   */
  options: SamlOptions;
  // This is only for testing
  cacheProvider: CacheProvider;

  constructor(ctorOptions: SamlConfig) {
    this.options = this.initialize(ctorOptions);
    this.cacheProvider = this.options.cacheProvider;
  }

  initialize(ctorOptions: SamlConfig): SamlOptions {
    if (!ctorOptions) {
      throw new TypeError("SamlOptions required on construction");
    }

    assertRequired(ctorOptions.issuer, "issuer is required");
    assertRequired(ctorOptions.cert, "cert is required");

    // Prevent a JS user from passing in "false", which is truthy, and doing the wrong thing
    assertBooleanIfPresent(ctorOptions.passive);
    assertBooleanIfPresent(ctorOptions.disableRequestedAuthnContext);
    assertBooleanIfPresent(ctorOptions.forceAuthn);
    assertBooleanIfPresent(ctorOptions.skipRequestCompression);
    assertBooleanIfPresent(ctorOptions.disableRequestAcsUrl);
    assertBooleanIfPresent(ctorOptions.allowCreate);
    assertBooleanIfPresent(ctorOptions.wantAssertionsSigned);
    assertBooleanIfPresent(ctorOptions.signMetadata);

    const options: SamlOptions = {
      ...ctorOptions,
      passive: ctorOptions.passive ?? false,
      disableRequestedAuthnContext: ctorOptions.disableRequestedAuthnContext ?? false,
      additionalParams: ctorOptions.additionalParams ?? {},
      additionalAuthorizeParams: ctorOptions.additionalAuthorizeParams ?? {},
      additionalLogoutParams: ctorOptions.additionalLogoutParams ?? {},
      forceAuthn: ctorOptions.forceAuthn ?? false,
      skipRequestCompression: ctorOptions.skipRequestCompression ?? false,
      disableRequestAcsUrl: ctorOptions.disableRequestAcsUrl ?? false,
      acceptedClockSkewMs: ctorOptions.acceptedClockSkewMs ?? 0,
      maxAssertionAgeMs: ctorOptions.maxAssertionAgeMs ?? 0,
      path: ctorOptions.path ?? "/saml/consume",
      host: ctorOptions.host ?? "localhost",
      issuer: ctorOptions.issuer,
      audience: ctorOptions.audience ?? ctorOptions.issuer ?? "unknown_audience", // use issuer as default
      identifierFormat:
        ctorOptions.identifierFormat === undefined
          ? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
          : ctorOptions.identifierFormat,
      allowCreate: ctorOptions.allowCreate ?? true,
      spNameQualifier: ctorOptions.spNameQualifier,
      wantAssertionsSigned: ctorOptions.wantAssertionsSigned ?? false,
      authnContext: ctorOptions.authnContext ?? [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      validateInResponseTo: ctorOptions.validateInResponseTo ?? ValidateInResponseTo.never,
      cert: ctorOptions.cert,
      requestIdExpirationPeriodMs: ctorOptions.requestIdExpirationPeriodMs ?? 28800000, // 8 hours
      cacheProvider:
        ctorOptions.cacheProvider ??
        new InMemoryCacheProvider({
          keyExpirationPeriodMs: ctorOptions.requestIdExpirationPeriodMs,
        }),
      logoutUrl: ctorOptions.logoutUrl ?? ctorOptions.entryPoint ?? "", // Default to Entry Point
      signatureAlgorithm: ctorOptions.signatureAlgorithm ?? "sha1", // sha1, sha256, or sha512
      authnRequestBinding: ctorOptions.authnRequestBinding ?? "HTTP-Redirect",
      generateUniqueId: ctorOptions.generateUniqueId ?? generateUniqueId,
      signMetadata: ctorOptions.signMetadata ?? false,
      racComparison: ctorOptions.racComparison ?? "exact",
    };

    /**
     * List of possible values:
     * - exact : Assertion context must exactly match a context in the list
     * - minimum:  Assertion context must be at least as strong as a context in the list
     * - maximum:  Assertion context must be no stronger than a context in the list
     * - better:  Assertion context must be stronger than all contexts in the list
     */
    if (!["exact", "minimum", "maximum", "better"].includes(options.racComparison)) {
      throw new TypeError("racComparison must be one of ['exact', 'minimum', 'maximum', 'better']");
    }

    return options;
  }

  protected getCallbackUrl(host?: string | undefined): string {
    // Post-auth destination
    if (this.options.callbackUrl) {
      return this.options.callbackUrl;
    } else {
      const url = new URL("http://localhost");
      if (host) {
        url.host = host;
      } else {
        url.host = this.options.host;
      }
      if (this.options.protocol) {
        url.protocol = this.options.protocol;
      }
      url.pathname = this.options.path;
      return url.toString();
    }
  }

  protected signRequest(samlMessage: querystring.ParsedUrlQueryInput): void {
    assertRequired(this.options.privateKey, "privateKey is required");

    const samlMessageToSign: querystring.ParsedUrlQueryInput = {};
    samlMessage.SigAlg = algorithms.getSigningAlgorithm(this.options.signatureAlgorithm);
    const signer = algorithms.getSigner(this.options.signatureAlgorithm);
    if (samlMessage.SAMLRequest) {
      samlMessageToSign.SAMLRequest = samlMessage.SAMLRequest;
    }
    if (samlMessage.SAMLResponse) {
      samlMessageToSign.SAMLResponse = samlMessage.SAMLResponse;
    }
    if (samlMessage.RelayState) {
      samlMessageToSign.RelayState = samlMessage.RelayState;
    }
    if (samlMessage.SigAlg) {
      samlMessageToSign.SigAlg = samlMessage.SigAlg;
    }
    signer.update(querystring.stringify(samlMessageToSign));
    samlMessage.Signature = signer.sign(keyToPEM(this.options.privateKey), "base64");
  }

  protected generateAuthorizeRequestAsync = generateAuthorizeRequestAsync;

  _generateLogoutRequest = _generateLogoutRequest;

  _generateLogoutResponse = _generateLogoutResponse;

  async _requestToUrlAsync(
    request: string | null | undefined,
    response: string | null,
    operation: string,
    additionalParameters: querystring.ParsedUrlQuery
  ): Promise<string> {
    assertRequired(this.options.entryPoint, "entryPoint is required");
    const requestOrResponse = request || response;
    assertRequired(requestOrResponse, "either request or response is required");

    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from(requestOrResponse, "utf8");
    } else {
      buffer = await deflateRawAsync(requestOrResponse);
    }

    const base64 = buffer.toString("base64");
    let target = new URL(this.options.entryPoint);

    if (operation === "logout") {
      if (this.options.logoutUrl) {
        target = new URL(this.options.logoutUrl);
      }
    } else if (operation !== "authorize") {
      throw new Error("Unknown operation: " + operation);
    }

    const samlMessage: querystring.ParsedUrlQuery = request
      ? {
          SAMLRequest: base64,
        }
      : {
          SAMLResponse: base64,
        };
    Object.keys(additionalParameters).forEach((k) => {
      samlMessage[k] = additionalParameters[k];
    });
    if (isValidSamlSigningOptions(this.options)) {
      if (!this.options.entryPoint) {
        throw new Error('"entryPoint" config parameter is required for signed messages');
      }

      // sets .SigAlg and .Signature
      this.signRequest(samlMessage);
    }
    Object.keys(samlMessage).forEach((k) => {
      target.searchParams.set(k, samlMessage[k] as string);
    });

    return target.toString();
  }

  _getAdditionalParams(
    relayState: string,
    operation: "authorize" | "logout",
    overrideParams?: querystring.ParsedUrlQuery
  ): querystring.ParsedUrlQuery {
    const additionalParams: querystring.ParsedUrlQuery = {};

    if (typeof relayState === "string" && relayState.length > 0) {
      additionalParams.RelayState = relayState;
    }

    return Object.assign(
      additionalParams,
      this.options.additionalParams,
      operation === "logout"
        ? this.options.additionalLogoutParams
        : this.options.additionalAuthorizeParams,
      overrideParams ?? {}
    );
  }

  async getAuthorizeUrlAsync(
    RelayState: string,
    host: string | undefined,
    options: AuthorizeOptions
  ): Promise<string> {
    const request = await this.generateAuthorizeRequestAsync(this.options.passive, false, host);
    const operation = "authorize";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      request,
      null,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams)
    );
  }

  async getAuthorizeFormAsync(RelayState: string, host?: string): Promise<string> {
    assertRequired(this.options.entryPoint, "entryPoint is required");

    // The quoteattr() function is used in a context, where the result will not be evaluated by javascript
    // but must be interpreted by an XML or HTML parser, and it must absolutely avoid breaking the syntax
    // of an element attribute.
    const quoteattr = function (
      s:
        | string
        | number
        | boolean
        | undefined
        | null
        | readonly string[]
        | readonly number[]
        | readonly boolean[],
      preserveCR?: boolean
    ) {
      const preserveCRChar = preserveCR ? "&#13;" : "\n";
      return (
        ("" + s) // Forces the conversion to string.
          .replace(/&/g, "&amp;") // This MUST be the 1st replacement.
          .replace(/'/g, "&apos;") // The 4 other predefined entities, required.
          .replace(/"/g, "&quot;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          // Add other replacements here for HTML only
          // Or for XML, only if the named entities are defined in its DTD.
          .replace(/\r\n/g, preserveCRChar) // Must be before the next replacement.
          .replace(/[\r\n]/g, preserveCRChar)
      );
    };

    const request = await this.generateAuthorizeRequestAsync(this.options.passive, true, host);
    let buffer: Buffer;
    if (this.options.skipRequestCompression) {
      buffer = Buffer.from(request, "utf8");
    } else {
      buffer = await deflateRawAsync(request);
    }

    const operation = "authorize";
    const additionalParameters = this._getAdditionalParams(RelayState, operation);
    const samlMessage: querystring.ParsedUrlQueryInput = {
      SAMLRequest: buffer.toString("base64"),
    };

    Object.keys(additionalParameters).forEach((k) => {
      samlMessage[k] = additionalParameters[k] || "";
    });

    const formInputs = Object.keys(samlMessage)
      .map((k) => {
        return '<input type="hidden" name="' + k + '" value="' + quoteattr(samlMessage[k]) + '" />';
      })
      .join("\r\n");

    return [
      "<!DOCTYPE html>",
      "<html>",
      "<head>",
      '<meta charset="utf-8">',
      '<meta http-equiv="x-ua-compatible" content="ie=edge">',
      "</head>",
      '<body onload="document.forms[0].submit()">',
      "<noscript>",
      "<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>",
      "</noscript>",
      '<form method="post" action="' + encodeURI(this.options.entryPoint) + '">',
      formInputs,
      '<input type="submit" value="Submit" />',
      "</form>",
      '<script>document.forms[0].style.display="none";</script>', // Hide the form if JavaScript is enabled
      "</body>",
      "</html>",
    ].join("\r\n");
  }

  async getLogoutUrlAsync(
    user: Profile,
    RelayState: string,
    options: AuthenticateOptions & AuthorizeOptions
  ): Promise<string> {
    const request = await this._generateLogoutRequest(user);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      request,
      null,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams)
    );
  }

  getLogoutResponseUrl(
    samlLogoutRequest: Profile,
    RelayState: string,
    options: AuthenticateOptions & AuthorizeOptions,
    success: boolean,
    callback: (err: Error | null, url?: string) => void
  ): void {
    util.callbackify(() =>
      this.getLogoutResponseUrlAsync(samlLogoutRequest, RelayState, options, success)
    )(callback);
  }

  protected async getLogoutResponseUrlAsync(
    samlLogoutRequest: Profile,
    RelayState: string,
    options: AuthenticateOptions & AuthorizeOptions,
    success: boolean
  ): Promise<string> {
    const response = this._generateLogoutResponse(samlLogoutRequest, success);
    const operation = "logout";
    const overrideParams = options ? options.additionalParams || {} : {};
    return await this._requestToUrlAsync(
      null,
      response,
      operation,
      this._getAdditionalParams(RelayState, operation, overrideParams)
    );
  }

  protected async certsToCheck(): Promise<string[]> {
    let checkedCerts: string[];

    if (typeof this.options.cert === "function") {
      checkedCerts = await util
        .promisify(this.options.cert as CertCallback)()
        .then((certs) => {
          assertRequired(certs, "callback didn't return cert");
          if (!Array.isArray(certs)) {
            certs = [certs];
          }
          return certs;
        });
    } else if (Array.isArray(this.options.cert)) {
      checkedCerts = this.options.cert;
    } else {
      checkedCerts = [this.options.cert];
    }

    checkedCerts.forEach((cert) => {
      assertRequired(cert, "unknown cert found");
    });

    return checkedCerts;
  }

  async validatePostResponseAsync(
    container: Record<string, string>
  ): Promise<{ profile: Profile | null; loggedOut: boolean }> {
    let xml: string;
    let doc: Document;
    let inResponseTo: string | null = null;

    try {
      xml = Buffer.from(container.SAMLResponse, "base64").toString("utf8");
      doc = parseDomFromString(xml);

      if (!Object.prototype.hasOwnProperty.call(doc, "documentElement"))
        throw new Error("SAMLResponse is not valid base64-encoded XML");

      const inResponseToNodes = xpath.selectAttributes(
        doc,
        "/*[local-name()='Response']/@InResponseTo"
      );

      if (inResponseToNodes) {
        inResponseTo = inResponseToNodes.length ? inResponseToNodes[0].nodeValue : null;

        await this.validateInResponseTo(inResponseTo);
      }
      const certs = await this.certsToCheck();
      // Check if this document has a valid top-level signature
      let validSignature = false;
      if (validateSignature(xml, doc.documentElement, certs)) {
        validSignature = true;
      }

      const assertions = xpath.selectElements(
        doc,
        "/*[local-name()='Response']/*[local-name()='Assertion']"
      );
      const encryptedAssertions = xpath.selectElements(
        doc,
        "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']"
      );

      if (assertions.length + encryptedAssertions.length > 1) {
        // There's no reason I know of that we want to handle multiple assertions, and it seems like a
        //   potential risk vector for signature scope issues, so treat this as an invalid signature
        throw new Error("Invalid signature: multiple assertions");
      }

      if (assertions.length == 1) {
        if (
          (this.options.wantAssertionsSigned || !validSignature) &&
          !validateSignature(xml, assertions[0], certs)
        ) {
          throw new Error("Invalid signature");
        }

        return await this.processValidlySignedAssertionAsync(
          assertions[0].toString(),
          xml,
          inResponseTo
        );
      }

      if (encryptedAssertions.length == 1) {
        assertRequired(this.options.decryptionPvk, "No decryption key for encrypted SAML response");

        const encryptedAssertionXml = encryptedAssertions[0].toString();

        const decryptedXml = await decryptXml(encryptedAssertionXml, this.options.decryptionPvk);
        const decryptedDoc = parseDomFromString(decryptedXml);
        const decryptedAssertions = xpath.selectElements(
          decryptedDoc,
          "/*[local-name()='Assertion']"
        );
        if (decryptedAssertions.length != 1) throw new Error("Invalid EncryptedAssertion content");

        if (
          (this.options.wantAssertionsSigned || !validSignature) &&
          !validateSignature(decryptedXml, decryptedAssertions[0], certs)
        ) {
          throw new Error("Invalid signature from encrypted assertion");
        }

        return await this.processValidlySignedAssertionAsync(
          decryptedAssertions[0].toString(),
          xml,
          inResponseTo
        );
      }

      // If there's no assertion, fall back on xml2js response parsing for the status &
      //   LogoutResponse code.

      const xmljsDoc = await parseXml2JsFromString(xml);
      const response = xmljsDoc.Response;
      if (response) {
        const assertion = response.Assertion;
        if (!assertion) {
          const status = response.Status;
          if (status) {
            const statusCode = status[0].StatusCode;
            if (
              statusCode &&
              statusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:Responder"
            ) {
              const nestedStatusCode = statusCode[0].StatusCode;
              if (
                nestedStatusCode &&
                nestedStatusCode[0].$.Value === "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
              ) {
                if (!validSignature) {
                  throw new Error("Invalid signature: NoPassive");
                }
                return { profile: null, loggedOut: false };
              }
            }

            // Note that we're not requiring a valid signature before this logic -- since we are
            //   throwing an error in any case, and some providers don't sign error results,
            //   let's go ahead and give the potentially more helpful error.
            if (statusCode && statusCode[0].$.Value) {
              const msgType = statusCode[0].$.Value.match(/[^:]*$/)[0];
              if (msgType != "Success") {
                let msg = "unspecified";
                if (status[0].StatusMessage) {
                  msg = status[0].StatusMessage[0]._;
                } else if (statusCode[0].StatusCode) {
                  msg = statusCode[0].StatusCode[0].$.Value.match(/[^:]*$/)[0];
                }
                const statusXml = buildXml2JsObject("Status", status[0]);
                throw new ErrorWithXmlStatus(
                  "SAML provider returned " + msgType + " error: " + msg,
                  statusXml
                );
              }
            }
          }
        }
        throw new Error("Missing SAML assertion");
      } else {
        if (!validSignature) {
          throw new Error("Invalid signature: No response found");
        }
        const logoutResponse = xmljsDoc.LogoutResponse;
        if (logoutResponse) {
          return { profile: null, loggedOut: true };
        } else {
          throw new Error("Unknown SAML response message");
        }
      }
    } catch (err) {
      debug("validatePostResponse resulted in an error: %s", err);
      if (this.mustValidateInResponseTo(Boolean(inResponseTo))) {
        await this.cacheProvider.removeAsync(inResponseTo);
      }
      throw err;
    }
  }

  protected async validateInResponseTo(inResponseTo: string | null): Promise<void> {
    if (this.mustValidateInResponseTo(Boolean(inResponseTo))) {
      if (inResponseTo) {
        const result = await this.cacheProvider.getAsync(inResponseTo);
        if (!result) throw new Error("InResponseTo is not valid");
        return;
      } else {
        throw new Error("InResponseTo is missing from response");
      }
    }
  }

  async validateRedirectAsync(
    container: ParsedQs,
    originalQuery: string
  ): Promise<{ profile: Profile | null; loggedOut: boolean }> {
    const samlMessageType = container.SAMLRequest ? "SAMLRequest" : "SAMLResponse";

    const data = Buffer.from(container[samlMessageType] as string, "base64");
    const inflated = await inflateRawAsync(data);

    const dom = parseDomFromString(inflated.toString());
    const doc: XMLOutput = await parseXml2JsFromString(inflated);
    samlMessageType === "SAMLResponse"
      ? await this.verifyLogoutResponse(doc)
      : this.verifyLogoutRequest(doc);
    await this.hasValidSignatureForRedirect(container, originalQuery);
    return await this.processValidlySignedSamlLogoutAsync(doc, dom);
  }

  protected async hasValidSignatureForRedirect(
    container: ParsedQs,
    originalQuery: string
  ): Promise<boolean | void> {
    const tokens = originalQuery.split("&");
    const getParam = (key: string) => {
      const exists = tokens.filter((t) => {
        return new RegExp(key).test(t);
      });
      return exists[0];
    };

    if (container.Signature) {
      let urlString = getParam("SAMLRequest") || getParam("SAMLResponse");

      if (getParam("RelayState")) {
        urlString += "&" + getParam("RelayState");
      }

      urlString += "&" + getParam("SigAlg");

      const certs = await this.certsToCheck();
      const hasValidQuerySignature = certs.some((cert) => {
        return this.validateSignatureForRedirect(
          urlString,
          container.Signature as string,
          container.SigAlg as string,
          cert
        );
      });
      if (!hasValidQuerySignature) {
        throw new Error("Invalid query signature");
      }
    } else {
      return true;
    }
  }

  protected validateSignatureForRedirect(
    urlString: crypto.BinaryLike,
    signature: string,
    alg: string,
    cert: string
  ): boolean {
    // See if we support a matching algorithm, case-insensitive. Otherwise, throw error.
    function hasMatch(ourAlgo: string) {
      // The incoming algorithm is forwarded as a URL.
      // We trim everything before the last # get something we can compare to the Node.js list
      const algFromURI = alg.toLowerCase().replace(/.*#(.*)$/, "$1");
      return ourAlgo.toLowerCase() === algFromURI;
    }
    const i = crypto.getHashes().findIndex(hasMatch);
    let matchingAlgo;
    if (i > -1) {
      matchingAlgo = crypto.getHashes()[i];
    } else {
      throw new Error(alg + " is not supported");
    }

    const verifier = crypto.createVerify(matchingAlgo);
    verifier.update(urlString);

    return verifier.verify(certToPEM(cert), signature, "base64");
  }

  protected verifyLogoutRequest(doc: XMLOutput): void {
    this.verifyIssuer(doc.LogoutRequest);
    const nowMs = new Date().getTime();
    const conditions = doc.LogoutRequest.$;
    const conErr = this.checkTimestampsValidityError(
      nowMs,
      conditions.NotBefore,
      conditions.NotOnOrAfter
    );
    if (conErr) {
      throw conErr;
    }
  }

  protected async verifyLogoutResponse(doc: XMLOutput): Promise<void> {
    const statusCode = doc.LogoutResponse.Status[0].StatusCode[0].$.Value;
    if (statusCode !== "urn:oasis:names:tc:SAML:2.0:status:Success")
      throw new Error("Bad status code: " + statusCode);

    this.verifyIssuer(doc.LogoutResponse);
    const inResponseTo = doc.LogoutResponse.$.InResponseTo;
    if (inResponseTo) {
      return this.validateInResponseTo(inResponseTo);
    }

    return;
  }

  protected verifyIssuer(samlMessage: XMLOutput): void {
    if (this.options.idpIssuer != null) {
      const issuer = samlMessage.Issuer;
      if (issuer) {
        if (issuer[0]._ !== this.options.idpIssuer)
          throw new Error(
            "Unknown SAML issuer. Expected: " + this.options.idpIssuer + " Received: " + issuer[0]._
          );
      } else {
        throw new Error("Missing SAML issuer");
      }
    }
  }

  protected processValidlySignedAssertionAsync = processValidlySignedAssertionAsync;

  protected checkTimestampsValidityError(
    nowMs: number,
    notBefore: string,
    notOnOrAfter: string,
    maxTimeLimitMs?: number
  ): Error | null {
    if (this.options.acceptedClockSkewMs == -1) return null;

    if (notBefore) {
      const notBeforeMs = dateStringToTimestamp(notBefore, "NotBefore");
      if (nowMs + this.options.acceptedClockSkewMs < notBeforeMs)
        return new Error("SAML assertion not yet valid");
    }
    if (notOnOrAfter) {
      const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
      if (nowMs - this.options.acceptedClockSkewMs >= notOnOrAfterMs)
        return new Error("SAML assertion expired: clocks skewed too much");
    }
    if (maxTimeLimitMs) {
      if (nowMs - this.options.acceptedClockSkewMs >= maxTimeLimitMs)
        return new Error("SAML assertion expired: assertion too old");
    }

    return null;
  }

  protected checkAudienceValidityError(
    expectedAudience: string,
    audienceRestrictions: AudienceRestrictionXML[]
  ): Error | null {
    if (!audienceRestrictions || audienceRestrictions.length < 1) {
      return new Error("SAML assertion has no AudienceRestriction");
    }
    const errors = audienceRestrictions
      .map((restriction) => {
        if (!restriction.Audience || !restriction.Audience[0] || !restriction.Audience[0]._) {
          return new Error("SAML assertion AudienceRestriction has no Audience value");
        }
        if (restriction.Audience[0]._ !== expectedAudience) {
          return new Error("SAML assertion audience mismatch");
        }
        return null;
      })
      .filter((result) => {
        return result !== null;
      });
    if (errors.length > 0) {
      return errors[0];
    }
    return null;
  }

  async validatePostRequestAsync(
    container: Record<string, string>
  ): Promise<{ profile: Profile; loggedOut: boolean }> {
    const xml = Buffer.from(container.SAMLRequest, "base64").toString("utf8");
    const dom = parseDomFromString(xml);
    const doc = await parseXml2JsFromString(xml);
    const certs = await this.certsToCheck();
    if (!validateSignature(xml, dom.documentElement, certs)) {
      throw new Error("Invalid signature on documentElement");
    }
    return await this.processValidlySignedPostRequestAsync(doc, dom);
  }

  protected processValidlySignedPostRequestAsync = processValidlySignedPostRequestAsync;

  protected processValidlySignedSamlLogoutAsync = processValidlySignedSamlLogoutAsync;

  generateServiceProviderMetadata = generateServiceProviderMetadata;

  /**
   * Process max age assertion and use it if it is more restrictive than the NotOnOrAfter age
   * assertion received in the SAMLResponse.
   *
   * @param maxAssertionAgeMs Max time after IssueInstant that we will accept assertion, in Ms.
   * @param notOnOrAfter Expiration provided in response.
   * @param issueInstant Time when response was issued.
   * @returns {*} The expiration time to be used, in Ms.
   */
  protected calcMaxAgeAssertionTime(
    maxAssertionAgeMs: number,
    notOnOrAfter: string,
    issueInstant: string
  ): number {
    const notOnOrAfterMs = dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter");
    const issueInstantMs = dateStringToTimestamp(issueInstant, "IssueInstant");

    if (maxAssertionAgeMs === 0) {
      return notOnOrAfterMs;
    }

    const maxAssertionTimeMs = issueInstantMs + maxAssertionAgeMs;
    return maxAssertionTimeMs < notOnOrAfterMs ? maxAssertionTimeMs : notOnOrAfterMs;
  }

  protected mustValidateInResponseTo(hasInResponseTo: boolean): boolean {
    return (
      this.options.validateInResponseTo === ValidateInResponseTo.always ||
      (this.options.validateInResponseTo === ValidateInResponseTo.ifPresent && hasInResponseTo)
    );
  }
}

export { SAML };
