import * as querystring from "querystring";
import { ParsedUrlQuery } from "querystring";
import * as util from "util";
import * as zlib from "zlib";
import * as algorithms from "../algorithms";
import { keyToPEM } from "../crypto";

const deflateRawAsync = util.promisify(zlib.deflateRaw);

export const getAdditionalParams = (params: {
  relayState: string;
  globalAdditionalParams: NodeJS.Dict<string>;
  operationAdditionalParams: NodeJS.Dict<string>;
  overrideParams?: ParsedUrlQuery;
}): ParsedUrlQuery => {
  const { relayState, globalAdditionalParams, operationAdditionalParams, overrideParams } = params;

  const additionalParams: ParsedUrlQuery = {};

  if (typeof relayState === "string" && relayState.length > 0) {
    additionalParams.RelayState = relayState;
  }

  return Object.assign(
    additionalParams,
    globalAdditionalParams,
    operationAdditionalParams,
    overrideParams ?? {}
  );
};

const signRequest = (
  samlMessage: ParsedUrlQuery,
  privateKey: string | Buffer,
  signatureAlgorithm: string
): void => {
  const samlMessageToSign: ParsedUrlQuery = {};

  samlMessage.SigAlg = algorithms.getSigningAlgorithm(signatureAlgorithm);
  const signer = algorithms.getSigner(signatureAlgorithm);
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
  samlMessage.Signature = signer.sign(keyToPEM(privateKey), "base64");
};

export const requestToUrlAsync = async (params: {
  targetUrl: string;
  skipRequestCompression: boolean;
  message: string;
  messageType: "SAMLRequest" | "SAMLResponse";
  additionalParameters: ParsedUrlQuery;
  privateKey?: string | Buffer;
  signatureAlgorithm: string;
}): Promise<string> => {
  const {
    skipRequestCompression,
    message,
    messageType,
    targetUrl,
    additionalParameters,
    privateKey,
    signatureAlgorithm,
  } = params;

  const buffer = skipRequestCompression
    ? Buffer.from(message, "utf8")
    : await deflateRawAsync(message);
  const base64 = buffer.toString("base64");

  const samlMessage: ParsedUrlQuery = {
    [messageType]: base64,
  };
  Object.keys(additionalParameters).forEach((k) => {
    samlMessage[k] = additionalParameters[k];
  });
  if (privateKey != null) {
    // sets .SigAlg and .Signature
    signRequest(samlMessage, privateKey, signatureAlgorithm);
  }

  const target = new URL(targetUrl);
  Object.keys(samlMessage).forEach((k) => {
    // TODO if we want to assume value are string, we should use
    // NodeJS.Dict<string> rather than ParsedUrlQuery
    target.searchParams.set(k, samlMessage[k] as string);
  });
  return target.toString();
};
