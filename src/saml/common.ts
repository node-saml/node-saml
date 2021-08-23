import { ParsedUrlQuery } from "querystring";

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
