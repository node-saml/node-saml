import { generateInstant } from "../datetime";
import { SAML } from "../saml";
import { signAuthnRequestPost } from "../saml-post-signing";
import {
  AuthorizeRequestXML,
  isValidSamlSigningOptions,
  LogoutRequestXML,
  Profile,
  SamlIDPEntryConfig,
  SamlIDPListConfig,
  XMLInput,
} from "../types";
import { assertRequired } from "../utility";
import { buildXmlBuilderObject } from "../xml";
import { generateServiceProviderMetadata as generateMetadata } from "../metadata";

export async function _generateLogoutRequest(this: SAML, user: Profile): Promise<string> {
  const id = this.options.generateUniqueId();
  const instant = generateInstant();

  const request = {
    "samlp:LogoutRequest": {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
      "@ID": id,
      "@Version": "2.0",
      "@IssueInstant": instant,
      "@Destination": this.options.logoutUrl,
      "saml:Issuer": {
        "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "#text": this.options.issuer,
      },
      "samlp:Extensions": {},
      "saml:NameID": {
        "@Format": user.nameIDFormat,
        "#text": user.nameID,
      },
    },
  } as LogoutRequestXML;

  const samlLogoutRequestExtensions = this.options.samlLogoutRequestExtensions;
  if (samlLogoutRequestExtensions != null) {
    if (typeof samlLogoutRequestExtensions != "object") {
      throw new TypeError("samlLogoutRequestExtensions should be Object");
    }
    request["samlp:LogoutRequest"]["samlp:Extensions"] = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      ...samlLogoutRequestExtensions,
    };
  } else {
    delete request["samlp:LogoutRequest"]["samlp:Extensions"];
  }

  if (user.nameQualifier != null) {
    request["samlp:LogoutRequest"]["saml:NameID"]["@NameQualifier"] = user.nameQualifier;
  }

  if (user.spNameQualifier != null) {
    request["samlp:LogoutRequest"]["saml:NameID"]["@SPNameQualifier"] = user.spNameQualifier;
  }

  if (user.sessionIndex) {
    request["samlp:LogoutRequest"]["saml2p:SessionIndex"] = {
      "@xmlns:saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
      "#text": user.sessionIndex,
    };
  }

  await this.cacheProvider.saveAsync(id, instant);
  return buildXmlBuilderObject(request, false);
}

export function _generateLogoutResponse(
  this: SAML,
  logoutRequest: Profile,
  success: boolean
): string {
  const id = this.options.generateUniqueId();
  const instant = generateInstant();

  const successStatus = {
    "samlp:StatusCode": {
      "@Value": "urn:oasis:names:tc:SAML:2.0:status:Success",
    },
  };

  const failStatus = {
    "samlp:StatusCode": {
      "@Value": "urn:oasis:names:tc:SAML:2.0:status:Requester",
      "samlp:StatusCode": {
        "@Value": "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
      },
    },
  };

  const request = {
    "samlp:LogoutResponse": {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
      "@ID": id,
      "@Version": "2.0",
      "@IssueInstant": instant,
      "@Destination": this.options.logoutUrl,
      "@InResponseTo": logoutRequest.ID,
      "saml:Issuer": {
        "#text": this.options.issuer,
      },
      "samlp:Status": success ? successStatus : failStatus,
    },
  };

  return buildXmlBuilderObject(request, false);
}

export async function generateAuthorizeRequestAsync(
  this: SAML,
  isPassive: boolean,
  isHttpPostBinding: boolean,
  host: string | undefined
): Promise<string> {
  assertRequired(this.options.entryPoint, "entryPoint is required");

  const id = this.options.generateUniqueId();
  const instant = generateInstant();

  if (this.mustValidateInResponseTo(true)) {
    await this.cacheProvider.saveAsync(id, instant);
  }
  const request: AuthorizeRequestXML = {
    "samlp:AuthnRequest": {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@ID": id,
      "@Version": "2.0",
      "@IssueInstant": instant,
      "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "@Destination": this.options.entryPoint,
      "saml:Issuer": {
        "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "#text": this.options.issuer,
      },
    },
  };

  if (isPassive) request["samlp:AuthnRequest"]["@IsPassive"] = true;

  if (this.options.forceAuthn === true) {
    request["samlp:AuthnRequest"]["@ForceAuthn"] = true;
  }

  if (!this.options.disableRequestAcsUrl) {
    request["samlp:AuthnRequest"]["@AssertionConsumerServiceURL"] = this.getCallbackUrl(host);
  }

  const samlAuthnRequestExtensions = this.options.samlAuthnRequestExtensions;
  if (samlAuthnRequestExtensions != null) {
    if (typeof samlAuthnRequestExtensions != "object") {
      throw new TypeError("samlAuthnRequestExtensions should be Object");
    }
    request["samlp:AuthnRequest"]["samlp:Extensions"] = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      ...samlAuthnRequestExtensions,
    };
  }

  const nameIDPolicy: XMLInput = {
    "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "@AllowCreate": this.options.allowCreate,
  };

  if (this.options.identifierFormat != null) {
    nameIDPolicy["@Format"] = this.options.identifierFormat;
  }

  if (this.options.spNameQualifier != null) {
    nameIDPolicy["@SPNameQualifier"] = this.options.spNameQualifier;
  }

  request["samlp:AuthnRequest"]["samlp:NameIDPolicy"] = nameIDPolicy;

  if (!this.options.disableRequestedAuthnContext) {
    const authnContextClassRefs: XMLInput[] = [];
    (this.options.authnContext as string[]).forEach(function (value) {
      authnContextClassRefs.push({
        "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "#text": value,
      });
    });

    request["samlp:AuthnRequest"]["samlp:RequestedAuthnContext"] = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
      "@Comparison": this.options.racComparison,
      "saml:AuthnContextClassRef": authnContextClassRefs,
    };
  }

  if (this.options.attributeConsumingServiceIndex != null) {
    request["samlp:AuthnRequest"]["@AttributeConsumingServiceIndex"] =
      this.options.attributeConsumingServiceIndex;
  }

  if (this.options.providerName != null) {
    request["samlp:AuthnRequest"]["@ProviderName"] = this.options.providerName;
  }

  if (this.options.scoping != null) {
    const scoping: XMLInput = {
      "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    };

    if (typeof this.options.scoping.proxyCount === "number") {
      scoping["@ProxyCount"] = this.options.scoping.proxyCount;
    }

    if (this.options.scoping.idpList) {
      scoping["samlp:IDPList"] = this.options.scoping.idpList.map(
        (idpListItem: SamlIDPListConfig) => {
          const formattedIdpListItem: XMLInput = {
            "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
          };

          if (idpListItem.entries) {
            formattedIdpListItem["samlp:IDPEntry"] = idpListItem.entries.map(
              (entry: SamlIDPEntryConfig) => {
                const formattedEntry: XMLInput = {
                  "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                };

                formattedEntry["@ProviderID"] = entry.providerId;

                if (entry.name) {
                  formattedEntry["@Name"] = entry.name;
                }

                if (entry.loc) {
                  formattedEntry["@Loc"] = entry.loc;
                }

                return formattedEntry;
              }
            );
          }

          if (idpListItem.getComplete) {
            formattedIdpListItem["samlp:GetComplete"] = idpListItem.getComplete;
          }

          return formattedIdpListItem;
        }
      );
    }

    if (this.options.scoping.requesterId) {
      scoping["samlp:RequesterID"] = this.options.scoping.requesterId;
    }

    request["samlp:AuthnRequest"]["samlp:Scoping"] = scoping;
  }

  let stringRequest = buildXmlBuilderObject(request, false);
  // TODO: maybe we should always sign here
  if (isHttpPostBinding && isValidSamlSigningOptions(this.options)) {
    stringRequest = signAuthnRequestPost(stringRequest, this.options);
  }
  return stringRequest;
}

export function generateServiceProviderMetadata(
  this: SAML,
  decryptionCert: string | null,
  signingCerts?: string | string[] | null
): string {
  const callbackUrl = this.getCallbackUrl(); // TODO it would probably be useful to have a host parameter here

  return generateMetadata({
    ...this.options,
    callbackUrl,
    decryptionCert,
    signingCerts,
  });
}
