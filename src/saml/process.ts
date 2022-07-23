import { SAML } from "../saml";
import { Profile, XMLObject, XMLOutput, XMLValue } from "../types";
import { getNameIdAsync, parseXml2JsFromString } from "../xml";

export async function processValidlySignedPostRequestAsync(
  this: SAML,
  doc: XMLOutput,
  dom: Document
): Promise<{ profile: Profile; loggedOut: boolean }> {
  const request = doc.LogoutRequest;
  if (request) {
    const profile = {} as Profile;
    if (request.$.ID) {
      profile.ID = request.$.ID;
    } else {
      throw new Error("Missing SAML LogoutRequest ID");
    }
    const issuer = request.Issuer;
    if (issuer && issuer[0]._) {
      profile.issuer = issuer[0]._;
    } else {
      throw new Error("Missing SAML issuer");
    }
    const nameID = await getNameIdAsync(dom, this.options.decryptionPvk ?? null);
    if (nameID.value) {
      profile.nameID = nameID.value;
      if (nameID.format) {
        profile.nameIDFormat = nameID.format;
      }
    } else {
      throw new Error("Missing SAML NameID");
    }
    const sessionIndex = request.SessionIndex;
    if (sessionIndex) {
      profile.sessionIndex = sessionIndex[0]._;
    }
    return { profile, loggedOut: true };
  } else {
    throw new Error("Unknown SAML request message");
  }
}

export async function processValidlySignedSamlLogoutAsync(
  this: SAML,
  doc: XMLOutput,
  dom: Document
): Promise<{ profile: Profile | null; loggedOut: boolean }> {
  const response = doc.LogoutResponse;
  const request = doc.LogoutRequest;

  if (response) {
    return { profile: null, loggedOut: true };
  } else if (request) {
    return await this.processValidlySignedPostRequestAsync(doc, dom);
  } else {
    throw new Error("Unknown SAML response message");
  }
}

export async function processValidlySignedAssertionAsync(
  this: SAML,
  xml: string,
  samlResponseXml: string,
  inResponseTo: string | null
): Promise<{ profile: Profile; loggedOut: boolean }> {
  let msg;
  const nowMs = new Date().getTime();
  const profile = {} as Profile;
  const doc: XMLOutput = await parseXml2JsFromString(xml);
  const parsedAssertion: XMLOutput = doc;
  const assertion: XMLOutput = doc.Assertion;
  getInResponseTo: {
    const issuer = assertion.Issuer;
    if (issuer && issuer[0]._) {
      profile.issuer = issuer[0]._;
    }

    if (inResponseTo != null) {
      profile.inResponseTo = inResponseTo;
    }

    const authnStatement = assertion.AuthnStatement;
    if (authnStatement) {
      if (authnStatement[0].$ && authnStatement[0].$.SessionIndex) {
        profile.sessionIndex = authnStatement[0].$.SessionIndex;
      }
    }

    const subject = assertion.Subject;
    let subjectConfirmation: XMLOutput | null | undefined;
    let confirmData: XMLOutput | null = null;
    let subjectConfirmations: XMLOutput[] | null = null;
    if (subject) {
      const nameID = subject[0].NameID;
      if (nameID && nameID[0]._) {
        profile.nameID = nameID[0]._;

        if (nameID[0].$ && nameID[0].$.Format) {
          profile.nameIDFormat = nameID[0].$.Format;
          profile.nameQualifier = nameID[0].$.NameQualifier;
          profile.spNameQualifier = nameID[0].$.SPNameQualifier;
        }
      }
      subjectConfirmations = subject[0].SubjectConfirmation;
      subjectConfirmation = subjectConfirmations?.find((_subjectConfirmation: XMLOutput) => {
        const _confirmData = _subjectConfirmation.SubjectConfirmationData?.[0];
        if (_confirmData?.$) {
          const subjectNotBefore = _confirmData.$.NotBefore;
          const subjectNotOnOrAfter = _confirmData.$.NotOnOrAfter;
          const maxTimeLimitMs = this.calcMaxAgeAssertionTime(
            this.options.maxAssertionAgeMs,
            subjectNotOnOrAfter,
            assertion.$.IssueInstant
          );

          const subjErr = this.checkTimestampsValidityError(
            nowMs,
            subjectNotBefore,
            subjectNotOnOrAfter,
            maxTimeLimitMs
          );
          if (subjErr === null) return true;
        }

        return false;
      });

      if (subjectConfirmation != null) {
        confirmData = subjectConfirmation.SubjectConfirmationData[0];
      }
    }

    /**
     * Test to see that if we have a SubjectConfirmation InResponseTo that it matches
     * the 'InResponseTo' attribute set in the Response
     */
    if (this.mustValidateInResponseTo(Boolean(inResponseTo))) {
      if (subjectConfirmation) {
        if (confirmData?.$) {
          const subjectInResponseTo = confirmData.$.InResponseTo;

          if (inResponseTo && subjectInResponseTo && subjectInResponseTo != inResponseTo) {
            await this.cacheProvider.removeAsync(inResponseTo);
            throw new Error("InResponseTo does not match subjectInResponseTo");
          } else if (subjectInResponseTo) {
            let foundValidInResponseTo = false;
            const result = await this.cacheProvider.getAsync(subjectInResponseTo);
            if (result) {
              const createdAt = new Date(result);
              if (nowMs < createdAt.getTime() + this.options.requestIdExpirationPeriodMs)
                foundValidInResponseTo = true;
            }
            await this.cacheProvider.removeAsync(inResponseTo);
            if (!foundValidInResponseTo) {
              throw new Error("SubjectInResponseTo is not valid");
            }
            break getInResponseTo;
          }
        }
      } else {
        if (subjectConfirmations != null && subjectConfirmation == null) {
          msg = "No valid subject confirmation found among those available in the SAML assertion";
          throw new Error(msg);
        } else {
          await this.cacheProvider.removeAsync(inResponseTo);
          break getInResponseTo;
        }
      }
    } else {
      break getInResponseTo;
    }
  }
  const conditions = assertion.Conditions ? assertion.Conditions[0] : null;
  if (assertion.Conditions && assertion.Conditions.length > 1) {
    msg = "Unable to process multiple conditions in SAML assertion";
    throw new Error(msg);
  }
  if (conditions && conditions.$) {
    const maxTimeLimitMs = this.calcMaxAgeAssertionTime(
      this.options.maxAssertionAgeMs,
      conditions.$.NotOnOrAfter,
      assertion.$.IssueInstant
    );
    const conErr = this.checkTimestampsValidityError(
      nowMs,
      conditions.$.NotBefore,
      conditions.$.NotOnOrAfter,
      maxTimeLimitMs
    );
    if (conErr) throw conErr;
  }

  if (this.options.audience !== false) {
    const audienceErr = this.checkAudienceValidityError(
      this.options.audience,
      conditions.AudienceRestriction
    );
    if (audienceErr) throw audienceErr;
  }

  const attributeStatement = assertion.AttributeStatement;
  if (attributeStatement) {
    const attributes: XMLOutput[] = [].concat(
      ...attributeStatement
        .filter((attr: XMLObject) => Array.isArray(attr.Attribute))
        .map((attr: XMLObject) => attr.Attribute)
    );

    const attrValueMapper = (value: XMLObject) => {
      const hasChildren = Object.keys(value).some((cur) => {
        return cur !== "_" && cur !== "$";
      });
      return hasChildren ? value : value._;
    };

    if (attributes.length > 0) {
      const profileAttributes: Record<string, XMLValue | XMLValue[]> = {};

      attributes.forEach((attribute) => {
        if (!Object.prototype.hasOwnProperty.call(attribute, "AttributeValue")) {
          // if attributes has no AttributeValue child, continue
          return;
        }

        const name: string = attribute.$.Name;
        const value: XMLValue | XMLValue[] =
          attribute.AttributeValue.length === 1
            ? attrValueMapper(attribute.AttributeValue[0])
            : attribute.AttributeValue.map(attrValueMapper);

        profileAttributes[name] = value;

        /**
         * If any property is already present in profile and is also present
         * in attributes, then skip the one from attributes. Handle this
         * conflict gracefully without returning any error
         */
        if (Object.prototype.hasOwnProperty.call(profile, name)) {
          return;
        }

        profile[name] = value;
      });

      profile.attributes = profileAttributes;
    }
  }

  if (!profile.mail && profile["urn:oid:0.9.2342.19200300.100.1.3"]) {
    /**
     * See https://spaces.internet2.edu/display/InCFederation/Supported+Attribute+Summary
     * for definition of attribute OIDs
     */
    profile.mail = profile["urn:oid:0.9.2342.19200300.100.1.3"];
  }

  if (!profile.email && profile.mail) {
    profile.email = profile.mail;
  }

  profile.getAssertionXml = () => xml.toString();
  profile.getAssertion = () => parsedAssertion;
  profile.getSamlResponseXml = () => samlResponseXml;

  return { profile, loggedOut: false };
}
