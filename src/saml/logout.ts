import { Profile, XMLOutput } from "../types";
import { assertRequired } from "../utility";
import { decryptXml, parseDomFromString, xpath } from "../xml";

export interface NameID {
  value: string | null;
  format: string | null;
}

const promiseWithNameId = async (nameid: Node): Promise<NameID> => {
  const format = xpath.selectAttributes(nameid, "@Format");
  return {
    value: nameid.textContent,
    format: format && format[0] && format[0].nodeValue,
  };
};

const getNameIdAsync = async (
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
    throw new Error("Invalid LogoutRequest");
  }
  if (nameIds.length === 1) {
    return promiseWithNameId(nameIds[0]);
  }
  if (encryptedIds.length === 1) {
    decryptionPvk = assertRequired(
      decryptionPvk,
      "No decryption key found getting name ID for encrypted SAML response"
    );

    const encryptedDatas = xpath.selectElements(
      encryptedIds[0],
      "./*[local-name()='EncryptedData']"
    );

    if (encryptedDatas.length !== 1) {
      throw new Error("Invalid LogoutRequest");
    }
    const encryptedDataXml = encryptedDatas[0].toString();

    const decryptedXml = await decryptXml(encryptedDataXml, decryptionPvk);
    const decryptedDoc = parseDomFromString(decryptedXml);
    const decryptedIds = xpath.selectElements(decryptedDoc, "/*[local-name()='NameID']");
    if (decryptedIds.length !== 1) {
      throw new Error("Invalid EncryptedAssertion content");
    }
    return await promiseWithNameId(decryptedIds[0]);
  }
  throw new Error("Missing SAML NameID");
};

export const processValidlySignedPostRequestAsync = async (
  doc: XMLOutput,
  dom: Document,
  decryptionPvk: string | Buffer | null
): Promise<{ profile: Profile; loggedOut: true }> => {
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
    const nameID = await getNameIdAsync(dom, decryptionPvk);
    if (nameID && nameID.value) {
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
};

export const processValidlySignedSamlLogoutAsync = async (
  doc: XMLOutput,
  dom: Document,
  decryptionPvk: string | Buffer | null
): Promise<{ profile: Profile | null; loggedOut: true }> => {
  const response = doc.LogoutResponse;
  const request = doc.LogoutRequest;

  if (response) {
    return { profile: null, loggedOut: true };
  } else if (request) {
    return await processValidlySignedPostRequestAsync(doc, dom, decryptionPvk);
  } else {
    throw new Error("Unknown SAML response message");
  }
};
