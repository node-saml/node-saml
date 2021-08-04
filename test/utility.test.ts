import * as should from "should";
import { JSONXMLSchemaError } from "../src/types";
import { validateXMLNamespace, validateSAMLExtensionsElement } from "../src/utility";

const xmlElementSchemaNamespaceCheck: any[] = [
  {
    name: "should throw JSONXMLSchemaError error when missing element namespace",
    jsonXMLElementKey: "md:RequestedAttribute",
    jsonXMLElementValue: {
      "@isRequired": "true",
      "@Name": "Lastname",
    },
    result: {
      throw: {
        message: "Namespace @xmlns:md is not defined for element md:RequestedAttribute",
      },
    },
  },
  {
    name: "should throw JSONXMLSchemaError error when missing element namespace",
    jsonXMLElementKey: "vetuma",
    jsonXMLElementValue: {
      LG: {
        "#text": "sv",
      },
    },
    result: {
      throw: {
        message: "Namespace @xmlns is not defined for element vetuma",
      },
    },
  },
  {
    name: "should throw JSONXMLSchemaError error when wrong element namespace",
    jsonXMLElementKey: "md:RequestedAttribute",
    jsonXMLElementValue: {
      "@isRequired": "true",
      "@Name": "Lastname",
      "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
    },
    result: {
      throw: {
        message: "Namespace @xmlns:md is not defined for element md:RequestedAttribute",
      },
    },
  },
  {
    name: "should return true when valid element",
    jsonXMLElementKey: "md:RequestedAttribute",
    jsonXMLElementValue: {
      "@isRequired": "true",
      "@Name": "Lastname",
      "@xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
    },

    result: true,
  },
  {
    name: "should return true when valid element",
    jsonXMLElementKey: "RequestedAttribute",
    jsonXMLElementValue: {
      "@isRequired": "true",
      "@Name": "Lastname",
      "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
    },

    result: true,
  },
];

const samlExtensionElementSchemaNamespaceCheck: any[] = [
  {
    name: "should throw JSONXMLSchemaError error when missing element namespace",
    value: {
      "md:RequestedAttribute": {
        "@isRequired": "true",
        "@Name": "Lastname",
      },
    },
    result: {
      throw: {
        message: "Namespace @xmlns:md is not defined for element md:RequestedAttribute",
      },
    },
  },
  {
    name: "should throw JSONXMLSchemaError error when missing element namespace",
    value: {
      vetuma: {
        LG: {
          "#text": "sv",
        },
      },
    },
    result: {
      throw: {
        message: "Namespace @xmlns is not defined for element vetuma",
      },
    },
  },
  {
    name: "should throw JSONXMLSchemaError error when wrong element namespace",
    value: {
      "md:RequestedAttribute": {
        "@isRequired": "true",
        "@Name": "Lastname",
      },
      vetuma: {
        "@xmlns": "urn:vetuma:SAML:2.0:extensions",
        LG: { "#text": "sv" },
      },
    },
    result: {
      throw: {
        message: "Namespace @xmlns:md is not defined for element md:RequestedAttribute",
      },
    },
  },
  {
    name: "should return true when valid element",
    value: {
      "md:RequestedAttribute": {
        "@isRequired": "true",
        "@Name": "Lastname",
        "@xmlns:md": "urn:vetuma:SAML:2.0:extensions",
      },
    },
    result: true,
  },
  {
    name: "should return true when valid element",
    value: {
      RequestedAttribute: {
        "@isRequired": "true",
        "@Name": "Lastname",
        "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
      },
      vetuma: {
        "@xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
        LG: {
          "#text": "sv",
        },
      },
    },
    result: true,
  },
];

describe("test validateXMLNamespace", () => {
  it("should be exists", () => {
    should.exist(validateXMLNamespace);
  });

  it("should be function", () => {
    validateXMLNamespace.should.be.Function();
  });

  it("should throw TypeError when values are invalid", () => {
    should(() => {
      validateXMLNamespace("", undefined);
    }).throw();
    should(() => {
      validateXMLNamespace("", undefined);
    }).throw(TypeError);
    should(() => {
      validateXMLNamespace("", undefined);
    }).throw("key should be define");
    should(() => {
      validateXMLNamespace("test", {});
    }).throw("test XML Element value should be object and not empty");
  });

  xmlElementSchemaNamespaceCheck.forEach((check) => {
    it(check.name, () => {
      if (check.result.throw) {
        should(() => {
          validateXMLNamespace(check.jsonXMLElementKey, check.jsonXMLElementValue);
        }).throw(JSONXMLSchemaError);
        should(() => {
          validateXMLNamespace(check.jsonXMLElementKey, check.jsonXMLElementValue);
        }).throw(check.result.throw.message);
      } else if (check.result === true) {
        const isValid = validateXMLNamespace(check.jsonXMLElementKey, check.jsonXMLElementValue);
        isValid.should.be.True();
      }
    });
  });
});

describe("test validateSAMLExtensionsElement", () => {
  it("should be exists", () => {
    should.exist(validateSAMLExtensionsElement);
  });

  it("should be function", () => {
    validateSAMLExtensionsElement.should.be.Function();
  });

  it("should throw TypeError when values are invalid", () => {
    should(() => {
      validateSAMLExtensionsElement(undefined);
    }).throw();
    should(() => {
      validateSAMLExtensionsElement(undefined);
    }).throw(TypeError);
    should(() => {
      validateSAMLExtensionsElement(undefined);
    }).throw("samlExtensions Element value should be object and not empty");
    should(() => {
      validateSAMLExtensionsElement({});
    }).throw("samlExtensions Element value should be object and not empty");
    should(() => {
      validateSAMLExtensionsElement("test");
    }).throw("samlExtensions Element value should be object and not empty");
  });

  samlExtensionElementSchemaNamespaceCheck.forEach((check) => {
    it(check.name, () => {
      if (check.result.throw) {
        should(() => {
          validateSAMLExtensionsElement(check.value);
        }).throw(JSONXMLSchemaError);
        should(() => {
          validateSAMLExtensionsElement(check.value);
        }).throw(check.result.throw.message);
      } else if (check.result === true) {
        const isValid = validateSAMLExtensionsElement(check.value);
        isValid.should.be.True();
      }
    });
  });
});
