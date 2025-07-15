import { expect } from "chai";
import { parseString } from "xml2js";
import { SAML, SamlConfig, AttributeConsumingService } from "../src";

describe("AttributeConsumingService", function () {
  const FAKE_CERT = "fake cert";

  it("should generate metadata with AttributeConsumingService", function (done) {
    const attributeConsumingServices: AttributeConsumingService[] = [
      {
        "@index": "0",
        "@isDefault": true,
        ServiceName: [
          {
            "@xml:lang": "en",
            "#text": "My Service",
          },
        ],
        ServiceDescription: [
          {
            "@xml:lang": "en",
            "#text": "My Service Description",
          },
        ],
        RequestedAttribute: [
          {
            "@Name": "urn:oid:2.5.4.42",
            "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "@FriendlyName": "givenName",
            "@isRequired": true,
          },
          {
            "@Name": "urn:oid:2.5.4.4",
            "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "@FriendlyName": "sn",
            "@isRequired": true,
          },
          {
            "@Name": "urn:oid:1.2.840.113549.1.9.1",
            "@NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "@FriendlyName": "emailAddress",
            "@isRequired": false,
          },
        ],
      },
    ];

    const samlConfig: SamlConfig = {
      issuer: "http://example.serviceprovider.com",
      callbackUrl: "http://example.serviceprovider.com/saml/callback",
      idpCert: FAKE_CERT,
      metadataAttributeConsumingServices: attributeConsumingServices,
      generateUniqueId: () => "test-unique-id",
    };

    const samlObj = new SAML(samlConfig);
    const metadata = samlObj.generateServiceProviderMetadata(null);

    parseString(metadata, function (err, result) {
      if (err) {
        done(err);
        return;
      }

      try {
        const spssoDescriptor = result.EntityDescriptor.SPSSODescriptor[0];

        // Check that AttributeConsumingService is present
        expect(spssoDescriptor.AttributeConsumingService).to.exist;
        expect(spssoDescriptor.AttributeConsumingService).to.have.length(1);

        const attributeConsumingService = spssoDescriptor.AttributeConsumingService[0];

        // Check index and isDefault
        expect(attributeConsumingService.$.index).to.equal("0");
        expect(attributeConsumingService.$.isDefault).to.equal("true");

        // Check ServiceName
        expect(attributeConsumingService.ServiceName).to.exist;
        expect(attributeConsumingService.ServiceName).to.have.length(1);
        expect(attributeConsumingService.ServiceName[0].$["xml:lang"]).to.equal("en");
        expect(attributeConsumingService.ServiceName[0]._).to.equal("My Service");

        // Check ServiceDescription
        expect(attributeConsumingService.ServiceDescription).to.exist;
        expect(attributeConsumingService.ServiceDescription).to.have.length(1);
        expect(attributeConsumingService.ServiceDescription[0].$["xml:lang"]).to.equal("en");
        expect(attributeConsumingService.ServiceDescription[0]._).to.equal(
          "My Service Description"
        );

        // Check RequestedAttribute
        expect(attributeConsumingService.RequestedAttribute).to.exist;
        expect(attributeConsumingService.RequestedAttribute).to.have.length(3);

        const givenNameAttr = attributeConsumingService.RequestedAttribute[0];
        expect(givenNameAttr.$.Name).to.equal("urn:oid:2.5.4.42");
        expect(givenNameAttr.$.NameFormat).to.equal(
          "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        );
        expect(givenNameAttr.$.FriendlyName).to.equal("givenName");
        expect(givenNameAttr.$.isRequired).to.equal("true");

        const emailAttr = attributeConsumingService.RequestedAttribute[2];
        expect(emailAttr.$.Name).to.equal("urn:oid:1.2.840.113549.1.9.1");
        expect(emailAttr.$.isRequired).to.equal("false");

        done();
      } catch (testErr) {
        done(testErr);
      }
    });
  });

  it("should generate metadata without AttributeConsumingService when not provided", function (done) {
    const samlConfig: SamlConfig = {
      issuer: "http://example.serviceprovider.com",
      callbackUrl: "http://example.serviceprovider.com/saml/callback",
      idpCert: FAKE_CERT,
      generateUniqueId: () => "test-unique-id",
    };

    const samlObj = new SAML(samlConfig);
    const metadata = samlObj.generateServiceProviderMetadata(null);

    parseString(metadata, function (err, result) {
      if (err) {
        done(err);
        return;
      }

      try {
        const spssoDescriptor = result.EntityDescriptor.SPSSODescriptor[0];

        // Check that AttributeConsumingService is not present
        expect(spssoDescriptor.AttributeConsumingService).to.be.undefined;

        done();
      } catch (testErr) {
        done(testErr);
      }
    });
  });

  it("should generate metadata with multiple AttributeConsumingService elements", function (done) {
    const attributeConsumingServices: AttributeConsumingService[] = [
      {
        "@index": "0",
        "@isDefault": true,
        ServiceName: [
          {
            "@xml:lang": "en",
            "#text": "Basic Service",
          },
        ],
        RequestedAttribute: [
          {
            "@Name": "urn:oid:2.5.4.42",
            "@FriendlyName": "givenName",
            "@isRequired": true,
          },
        ],
      },
      {
        "@index": "1",
        ServiceName: [
          {
            "@xml:lang": "en",
            "#text": "Extended Service",
          },
        ],
        RequestedAttribute: [
          {
            "@Name": "urn:oid:2.5.4.42",
            "@FriendlyName": "givenName",
            "@isRequired": true,
          },
          {
            "@Name": "urn:oid:2.5.4.4",
            "@FriendlyName": "sn",
            "@isRequired": true,
          },
        ],
      },
    ];

    const samlConfig: SamlConfig = {
      issuer: "http://example.serviceprovider.com",
      callbackUrl: "http://example.serviceprovider.com/saml/callback",
      idpCert: FAKE_CERT,
      metadataAttributeConsumingServices: attributeConsumingServices,
      generateUniqueId: () => "test-unique-id",
    };

    const samlObj = new SAML(samlConfig);
    const metadata = samlObj.generateServiceProviderMetadata(null);

    parseString(metadata, function (err, result) {
      if (err) {
        done(err);
        return;
      }

      try {
        const spssoDescriptor = result.EntityDescriptor.SPSSODescriptor[0];

        // Check that we have two AttributeConsumingService elements
        expect(spssoDescriptor.AttributeConsumingService).to.exist;
        expect(spssoDescriptor.AttributeConsumingService).to.have.length(2);

        const firstService = spssoDescriptor.AttributeConsumingService[0];
        expect(firstService.$.index).to.equal("0");
        expect(firstService.$.isDefault).to.equal("true");
        expect(firstService.RequestedAttribute).to.have.length(1);

        const secondService = spssoDescriptor.AttributeConsumingService[1];
        expect(secondService.$.index).to.equal("1");
        expect(secondService.$.isDefault).to.be.undefined;
        expect(secondService.RequestedAttribute).to.have.length(2);

        done();
      } catch (testErr) {
        done(testErr);
      }
    });
  });
});
