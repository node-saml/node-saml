import { expect } from "chai";
import * as sinon from "sinon";
import { SAML } from "../src/saml";
import { SamlConfig, ValidateInResponseTo } from "../src/types";
import { FAKE_CERT } from "./types";

describe("Cache tests /", () => {
  let fakeClock: sinon.SinonFakeTimers;

  beforeEach(function () {
    fakeClock = sinon.useFakeTimers();
  });

  afterEach(function () {
    fakeClock.restore();
  });

  it("should expire a cached request id after the time", async () => {
    const requestId = "_dfab47d5d46374cd4b71";
    const requestIdExpirationPeriodMs = 100;
    const samlConfig: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs,
      cert: FAKE_CERT,
      issuer: "onesaml_login",
    };
    const samlObj = new SAML(samlConfig);

    await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

    await fakeClock.tickAsync(300);
    const value = await samlObj.cacheProvider.getAsync(requestId);
    expect(value).to.not.exist;
  });

  it("should not return an expired item", async () => {
    const requestId1 = "_dfab47d5d46374cd4b71";
    const requestId2 = "_dfab47d5d46374cd4b72";
    const requestId3 = "_dfab47d5d46374cd4b73";
    const requestIdExpirationPeriodMs = 100;
    const samlConfig: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs,
      cert: FAKE_CERT,
      issuer: "onesaml_login",
    };
    const samlObj = new SAML(samlConfig);

    await samlObj.cacheProvider.saveAsync(requestId1, new Date().toISOString());
    await fakeClock.tickAsync(requestIdExpirationPeriodMs / 2 + 1);
    await samlObj.cacheProvider.saveAsync(requestId2, new Date().toISOString());
    await fakeClock.tickAsync(requestIdExpirationPeriodMs / 2 + 1);
    await samlObj.cacheProvider.saveAsync(requestId3, new Date().toISOString());
    await fakeClock.tickAsync(requestIdExpirationPeriodMs / 2 + 1);
    const value1 = await samlObj.cacheProvider.getAsync(requestId1);
    expect(value1).to.not.exist;
    const value2 = await samlObj.cacheProvider.getAsync(requestId2);
    expect(value2).to.not.exist;
    const value3 = await samlObj.cacheProvider.getAsync(requestId3);
    expect(value3).to.exist;
  });

  it("should expire many cached request ids after the time", async () => {
    const expiredRequestId1 = "_dfab47d5d46374cd4b71";
    const expiredRequestId2 = "_dfab47d5d46374cd4b72";
    const requestId1 = "_dfab47d5d46374cd4b73";

    const requestIdExpirationPeriodMs = 100;

    const samlConfig: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs,
      cert: FAKE_CERT,
      issuer: "onesaml_login",
    };
    const samlObj = new SAML(samlConfig);

    await samlObj.cacheProvider.saveAsync(expiredRequestId1, new Date().toISOString());
    await samlObj.cacheProvider.saveAsync(expiredRequestId2, new Date().toISOString());

    await fakeClock.tickAsync(requestIdExpirationPeriodMs * 3);
    await samlObj.cacheProvider.saveAsync(requestId1, new Date().toISOString());

    const value1 = await samlObj.cacheProvider.getAsync(expiredRequestId1);
    expect(value1).to.not.exist;
    const value2 = await samlObj.cacheProvider.getAsync(expiredRequestId2);
    expect(value2).to.not.exist;
    const value3 = await samlObj.cacheProvider.getAsync(requestId1);
    expect(value3).to.exist;
    await fakeClock.tickAsync(requestIdExpirationPeriodMs * 3);
    const value4 = await samlObj.cacheProvider.getAsync(requestId1);
    expect(value4).to.not.exist;
  });

  it("should expire a key if it is old when we add it again", async () => {
    const requestId1 = "_dfab47d5d46374cd4b74";
    const requestIdExpirationPeriodMs = 100;
    const samlConfig: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs,
      cert: FAKE_CERT,
      issuer: "onesaml_login",
    };
    const samlObj = new SAML(samlConfig);

    await samlObj.cacheProvider.saveAsync(requestId1, new Date().toISOString());

    // Check to make sure that we will remove an expired key exactly when we should if we try to save again
    await fakeClock.tickAsync(requestIdExpirationPeriodMs);
    const removed = await samlObj.cacheProvider.saveAsync(requestId1, new Date().toISOString());
    expect(removed?.createdAt).to.equal(100);
  });

  it("should expire a key if it is old when we add a different one", async () => {
    const requestId1 = "_dfab47d5d46374cd4b74";
    const requestId2 = "_dfab47d5d46374cd4b75";
    const requestId3 = "_dfab47d5d46374cd4b76";
    const samlConfig: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      validateInResponseTo: ValidateInResponseTo.always,
      cert: FAKE_CERT,
      issuer: "onesaml_login",
    };
    const samlObj = new SAML(samlConfig);
    const cacheRemoveSpy = sinon.spy(samlObj.cacheProvider, "removeAsync");

    await samlObj.cacheProvider.saveAsync(requestId1, new Date().toISOString());
    await fakeClock.tickAsync("05:00:00");
    await samlObj.cacheProvider.saveAsync(requestId2, new Date().toISOString());
    await fakeClock.tickAsync("05:00:00");
    await samlObj.cacheProvider.saveAsync(requestId3, new Date().toISOString());
    await fakeClock.tickAsync("05:00:00");
    expect(cacheRemoveSpy.called).to.be.true;
    expect(cacheRemoveSpy.calledWith(requestId1)).to.be.true;
    const removed = await samlObj.cacheProvider.getAsync(requestId1);
    expect(removed).to.not.exist;

    sinon.restore();
  });

  it("should not update the expire time of duplicate entries", async () => {
    const requestId = "_dfab47d5d46374cd4b74";
    const requestIdExpirationPeriodMs = 100;
    const samlConfig: SamlConfig = {
      callbackUrl: "http://localhost/saml/consume",
      validateInResponseTo: ValidateInResponseTo.always,
      requestIdExpirationPeriodMs,
      cert: FAKE_CERT,
      issuer: "onesaml_login",
    };
    const samlObj = new SAML(samlConfig);

    await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());

    // Check to make sure that we can't add the same data twice
    const duplicate = await samlObj.cacheProvider.saveAsync(requestId, new Date().toISOString());
    expect(duplicate).to.not.exist;
  });
});
