# Changelog

## 5.1.0 (2025-07-21)

### 🚀 Minor Changes

- Export custom SamlStatusError [#394](https://github.com/node-saml/node-saml/pull/394)

### 🔗 Dependencies

- Update dependencies [#391](https://github.com/node-saml/node-saml/pull/391)

### 🐛 Bug Fixes

- [**security**] Use new .signedReferences interace in xml-crypto to "see what is signed" [#397](https://github.com/node-saml/node-saml/pull/397)

### 📚 Documentation

- update sponsors-Stytch [#395](https://github.com/node-saml/node-saml/pull/395)

### ⚙️ Technical Tasks

- Add CI test & lint for Node.js 22 [#386](https://github.com/node-saml/node-saml/pull/386)
- Adjust linting rules for line endings [#393](https://github.com/node-saml/node-saml/pull/393)

---

## v5.0.1 (2025-03-14)

### 🚀 Minor Changes

- feat: improve error messages when validating pems [#373](https://github.com/node-saml/node-saml/pull/373)

### 🐛 Bug Fixes

- [**security**] Update xml-crypto to address CVE [#388](https://github.com/node-saml/node-saml/pull/388)

### 📚 Documentation

- docs: Update README.md set never default validateInResponseTo [#384](https://github.com/node-saml/node-saml/pull/384)
- Docs: add pitch to encourage more sponsors [#366](https://github.com/node-saml/node-saml/pull/366)
- Update sponsor acknowledgements [#365](https://github.com/node-saml/node-saml/pull/365)

### ⚙️ Technical Tasks

- Adjust to support type stripping [#389](https://github.com/node-saml/node-saml/pull/389)

---

## v5.0.0 (2024-02-27)

### 💣 Major Changes

- Update minor dependencies and Node to 18 [#344](https://github.com/node-saml/node-saml/pull/344)
- Rename `cert` to `idpCert` and `signingCert` to `publicCert` [#343](https://github.com/node-saml/node-saml/pull/343)
- Update to current Node versions [#342](https://github.com/node-saml/node-saml/pull/342)
- Upgrade to latest version of xml-crypto [#341](https://github.com/node-saml/node-saml/pull/341)
- Fix spelling and normalize naming [#278](https://github.com/node-saml/node-saml/pull/278)
- Export types required for SamlOptions [#224](https://github.com/node-saml/node-saml/pull/224)
- Simplify callback URL options; remove `path`, `protocol`, and `host`. [#214](https://github.com/node-saml/node-saml/pull/214)

### 🚀 Minor Changes

- Added X509 certificate to KeyInfo X509Data, if passed through options [#36](https://github.com/node-saml/node-saml/pull/36)
- Export generateServiceProviderMetadata [#337](https://github.com/node-saml/node-saml/pull/337)
- Fixes `node-saml` not checking all `Audience`s in an `AudienceRestriction` [#340](https://github.com/node-saml/node-saml/pull/340)
- Add public key support [#225](https://github.com/node-saml/node-saml/pull/225)
- feat: support additionalParams on HTTP-POST binding [#263](https://github.com/node-saml/node-saml/pull/263)
- Improve audience mismatch error message [#257](https://github.com/node-saml/node-saml/pull/257)

### 🔗 Dependencies

- [**javascript**] Bump release-it from 16.3.0 to 17.0.5 [#348](https://github.com/node-saml/node-saml/pull/348)
- [**javascript**] Bump eslint-plugin-prettier from 4.2.1 to 5.1.3 [#346](https://github.com/node-saml/node-saml/pull/346)
- [**javascript**] Bump eslint-config-prettier from 8.10.0 to 9.1.0 [#345](https://github.com/node-saml/node-saml/pull/345)
- [**javascript**] Bump eslint-plugin-deprecation from 1.5.0 to 2.0.0 [#347](https://github.com/node-saml/node-saml/pull/347)
- [**javascript**] Bump sinon and @types/sinon [#349](https://github.com/node-saml/node-saml/pull/349)
- [**github_actions**] Bump actions/checkout from 3 to 4 [#330](https://github.com/node-saml/node-saml/pull/330)
- [**javascript**] Bump prettier from 2.8.8 to 3.0.0 [#300](https://github.com/node-saml/node-saml/pull/300)
- [**javascript**] Bump prettier-plugin-packagejson from 2.4.3 to 2.4.5 [#307](https://github.com/node-saml/node-saml/pull/307)
- [**javascript**] Bump eslint from 8.42.0 to 8.45.0 [#306](https://github.com/node-saml/node-saml/pull/306)
- [**javascript**] Bump release-it from 15.11.0 to 16.1.3 [#305](https://github.com/node-saml/node-saml/pull/305)
- [**javascript**] Bump @cjbarth/github-release-notes from 4.0.0 to 4.1.0 [#304](https://github.com/node-saml/node-saml/pull/304)
- [**javascript**] Bump @types/node from 14.18.50 to 14.18.53 [#303](https://github.com/node-saml/node-saml/pull/303)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.59.9 to 5.62.0 [#302](https://github.com/node-saml/node-saml/pull/302)
- [**javascript**] Bump @xmldom/xmldom from 0.8.8 to 0.8.10 [#301](https://github.com/node-saml/node-saml/pull/301)
- [**javascript**] Bump @typescript-eslint/parser from 5.59.9 to 5.62.0 [#299](https://github.com/node-saml/node-saml/pull/299)
- [**javascript**] Bump word-wrap from 1.2.3 to 1.2.4 [#298](https://github.com/node-saml/node-saml/pull/298)
- [**javascript**] Bump sinon from 14.0.2 to 15.2.0 [#294](https://github.com/node-saml/node-saml/pull/294)
- [**javascript**] Bump typescript from 4.8.4 to 5.1.6 [#293](https://github.com/node-saml/node-saml/pull/293)
- [**javascript**] Bump @typescript-eslint/parser from 5.59.9 to 5.60.1 [#292](https://github.com/node-saml/node-saml/pull/292)
- [**javascript**] Bump concurrently from 7.6.0 to 8.2.0 [#290](https://github.com/node-saml/node-saml/pull/290)
- Remove dependency on Passport types [#296](https://github.com/node-saml/node-saml/pull/296)
- Remove `express` dependency [#284](https://github.com/node-saml/node-saml/pull/284)
- Update minor dependencies [#283](https://github.com/node-saml/node-saml/pull/283)
- [**github_actions**] Bump codecov/codecov-action from 3.1.1 to 3.1.4 [#279](https://github.com/node-saml/node-saml/pull/279)
- [**javascript**] Bump @typescript-eslint/parser from 5.58.0 to 5.59.8 [#281](https://github.com/node-saml/node-saml/pull/281)
- [**javascript**] Bump prettier from 2.8.7 to 2.8.8 [#274](https://github.com/node-saml/node-saml/pull/274)
- [**javascript**] Bump json5 from 2.2.1 to 2.2.3 [#244](https://github.com/node-saml/node-saml/pull/244)
- [**javascript**] Bump vm2 from 3.9.16 to 3.9.19 [#277](https://github.com/node-saml/node-saml/pull/277)
- Update minor dependencies [#269](https://github.com/node-saml/node-saml/pull/269)

### 🐛 Bug Fixes

- Fix metadata order [#334](https://github.com/node-saml/node-saml/pull/334)

### 📚 Documentation

- Roll-up changelog entries for beta releases [#282](https://github.com/node-saml/node-saml/pull/282)

### ⚙️ Technical Tasks

- Add test coverage for initialize() of saml.ts [#327](https://github.com/node-saml/node-saml/pull/327)
- Add tests for XML parsing with comments [#285](https://github.com/node-saml/node-saml/pull/285)
- Separate linting out from testing [#288](https://github.com/node-saml/node-saml/pull/288)
- Add test coverage [#287](https://github.com/node-saml/node-saml/pull/287)
- Prefer Chai `expect` to Node `assert` [#286](https://github.com/node-saml/node-saml/pull/286)
- Remove types specific to Passport [#226](https://github.com/node-saml/node-saml/pull/226)
- Acknowledge that XML can be parsed to `any` [#271](https://github.com/node-saml/node-saml/pull/271)

### 🙈 Other

- Enforce valid setting for validateInResponseTo [#314](https://github.com/node-saml/node-saml/pull/314)
- feat: add public getAuthorizeMessage method [#235](https://github.com/node-saml/node-saml/pull/235)

---

## v4.0.4 (2023-04-11)

### 🔗 Dependencies

- [**security**] [**javascript**] Bump xml2js from 0.4.23 to 0.5.0 [#268](https://github.com/node-saml/node-saml/pull/268)
- [**javascript**] Bump xml-encryption from 3.0.1 to 3.0.2 [#236](https://github.com/node-saml/node-saml/pull/236)

---

## v4.0.3 (2022-12-13)

### 🔗 Dependencies

- [**javascript**] Bump eslint from 8.26.0 to 8.29.0 [#234](https://github.com/node-saml/node-saml/pull/234)
- [**javascript**] Bump eslint-plugin-deprecation from 1.3.2 to 1.3.3 [#232](https://github.com/node-saml/node-saml/pull/232)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.43.0 to 5.45.0 [#231](https://github.com/node-saml/node-saml/pull/231)
- [**javascript**] Bump concurrently from 7.5.0 to 7.6.0 [#230](https://github.com/node-saml/node-saml/pull/230)
- [**javascript**] Bump prettier from 2.7.1 to 2.8.0 [#229](https://github.com/node-saml/node-saml/pull/229)

---

## v4.0.2 (2022-11-23)

### 🐛 Bug Fixes

- fix: correct handling of XML entities in signature attributes [#221](https://github.com/node-saml/node-saml/pull/221)
- Expose ValidateInResponseTo as it is required in options [#220](https://github.com/node-saml/node-saml/pull/220)

### 📚 Documentation

- Remove pre-release comments from README [#223](https://github.com/node-saml/node-saml/pull/223)

---

## v4.0.1 (2022-11-16)

### 🔗 Dependencies

- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.41.0 to 5.43.0 [#216](https://github.com/node-saml/node-saml/pull/216)
- [**javascript**] Bump @typescript-eslint/parser from 5.41.0 to 5.43.0 [#217](https://github.com/node-saml/node-saml/pull/217)
- Lock to TypeScript <4.9.0 due to a regression in 4.9.3 [#219](https://github.com/node-saml/node-saml/pull/219)
- [**javascript**] Bump @types/node from 14.18.32 to 14.18.33 [#201](https://github.com/node-saml/node-saml/pull/201)
- [**javascript**] Bump xml-crypto from 3.0.0 to 3.0.1 [#205](https://github.com/node-saml/node-saml/pull/205)
- Update @xmldom/xmldom [#213](https://github.com/node-saml/node-saml/pull/213)

### 📚 Documentation

- Fixes #208, updated readme by updating package names. [#210](https://github.com/node-saml/node-saml/pull/210)

### ⚙️ Technical Tasks

- Remove check now covered by dependency [#215](https://github.com/node-saml/node-saml/pull/215)

---

## v4.0.0 (2022-10-28)

### 💣 Major Changes

- Require all assertions be signed; new option wantAssertionsSigned can be set to false to enabled the older, less secure behavior. [#177](https://github.com/node-saml/node-saml/pull/177)
- Document signatures are now required by default. Setting wantAuthenResponseSigned=false disables this feature and restores the prior, less secure behavior [#83](https://github.com/node-saml/node-saml/pull/83)
- Make `issuer` required; remove OneLogin default [#61](https://github.com/node-saml/node-saml/pull/61)
- Make Audience a required setting [#25](https://github.com/node-saml/node-saml/pull/25)
- Allow to validate InResponseTo only if provided, to support IDP-initiated login [#40](https://github.com/node-saml/node-saml/pull/40)
- Update packages; bump minimum node to 14 [#45](https://github.com/node-saml/node-saml/pull/45)
- Add support for a failed logout response [#10](https://github.com/node-saml/node-saml/pull/10)
- Set AuthnRequestsSigned in SP metadata if configured for signing. [#20](https://github.com/node-saml/node-saml/pull/20)

### 🚀 Minor Changes

- feat: expose getLogoutResponseUrlAsync publicly [#194](https://github.com/node-saml/node-saml/pull/194)
- fix generate unique metadata ID [#158](https://github.com/node-saml/node-saml/pull/158)
- Include AuthnRequestsSigned attribute in all metadata [#143](https://github.com/node-saml/node-saml/pull/143)
- Add support for metadata ContactPerson and Organization [#140](https://github.com/node-saml/node-saml/pull/140)
- Support multiple Assertion SubjectConfirmation [#43](https://github.com/node-saml/node-saml/pull/43)
- Extend available options for NameIDPolicy attributes [#67](https://github.com/node-saml/node-saml/pull/67)
- Migrate from "should" to "chai" [#41](https://github.com/node-saml/node-saml/pull/41)
- Set a unique ID value in generated metadata [#30](https://github.com/node-saml/node-saml/pull/30)
- Add option to sign generated metadata [#24](https://github.com/node-saml/node-saml/pull/24)
- Feature: add facility in config to add `<Extensions>` element in SAML request [#11](https://github.com/node-saml/node-saml/pull/11)
- Add ability to publish multiple signing certs in metadata [#23](https://github.com/node-saml/node-saml/pull/23)
- CacheProvider interface [#29](https://github.com/node-saml/node-saml/pull/29)
- Support importing to `passport-saml` project [#9](https://github.com/node-saml/node-saml/pull/9)
- Add assertion attributes to child object on profile (passport-saml#543) [#5](https://github.com/node-saml/node-saml/pull/5)

### 🔗 Dependencies

- Update dependencies, including locked ones [#198](https://github.com/node-saml/node-saml/pull/198)
- Update Dependencies [#197](https://github.com/node-saml/node-saml/pull/197)
- Bump @xmldom/xmldom from 0.7.5 to 0.7.6 [#196](https://github.com/node-saml/node-saml/pull/196)
- [**javascript**] Bump @xmldom/xmldom from 0.8.2 to 0.8.3 [#188](https://github.com/node-saml/node-saml/pull/188)
- [**javascript**] Bump node-fetch and release-it [#187](https://github.com/node-saml/node-saml/pull/187)
- [**javascript**] Bump parse-url and release-it [#176](https://github.com/node-saml/node-saml/pull/176)
- [**javascript**] Bump @typescript-eslint/parser from 5.36.2 to 5.40.0 [#186](https://github.com/node-saml/node-saml/pull/186)
- [**javascript**] Bump prettier-plugin-packagejson from 2.2.18 to 2.3.0 [#185](https://github.com/node-saml/node-saml/pull/185)
- [**javascript**] Bump @types/passport from 1.0.9 to 1.0.11 [#182](https://github.com/node-saml/node-saml/pull/182)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.36.2 to 5.38.1 [#183](https://github.com/node-saml/node-saml/pull/183)
- [**javascript**] Bump typescript from 4.8.3 to 4.8.4 [#181](https://github.com/node-saml/node-saml/pull/181)
- [**github_actions**] Bump codecov/codecov-action from 3.1.0 to 3.1.1 [#180](https://github.com/node-saml/node-saml/pull/180)
- [**javascript**] Bump vm2 from 3.9.10 to 3.9.11 [#179](https://github.com/node-saml/node-saml/pull/179)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.30.7 to 5.36.2 [#171](https://github.com/node-saml/node-saml/pull/171)
- [**javascript**] Bump @types/chai from 4.3.1 to 4.3.3 [#172](https://github.com/node-saml/node-saml/pull/172)
- [**javascript**] Bump @typescript-eslint/parser from 5.30.7 to 5.36.2 [#170](https://github.com/node-saml/node-saml/pull/170)
- [**javascript**] Bump eslint from 8.19.0 to 8.23.0 [#163](https://github.com/node-saml/node-saml/pull/163)
- [**javascript**] Bump typescript from 4.7.4 to 4.8.3 [#169](https://github.com/node-saml/node-saml/pull/169)
- [**javascript**] Bump concurrently from 7.2.2 to 7.3.0 [#136](https://github.com/node-saml/node-saml/pull/136)
- [**javascript**] Bump @types/sinon from 10.0.12 to 10.0.13 [#134](https://github.com/node-saml/node-saml/pull/134)
- deps: move express to devDependencies because it is only used in a test. [#161](https://github.com/node-saml/node-saml/pull/161)
- Update changelog [#162](https://github.com/node-saml/node-saml/pull/162)
- [**javascript**] Bump @typescript-eslint/parser from 5.30.5 to 5.30.7 [#125](https://github.com/node-saml/node-saml/pull/125)
- [**javascript**] Bump @types/node from 14.18.16 to 14.18.22 [#124](https://github.com/node-saml/node-saml/pull/124)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.30.6 to 5.30.7 [#123](https://github.com/node-saml/node-saml/pull/123)
- [**javascript**] Bump release-it from 15.1.1 to 15.1.2 [#122](https://github.com/node-saml/node-saml/pull/122)
- [**javascript**] Bump ts-node from 10.8.2 to 10.9.1 [#126](https://github.com/node-saml/node-saml/pull/126)
- [**javascript**] Bump release-it from 15.0.0 to 15.1.1 [#117](https://github.com/node-saml/node-saml/pull/117)
- [**javascript**] Bump xml-crypto from 2.1.3 to 2.1.4 [#118](https://github.com/node-saml/node-saml/pull/118)
- [**javascript**] Bump ts-node from 10.7.0 to 10.8.2 [#119](https://github.com/node-saml/node-saml/pull/119)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.30.5 to 5.30.6 [#120](https://github.com/node-saml/node-saml/pull/120)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.30.3 to 5.30.5 [#114](https://github.com/node-saml/node-saml/pull/114)
- [**javascript**] Bump parse-url from 6.0.0 to 6.0.2 [#115](https://github.com/node-saml/node-saml/pull/115)
- [**javascript**] Bump @typescript-eslint/parser from 5.22.0 to 5.30.5 [#113](https://github.com/node-saml/node-saml/pull/113)
- [**javascript**] Bump @types/passport from 1.0.7 to 1.0.9 [#112](https://github.com/node-saml/node-saml/pull/112)
- [**javascript**] Bump eslint from 8.14.0 to 8.19.0 [#111](https://github.com/node-saml/node-saml/pull/111)
- [**javascript**] Bump eslint-plugin-prettier from 4.0.0 to 4.2.1 [#104](https://github.com/node-saml/node-saml/pull/104)
- [**javascript**] Bump prettier from 2.6.2 to 2.7.1 [#107](https://github.com/node-saml/node-saml/pull/107)
- [**javascript**] Bump @types/sinon from 10.0.11 to 10.0.12 [#106](https://github.com/node-saml/node-saml/pull/106)
- [**javascript**] Bump typescript from 4.6.4 to 4.7.4 [#105](https://github.com/node-saml/node-saml/pull/105)
- [**javascript**] Bump sinon from 13.0.2 to 14.0.0 [#102](https://github.com/node-saml/node-saml/pull/102)
- [**javascript**] Bump concurrently from 7.1.0 to 7.2.2 [#100](https://github.com/node-saml/node-saml/pull/100)
- [**javascript**] Bump prettier-plugin-packagejson from 2.2.17 to 2.2.18 [#103](https://github.com/node-saml/node-saml/pull/103)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.22.0 to 5.30.3 [#99](https://github.com/node-saml/node-saml/pull/99)
- [**github_actions**] Bump actions/checkout from 2 to 3 [#97](https://github.com/node-saml/node-saml/pull/97)
- Update CodeQL to v2 [#95](https://github.com/node-saml/node-saml/pull/95)
- Bump npm from 8.6.0 to 8.11.0 [#88](https://github.com/node-saml/node-saml/pull/88)
- Update dependencies [#81](https://github.com/node-saml/node-saml/pull/81)
- Update dependencies [#75](https://github.com/node-saml/node-saml/pull/75)
- Move dependency types next to dependencies [#73](https://github.com/node-saml/node-saml/pull/73)
- Remove unused `qs` types [#72](https://github.com/node-saml/node-saml/pull/72)
- Remove unused request dependency [#71](https://github.com/node-saml/node-saml/pull/71)
- Support Node 18 [#68](https://github.com/node-saml/node-saml/pull/68)
- [**security**] Upgrade xml-encryption to 2.0.0 (fixes audit issue) [#44](https://github.com/node-saml/node-saml/pull/44)
- Update xmldom [#17](https://github.com/node-saml/node-saml/pull/17)

### 🐛 Bug Fixes

- [**security**] Throw if multiple XML roots detected [#195](https://github.com/node-saml/node-saml/pull/195)
- Make Issuer Required in the Types Too (like it is at runtime) [#90](https://github.com/node-saml/node-saml/pull/90)
- Bypass for InResponseTo [#87](https://github.com/node-saml/node-saml/pull/87)
- Fix broken request tests [#86](https://github.com/node-saml/node-saml/pull/86)
- [**security**] Address polynomial regular expression used on uncontrolled data [#79](https://github.com/node-saml/node-saml/pull/79)
- Fix issues with cache provider potentially returning expired keys [#59](https://github.com/node-saml/node-saml/pull/59)
- Correctly reset Sinon fake timers [#60](https://github.com/node-saml/node-saml/pull/60)
- Correct carriage-return entity handling [#38](https://github.com/node-saml/node-saml/pull/38)
- #13 GCM EncryptionMethod [#15](https://github.com/node-saml/node-saml/pull/15)
- [**security**] Limit transforms for signed nodes [#6](https://github.com/node-saml/node-saml/pull/6)
- Remove duplicate calls to the cache provider [#4](https://github.com/node-saml/node-saml/pull/4)

### 📚 Documentation

- Update documentation to remove ADFS references; rename passport-saml [#190](https://github.com/node-saml/node-saml/pull/190)
- Changelog [#173](https://github.com/node-saml/node-saml/pull/173)
- Remove insecure clockSkew recommendation [#151](https://github.com/node-saml/node-saml/pull/151)
- Update badges for scoped package [#93](https://github.com/node-saml/node-saml/pull/93)
- Add codecov and DeepScan badges [#76](https://github.com/node-saml/node-saml/pull/76)
- Correct several typos in documentation [#39](https://github.com/node-saml/node-saml/pull/39)
- Update README.md [#1](https://github.com/node-saml/node-saml/pull/1)

### ⚙️ Technical Tasks

- Update types [#199](https://github.com/node-saml/node-saml/pull/199)
- Update changelog build tools [#189](https://github.com/node-saml/node-saml/pull/189)
- Clean up signature tests [#178](https://github.com/node-saml/node-saml/pull/178)
- Remove some usage of `any` type [#175](https://github.com/node-saml/node-saml/pull/175)
- Add prerelease script [#174](https://github.com/node-saml/node-saml/pull/174)
- Reduce frequency of dependabot updates [#152](https://github.com/node-saml/node-saml/pull/152)
- Consolidate all SAML class code to single file [#147](https://github.com/node-saml/node-saml/pull/147)
- Improve tests [#141](https://github.com/node-saml/node-saml/pull/141)
- Refactor process routines out of saml.ts [#130](https://github.com/node-saml/node-saml/pull/130)
- Refactor generate functions to a separate file [#129](https://github.com/node-saml/node-saml/pull/129)
- Coerce booleans when constructing options object [#85](https://github.com/node-saml/node-saml/pull/85)
- Refactor code for better functional grouping [#128](https://github.com/node-saml/node-saml/pull/128)
- Have dependabot update package.json too [#109](https://github.com/node-saml/node-saml/pull/109)
- Add dependabot config file [#96](https://github.com/node-saml/node-saml/pull/96)
- Simplify configs for compilation and release [#92](https://github.com/node-saml/node-saml/pull/92)
- Move to NPM organization [#91](https://github.com/node-saml/node-saml/pull/91)
- Factor out metadata routines [#78](https://github.com/node-saml/node-saml/pull/78)
- Clear up ambiguous branch [#80](https://github.com/node-saml/node-saml/pull/80)
- Tighten `any` type [#77](https://github.com/node-saml/node-saml/pull/77)
- Add code coverage [#74](https://github.com/node-saml/node-saml/pull/74)
- Clean up exception messages and related tests [#69](https://github.com/node-saml/node-saml/pull/69)
- Saml options typing [#66](https://github.com/node-saml/node-saml/pull/66)
- Stop using import assignments [#65](https://github.com/node-saml/node-saml/pull/65)
- Remove unused vars [#64](https://github.com/node-saml/node-saml/pull/64)
- Stop using import assignments [#63](https://github.com/node-saml/node-saml/pull/63)
- Remove useless not null assertions [#54](https://github.com/node-saml/node-saml/pull/54)
- Enable `assertRequired` to type narrow [#62](https://github.com/node-saml/node-saml/pull/62)
- fix a linting warning by adding a return type [#56](https://github.com/node-saml/node-saml/pull/56)
- remove warnings related to loggedOut in tests [#55](https://github.com/node-saml/node-saml/pull/55)
- remove useless any type declaration [#53](https://github.com/node-saml/node-saml/pull/53)
- removes an unused variable in a test [#52](https://github.com/node-saml/node-saml/pull/52)
- remove useless not null assertions on errors [#50](https://github.com/node-saml/node-saml/pull/50)
- transform a test that does not use some of its variables [#51](https://github.com/node-saml/node-saml/pull/51)
- remove a not null assertion by checking certificate's validity [#49](https://github.com/node-saml/node-saml/pull/49)
- add an assertion to remove a linting warning [#47](https://github.com/node-saml/node-saml/pull/47)
- remove useless not null assertions [#48](https://github.com/node-saml/node-saml/pull/48)
- fix a linting warning by adding a return type [#46](https://github.com/node-saml/node-saml/pull/46)
- [Split saml.ts #1] Move getAdditionalParams out of saml.ts [#32](https://github.com/node-saml/node-saml/pull/32)
- Move non SAML code out of saml.ts [#18](https://github.com/node-saml/node-saml/pull/18)
- Fix workflow for Node 16.x [#7](https://github.com/node-saml/node-saml/pull/7)
- Remove passport-saml code and tests [#3](https://github.com/node-saml/node-saml/pull/3)

---

## v3.0.0 (2021-05-14)

_No changelog for this release._
