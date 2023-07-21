# Changelog

## 4.0.0-beta.6 (2022-10-13)

#### ⚙️ Technical Tasks:

- Update changelog build tools [#189](https://github.com/node-saml/node-saml/pull/189)

---

## v4.0.0-beta.5 (2022-10-11)

#### 💣 Major Changes:

- Require all assertions be signed; add option to disable [#177](https://github.com/node-saml/node-saml/pull/177)
- Add option to require a document signature. [#83](https://github.com/node-saml/node-saml/pull/83)

#### 🔗 Dependencies:

- [**javascript**] Bump node-fetch and release-it [#187](https://github.com/node-saml/node-saml/pull/187)
- [**javascript**] Bump parse-url and release-it [#176](https://github.com/node-saml/node-saml/pull/176)
- [**javascript**] Bump @typescript-eslint/parser from 5.36.2 to 5.40.0 [#186](https://github.com/node-saml/node-saml/pull/186)
- [**javascript**] Bump prettier-plugin-packagejson from 2.2.18 to 2.3.0 [#185](https://github.com/node-saml/node-saml/pull/185)
- [**javascript**] Bump @types/passport from 1.0.9 to 1.0.11 [#182](https://github.com/node-saml/node-saml/pull/182)
- [**javascript**] Bump @typescript-eslint/eslint-plugin from 5.36.2 to 5.38.1 [#183](https://github.com/node-saml/node-saml/pull/183)
- [**javascript**] Bump typescript from 4.8.3 to 4.8.4 [#181](https://github.com/node-saml/node-saml/pull/181)
- [**github_actions**] Bump codecov/codecov-action from 3.1.0 to 3.1.1 [#180](https://github.com/node-saml/node-saml/pull/180)
- [**javascript**] Bump vm2 from 3.9.10 to 3.9.11 [#179](https://github.com/node-saml/node-saml/pull/179)

#### 🐛 Bug Fixes:

- [**security**] Fix CVE-2022-39300 [GHSA-5p8w-2mvw-38pv](https://github.com/node-saml/passport-saml/security/advisories/ GHSA-5p8w-2mvw-38pv)

#### ⚙️ Technical Tasks:

- Clean up signature tests [#178](https://github.com/node-saml/node-saml/pull/178)
- Remove some usage of `any` type [#175](https://github.com/node-saml/node-saml/pull/175)
- Add prerelease script [#174](https://github.com/node-saml/node-saml/pull/174)

---

## v4.0.0-beta.4 (2022-09-10)

#### 🚀 Minor Changes:

- fix generate unique metadata ID [#158](https://github.com/node-saml/node-saml/pull/158)
- Include AuthnRequestsSigned attribute in all metadata [#143](https://github.com/node-saml/node-saml/pull/143)
- Add support for metadata ContactPerson and Organization [#140](https://github.com/node-saml/node-saml/pull/140)

#### 🔗 Dependencies:

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

#### 📚 Documentation:

- Changelog [#173](https://github.com/node-saml/node-saml/pull/173)
- Remove insecure clockSkew recommendation [#151](https://github.com/node-saml/node-saml/pull/151)
- Update badges for scoped package [#93](https://github.com/node-saml/node-saml/pull/93)

#### ⚙️ Technical Tasks:

- Have dependabot update package.json too [#109](https://github.com/node-saml/node-saml/pull/109)
- Reduce frequency of dependabot updates [#152](https://github.com/node-saml/node-saml/pull/152)
- Consolidate all SAML class code to single file [#147](https://github.com/node-saml/node-saml/pull/147)
- Refactor generate functions to a separate file [#129](https://github.com/node-saml/node-saml/pull/129)
- Improve tests [#141](https://github.com/node-saml/node-saml/pull/141)
- Refactor process routines out of saml.ts [#130](https://github.com/node-saml/node-saml/pull/130)
- Refactor code for better functional grouping [#128](https://github.com/node-saml/node-saml/pull/128)
- Coerce booleans when constructing options object [#85](https://github.com/node-saml/node-saml/pull/85)
- Add dependabot config file [#96](https://github.com/node-saml/node-saml/pull/96)

---

## v4.0.0-beta.3 (2022-06-25)

#### 💣 Major Changes:

- Make Audience a required setting [#25](https://github.com/node-saml/node-saml/pull/25)
- Make `issuer` required; remove OneLogin default [#61](https://github.com/node-saml/node-saml/pull/61)
- Allow to validate InReponseTo only if provided, to support IDP-initiated login [#40](https://github.com/node-saml/node-saml/pull/40)
- Update packages; bump minimum node to 14 [#45](https://github.com/node-saml/node-saml/pull/45)

#### 🚀 Minor Changes:

- Support multiple Assertion SubjectConfirmation [#43](https://github.com/node-saml/node-saml/pull/43)
- Extend available options for NameIDPolicy attributes [#67](https://github.com/node-saml/node-saml/pull/67)
- Migrate from "should" to "chai" [#41](https://github.com/node-saml/node-saml/pull/41)

#### 🔗 Dependencies:

- Bump npm from 8.6.0 to 8.11.0 [#88](https://github.com/node-saml/node-saml/pull/88)
- Update dependencies [#81](https://github.com/node-saml/node-saml/pull/81)
- Update dependencies [#75](https://github.com/node-saml/node-saml/pull/75)
- Move dependency types next to dependencies [#73](https://github.com/node-saml/node-saml/pull/73)
- Remove unused `qs` types [#72](https://github.com/node-saml/node-saml/pull/72)
- Remove unused request dependency [#71](https://github.com/node-saml/node-saml/pull/71)
- Support Node 18 [#68](https://github.com/node-saml/node-saml/pull/68)
- [**security**] Upgrade xml-encryption to 2.0.0 (fixes audit issue) [#44](https://github.com/node-saml/node-saml/pull/44)

#### 🐛 Bug Fixes:

- [**security**] Address polynomial regular expression used on uncontrolled data [#79](https://github.com/node-saml/node-saml/pull/79)
- Fix issues with cache provider potentially returning expired keys [#59](https://github.com/node-saml/node-saml/pull/59)
- Correctly reset Sinon fake timers [#60](https://github.com/node-saml/node-saml/pull/60)
- Correct carriage-return entity handling [#38](https://github.com/node-saml/node-saml/pull/38)
- Make Issuer Required in the Types Too (like it is at runtime) [#90](https://github.com/node-saml/node-saml/pull/90)
- Bypass for InResponseTo [#87](https://github.com/node-saml/node-saml/pull/87)
- Fix broken request tests [#86](https://github.com/node-saml/node-saml/pull/86)

#### 📚 Documentation:

- Add codecov and DeepScan badges [#76](https://github.com/node-saml/node-saml/pull/76)
- Correct several typos in documentation [#39](https://github.com/node-saml/node-saml/pull/39)

#### ⚙️ Technical Tasks:

- Move to NPM organization [#91](https://github.com/node-saml/node-saml/pull/91)
- Factor out metadata routines [#78](https://github.com/node-saml/node-saml/pull/78)
- Clear up ambiguous branch [#80](https://github.com/node-saml/node-saml/pull/80)
- Tighten `any` type [#77](https://github.com/node-saml/node-saml/pull/77)
- Add code coverage [#74](https://github.com/node-saml/node-saml/pull/74)
- Clean up exception messages and related tests [#69](https://github.com/node-saml/node-saml/pull/69)
- Saml options typing [#66](https://github.com/node-saml/node-saml/pull/66)
- Stop using import assignments [#65](https://github.com/node-saml/node-saml/pull/65)
- Stop using import assignments [#63](https://github.com/node-saml/node-saml/pull/63)
- Remove unused vars [#64](https://github.com/node-saml/node-saml/pull/64)
- fix a linting warning by adding a return type [#46](https://github.com/node-saml/node-saml/pull/46)
- add an assertion to remove a linting warning [#47](https://github.com/node-saml/node-saml/pull/47)
- remove useless not null assertions [#48](https://github.com/node-saml/node-saml/pull/48)
- remove a not null assertion by checking certificate's validity [#49](https://github.com/node-saml/node-saml/pull/49)
- remove useless not null assertions on errors [#50](https://github.com/node-saml/node-saml/pull/50)
- transform a test that does not use some of its variables [#51](https://github.com/node-saml/node-saml/pull/51)
- removes an unused variable in a test [#52](https://github.com/node-saml/node-saml/pull/52)
- remove useless any type declaration [#53](https://github.com/node-saml/node-saml/pull/53)
- Remove useless not null assertions [#54](https://github.com/node-saml/node-saml/pull/54)
- remove warnings related to loggedOut in tests [#55](https://github.com/node-saml/node-saml/pull/55)
- fix a linting warning by adding a return type [#56](https://github.com/node-saml/node-saml/pull/56)
- Enable `assertRequired` to type narrow [#62](https://github.com/node-saml/node-saml/pull/62)
- Simplify configs for compilation and release [#92](https://github.com/node-saml/node-saml/pull/92)
- [Split saml.ts #1] Move getAdditionalParams out of saml.ts [#32](https://github.com/node-saml/node-saml/pull/32)

---

## v4.0.0-beta.2 (2021-11-17)

#### 🚀 Minor Changes:

- Set a unique ID value in generated metadata [#30](https://github.com/node-saml/node-saml/pull/30)
- Feature: add facility in config to add `<Extensions>` element in SAML request [#11](https://github.com/node-saml/node-saml/pull/11)
- Add option to sign generated metadata [#24](https://github.com/node-saml/node-saml/pull/24)

---

## v4.0.0-beta.1 (2021-10-26)

#### 💣 Major Changes:

- Add support for a failed logout response [#10](https://github.com/node-saml/node-saml/pull/10)
- Set AuthnRequestsSigned in SP metadata if configured for signing. [#20](https://github.com/node-saml/node-saml/pull/20)

#### 🚀 Minor Changes:

- Add ability to publish multiple signing certs in metadata [#23](https://github.com/node-saml/node-saml/pull/23)
- CacheProvider interface [#29](https://github.com/node-saml/node-saml/pull/29)

#### 🔗 Dependencies:

- Update xmldom [#17](https://github.com/node-saml/node-saml/pull/17)

#### 🐛 Bug Fixes:

- #13 GCM EncryptionMethod [#15](https://github.com/node-saml/node-saml/pull/15)

#### ⚙️ Technical Tasks:

- Move non SAML code out of saml.ts [#18](https://github.com/node-saml/node-saml/pull/18)

---

## v4.0.0-beta.0 (2021-06-30)

#### 🚀 Minor Changes:

- Support importing to `passport-saml` project [#9](https://github.com/node-saml/node-saml/pull/9)
- Add assertion attributes to child object on profile (passport-saml#543) [#5](https://github.com/node-saml/node-saml/pull/5)

#### 🐛 Bug Fixes:

- Remove duplicate calls to the cache provider [#4](https://github.com/node-saml/node-saml/pull/4)
- [**security**] Limit transforms for signed nodes [#6](https://github.com/node-saml/node-saml/pull/6)

#### 📚 Documentation:

- Update README.md [#1](https://github.com/node-saml/node-saml/pull/1)

#### ⚙️ Technical Tasks:

- Remove passport-saml code and tests [#3](https://github.com/node-saml/node-saml/pull/3)
- Fix workflow for Node 16.x [#7](https://github.com/node-saml/node-saml/pull/7)

---

## v3.0.0 (2021-05-14)

#### 💣 Major Changes:

- Node saml separated from [passport-saml](https://github.com/node-saml/passport-saml) [#574](https://github.com/node-saml/passport-saml/pull/574)

---

For Changes prior to v3.0.0 see [passport-saml](https://github.com/node-saml/passport-saml)
