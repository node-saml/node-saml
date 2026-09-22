import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { expect } from "chai";

const repoRoot = path.join(__dirname, "..");
const tscEntry = path.join(repoRoot, "node_modules", "typescript", "bin", "tsc");
const packageEntry = JSON.stringify(repoRoot);

// Compiles `source` against the emitted `.d.ts` rather than the sources, because that is the
// shape a consumer sees and `declaration` options can change it without changing `src`.
function typeCheck(source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "node-saml-type-surface-"));
  try {
    const file = path.join(dir, "consumer.ts");
    fs.writeFileSync(file, source);
    const { stdout } = spawnSync(
      process.execPath,
      [
        tscEntry,
        "--noEmit",
        "--strict",
        "--target",
        "es2018",
        "--module",
        "commonjs",
        "--moduleResolution",
        "node",
        "--skipLibCheck",
        "--types",
        "node",
        file,
      ],
      { cwd: repoRoot, encoding: "utf8" },
    );
    return stdout;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("published type surface", function () {
  // tsc is slow enough to blow the default timeout, and it runs once per test.
  this.timeout(60000);

  before(function () {
    // Always rebuild: running this spec alone after editing `src/` would otherwise pass
    // against the previous build.
    const build = spawnSync(process.execPath, [tscEntry], { cwd: repoRoot, encoding: "utf8" });
    expect(build.status, `tsc failed to build lib/:\n${build.stdout}`).to.equal(0);
  });

  // `SAML` is exported from the barrel, so an override's signature is part of the semver
  // contract. A second overload on any of these methods breaks every existing override, and a new
  // required parameter breaks the override's `super` call.
  it("keeps compiling a subclass written against the previous signatures", function () {
    const errors = typeCheck(`
      import { SAML, AuthOptions, Profile } from ${packageEntry};
      import type * as querystring from "querystring";

      class LegacySubclass extends SAML {
        async getAuthorizeUrlAsync(
          RelayState: string,
          host: string | undefined,
          options: AuthOptions,
        ): Promise<string> {
          return super.getAuthorizeUrlAsync(RelayState, host, options);
        }

        async getAuthorizeMessageAsync(
          RelayState: string,
          host?: string,
          options?: AuthOptions,
        ): Promise<querystring.ParsedUrlQueryInput> {
          return super.getAuthorizeMessageAsync(RelayState, host, options);
        }

        async getAuthorizeFormAsync(
          RelayState: string,
          host?: string,
          options?: AuthOptions,
        ): Promise<string> {
          return super.getAuthorizeFormAsync(RelayState, host, options);
        }

        protected async processValidlySignedAssertionAsync(
          xml: string,
          samlResponseXml: string,
          inResponseTo: string | null,
        ): Promise<{ profile: Profile; loggedOut: boolean }> {
          return super.processValidlySignedAssertionAsync(xml, samlResponseXml, inResponseTo);
        }
      }

      export { LegacySubclass };
    `);

    expect(errors).to.equal("");
  });

  it("accepts every call shape the deprecation supports", function () {
    const errors = typeCheck(`
      import { SAML, AuthOptions } from ${packageEntry};

      declare const saml: SAML;
      declare const options: AuthOptions;

      void saml.getAuthorizeUrlAsync("rs", "host.example", options);
      void saml.getAuthorizeUrlAsync("rs", undefined, options);
      void saml.getAuthorizeUrlAsync("rs", options);
      void saml.getAuthorizeMessageAsync("rs", "host.example", options);
      void saml.getAuthorizeMessageAsync("rs", undefined, options);
      void saml.getAuthorizeMessageAsync("rs", options);
      void saml.getAuthorizeFormAsync("rs", "host.example", options);
      void saml.getAuthorizeFormAsync("rs", undefined, options);
      void saml.getAuthorizeFormAsync("rs", options);

      // Both of these took every argument optionally before the deprecation.
      void saml.getAuthorizeMessageAsync("rs");
      void saml.getAuthorizeFormAsync("rs");
    `);

    expect(errors).to.equal("");
  });

  // `getAuthorizeUrlAsync` required both `host` and `options`, and the shape replacing them
  // still requires `options`, so widening must not quietly make the argument optional.
  it("still requires an argument after RelayState on getAuthorizeUrlAsync", function () {
    const errors = typeCheck(`
      import { SAML } from ${packageEntry};

      declare const saml: SAML;
      void saml.getAuthorizeUrlAsync("rs");
    `);

    expect(errors).to.contain("error TS");
  });

  it("keeps compiling a cache provider written without consumeAsync", function () {
    const errors = typeCheck(`
      import { CacheItem, CacheProvider } from ${packageEntry};

      class LegacyCacheProvider implements CacheProvider {
        async saveAsync(key: string, value: string): Promise<CacheItem | null> {
          return { value, createdAt: Date.now() };
        }
        async getAsync(key: string): Promise<string | null> {
          return null;
        }
        async removeAsync(key: string | null): Promise<string | null> {
          return key;
        }
      }

      export { LegacyCacheProvider };
    `);

    expect(errors).to.equal("");
  });

  it("accepts a cache provider with consumeAsync in a SamlConfig literal", function () {
    const errors = typeCheck(`
      import { SAML } from ${packageEntry};

      void new SAML({
        callbackUrl: "https://sp.example.com/callback",
        issuer: "sp",
        idpCert: "cert",
        cacheProvider: {
          saveAsync: async (key: string, value: string) => ({ value, createdAt: Date.now() }),
          getAsync: async () => null,
          removeAsync: async () => null,
          consumeAsync: async () => null,
        },
      });
    `);

    expect(errors).to.equal("");
  });

  // Without this, the tests above would pass if `typeCheck` stopped reporting anything.
  it("reports an error when the consumer really is wrong", function () {
    const errors = typeCheck(`
      import { SAML } from ${packageEntry};

      declare const saml: SAML;
      void saml.getAuthorizeUrlAsync(42);
    `);

    expect(errors).to.contain("error TS");
  });
});
