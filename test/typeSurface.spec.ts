import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { expect } from "chai";

const repoRoot = path.join(__dirname, "..");
const tscEntry = path.join(repoRoot, "node_modules", "typescript", "bin", "tsc");
const packageEntry = JSON.stringify(repoRoot);

/**
 * Compiles `source` on its own against the declarations this package publishes and returns
 * whatever tsc reported.
 *
 * The checks below are about the emitted `.d.ts`, not the sources: a consumer sees the shape
 * TypeScript wrote out, and options like `declaration` can change it without changing `src`.
 */
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
    // `npm test` builds first, but a bare mocha run need not have.
    if (!fs.existsSync(path.join(repoRoot, "lib", "index.d.ts"))) {
      const build = spawnSync(process.execPath, [tscEntry], { cwd: repoRoot, encoding: "utf8" });
      expect(build.status, `tsc failed to build lib/:\n${build.stdout}`).to.equal(0);
    }
  });

  // `SAML` is exported from the barrel, so subclassing it is part of the exposed surface and
  // an override's signature is part of the semver contract. Adding a second overload to any of
  // these methods makes every override written against the previous signature stop compiling,
  // which is a major change; this test is what catches that.
  it("keeps compiling a subclass written against the previous signatures", function () {
    const errors = typeCheck(`
      import { SAML, AuthOptions } from ${packageEntry};
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
    `);

    expect(errors).to.equal("");
  });

  // Without this, the two tests above would pass just as happily if `typeCheck` silently
  // stopped reporting anything.
  it("reports an error when the consumer really is wrong", function () {
    const errors = typeCheck(`
      import { SAML } from ${packageEntry};

      declare const saml: SAML;
      void saml.getAuthorizeUrlAsync(42);
    `);

    expect(errors).to.contain("error TS");
  });
});
