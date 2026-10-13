import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as ts from "typescript";
import { expect } from "chai";

const repoRoot = path.join(__dirname, "..");
const tscEntry = path.join(repoRoot, "node_modules", "typescript", "bin", "tsc");
const packageEntry = JSON.stringify(repoRoot);
const qsTypesEntry = JSON.stringify(path.join(repoRoot, "node_modules", "@types", "qs"));

// Compiles `source` against the emitted `.d.ts` rather than the sources, because that is the
// shape a consumer sees and `declaration` options can change it without changing `src`.
function typeCheck(source: string, extraOptions: string[] = []): string {
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
        ...extraOptions,
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

// Walks the declarations of everything `entry` exports, and of every type they reach that is
// declared in `packageDir`, and returns each such type that `entry` itself does not export.
function unexportedTypesReachableFrom(entry: string, packageDir = path.dirname(entry)): string[] {
  const ownDir = packageDir + path.sep;
  const program = ts.createProgram([entry], { noEmit: true, types: [] });
  const checker = program.getTypeChecker();
  const entryFile = program.getSourceFile(entry);
  const entryModule = entryFile && checker.getSymbolAtLocation(entryFile);
  if (entryModule == null) {
    throw new Error(`${entry} is not a module`);
  }

  const resolve = (symbol: ts.Symbol | undefined) =>
    symbol != null && symbol.flags & ts.SymbolFlags.Alias
      ? checker.getAliasedSymbol(symbol)
      : symbol;
  const ownDeclarations = (symbol: ts.Symbol) =>
    (symbol.declarations ?? []).filter((declaration) =>
      path.normalize(declaration.getSourceFile().fileName).startsWith(ownDir),
    );
  const referencedName = (node: ts.Node): ts.Node | undefined => {
    let name: ts.Node | undefined;
    if (ts.isTypeReferenceNode(node)) name = node.typeName;
    else if (ts.isExpressionWithTypeArguments(node)) name = node.expression;
    else if (ts.isTypeQueryNode(node)) name = node.exprName;
    else if (ts.isImportTypeNode(node)) name = node.qualifier;
    if (name != null && ts.isQualifiedName(name)) return name.right;
    if (name != null && ts.isPropertyAccessExpression(name)) return name.name;
    return name;
  };

  const exported = new Set(checker.getExportsOfModule(entryModule).map(resolve));
  const reachedFrom = new Map<ts.Symbol, ts.Symbol>();
  const pending = [...exported].filter((symbol): symbol is ts.Symbol => symbol != null);

  for (let symbol = pending.shift(); symbol != null; symbol = pending.shift()) {
    const referrer = symbol;
    const visit = (node: ts.Node): void => {
      const name = referencedName(node);
      const referenced = name && resolve(checker.getSymbolAtLocation(name));
      if (referenced && !reachedFrom.has(referenced) && ownDeclarations(referenced).length > 0) {
        reachedFrom.set(referenced, referrer);
        pending.push(referenced);
      }
      ts.forEachChild(node, visit);
    };
    ownDeclarations(symbol).forEach(visit);
  }

  return [...reachedFrom]
    .filter(([symbol]) => !exported.has(symbol))
    .map(([symbol, referrer]) => `${symbol.getName()} (via ${referrer.getName()})`)
    .sort();
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
      import type { ParsedQs } from ${qsTypesEntry};
      import type * as querystring from "querystring";

      class LegacySubclass extends SAML {
        async validateRedirectAsync(
          container: ParsedQs,
          originalQuery: string,
        ): Promise<{ profile: Profile | null; loggedOut: boolean }> {
          return super.validateRedirectAsync(container, originalQuery);
        }

        protected async hasValidSignatureForRedirect(
          container: ParsedQs,
          originalQuery: string,
        ): Promise<boolean | void> {
          return super.hasValidSignatureForRedirect(container, originalQuery);
        }

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

        protected async processValidlySignedSamlLogoutAsync(
          doc: Record<string, any>,
          dom: Document,
        ): Promise<{ profile: Profile | null; loggedOut: boolean }> {
          return super.processValidlySignedSamlLogoutAsync(doc, dom);
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

  it("exports InMemoryCacheProvider for a SamlConfig, with or without options", function () {
    const errors = typeCheck(`
      import { InMemoryCacheProvider, SAML } from ${packageEntry};

      const config = { callbackUrl: "https://sp.example.com/callback", issuer: "sp", idpCert: "cert" };
      void new SAML({ ...config, cacheProvider: new InMemoryCacheProvider() });
      void new SAML({
        ...config,
        cacheProvider: new InMemoryCacheProvider({ keyExpirationPeriodMs: 3600000 }),
      });
    `);

    expect(errors).to.equal("");
  });

  // Without this, the tests above would pass if `typeCheck` stopped reporting anything.
  it("accepts validateRedirectAsync with the query string alone and with a parsed query before it", function () {
    const consumer = `
      import { SAML, Profile } from ${packageEntry};
      import type { ParsedQs } from ${qsTypesEntry};
      import type * as querystring from "querystring";

      declare const saml: SAML;
      declare const originalQuery: string;
      declare const parsedByQs: ParsedQs;
      declare const parsedByQuerystring: querystring.ParsedUrlQuery;
      declare const handBuilt: Record<string, string>;

      void saml.validateRedirectAsync(parsedByQs, originalQuery);
      void saml.validateRedirectAsync(parsedByQuerystring, originalQuery);
      void saml.validateRedirectAsync(handBuilt, originalQuery);

      // Callers whose own query type is looser than ParsedQs cast to the parameter's type, and
      // callers that wrap the method take its argument list.
      declare const loose: Record<string, unknown>;
      void saml.validateRedirectAsync(
        loose as Parameters<typeof saml.validateRedirectAsync>[0],
        originalQuery,
      );
      const forwarded: Parameters<SAML["validateRedirectAsync"]> = [handBuilt, originalQuery];
      void saml.validateRedirectAsync(...forwarded);

      async function logout(): Promise<{ profile: Profile | null; relayState: string | undefined }> {
        const { profile, relayState } = await saml.validateRedirectAsync(originalQuery);
        return { profile, relayState };
      }

      export { logout };
    `;

    expect(typeCheck(consumer)).to.equal("");
    expect(typeCheck(consumer, ["--exactOptionalPropertyTypes"])).to.equal("");
  });

  // The query string was required beside a parsed query, and accepting it alone must not make it
  // optional there.
  it("still requires the query string after a parsed query on validateRedirectAsync", function () {
    const source = `
      import { SAML } from ${packageEntry};

      declare const saml: SAML;
      declare const parsed: Record<string, string>;
      void saml.validateRedirectAsync(parsed);
    `;
    const callLine =
      source.split("\n").findIndex((line) => line.includes("validateRedirectAsync")) + 1;

    const reported = typeCheck(source)
      .split("\n")
      .filter((line) => line.includes("error TS"));
    expect(reported).to.have.lengthOf(1);
    expect(reported[0]).to.contain(`consumer.ts(${callLine},`);
    expect(reported[0]).to.contain("error TS2345");
  });

  it("reports an error when the consumer really is wrong", function () {
    const errors = typeCheck(`
      import { SAML } from ${packageEntry};

      declare const saml: SAML;
      void saml.getAuthorizeUrlAsync(42);
    `);

    expect(errors).to.contain("error TS");
  });

  // The parameter and its exact published type stay until the next major, because a 5.1 consumer has
  // to keep compiling. That it can no longer alter verification is `test-signatures.spec.ts`'s job.
  it("still accepts the injected-dependency argument it no longer honors", function () {
    const ordinaryCall = typeCheck(`
      import { SAML } from ${packageEntry};

      declare const saml: SAML;
      declare const body: Record<string, string>;
      void saml.validatePostRequestAsync(body);
    `);

    expect(ordinaryCall, "a one-argument call is what consumers write").to.equal("");

    // The forms the v5.1 declaration permits: callbacks whose parameters infer, which `() => true`
    // alone would not exercise; an explicitly `undefined` property; and an override forwarding the
    // published type to `super`.
    const legacyConsumer = `
      import { SAML, Profile } from ${packageEntry};
      import type { XmlJsObject } from ${JSON.stringify(path.join(repoRoot, "lib", "types"))};

      declare const saml: SAML;
      declare const body: Record<string, string>;

      void saml.validatePostRequestAsync(body, {
        _parseDomFromString: (xml) => Promise.reject(new Error(xml)),
        _parseXml2JsFromString: (xml) => Promise.reject(new Error(String(xml))),
        _validateSignature: (fullXml, currentNode, pemFiles) =>
          fullXml.length > 0 && currentNode != null && pemFiles.length > 0,
      });

      void saml.validatePostRequestAsync(body, { _validateSignature: () => true });
      void saml.validatePostRequestAsync(body, { _validateSignature: undefined });

      class LegacySubclass extends SAML {
        async validatePostRequestAsync(
          container: Record<string, string>,
          injected?: {
            _parseDomFromString?: ((xml: string) => Promise<Document>) | undefined;
            _parseXml2JsFromString?: ((xml: string | Buffer) => Promise<XmlJsObject>) | undefined;
            _validateSignature?:
              | ((fullXml: string, currentNode: Element, pemFiles: string[]) => boolean)
              | undefined;
          },
        ): Promise<{ profile: Profile; loggedOut: boolean }> {
          return super.validatePostRequestAsync(container, injected);
        }
      }

      export { LegacySubclass };
    `;

    expect(typeCheck(legacyConsumer), "a v5.1 consumer still compiles").to.equal("");

    // `exactOptionalPropertyTypes` is what makes the `| undefined` load-bearing, in the call and in
    // the override's `super`. The repository does not set it, but a consumer may.
    expect(
      typeCheck(legacyConsumer, ["--exactOptionalPropertyTypes"]),
      "a v5.1 consumer with exactOptionalPropertyTypes still compiles",
    ).to.equal("");
  });

  // A consumer should never need a path under `lib/` to name a type the root API makes it use.
  it("exports from the package root every type its API references", function () {
    expect(unexportedTypesReachableFrom(path.join(repoRoot, "lib", "index.d.ts"))).to.deep.equal(
      [],
    );
  });

  // Without this, the test above would pass if the walk stopped finding anything. The entry is the
  // package root as it was before these types were exported, over the real build.
  it("finds the types an earlier, narrower root left reachable only through lib/", function () {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "node-saml-type-walk-"));
    try {
      const entry = path.join(dir, "index.d.ts");
      fs.writeFileSync(
        entry,
        `export {
          SAML, generateServiceProviderMetadata, CacheItem, CacheProvider, InMemoryCacheProvider,
          SamlOptions, MandatorySamlOptions, Profile, SamlConfig, ValidateInResponseTo, RacComparison,
          SamlScopingConfig, SamlIDPListConfig, SamlIDPEntryConfig, SignatureAlgorithm, IdpCertCallback,
          AuthOptions, SamlStatusError,
        } from ${JSON.stringify(path.join(repoRoot, "lib"))};`,
      );

      const found = unexportedTypesReachableFrom(entry, path.join(repoRoot, "lib"));

      expect(found.map((type) => type.split(" ")[0])).to.include.members([
        "AudienceRestrictionXML",
        "CacheProviderOptions",
        "GenerateServiceProviderMetadataParams",
        "SamlSigningOptions",
        "XMLObject",
        "XMLOutput",
        "XMLValue",
        "XmlJsObject",
      ]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
