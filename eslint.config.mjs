import eslint from "@eslint/js";
import eslintPluginTypeScript from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import eslintConfigPrettier from "eslint-config-prettier/flat";
import pluginChaiFriendly from "eslint-plugin-chai-friendly";
import mochaPlugin from "eslint-plugin-mocha";
import { globalIgnores } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config([
  globalIgnores(["dist/**", "coverage/**", "lib/**"]),
  eslint.configs.recommended,
  tseslint.configs.recommended,
  tseslint.configs.strict,
  mochaPlugin.configs.flat.recommended,
  {
    files: ["**/*"],
    rules: {
      "linebreak-style": ["error", "unix"],
    },
  },
  {
    files: ["**/*.{js,ts}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.eslint.json",
        ecmaVersion: 2020,
        sourceType: "module",
      },
      globals: { ...globals.node },
    },
    plugins: {
      "@typescript-eslint": eslintPluginTypeScript,
    },
    rules: {
      "no-console": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-unused-vars": "error",
      "@typescript-eslint/no-invalid-void-type": "off",
      "@typescript-eslint/no-dynamic-delete": "off",
      "@typescript-eslint/no-unused-expressions": "off",
    },
  },
  {
    files: ["**/*.spec.{js,ts}"],
    languageOptions: {
      globals: { ...globals.mocha },
    },
    plugins: {
      mocha: mochaPlugin,
      "chai-friendly": pluginChaiFriendly,
    },
    rules: {
      "mocha/no-async-describe": "off",
      "@typescript-eslint/no-unused-expressions": "off",
      "mocha/no-setup-in-describe": "off",
      "mocha/no-exports": "off",
      "mocha/consistent-spacing-between-blocks": "off",
      "mocha/no-mocha-arrows": "off",
      "mocha/no-pending-tests": "off",
      "mocha/no-top-level-hooks": "off",
      "mocha/no-sibling-hooks": "off",
      "mocha/no-hooks-for-single-case": "off",
      "mocha/no-global-tests": "off",
      "chai-friendly/no-unused-expressions": "off",
    },
  },
  eslintConfigPrettier, // goes last
]);
