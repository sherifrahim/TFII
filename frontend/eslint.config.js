import js from "@eslint/js";
import globals from "globals";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";

export default [
  { ignores: ["build/**", "node_modules/**"] },
  js.configs.recommended,
  {
    files: ["src/**/*.js"],
    plugins: { react, "react-hooks": reactHooks },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser, ...globals.es2021 },
    },
    linterOptions: { reportUnusedDisableDirectives: "off" },
    settings: { react: { version: "18" } },
    rules: {
      "react/jsx-uses-vars": "error",
      "react/jsx-uses-react": "error",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "no-unused-vars": ["warn", { args: "none", ignoreRestSiblings: true, caughtErrors: "none" }],
      "no-empty": ["error", { allowEmptyCatch: true }],
      "no-script-url": "error",
    },
  },
  { files: ["src/**/*.test.js"], languageOptions: { globals: { ...globals.vitest, ...globals.node } } },
];
