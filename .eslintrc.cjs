module.exports = {
  root: true,
  env: {
    browser: true,
    node: true,
    es2021: true,
  },
  parserOptions: {
    ecmaVersion: 2021,
    sourceType: "module",
  },
  extends: ["eslint:recommended"],
  globals: {
    TextEncoder: "readonly",
    TextDecoder: "readonly",
    atob: "readonly",
    btoa: "readonly",
    navigator: "readonly",
    crypto: "readonly",
    indexedDB: "readonly",
  },
  rules: {
    "no-console": "off",
    "no-unused-vars": ["warn", { "argsIgnorePattern": "^_", "varsIgnorePattern": "^_" }],
    "no-empty": ["error", { "allowEmptyCatch": true }],
    "quotes": "off",
    "comma-dangle": "off",
  },
};
