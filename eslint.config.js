import js from "@eslint/js";

export default [
  {
    ignores: [
      "dist/**",
      "build/**",
      "coverage/**",
      "node_modules/**",
      ".git/**",
      "*.min.js"
    ]
  },

  js.configs.recommended,

  {
    files: [
      "**/*.js",
      "**/*.mjs"
    ],

    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module"
    },

    rules: {
      "no-console": "warn",
      "no-debugger": "error",

      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",

      "no-unsafe-finally": "error",
      "no-unsafe-negation": "error",

      "no-var": "error",
      "prefer-const": "error",

      "eqeqeq": [
        "error",
        "always"
      ],

      "curly": [
        "error",
        "all"
      ],

      "no-throw-literal": "error",

      "no-unused-vars": [
        "error",
        {
          "args": "after-used",
          "argsIgnorePattern": "^_",
          "varsIgnorePattern": "^_",
          "caughtErrors": "none"
        }
      ],

      "no-use-before-define": [
        "error",
        {
          "functions": false,
          "classes": true,
          "variables": true
        }
      ],

      "no-duplicate-imports": "error",

      "no-self-compare": "error",
      "no-unmodified-loop-condition": "error",

      "consistent-return": "error",

      "no-return-await": "error",

      "no-prototype-builtins": "error",

      "object-shorthand": [
        "error",
        "always"
      ],

      "prefer-template": "error",

      "template-curly-spacing": [
        "error",
        "never"
      ],

      "quotes": [
        "error",
        "double",
        {
          "avoidEscape": true,
          "allowTemplateLiterals": true
        }
      ],

      "semi": [
        "error",
        "always"
      ],

      "indent": [
        "error",
        2,
        {
          "SwitchCase": 1
        }
      ],

      "comma-dangle": [
        "error",
        "never"
      ],

      "no-multi-spaces": "error",
      "no-trailing-spaces": "error"
    }
  },

  {
    files: [
      "src/background/**/*.js",
      "src/background/**/*.mjs"
    ],

    languageOptions: {
      globals: {
        chrome: "readonly"
      }
    }
  },

  {
    files: [
      "src/content/**/*.js",
      "src/content/**/*.mjs"
    ],

    languageOptions: {
      globals: {
        chrome: "readonly",
        browser: "readonly"
      }
    }
  },

  {
    files: [
      "src/**/*.test.js",
      "src/**/*.test.mjs",
      "test/**/*.js",
      "test/**/*.mjs"
    ],

    languageOptions: {
      globals: {
        chrome: "readonly",
        browser: "readonly"
      }
    },

    rules: {
      "no-console": "off"
    }
  },

  {
    files: [
      "scripts/**/*.js",
      "scripts/**/*.mjs"
    ],

    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly"
      }
    }
  }
];
