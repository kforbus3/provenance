// Flat ESLint config (ESLint 9+) for the Fleet Terminal frontend.
//
// Philosophy: errors for things that are real bugs, warnings for style/quality
// so the gate can pass on the existing tree without a large refactor. Tighten
// warnings to errors over time. Run with `npm run lint`.

import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // Not linted: build output, deps, generated help content, e2e artifacts,
    // and vendored player assets.
    ignores: [
      'dist',
      'node_modules',
      'test-results',
      'playwright-report',
      'coverage',
      'public/**',
      'src/help/help-content.ts',
      'src/**/*.gen.ts',
      '**/*.generated.*',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // Fast-refresh correctness: warn, since some files legitimately export
      // constants alongside components.
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],

      // Real bugs -> error.
      'no-debugger': 'error',
      '@typescript-eslint/no-misused-promises': 'off', // needs type-info program; keep off for speed

      // Pragmatic downgrades so the existing codebase passes; revisit later.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/ban-ts-comment': 'warn',
      'no-empty': ['warn', { allowEmptyCatch: true }],
      'prefer-const': 'warn',
      'no-console': 'off',
      // Empty interfaces are used for MUI module augmentation; ternary-as-
      // statement appears intentionally. Style, not bugs -> warn.
      '@typescript-eslint/no-empty-object-type': 'warn',
      '@typescript-eslint/no-unused-expressions': 'warn',
    },
  },
  {
    // Test and Node-side tooling files: allow Node globals and looser rules.
    files: [
      '**/*.test.{ts,tsx}',
      '**/*.spec.{ts,tsx}',
      'e2e/**',
      'scripts/**',
      'test/**',
      '*.config.{js,ts}',
    ],
    languageOptions: {
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },
);
