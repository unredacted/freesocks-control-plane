// Minimal ESLint flat config (ESLint v9+ format).
//
// We rely on TypeScript's compiler for the bulk of correctness checking
// (`bun run typecheck`); ESLint here is purely for catching the few issues
// the type system can't, plus a guard rail for accidental console.log /
// debugger leaks. Heavier linting (typescript-eslint, react-specific rules)
// is intentionally not pulled in: it'd add ~30s to CI for marginal value
// when `tsc --strict` already enforces most of what those plugins check.

export default [
  {
    ignores: [
      'dist/**',
      'dist-bun/**',
      'node_modules/**',
      'src/lib/paraglide/**', // Paraglide-compiled output (generated, gitignored)
      'src/server/db/migrations/**',
      'worker-configuration.d.ts',
      '.wrangler/**',
      'coverage/**',
    ],
  },
  {
    // ESLint applies only to plain JS files. TypeScript correctness is
    // covered by `tsc --strict` (`bun run typecheck`); pulling in
    // typescript-eslint would add ~30s to CI for marginal value when
    // tsc already enforces most of what those plugins check. If we
    // ever add custom lint rules that target TS-specific patterns,
    // install typescript-eslint at that point.
    files: ['**/*.{js,mjs}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        // Browser
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        location: 'readonly',
        fetch: 'readonly',
        crypto: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        AbortController: 'readonly',
        AbortSignal: 'readonly',
        Request: 'readonly',
        Response: 'readonly',
        Headers: 'readonly',
        FormData: 'readonly',
        Blob: 'readonly',
        File: 'readonly',
        atob: 'readonly',
        btoa: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        Uint8Array: 'readonly',
        ArrayBuffer: 'readonly',
        // Node / Worker
        process: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        // React-specific (JSX)
        React: 'readonly',
      },
    },
    rules: {
      'no-debugger': 'error',
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-unreachable': 'error',
      'no-constant-condition': ['error', { checkLoops: false }],
      'prefer-const': 'warn',
      'no-var': 'error',
    },
  },
];
