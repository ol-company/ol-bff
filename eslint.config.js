// ESLint flat config dùng chung cho các repo Node/TypeScript của OL-Platform
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'coverage/**', 'node_modules/**'] }, // Không lint code sinh ra
  js.configs.recommended, // Luật cơ bản của ESLint
  ...tseslint.configs.recommended, // Luật cho TypeScript
  {
    rules: {
      // Cho phép tham số không dùng nếu bắt đầu bằng "_" (ví dụ _next trong middleware lỗi)
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // Cấm console.* — mọi log đi qua pino để có JSON + trace_id
      'no-console': 'error',
      // Bắt buộc dùng `import type` cho import chỉ chứa kiểu
      '@typescript-eslint/consistent-type-imports': 'error',
    },
  },
  {
    files: ['test/**/*.ts', 'scripts/**/*.{js,mjs,ts}'],
    rules: { 'no-console': 'off' }, // Script và test được in ra console
  },
  {
    // File .mjs/.js không được typescript-eslint tắt `no-undef`, nên phải khai báo global của Node
    files: ['scripts/**/*.{js,mjs}'],
    languageOptions: { globals: { process: 'readonly', console: 'readonly' } },
  },
);
