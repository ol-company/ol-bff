import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node', // Chạy test trong Node, không cần DOM
    include: ['test/**/*.test.ts'], // Chỉ lấy file test trong thư mục test/
    testTimeout: 60_000, // Integration test cần khởi động container PostgreSQL
    hookTimeout: 120_000,
    pool: 'forks', // Mỗi file test một process — tránh rò trạng thái giữa các file
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
    },
  },
});
