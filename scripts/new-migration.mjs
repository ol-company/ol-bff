// Tạo file migration SQL mới và thêm vào migrations/meta/_journal.json (định dạng migrator của Drizzle).
// Dùng: pnpm db:new add_user_locale   → tạo migrations/0001_add_user_locale.sql
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const name = process.argv[2];
if (!name || !/^[a-z0-9_]+$/.test(name)) {
  console.error('Cách dùng: pnpm db:new <ten_migration> (chữ thường, số, gạch dưới)');
  process.exit(1);
}

const dir = join(process.cwd(), 'migrations');
const journalPath = join(dir, 'meta', '_journal.json');
const journal = JSON.parse(readFileSync(journalPath, 'utf8'));
const idx = journal.entries.length; // Số thứ tự tiếp theo
const tag = `${String(idx).padStart(4, '0')}_${name}`;
const file = join(dir, `${tag}.sql`);
if (existsSync(file)) {
  console.error(`Đã tồn tại: ${file}`);
  process.exit(1);
}

writeFileSync(
  file,
  `-- ${tag}\n-- Quy tắc: tương thích ngược (expand/contract). Không DROP/RENAME cột mà phiên bản đang chạy còn dùng.\n\n`,
);
journal.entries.push({ idx, version: '7', when: Date.now(), tag, breakpoints: false });
writeFileSync(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
console.log(`Đã tạo ${file}`);
