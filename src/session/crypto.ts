// Mã hóa token khi lưu và băm session id — dùng node:crypto chuẩn (AES-256-GCM, SHA-256),
// không tự viết thuật toán mật mã.
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export class TokenSealer {
  private readonly key: Buffer;

  constructor(base64Key: string) {
    this.key = Buffer.from(base64Key, 'base64');
    if (this.key.length !== 32) throw new Error('SESSION_ENC_KEY phải là 32 byte');
  }

  // Kết quả: base64url(iv[12] | tag[16] | ciphertext). IV ngẫu nhiên mỗi lần → cùng token cho ra chuỗi khác nhau
  seal(plain: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64url');
  }

  // Ném lỗi nếu dữ liệu bị sửa (GCM kiểm tra tính toàn vẹn qua authTag)
  open(sealed: string): string {
    const buf = Buffer.from(sealed, 'base64url');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  }
}

// Session id: 32 byte ngẫu nhiên (256 bit) → không đoán được
export function newSessionId(): string {
  return randomBytes(32).toString('base64url');
}

export function hashSessionId(id: string): string {
  return createHash('sha256').update(id).digest('hex');
}
