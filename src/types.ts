// Bổ sung kiểu cho Request của Express trong BFF
import type { Session } from './session/session-store.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: Session; // Gán bởi requireSession
    }
  }
}

export {};
