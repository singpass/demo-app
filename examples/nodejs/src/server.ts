import { router } from './router';
import * as crypto from 'crypto';
import config from '../../config.json';
import Koa from 'koa';
import logger from 'koa-logger';
import serve from 'koa-static';
import session from 'koa-session';

function createInMemorySessionStore() {
  const sessions = new Map<string, unknown>();
  return {
    async get(key: string) {
      return sessions.get(key);
    },
    async set(key: string, value: unknown) {
      sessions.set(key, value);
    },
    async destroy(key: string) {
      sessions.delete(key);
    },
  };
}

const app = new Koa();

// (Optional) Log all requests to this server
app.use(logger());

// Serve the static frontend
app.use(serve('../frontend'));

// Manage sessions using an in-memory session store and signed, SameSite=Lax, HttpOnly cookies
app.keys = [crypto.randomBytes(8).toString('hex')];
app.use(session({ store: createInMemorySessionStore(), sameSite: 'lax', httpOnly: true }, app));

// Serve the backend routes
app.use(router.routes()).listen(config.SERVER_PORT);

console.log(`[INFO]: Server started at http://localhost:${config.SERVER_PORT}\n`);
