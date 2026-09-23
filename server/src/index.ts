/**
 * CipherChat blind relay - entry point.
 *
 *   PORT=3401 ALLOWED_ORIGINS=https://example.github.io SQLITE_PATH=./relay.sqlite node dist/server.js
 */
import { createRelayServer } from './app.ts';
import { loadConfig } from './config.ts';

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  const server = await createRelayServer(config);
  await server.listen();
  let closing = false;
  const shutdown = (signal: string): void => {
    if (closing) return;
    closing = true;
    server.logger.info('server.shutdown', { signal });
    const force = setTimeout(() => process.exit(1), 5000);
    force.unref();
    void server.close().then(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((e: unknown) => {
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level: 'error', evt: 'server.fatal', msg: String(e) }) + '\n');
  process.exit(1);
});
