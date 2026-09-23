// Runs the relay (port 3401) and the Vite client (port 3402) together, cross-platform.
import { spawn } from 'node:child_process';

const procs = [
  ['server', 'npm run dev -w server'],
  ['client', 'npm run dev -w client'],
].map(([name, cmd]) => {
  const p = spawn(cmd, { shell: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const tag = name === 'server' ? '\x1b[36m[relay] \x1b[0m' : '\x1b[35m[client]\x1b[0m';
  for (const s of [p.stdout, p.stderr]) s.on('data', (d) => process.stdout.write(String(d).replace(/^(?=.)/gm, `${tag} `)));
  p.on('exit', (code) => {
    console.log(`${tag} exited (${code})`);
    shutdown();
  });
  return p;
});

let down = false;
function shutdown() {
  if (down) return;
  down = true;
  for (const p of procs) p.kill();
  setTimeout(() => process.exit(0), 300);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
