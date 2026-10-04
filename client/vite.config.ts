import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Production builds get a strict Content-Security-Policy. `wasm-unsafe-eval`
 * is required for the Argon2id WebAssembly module; no inline scripts, no
 * third-party origins (fonts, QR codes and crypto are all local).
 */
function csp(): Plugin {
  return {
    name: 'cipherchat-csp',
    apply: 'build',
    transformIndexHtml(html) {
      const policy = [
        "default-src 'self'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob:",
        "media-src 'self' blob:",
        "connect-src 'self' ws: wss:",
        "worker-src 'self' blob:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
      ].join('; ');
      return html.replace(
        '<meta charset="UTF-8" />',
        `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />\n    <meta name="referrer" content="no-referrer" />`,
      );
    },
  };
}

export default defineConfig(({ mode }) => ({
  // GitHub Pages serves the demo from /cipher-chat/; Cloudflare Pages (CF_PAGES set) from the root
  base: mode === 'demo' && !process.env.CF_PAGES ? '/cipher-chat/' : '/',
  plugins: [react(), csp()],
  server: { port: 3402, strictPort: true },
  preview: { port: 3403, strictPort: true },
  build: {
    target: 'es2022',
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
}));
