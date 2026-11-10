import { defineConfig, type Plugin } from 'vite';

// Content-Security-Policy for the production build.
// - No inline or remote scripts, no eval: injected markup cannot run code.
// - Trusted Types: every innerHTML must pass through the app's sanitizing policy (Chromium).
// - Network: the page may only talk to its own origin, so tool input cannot be exfiltrated
//   and remote images in user markdown cannot track viewers.
// frame-ancestors / X-Frame-Options cannot be set from a <meta> tag; see public/_headers.
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types devkit devkit-inert dompurify",
].join('; ');

function cspMeta(): Plugin {
  return {
    name: 'devkit-csp',
    apply: 'build', // the dev server needs inline HMR code, so CSP applies to builds only
    transformIndexHtml: () => [{ tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP }, injectTo: 'head-prepend' }],
  };
}

export default defineConfig({
  plugins: [cspMeta()],
  build: { sourcemap: false },
  worker: { format: 'es' },
});
