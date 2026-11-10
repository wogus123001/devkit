// Central security layer. Every HTML string that reaches the DOM goes through here.
//
// Defense in depth:
//  1. Tools build HTML only from escapeHtml()-ed text.
//  2. setHtml() still runs that HTML through DOMPurify with a strict allowlist.
//  3. In production a CSP with `require-trusted-types-for 'script'` makes any
//     other innerHTML assignment throw (Chromium), so a forgotten sink fails closed.
import DOMPurify, { type Config } from 'dompurify';

/** Inputs larger than this are rejected before processing (DoS guard). */
export const MAX_INPUT_CHARS = 5_000_000;
/** Outputs larger than this are shown as plain text instead of highlighted HTML. */
export const HIGHLIGHT_LIMIT = 400_000;

// ---------- Trusted Types ----------
interface TTPolicy {
  createHTML(s: string): unknown;
  createScriptURL(s: string): unknown;
}
interface TTRules {
  createHTML?(s: string): string;
  createScriptURL?(s: string): string;
}
const tt = (globalThis as { trustedTypes?: { createPolicy(name: string, rules: TTRules): TTPolicy } }).trustedTypes;

/** Only this app's own bundled worker scripts may be loaded as workers. */
function vetWorkerUrl(s: string): string {
  const u = new URL(s, location.href);
  if (u.origin !== location.origin || !/\/(?:assets\/)?[\w.-]*\.worker[\w.-]*\.(?:js|ts)$/.test(u.pathname)) throw new TypeError('허용되지 않은 워커 스크립트: ' + u.href);
  return u.href;
}

const HIGHLIGHT_CONFIG: Config = {
  ALLOWED_TAGS: ['span', 'mark', 'div', 'details', 'summary', 'ins', 'del', 'em', 'strong', 'br'],
  ALLOWED_ATTR: ['class', 'title', 'open'],
  ALLOW_DATA_ATTR: false,
  ALLOW_ARIA_ATTR: false,
  SANITIZE_NAMED_PROPS: true,
};

const MARKDOWN_CONFIG: Config = {
  USE_PROFILES: { html: true },
  // No forms, frames, embedded documents, styles or SVG/MathML (mXSS-prone namespaces).
  FORBID_TAGS: ['style', 'form', 'input', 'button', 'textarea', 'select', 'option', 'iframe', 'frame', 'frameset', 'object', 'embed', 'base', 'link', 'meta', 'svg', 'math', 'template', 'dialog', 'video', 'audio', 'source', 'track', 'picture'],
  FORBID_ATTR: ['style', 'srcset', 'action', 'formaction', 'ping', 'background', 'poster'],
  ALLOW_DATA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  SANITIZE_NAMED_PROPS: true, // prefixes id/name to stop DOM clobbering
  ALLOWED_URI_REGEXP: /^(?:https?:|mailto:|#|\/(?!\/)|\.{0,2}\/|data:image\/(?:png|jpe?g|gif|webp|avif|bmp);base64,)/i,
};

const policy: TTPolicy | null = tt
  ? tt.createPolicy('devkit', { createHTML: (s) => DOMPurify.sanitize(s, HIGHLIGHT_CONFIG) as string, createScriptURL: vetWorkerUrl })
  : null;

/** Start a module worker from a URL that passed the same-origin worker allowlist. */
export function createWorker(url: URL): Worker {
  const vetted = policy ? policy.createScriptURL(url.href) : vetWorkerUrl(url.href);
  return new Worker(vetted as string, { type: 'module' });
}
// Used ONLY to feed DOMParser, whose documents are inert (no script execution, no resource loads).
const inertPolicy: TTPolicy | null = tt ? tt.createPolicy('devkit-inert', { createHTML: (s) => s }) : null;

/** Escape text for safe inclusion in HTML element content or quoted attributes. */
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** Render highlighter output (already escaped) after strict sanitization. */
export function setHtml(el: Element, html: string): void {
  const clean = DOMPurify.sanitize(html, HIGHLIGHT_CONFIG) as string;
  (el as unknown as { innerHTML: unknown }).innerHTML = policy ? policy.createHTML(clean) : clean;
}

let markdownHooked = false;
/** Sanitize user-authored HTML (markdown output) for display. Remote images are blocked. */
export function setUntrustedHtml(el: Element, html: string): { blockedImages: number } {
  let blockedImages = 0;
  if (!markdownHooked) {
    markdownHooked = true;
    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
      if (node.tagName === 'A') {
        const href = node.getAttribute('href') ?? '';
        if (/^https?:|^mailto:/i.test(href)) {
          node.setAttribute('target', '_blank');
          node.setAttribute('rel', 'noopener noreferrer nofollow');
        }
      }
    });
  }
  const frag = DOMPurify.sanitize(html, { ...MARKDOWN_CONFIG, RETURN_DOM_FRAGMENT: true }) as DocumentFragment;
  // Remote images would leak the viewer's IP/timing to a third party: replace them with their alt text.
  frag.querySelectorAll('img').forEach((img) => {
    const src = img.getAttribute('src') ?? '';
    if (!/^data:image\//i.test(src)) {
      blockedImages++;
      const span = document.createElement('span');
      span.className = 'blocked-img';
      span.textContent = `🖼 외부 이미지 차단됨${img.alt ? `: ${img.alt}` : ''}`;
      span.title = src;
      img.replaceWith(span);
    }
  });
  el.replaceChildren(frag);
  return { blockedImages };
}

/** Parse a string with DOMParser. The resulting document is inert. */
export function parseInert(src: string, type: DOMParserSupportedType): Document {
  const value = inertPolicy ? inertPolicy.createHTML(src) : src;
  return new DOMParser().parseFromString(value as string, type);
}

/** Allow only URL schemes that cannot execute script in this origin. */
export function safeUrl(url: string, kind: 'href' | 'src'): string {
  const u = url.trim();
  if (u === '' || u.startsWith('#')) return u;
  if (/^blob:/i.test(u)) return u; // created by us from data typed as non-executable
  if (/^data:image\/(png|jpe?g|gif|webp|avif|bmp|svg\+xml)[;,]/i.test(u)) return u; // images render inert in <img>
  if (kind === 'href' && /^(https?:|mailto:)/i.test(u)) return u;
  if (kind === 'href' && /^\/(?![/\\])/.test(u)) return u; // same-origin path; `//x` and `/\x` would leave the origin
  if (kind === 'src' && /^https?:/i.test(u)) return u;
  return 'about:blank';
}

// ---------- invisible / deceptive characters ----------
const SUSPICIOUS: [string, RegExp][] = [
  ['양방향 제어 문자 (Trojan Source)', /[‪-‮⁦-⁩‎‏؜]/g],
  ['폭 없는 문자 (Zero-width)', /[​-‍⁠﻿᠎]/g],
  ['유니코드 태그 문자 (숨은 텍스트)', /[\u{E0000}-\u{E007F}]/gu],
  ['제어 문자', /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g],
  ['소프트 하이픈 / 채움 문자', /[­ᅟᅠㅤﾠ]/g],
];

export interface Suspicious {
  label: string;
  count: number;
}

/** Find characters that are invisible or reorder text — used in homoglyph/Trojan Source tricks. */
export function findSuspicious(text: string): Suspicious[] {
  if (text.length > MAX_INPUT_CHARS) return [];
  const out: Suspicious[] = [];
  for (const [label, re] of SUSPICIOUS) {
    re.lastIndex = 0;
    const n = text.match(re)?.length ?? 0;
    if (n) out.push({ label, count: n });
  }
  return out;
}

export function stripSuspicious(text: string): string {
  return SUSPICIOUS.reduce((t, [, re]) => t.replace(re, ''), text);
}

/** Throw a readable error when input is too large to process safely. */
export function assertInputSize(text: string, max = MAX_INPUT_CHARS): void {
  if (text.length > max) throw new Error(`입력이 너무 큽니다 (${text.length.toLocaleString()}자). 최대 ${max.toLocaleString()}자까지 처리합니다.`);
}

/** Create a plain object with no prototype, so keys like "__proto__" or "constructor" stay ordinary data. */
export function bareObject<T = unknown>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}
