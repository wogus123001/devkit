import type { Tool } from '../types';
import { base64ToBytes, bytesToBase64, bytesToDisplay, formatBytes, fromHex, toHex, utf8 } from '../bytes';
import { button, copyButton, escapeHtml, h, highlightJson, panel, setHtml, textarea, toast, transformer } from '../ui';
import { assertInputSize, parseInert } from '../security';

/** Raster formats that browsers render as images only. SVG is excluded: it can carry script. */
const SAFE_PREVIEW = /^image\/(png|jpe?g|gif|webp|avif|bmp|x-icon|vnd\.microsoft\.icon)$/i;

// ---------- Base32 (RFC 4648) ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes: Uint8Array, pad: boolean): string {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  if (pad) while (out.length % 8) out += '=';
  return out;
}
function base32Decode(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/[\s=]/g, '');
  const out: number[] = [];
  let bits = 0, value = 0;
  for (const c of clean) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error(`Base32에 사용할 수 없는 문자: "${c}"`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// ---------- HTML entities ----------
const NAMED: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', ' ': '&nbsp;', '©': '&copy;', '®': '&reg;', '™': '&trade;' };
function htmlEncode(s: string, all: boolean): string {
  let out = '';
  for (const ch of s) {
    if (NAMED[ch]) out += NAMED[ch];
    else if (all && ch.codePointAt(0)! > 126) out += `&#${ch.codePointAt(0)};`;
    else out += ch;
  }
  return out;
}
function htmlDecode(s: string): string {
  // Parsed in an inert DOMParser document: scripts never run and no resources are fetched.
  // Inside <textarea> (RCDATA) only entities are decoded; tags stay literal text.
  const doc = parseInert(`<!doctype html><textarea>${s.replace(/<\/textarea/gi, '&lt;/textarea')}</textarea>`, 'text/html');
  return doc.querySelector('textarea')!.value;
}

// ---------- Unicode escapes ----------
function unicodeEscape(s: string, style: string, all: boolean): string {
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (!all && cp >= 32 && cp < 127) {
      out += ch;
      continue;
    }
    if (style === 'es6') out += `\\u{${cp.toString(16).toUpperCase()}}`;
    else if (style === 'html') out += `&#x${cp.toString(16).toUpperCase()};`;
    else if (style === 'css') out += `\\${cp.toString(16).toUpperCase()} `;
    else if (style === 'python' && cp > 0xffff) out += `\\U${cp.toString(16).padStart(8, '0')}`;
    else if (style === 'codepoint') out += `U+${cp.toString(16).toUpperCase().padStart(4, '0')} `;
    else for (let i = 0; i < ch.length; i++) out += `\\u${ch.charCodeAt(i).toString(16).padStart(4, '0')}`;
  }
  return style === 'codepoint' ? out.trim() : out;
}
function unicodeUnescape(s: string): string {
  return s
    .replace(/\\u\{([\da-fA-F]{1,6})\}/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\U([\da-fA-F]{8})/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([\da-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([\da-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#x([\da-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/U\+([\da-fA-F]{4,6})\s?/g, (_, h) => String.fromCodePoint(parseInt(h, 16)));
}

// ---------- Morse ----------
const MORSE: Record<string, string> = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--',
  N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
  0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
  ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', _: '..--.-', '"': '.-..-.', $: '...-..-', '@': '.--.-.',
};
const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));

function caesar(s: string, shift: number): string {
  const k = ((shift % 26) + 26) % 26;
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + k) % 26) + base);
  });
}

// ---------- JWT ----------
function decodeJwtPart(part: string): unknown {
  const text = bytesToDisplay(base64ToBytes(part));
  return JSON.parse(text);
}
const CLAIMS: Record<string, string> = {
  iss: '발급자 (issuer)', sub: '주체 (subject)', aud: '대상 (audience)', exp: '만료 시각', nbf: '유효 시작 시각', iat: '발급 시각',
  jti: '토큰 ID', alg: '서명 알고리즘', typ: '토큰 타입', kid: '키 ID', scope: '권한 범위', name: '이름', email: '이메일',
};

function jwtTool(root: HTMLElement) {
  const SAMPLE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Iu2Zjeq4uOuPmSIsImFkbWluIjp0cnVlLCJpYXQiOjE3NjI3NTY0MDAsImV4cCI6MjAwMDAwMDAwMH0.HyyQfmRGj2vigPdEfJRkl-oWH7I5HUQZzbYtxWOpOqQ';
  const input = textarea({ class: 'code short', placeholder: 'eyJhbGciOi… 형식의 JWT를 붙여넣으세요' });
  const out = h('div', { class: 'stack' });
  const update = () => {
    out.replaceChildren();
    const raw = input.value.trim().replace(/^Bearer\s+/i, '');
    if (!raw) return;
    const parts = raw.split('.');
    if (parts.length < 2 || parts.length > 3) {
      out.append(h('div', { class: 'error-box' }, `JWT는 점(.)으로 구분된 3개 부분이어야 합니다 (현재 ${parts.length}개)`));
      return;
    }
    if (raw.length > 100_000) {
      out.append(h('div', { class: 'error-box' }, 'JWT가 너무 깁니다 (최대 100,000자).'));
      return;
    }
    const rawView = h('div', { class: 'jwt-raw' });
    setHtml(rawView, `<span class="h">${escapeHtml(parts[0])}</span>.<span class="p">${escapeHtml(parts[1])}</span>${parts[2] !== undefined ? '.<span class="s">' + escapeHtml(parts[2]) + '</span>' : ''}`);
    out.append(panel('구조', [], rawView));
    const now = Date.now() / 1000;
    ['헤더 (Header)', '페이로드 (Payload)'].forEach((title, i) => {
      try {
        const obj = decodeJwtPart(parts[i]) as Record<string, unknown>;
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('JSON 객체가 아닙니다');
        const json = JSON.stringify(obj, null, 2);
        const pre = h('pre', { class: 'code short' });
        setHtml(pre, highlightJson(json));
        if (i === 0) {
          const alg = String(obj.alg ?? '');
          // Known JWT attack patterns visible from the header alone.
          if (!alg || alg.toLowerCase() === 'none')
            out.append(h('div', { class: 'error-box' }, '⚠ alg가 "none"입니다. 서명이 없는 토큰이므로 서버가 이를 허용하면 누구나 토큰을 위조할 수 있습니다 (CVE-2015-9235 계열).'));
          if (parts[2] === undefined || parts[2] === '')
            out.append(h('div', { class: 'error-box' }, '⚠ 서명 부분이 비어 있습니다.'));
          for (const k of ['jku', 'x5u', 'jwk'])
            if (k in obj) out.append(h('div', { class: 'error-box' }, `⚠ 헤더에 "${k}"가 있습니다. 서버가 이 값으로 검증 키를 가져오면 공격자가 자신의 키를 지정할 수 있습니다.`));
          if (typeof obj.kid === 'string' && /\.\.|[/\\'";]|\s/.test(obj.kid))
            out.append(h('div', { class: 'error-box' }, '⚠ kid 값에 경로/쿼리 조작에 쓰이는 문자가 있습니다 (경로 탐색·SQL 인젝션 시도일 수 있음).'));
        }
        const rows = Object.entries(obj).map(([k, v]) => {
          let value = typeof v === 'object' ? JSON.stringify(v) : String(v);
          if (['exp', 'iat', 'nbf', 'auth_time'].includes(k) && typeof v === 'number') {
            const d = new Date(v * 1000);
            value += `  →  ${d.toLocaleString()}`;
            if (k === 'exp') value += v < now ? '  (만료됨)' : '  (유효)';
          }
          return h('tr', null, h('th', null, k, CLAIMS[k] ? h('div', { class: 'note' }, CLAIMS[k]) : null), h('td', null, value));
        });
        out.append(
          h('div', { class: 'io-grid' },
            panel(title, [copyButton(() => json)], pre, 'jwt-part'),
            panel('클레임 설명', [], h('table', { class: 'kv' }, ...rows)),
          ),
        );
        if (i === 1 && typeof obj.exp === 'number' && obj.exp < now) out.append(h('div', { class: 'error-box' }, '이 토큰은 만료되었습니다.'));
      } catch (e) {
        out.append(h('div', { class: 'error-box' }, `${title} 디코딩 실패: ${(e as Error).message}`));
      }
    });
    out.append(h('p', { class: 'note' }, '서명(Signature)은 비밀키 없이 검증할 수 없으므로 디코딩만 수행합니다. 토큰은 서버로 전송되지 않습니다.'));
  };
  input.addEventListener('input', update);
  root.append(
    h('div', { class: 'stack' },
      panel('JWT', [button('예시', () => ((input.value = SAMPLE), update())), button('지우기', () => ((input.value = ''), update()))], input),
      out,
    ),
  );
}

// ---------- Base64 file / image ----------
function base64FileTool(root: HTMLElement) {
  const fileInput = h('input', { type: 'file', hidden: true });
  const drop = h('div', { class: 'dropzone', tabindex: '0', role: 'button' }, '파일을 끌어다 놓거나 클릭해서 선택하세요 (이미지는 미리보기 지원)');
  const info = h('div', { class: 'note' });
  const preview = h('div');
  const out = textarea({ class: 'code short', readonly: true, placeholder: 'Data URL / Base64 결과' });
  let dataUrl = '';
  let withPrefix = true;
  const sync = () => (out.value = withPrefix ? dataUrl : dataUrl.replace(/^data:[^,]*,/, ''));
  const load = (file: File) => {
    if (file.size > 20 * 1024 * 1024) return toast('20MB 이하 파일만 지원합니다');
    const reader = new FileReader();
    reader.onload = () => {
      dataUrl = String(reader.result);
      info.textContent = `${file.name} · ${file.type || '알 수 없는 형식'} · ${formatBytes(file.size)} → Base64 ${formatBytes(dataUrl.length)}`;
      // data: URLs get an opaque origin, so even an SVG preview cannot reach this page.
      preview.replaceChildren(file.type.startsWith('image/') ? h('img', { class: 'preview-img', src: dataUrl, alt: file.name }) : '');
      sync();
    };
    reader.readAsDataURL(file);
  };
  fileInput.addEventListener('change', () => fileInput.files?.[0] && load(fileInput.files[0]));
  drop.addEventListener('click', () => fileInput.click());
  drop.addEventListener('keydown', (e) => (e.key === 'Enter' || e.key === ' ') && fileInput.click());
  drop.addEventListener('dragover', (e) => (e.preventDefault(), drop.classList.add('over')));
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    const f = e.dataTransfer?.files[0];
    if (f) load(f);
  });

  // Reverse: base64 → file
  const b64in = textarea({ class: 'code short', placeholder: 'data:image/png;base64,… 또는 순수 Base64' });
  const mime = h('input', { class: 'input mono', value: 'application/octet-stream', 'aria-label': 'MIME 타입' });
  const decodedPreview = h('div', { class: 'stack' });
  const urls: string[] = [];
  const revokeAll = () => urls.splice(0).forEach((u) => URL.revokeObjectURL(u));
  const decode = () => {
    revokeAll();
    decodedPreview.replaceChildren();
    const v = b64in.value.trim();
    if (!v) return;
    try {
      assertInputSize(v, 30_000_000);
      const m = v.match(/^data:([^;,]+)/);
      const type = (m ? m[1] : mime.value || 'application/octet-stream').trim().toLowerCase();
      if (!/^[\w.+-]+\/[\w.+-]+$/.test(type)) throw new Error('MIME 타입 형식이 올바르지 않습니다 (예: image/png)');
      const bytes = base64ToBytes(v);
      // Blob URLs share this page's origin. Typing the download as octet-stream means opening it
      // in a tab downloads instead of rendering, so a decoded HTML/SVG file cannot run script here.
      const fileUrl = URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/octet-stream' }));
      urls.push(fileUrl);
      const ext = (type.split('/')[1]?.split('+')[0] ?? 'bin').replace(/[^a-z0-9]/g, '').slice(0, 10) || 'bin';
      let previewEl: Node | string = '';
      if (SAFE_PREVIEW.test(type)) {
        const imgUrl = URL.createObjectURL(new Blob([bytes as BlobPart], { type }));
        urls.push(imgUrl);
        previewEl = h('img', { class: 'preview-img', src: imgUrl, alt: '디코딩된 이미지' });
      } else if (type === 'image/svg+xml') {
        previewEl = h('img', { class: 'preview-img', src: 'data:image/svg+xml;base64,' + bytesToBase64(bytes), alt: '디코딩된 SVG' });
      }
      decodedPreview.append(
        h('div', { class: 'note' }, `${type} · ${formatBytes(bytes.length)}`),
        previewEl,
        h('a', { class: 'btn btn-primary', href: fileUrl, download: `decoded.${ext}` }, '파일로 저장'),
      );
    } catch (e) {
      decodedPreview.append(h('div', { class: 'error-box' }, (e as Error).message));
    }
  };
  b64in.addEventListener('input', decode);
  mime.addEventListener('input', decode);

  root.append(
    h('div', { class: 'stack' },
      drop, fileInput, info, preview,
      panel('결과', [
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: true, onchange: (e: Event) => ((withPrefix = (e.target as HTMLInputElement).checked), sync()) }), 'data: 접두어 포함'),
        copyButton(() => out.value),
      ], out),
      h('h2', { style: { fontSize: '16px', margin: '18px 0 0' } }, 'Base64 → 파일'),
      panel('Base64 입력', [h('label', { class: 'field inline' }, h('span', { class: 'field-label' }, 'MIME'), mime)], b64in),
      decodedPreview,
    ),
  );
  return revokeAll;
}

export const encodingTools: Tool[] = [
  {
    id: 'base64',
    name: 'Base64 인코더/디코더',
    category: 'encode',
    description: '텍스트를 Base64로 인코딩하거나 디코딩합니다. UTF-8과 URL-safe 변형을 지원합니다.',
    keywords: ['b64', 'base 64', 'atob', 'btoa'],
    render: (root) =>
      transformer(root, {
        id: 'base64',
        swap: true,
        modes: [
          { id: 'encode', label: '인코딩', run: (s, o) => bytesToBase64(utf8(s), Boolean(o.urlsafe)) },
          { id: 'decode', label: '디코딩', run: (s) => bytesToDisplay(base64ToBytes(s)) },
        ],
        options: [{ id: 'urlsafe', label: 'URL-safe (-_ , 패딩 제거)', type: 'checkbox', default: false, modes: ['encode'] }],
        sample: (m) => (m === 'encode' ? 'Hello, 세계! 👋' : 'SGVsbG8sIOyEuOqzhCEg8J+Riw=='),
      }),
  },
  {
    id: 'base64-file',
    name: 'Base64 파일/이미지',
    category: 'encode',
    description: '파일이나 이미지를 Base64 Data URL로 변환하고, Base64를 다시 파일로 저장합니다.',
    keywords: ['data url', 'image', '이미지', 'datauri'],
    render: base64FileTool,
  },
  {
    id: 'url',
    name: 'URL 인코더/디코더',
    category: 'encode',
    description: '퍼센트 인코딩(%XX)으로 URL 또는 쿼리 파라미터를 인코딩/디코딩합니다.',
    keywords: ['percent', 'uri', 'encodeURIComponent', '퍼센트'],
    render: (root) =>
      transformer(root, {
        id: 'url',
        swap: true,
        modes: [
          { id: 'encode', label: '인코딩', run: (s, o) => (o.scope === 'full' ? encodeURI(s) : encodeURIComponent(s)) },
          {
            id: 'decode',
            label: '디코딩',
            run: (s, o) => {
              const t = o.plus ? s.replace(/\+/g, ' ') : s;
              try {
                return o.scope === 'full' ? decodeURI(t) : decodeURIComponent(t);
              } catch {
                throw new Error('잘못된 퍼센트 인코딩 시퀀스가 있습니다 (예: % 뒤에 16진수 2자리가 아님)');
              }
            },
          },
        ],
        options: [
          { id: 'scope', label: '범위', type: 'select', default: 'component', choices: [['component', '구성 요소 (encodeURIComponent)'], ['full', '전체 URL (encodeURI)']] },
          { id: 'plus', label: '+ 를 공백으로', type: 'checkbox', default: true, modes: ['decode'] },
        ],
        sample: (m) => (m === 'encode' ? 'https://example.com/검색?q=개발자 도구&lang=ko' : 'q%3D%EA%B0%9C%EB%B0%9C%EC%9E%90%20%EB%8F%84%EA%B5%AC%26page%3D1'),
      }),
  },
  {
    id: 'html-entity',
    name: 'HTML 엔티티',
    category: 'encode',
    description: '< > & " 같은 특수문자를 HTML 엔티티로 변환하거나 되돌립니다.',
    keywords: ['escape', 'html escape', '&amp;', 'entities'],
    render: (root) =>
      transformer(root, {
        id: 'html-entity',
        swap: true,
        modes: [
          { id: 'encode', label: '인코딩', run: (s, o) => htmlEncode(s, Boolean(o.all)) },
          { id: 'decode', label: '디코딩', run: htmlDecode },
        ],
        options: [{ id: 'all', label: 'ASCII 외 문자도 숫자 엔티티로', type: 'checkbox', default: false, modes: ['encode'] }],
        sample: (m) => (m === 'encode' ? '<a href="/?q=1&b=2">"링크" © 2026</a>' : '&lt;div class=&quot;box&quot;&gt;Tom &amp; Jerry&lt;/div&gt; &#54620;&#44544;'),
      }),
  },
  {
    id: 'unicode',
    name: '유니코드 이스케이프',
    category: 'encode',
    description: '문자를 \\uXXXX, \\u{…}, &#x…;, U+XXXX 형식으로 변환하거나 되돌립니다.',
    keywords: ['\\u', 'escape', 'codepoint', '코드포인트', 'native2ascii'],
    render: (root) =>
      transformer(root, {
        id: 'unicode',
        swap: true,
        modes: [
          { id: 'encode', label: '이스케이프', run: (s, o) => unicodeEscape(s, String(o.style), Boolean(o.all)) },
          { id: 'decode', label: '언이스케이프', run: unicodeUnescape },
        ],
        options: [
          { id: 'style', label: '형식', type: 'select', default: 'js', modes: ['encode'], choices: [['js', '\\uXXXX (JS/Java/JSON)'], ['es6', '\\u{XXXX} (ES6)'], ['python', 'Python (\\U 포함)'], ['html', '&#xXXXX; (HTML)'], ['css', '\\XXXX (CSS)'], ['codepoint', 'U+XXXX']] },
          { id: 'all', label: 'ASCII도 변환', type: 'checkbox', default: false, modes: ['encode'] },
        ],
        sample: (m) => (m === 'encode' ? '안녕하세요 😀 café' : '\\uc548\\ub155\\ud558\\uc138\\uc694 \\ud83d\\ude00'),
      }),
  },
  {
    id: 'string-escape',
    name: '문자열 이스케이프',
    category: 'encode',
    description: '따옴표, 줄바꿈, 탭 등을 JSON/JS 문자열 리터럴 형태로 이스케이프하거나 되돌립니다.',
    keywords: ['json string', 'escape', 'unescape', 'stringify', 'quote'],
    render: (root) =>
      transformer(root, {
        id: 'string-escape',
        swap: true,
        modes: [
          { id: 'encode', label: '이스케이프', run: (s, o) => { const j = JSON.stringify(s); return o.quotes ? j : j.slice(1, -1); } },
          {
            id: 'decode',
            label: '언이스케이프',
            run: (s) => {
              const t = s.trim();
              const body = /^".*"$/s.test(t) ? t : `"${t.replace(/(^|[^\\])"/g, '$1\\"')}"`;
              try {
                return JSON.parse(body.replace(/\n/g, '\\n')) as string;
              } catch (e) {
                throw new Error('올바른 이스케이프 문자열이 아닙니다: ' + (e as Error).message);
              }
            },
          },
        ],
        options: [{ id: 'quotes', label: '양쪽 따옴표 포함', type: 'checkbox', default: false, modes: ['encode'] }],
        sample: (m) => (m === 'encode' ? 'He said "hello"\n\tC:\\path\\file.txt' : 'He said \\"hello\\"\\n\\tC:\\\\path\\\\file.txt'),
      }),
  },
  {
    id: 'jwt',
    name: 'JWT 디코더',
    category: 'encode',
    description: 'JSON Web Token의 헤더와 페이로드를 디코딩하고, exp/iat 같은 시간 클레임을 읽기 쉽게 보여줍니다.',
    keywords: ['json web token', 'bearer', 'token', '토큰', 'oauth'],
    render: jwtTool,
  },
  {
    id: 'hex',
    name: 'Hex (16진수) 변환',
    category: 'encode',
    description: '텍스트를 UTF-8 바이트의 16진수로 변환하거나, 16진수를 텍스트로 되돌립니다.',
    keywords: ['hexadecimal', '16진수', 'bytes', 'hexdump'],
    render: (root) =>
      transformer(root, {
        id: 'hex',
        swap: true,
        modes: [
          { id: 'encode', label: '텍스트 → Hex', run: (s, o) => { const x = toHex(utf8(s), o.sep === 'none' ? '' : o.sep === 'space' ? ' ' : o.sep === 'colon' ? ':' : ''); return o.sep === '0x' ? toHex(utf8(s), ' ').split(' ').map((b) => '0x' + b).join(', ') : o.upper ? x.toUpperCase() : x; } },
          { id: 'decode', label: 'Hex → 텍스트', run: (s) => bytesToDisplay(fromHex(s)) },
        ],
        options: [
          { id: 'sep', label: '구분자', type: 'select', default: 'space', modes: ['encode'], choices: [['space', '공백'], ['none', '없음'], ['colon', '콜론 (:)'], ['0x', '0x.., (배열)']] },
          { id: 'upper', label: '대문자', type: 'checkbox', default: false, modes: ['encode'] },
        ],
        sample: (m) => (m === 'encode' ? 'DevKit 한글' : '44 65 76 4b 69 74 20 ed 95 9c ea b8 80'),
      }),
  },
  {
    id: 'binary',
    name: '2진수 텍스트 변환',
    category: 'encode',
    description: '텍스트를 바이트 단위 2진수(01000001…)로 변환하거나 되돌립니다.',
    keywords: ['binary', 'bits', '바이너리', '이진수'],
    render: (root) =>
      transformer(root, {
        id: 'binary',
        swap: true,
        modes: [
          { id: 'encode', label: '텍스트 → 2진수', run: (s) => Array.from(utf8(s), (b) => b.toString(2).padStart(8, '0')).join(' ') },
          {
            id: 'decode',
            label: '2진수 → 텍스트',
            run: (s) => {
              const bits = s.replace(/[^01]/g, '');
              if (/[^01\s]/.test(s)) throw new Error('0과 1, 공백만 입력할 수 있습니다');
              if (bits.length % 8) throw new Error(`비트 수(${bits.length})가 8의 배수가 아닙니다`);
              return bytesToDisplay(new Uint8Array(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2))));
            },
          },
        ],
        sample: (m) => (m === 'encode' ? 'Hi!' : '01001000 01101001 00100001'),
      }),
  },
  {
    id: 'base32',
    name: 'Base32 인코더/디코더',
    category: 'encode',
    description: 'RFC 4648 Base32 인코딩/디코딩. OTP 시크릿 키 확인 등에 사용됩니다.',
    keywords: ['b32', 'otp', 'totp'],
    render: (root) =>
      transformer(root, {
        id: 'base32',
        swap: true,
        modes: [
          { id: 'encode', label: '인코딩', run: (s, o) => base32Encode(utf8(s), Boolean(o.pad)) },
          { id: 'decode', label: '디코딩', run: (s) => bytesToDisplay(base32Decode(s)) },
        ],
        options: [{ id: 'pad', label: '= 패딩', type: 'checkbox', default: true, modes: ['encode'] }],
        sample: (m) => (m === 'encode' ? 'Hello DevKit' : 'JBSWY3DPEBCGK5SLNF2A===='),
      }),
  },
  {
    id: 'rot13',
    name: 'ROT13 / 시저 암호',
    category: 'encode',
    description: '알파벳을 지정한 칸만큼 밀어서 변환합니다. 13칸이면 ROT13입니다.',
    keywords: ['caesar', 'cipher', 'rot', '시저'],
    render: (root) =>
      transformer(root, {
        id: 'rot13',
        modes: [
          { id: 'encode', label: '암호화', run: (s, o) => caesar(s, Number(o.shift)) },
          { id: 'decode', label: '복호화', run: (s, o) => caesar(s, -Number(o.shift)) },
        ],
        options: [{ id: 'shift', label: '이동 칸 수', type: 'number', default: 13, min: 1, max: 25 }],
        sample: 'The Quick Brown Fox Jumps Over The Lazy Dog',
      }),
  },
  {
    id: 'morse',
    name: '모스 부호',
    category: 'encode',
    description: '영문/숫자를 모스 부호로 변환하거나 되돌립니다. 단어 사이는 / 로 구분합니다.',
    keywords: ['morse code', '모스'],
    render: (root) =>
      transformer(root, {
        id: 'morse',
        swap: true,
        modes: [
          {
            id: 'encode',
            label: '텍스트 → 모스',
            run: (s) => s.toUpperCase().trim().split(/\s+/).map((w) => [...w].map((c) => MORSE[c] ?? '?').join(' ')).join(' / '),
          },
          {
            id: 'decode',
            label: '모스 → 텍스트',
            run: (s) => s.trim().replace(/[·•]/g, '.').replace(/[–—_]/g, '-').split(/\s*[/|]\s*|\s{3,}/).map((w) => w.split(/\s+/).map((c) => MORSE_REV[c] ?? '?').join('')).join(' '),
          },
        ],
        sample: (m) => (m === 'encode' ? 'SOS Hello World' : '... --- ... / .... . .-.. .-.. ---'),
      }),
  },
];
