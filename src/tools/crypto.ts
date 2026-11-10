import type { Tool } from '../types';
import { md5 } from 'js-md5';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { hmac } from '@noble/hashes/hmac.js';
import { bytesToBase64, formatBytes, toHex, utf8 } from '../bytes';
import { button, checkbox, copyButton, debounce, field, h, panel, segmented, select, store, textarea, toast } from '../ui';

const ALGOS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512', 'RIPEMD-160'] as const;
type Algo = (typeof ALGOS)[number];
/** Algorithms Web Crypto lacks, implemented by the audited @noble/hashes library. */
const NOBLE = { 'SHA3-256': sha3_256, 'SHA3-512': sha3_512, 'RIPEMD-160': ripemd160 } as const;

async function digest(algo: Algo, data: Uint8Array, key: Uint8Array | null): Promise<Uint8Array> {
  if (algo === 'MD5') return new Uint8Array(key ? md5.hmac.arrayBuffer(key, data) : md5.arrayBuffer(data));
  if (algo in NOBLE) {
    const fn = NOBLE[algo as keyof typeof NOBLE];
    return key ? hmac(fn, key, data) : fn(data);
  }
  if (key) {
    const k = await crypto.subtle.importKey('raw', (key.length ? key : new Uint8Array(1)) as BufferSource, { name: 'HMAC', hash: algo }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, data as BufferSource));
  }
  return new Uint8Array(await crypto.subtle.digest(algo, data as BufferSource));
}

function hashTool(root: HTMLElement) {
  const saved = store.get('tool:hash', { text: 'Hello, DevKit', enc: 'hex', upper: false, hmac: false, key: '' });
  let source: 'text' | 'file' = 'text';
  let fileBytes: Uint8Array | null = null;
  let enc = saved.enc, upper = saved.upper, hmac = saved.hmac;
  const text = textarea({ class: 'code short', value: saved.text, placeholder: '해시할 텍스트', 'aria-label': '해시할 텍스트' });
  const keyInput = h('input', { class: 'input mono grow', value: saved.key, placeholder: 'HMAC 비밀키', 'aria-label': 'HMAC 비밀키' });
  const keyRow = h('div', { class: 'row' }, field('HMAC 비밀키 (UTF-8)', keyInput, 'grow'));
  keyRow.hidden = !hmac;
  const fileInput = h('input', { type: 'file', class: 'input' });
  const fileInfo = h('div', { class: 'note' });
  const filePanel = h('div', { class: 'panel-body stack' }, fileInput, fileInfo);
  filePanel.hidden = true;
  const out = h('div', { class: 'result-list' });
  const compare = h('input', { class: 'input mono grow', placeholder: '비교할 해시값을 붙여넣으면 일치 여부를 표시합니다', 'aria-label': '비교할 해시값' });
  let results: [Algo, string][] = [];

  async function update() {
    store.set('tool:hash', { text: text.value.length < 100_000 ? text.value : '', enc, upper, hmac, key: '' });
    const data = source === 'text' ? utf8(text.value) : fileBytes;
    if (!data) return out.replaceChildren(h('div', { class: 'note' }, '파일을 선택하세요.'));
    const key = hmac ? utf8(keyInput.value) : null;
    results = await Promise.all(ALGOS.map(async (a) => {
      const d = await digest(a, data, key);
      const v = enc === 'hex' ? toHex(d) : bytesToBase64(d);
      return [a, upper && enc === 'hex' ? v.toUpperCase() : v] as [Algo, string];
    }));
    const cmp = compare.value.trim().toLowerCase();
    out.replaceChildren(...results.map(([a, v]) => {
      const match = cmp && v.toLowerCase() === cmp;
      return h('div', { class: 'result-row', style: match ? { borderColor: 'var(--ok)' } : {} },
        h('span', { class: 'label' }, (hmac ? 'HMAC-' : '') + a, match ? h('span', { style: { color: 'var(--ok)', marginLeft: '6px' } }, '✓ 일치') : null),
        h('span', { class: 'value' }, v),
        copyButton(() => v));
    }));
    if (cmp && !results.some(([, v]) => v.toLowerCase() === cmp)) out.append(h('div', { class: 'note warn' }, '비교값과 일치하는 해시가 없습니다.'));
  }
  const run = debounce(() => void update(), 120);
  fileInput.addEventListener('change', async () => {
    const f = fileInput.files?.[0];
    if (!f) return;
    if (f.size > 200 * 1024 * 1024) return toast('200MB 이하 파일만 지원합니다');
    fileInfo.textContent = `${f.name} · ${formatBytes(f.size)}`;
    fileBytes = new Uint8Array(await f.arrayBuffer());
    update();
  });
  text.addEventListener('input', run);
  keyInput.addEventListener('input', run);
  compare.addEventListener('input', run);

  root.append(
    h('div', { class: 'stack' },
      h('div', { class: 'toolbar', style: { marginBottom: '0' } },
        segmented([['text', '텍스트'], ['file', '파일']], source, (v) => {
          source = v;
          text.hidden = v !== 'text';
          filePanel.hidden = v !== 'file';
          update();
        }),
        field('출력', select([['hex', 'Hex'], ['base64', 'Base64']], enc, (v) => ((enc = v), update())), 'inline'),
        checkbox('대문자', upper, (v) => ((upper = v), update())),
        checkbox('HMAC', hmac, (v) => ((hmac = v), (keyRow.hidden = !v), update())),
      ),
      panel('입력', [], h('div', null, text, filePanel)),
      keyRow,
      out,
      compare,
      h('p', { class: 'note' }, 'MD5와 SHA-1은 충돌 공격이 알려져 있어 보안 용도(비밀번호 저장, 서명)에는 적합하지 않습니다. 무결성 확인 용도로만 사용하세요.'),
    ),
  );
  update();
}

// ---------- password ----------
const SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>/?~',
};
const AMBIGUOUS = /[O0oIl1|`'"]/g;

/** Uniform random integer in [0, max) via rejection sampling. */
function randInt(max: number): number {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % max;
}

function passwordTool(root: HTMLElement) {
  const s = store.get('tool:password', { length: 20, count: 5, upper: true, lower: true, digits: true, symbols: true, noAmbiguous: false });
  const lengthInput = h('input', { type: 'range', min: '4', max: '128', value: String(s.length), style: { width: '220px', accentColor: 'var(--accent)' }, 'aria-label': '길이' });
  const lengthLabel = h('strong', { style: { fontFamily: 'var(--mono)', minWidth: '32px' } }, String(s.length));
  const countInput = h('input', { class: 'input input-num', type: 'number', min: '1', max: '100', value: String(s.count), 'aria-label': '개수' });
  const out = h('div', { class: 'result-list' });
  const meter = h('div', { class: 'strength' }, h('div'));
  const meterText = h('div', { class: 'note' });
  let generated: string[] = [];

  function gen() {
    s.length = Number(lengthInput.value);
    s.count = Math.min(100, Math.max(1, Number(countInput.value) || 1));
    lengthLabel.textContent = String(s.length);
    store.set('tool:password', s);
    const groups = (['upper', 'lower', 'digits', 'symbols'] as const).filter((k) => s[k]).map((k) => (s.noAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]));
    if (!groups.length) {
      out.replaceChildren(h('div', { class: 'note warn' }, '문자 종류를 하나 이상 선택하세요.'));
      return;
    }
    const pool = groups.join('');
    generated = Array.from({ length: s.count }, () => {
      // guarantee one character from each selected group, then shuffle
      const chars = groups.map((g) => g[randInt(g.length)]);
      while (chars.length < s.length) chars.push(pool[randInt(pool.length)]);
      for (let i = chars.length - 1; i > 0; i--) {
        const j = randInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
      }
      return chars.slice(0, s.length).join('');
    });
    const bits = Math.round(s.length * Math.log2(pool.length));
    const [label, color, pct] = bits < 40 ? ['매우 약함', '#dc2626', 15] : bits < 60 ? ['약함', '#ea580c', 35] : bits < 80 ? ['보통', '#ca8a04', 60] : bits < 110 ? ['강함', '#16a34a', 85] : ['매우 강함', '#0f766e', 100];
    const bar = meter.firstElementChild as HTMLElement;
    bar.style.width = pct + '%';
    bar.style.background = color;
    meterText.textContent = `엔트로피 약 ${bits}비트 · ${label}`;
    out.replaceChildren(...generated.map((p) => h('div', { class: 'result-row', style: { gridTemplateColumns: 'minmax(0,1fr) auto' } }, h('span', { class: 'value' }, p), copyButton(() => p))));
  }
  lengthInput.addEventListener('input', gen);
  countInput.addEventListener('input', gen);
  const opt = (k: 'upper' | 'lower' | 'digits' | 'symbols' | 'noAmbiguous', label: string) => checkbox(label, s[k], (v) => ((s[k] = v), gen()));
  root.append(
    h('div', { class: 'stack', style: { maxWidth: '820px' } },
      h('div', { class: 'toolbar', style: { marginBottom: '0' } },
        h('label', { class: 'field inline' }, h('span', { class: 'field-label' }, '길이'), lengthInput, lengthLabel),
        field('개수', countInput, 'inline'),
      ),
      h('div', { class: 'toolbar', style: { marginBottom: '0' } }, opt('upper', '대문자 A-Z'), opt('lower', '소문자 a-z'), opt('digits', '숫자 0-9'), opt('symbols', '특수문자 !@#'), opt('noAmbiguous', '헷갈리는 문자 제외 (0 O l 1)')),
      meter, meterText,
      h('div', { class: 'row' }, button('다시 생성', gen, 'btn btn-primary'), copyButton(() => generated.join('\n'), '전체 복사')),
      out,
      h('p', { class: 'note' }, '브라우저의 암호학적 난수 생성기(crypto.getRandomValues)를 사용하며, 생성된 비밀번호는 어디에도 저장되거나 전송되지 않습니다.'),
    ),
  );
  gen();
}

export const cryptoTools: Tool[] = [
  { id: 'hash', name: '해시 생성기', category: 'crypto', description: '텍스트나 파일의 MD5, SHA-1, SHA-2, SHA-3, RIPEMD-160 해시와 HMAC을 계산하고 비교합니다.', keywords: ['md5', 'sha1', 'sha256', 'sha512', 'sha3', 'ripemd160', 'keccak', 'hmac', 'checksum', '체크섬', 'digest'], render: hashTool },
  { id: 'password', name: '비밀번호 생성기', category: 'crypto', description: '길이와 문자 종류를 지정해 안전한 랜덤 비밀번호를 생성하고 강도를 표시합니다.', keywords: ['password generator', 'random', '랜덤', '패스워드'], render: passwordTool },
];
