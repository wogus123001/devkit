import type { Tool } from '../types';
import QRCode from 'qrcode';
import { toHex } from '../bytes';
import { button, checkbox, copyButton, debounce, field, h, panel, segmented, select, store, textarea } from '../ui';

// ---------- UUID ----------
function uuidV7(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  const ts = BigInt(Date.now());
  for (let i = 0; i < 6; i++) b[i] = Number((ts >> BigInt(8 * (5 - i))) & 0xffn);
  b[6] = (b[6] & 0x0f) | 0x70;
  b[8] = (b[8] & 0x3f) | 0x80;
  const x = toHex(b);
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}
const ULID_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function ulid(): string {
  let t = Date.now(), time = '';
  for (let i = 0; i < 10; i++) (time = ULID_CHARS[t % 32] + time), (t = Math.floor(t / 32));
  const r = crypto.getRandomValues(new Uint8Array(16));
  return time + Array.from(r, (n) => ULID_CHARS[n % 32]).join('');
}

function uuidTool(root: HTMLElement) {
  const s = store.get('tool:uuid', { version: 'v4', count: 5, upper: false, hyphens: true, braces: false });
  const count = h('input', { class: 'input input-num', type: 'number', min: '1', max: '1000', value: String(s.count), 'aria-label': '개수' });
  const out = textarea({ readonly: true, class: 'code short', 'aria-label': '생성된 UUID' });
  const validateInput = h('input', { class: 'input mono grow', placeholder: '검사할 UUID를 입력하세요', 'aria-label': '검사할 UUID' });
  const validateOut = h('table', { class: 'kv' });

  const one = () => {
    let id = s.version === 'v7' ? uuidV7() : s.version === 'ulid' ? ulid() : s.version === 'nil' ? '00000000-0000-0000-0000-000000000000' : crypto.randomUUID();
    if (s.version !== 'ulid') {
      if (!s.hyphens) id = id.replace(/-/g, '');
      if (s.braces) id = `{${id}}`;
    }
    return s.upper ? id.toUpperCase() : id;
  };
  const gen = () => {
    s.count = Math.min(1000, Math.max(1, Number(count.value) || 1));
    store.set('tool:uuid', s);
    out.value = Array.from({ length: s.count }, one).join('\n');
    out.rows = Math.min(20, s.count + 1);
  };
  const validate = () => {
    const v = validateInput.value.trim().replace(/^\{|\}$/g, '');
    validateOut.replaceChildren();
    if (!v) return;
    const m = v.match(/^([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{12})$/i);
    const row = (k: string, val: string) => h('tr', null, h('th', null, k), h('td', null, val));
    if (!m) return validateOut.append(row('결과', '❌ 올바른 UUID 형식이 아닙니다'));
    const hex = m.slice(1).join('').toLowerCase();
    const ver = parseInt(hex[12], 16);
    const variant = parseInt(hex[16], 16);
    validateOut.append(
      row('결과', '✅ 올바른 UUID 형식'),
      row('버전', hex === '0'.repeat(32) ? 'Nil UUID' : `v${ver} ${({ 1: '(시간 + MAC)', 3: '(MD5 이름 기반)', 4: '(랜덤)', 5: '(SHA-1 이름 기반)', 6: '(시간 정렬)', 7: '(Unix 시간 정렬)' } as Record<number, string>)[ver] ?? ''}`),
      row('Variant', variant >= 8 && variant <= 11 ? 'RFC 9562 (10xx)' : variant < 8 ? 'NCS (0xxx)' : 'Microsoft / 예약'),
    );
    if (ver === 7) validateOut.append(row('생성 시각', new Date(parseInt(hex.slice(0, 12), 16)).toLocaleString()));
    if (ver === 1) {
      const t = (BigInt('0x' + hex.slice(13, 16) + hex.slice(8, 12) + hex.slice(0, 8)) - 122192928000000000n) / 10000n;
      validateOut.append(row('생성 시각', new Date(Number(t)).toLocaleString()));
    }
  };
  count.addEventListener('input', gen);
  validateInput.addEventListener('input', validate);
  root.append(
    h('div', { class: 'stack', style: { maxWidth: '860px' } },
      h('div', { class: 'toolbar', style: { marginBottom: '0' } },
        segmented([['v4', 'UUID v4'], ['v7', 'UUID v7'], ['ulid', 'ULID'], ['nil', 'Nil']], s.version, (v) => ((s.version = v), gen())),
        field('개수', count, 'inline'),
        checkbox('대문자', s.upper, (v) => ((s.upper = v), gen())),
        checkbox('하이픈', s.hyphens, (v) => ((s.hyphens = v), gen())),
        checkbox('중괄호 { }', s.braces, (v) => ((s.braces = v), gen())),
      ),
      panel('결과', [button('다시 생성', gen), copyButton(() => out.value)], out),
      h('p', { class: 'note' }, 'v4는 완전 랜덤, v7은 생성 시각 순으로 정렬되어 DB 기본키에 적합합니다. ULID는 26자 정렬 가능한 ID입니다.'),
      h('h2', { style: { fontSize: '16px', margin: '10px 0 0' } }, 'UUID 검사'),
      validateInput,
      validateOut,
    ),
  );
  gen();
}

// ---------- Lorem ipsum ----------
const LOREM = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud exercitation ullamco laboris nisi aliquip ex ea commodo consequat duis aute irure in reprehenderit voluptate velit esse cillum fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt culpa qui officia deserunt mollit anim id est laborum'.split(' ');
const KO = '가나다 라마바 사아자 차카타 파하 그리고 개발자 도구 모음 서비스 사용자 화면 데이터 처리 결과 확인 다음 단계 진행 오늘 내일 우리는 함께 새로운 기능 디자인 테스트 문장 예시 내용 입니다 합니다 했습니다 됩니다'.split(' ');
function loremTool(root: HTMLElement) {
  const s = store.get('tool:lorem', { unit: 'p', count: 3, lang: 'la', startLorem: true });
  const count = h('input', { class: 'input input-num', type: 'number', min: '1', max: '200', value: String(s.count), 'aria-label': '개수' });
  const out = textarea({ readonly: true });
  const pick = (arr: string[]) => arr[Math.floor(Math.random() * arr.length)];
  const sentence = () => {
    const w = Array.from({ length: 6 + Math.floor(Math.random() * 10) }, () => pick(s.lang === 'ko' ? KO : LOREM)).join(' ');
    return w.charAt(0).toUpperCase() + w.slice(1) + '.';
  };
  const paragraph = () => Array.from({ length: 3 + Math.floor(Math.random() * 4) }, sentence).join(' ');
  const gen = () => {
    s.count = Math.min(200, Math.max(1, Number(count.value) || 1));
    store.set('tool:lorem', s);
    let t = s.unit === 'w' ? Array.from({ length: s.count }, () => pick(s.lang === 'ko' ? KO : LOREM)).join(' ') : s.unit === 's' ? Array.from({ length: s.count }, sentence).join(' ') : Array.from({ length: s.count }, paragraph).join('\n\n');
    if (s.lang === 'la' && s.startLorem) t = 'Lorem ipsum dolor sit amet, ' + t.charAt(0).toLowerCase() + t.slice(1);
    out.value = t;
  };
  count.addEventListener('input', gen);
  root.append(
    h('div', { class: 'stack' },
      h('div', { class: 'toolbar', style: { marginBottom: '0' } },
        segmented([['p', '문단'], ['s', '문장'], ['w', '단어']], s.unit, (v) => ((s.unit = v), gen())),
        field('개수', count, 'inline'),
        field('언어', select([['la', '라틴어 (Lorem)'], ['ko', '한국어 더미']], s.lang, (v) => ((s.lang = v), gen())), 'inline'),
        checkbox('"Lorem ipsum"으로 시작', s.startLorem, (v) => ((s.startLorem = v), gen())),
      ),
      panel('결과', [button('다시 생성', gen), copyButton(() => out.value)], out),
    ),
  );
  gen();
}

// ---------- QR ----------
function qrTool(root: HTMLElement) {
  const s = store.get('tool:qr', { text: 'https://example.com', ecl: 'M', size: 320, fg: '#000000', bg: '#ffffff' });
  const input = textarea({ class: 'code short', value: s.text, placeholder: 'URL 또는 텍스트', 'aria-label': 'QR 내용' });
  const canvas = h('canvas');
  const err = h('div', { class: 'error-box', hidden: true });
  const size = h('input', { class: 'input input-num', type: 'number', min: '128', max: '1024', step: '32', value: String(s.size), 'aria-label': '크기' });
  const fg = h('input', { type: 'color', value: s.fg, 'aria-label': '전경색' });
  const bg = h('input', { type: 'color', value: s.bg, 'aria-label': '배경색' });
  const download = h('a', { class: 'btn btn-primary', download: 'qrcode.png', href: '#' }, 'PNG 다운로드');
  const svgDownload = h('a', { class: 'btn', download: 'qrcode.svg', href: '#' }, 'SVG 다운로드');
  let svgUrl = '';
  const render = async () => {
    s.text = input.value;
    s.size = Math.min(1024, Math.max(128, Number(size.value) || 320));
    s.fg = fg.value;
    s.bg = bg.value;
    store.set('tool:qr', s);
    if (!s.text) return;
    const opts = { errorCorrectionLevel: s.ecl as QRCode.QRCodeErrorCorrectionLevel, width: s.size, margin: 2, color: { dark: s.fg, light: s.bg } };
    try {
      await QRCode.toCanvas(canvas, s.text, opts);
      download.href = canvas.toDataURL('image/png');
      const svg = await QRCode.toString(s.text, { ...opts, type: 'svg' });
      if (svgUrl) URL.revokeObjectURL(svgUrl);
      svgUrl = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
      svgDownload.href = svgUrl;
      err.hidden = true;
    } catch (e) {
      err.hidden = false;
      err.textContent = 'QR 생성 실패: ' + (e as Error).message;
    }
  };
  const run = debounce(render, 150);
  [input, size, fg, bg].forEach((el) => el.addEventListener('input', run));
  root.append(
    h('div', { class: 'io-grid' },
      h('div', { class: 'stack' },
        panel('내용', [], input),
        h('div', { class: 'toolbar' },
          field('오류 정정', select([['L', 'L (7%)'], ['M', 'M (15%)'], ['Q', 'Q (25%)'], ['H', 'H (30%)']], s.ecl, (v) => ((s.ecl = v), render())), 'inline'),
          field('크기(px)', size, 'inline'),
          field('전경', fg, 'inline'),
          field('배경', bg, 'inline'),
        ),
        err,
      ),
      panel('QR 코드', [], h('div', { class: 'qr-out stack' }, canvas, h('div', { class: 'row' }, download, svgDownload))),
    ),
  );
  render();
}

export const generateTools: Tool[] = [
  { id: 'uuid', name: 'UUID / ULID 생성기', category: 'generate', description: 'UUID v4, v7, ULID를 여러 개 생성하고 UUID의 버전과 생성 시각을 검사합니다.', keywords: ['guid', 'uuid v4', 'uuid v7', 'ulid', 'random id'], render: uuidTool },
  { id: 'qrcode', name: 'QR 코드 생성기', category: 'generate', description: 'URL이나 텍스트로 QR 코드를 만들고 PNG/SVG로 저장합니다.', keywords: ['qr', 'barcode', '큐알'], render: qrTool },
  { id: 'lorem', name: 'Lorem Ipsum 생성기', category: 'generate', description: '디자인/레이아웃 테스트용 더미 텍스트를 문단, 문장, 단어 단위로 생성합니다.', keywords: ['dummy text', 'placeholder', '더미', '샘플 텍스트'], render: loremTool },
];
