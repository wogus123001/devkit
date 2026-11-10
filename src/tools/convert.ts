import type { Tool } from '../types';
import YAML from 'yaml';
import cronstrue from 'cronstrue/i18n';
import { YAML_JS_OPTS, parseJson } from './format';
import { bareObject } from '../security';
import { copyButton, field, h, highlightJson, highlightYaml, panel, select, store, transformer } from '../ui';

// ---------- CSV ----------
function parseCsv(text: string, delim: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') (cell += '"'), i++;
      else if (c === '"') q = false;
      else cell += c;
    } else if (c === '"' && cell === '') q = true;
    else if (c === delim) row.push(cell), (cell = '');
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell), rows.push(row), (row = []), (cell = '');
    } else cell += c;
  }
  if (q) throw new Error('닫히지 않은 큰따옴표가 있습니다');
  if (cell !== '' || row.length) row.push(cell), rows.push(row);
  return rows.filter((r) => !(r.length === 1 && r[0] === ''));
}
/**
 * CSV/Formula injection (OWASP): spreadsheet apps execute cells starting with = + - @ (and tab/CR),
 * e.g. =HYPERLINK(...) or =cmd|... DDE payloads. With `guard`, such text cells get a leading apostrophe.
 * Real numbers (typeof number) are left alone so negative values stay numeric.
 */
const csvCell = (v: unknown, delim: string, guard: boolean) => {
  let s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (guard && typeof v !== 'number' && /^[=+\-@\t\r＝＋－＠]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) || s.includes(delim) ? `"${s.replace(/"/g, '""')}"` : s;
};
function flatten(obj: Record<string, unknown>, prefix = '', out: Record<string, unknown> = bareObject()) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v as Record<string, unknown>, key, out);
    else out[key] = v;
  }
  return out;
}
const autoType = (s: string): unknown => (s === '' ? '' : s === 'true' ? true : s === 'false' ? false : s === 'null' ? null : /^-?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?$/.test(s) && s.length < 16 ? Number(s) : s);
const DELIMS: [string, string][] = [[',', '쉼표 (,)'], ['\t', '탭'], [';', '세미콜론 (;)'], ['|', '파이프 (|)']];

// ---------- JSON → TypeScript ----------
function toTs(value: unknown, rootName: string, useType: boolean): string {
  const decls: string[] = [];
  const seen = new Map<string, string>();
  const used = new Set<string>();
  const pascal = (s: string) => (s.replace(/[^A-Za-z0-9]+(.)?/g, (_, c) => (c ? c.toUpperCase() : '')).replace(/^./, (c) => c.toUpperCase()) || 'Item').replace(/^\d/, '_$&');
  const typeOf = (v: unknown, name: string): string => {
    if (v === null) return 'null';
    if (Array.isArray(v)) {
      if (!v.length) return 'unknown[]';
      const objs = v.filter((x) => x && typeof x === 'object' && !Array.isArray(x)) as Record<string, unknown>[];
      const types = new Set(v.filter((x) => !(x && typeof x === 'object' && !Array.isArray(x))).map((x) => typeOf(x, name)));
      if (objs.length) {
        // Merge keys across array items; keys missing from some items become optional.
        // Maps (not plain objects) so keys like "__proto__" or "constructor" are ordinary data.
        const merged = new Map<string, unknown>();
        const counts = new Map<string, number>();
        for (const o of objs)
          for (const [k, x] of Object.entries(o)) {
            counts.set(k, (counts.get(k) ?? 0) + 1);
            if (!merged.has(k) || merged.get(k) === null) merged.set(k, x);
          }
        types.add(objectType([...merged], /s$/.test(name) ? name.replace(/s$/, '') : name + 'Item', (k) => counts.get(k)! < objs.length));
      }
      const t = [...types].join(' | ');
      return types.size > 1 ? `(${t})[]` : `${t}[]`;
    }
    if (typeof v === 'object') return objectType(Object.entries(v as object), name, () => false);
    return typeof v;
  };
  const objectType = (entries: [string, unknown][], name: string, optional: (k: string) => boolean): string => {
    const body = entries.map(([k, v]) => `  ${/^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k)}${optional(k) ? '?' : ''}: ${typeOf(v, pascal(k))};`).join('\n');
    const sig = body;
    if (seen.has(sig)) return seen.get(sig)!;
    const base = pascal(name);
    let n = base;
    for (let i = 2; used.has(n); i++) n = base + i;
    used.add(n);
    seen.set(sig, n);
    decls.push(useType ? `export type ${n} = {\n${body}\n};` : `export interface ${n} {\n${body}\n}`);
    return n;
  };
  const isObj = value && typeof value === 'object' && !Array.isArray(value);
  if (!isObj) used.add(pascal(rootName)); // reserve the alias name so item types never collide with it
  const top = typeOf(value, rootName);
  if (!isObj) decls.push(`export type ${pascal(rootName)} = ${top};`);
  return decls.join('\n\n');
}

// ---------- timestamp ----------
function timestampTool(root: HTMLElement): () => void {
  const now = h('div', { class: 'big-time' });
  const nowMs = h('div', { class: 'note' });
  const tick = () => {
    const t = Date.now();
    now.textContent = String(Math.floor(t / 1000));
    nowMs.textContent = `밀리초: ${t} · ${new Date(t).toLocaleString()}`;
  };
  tick();
  const timer = setInterval(tick, 1000);

  const tsInput = h('input', { class: 'input mono grow', placeholder: '1762756400 또는 1762756400000', value: store.get('tool:ts', String(Math.floor(Date.now() / 1000))), 'aria-label': '타임스탬프' });
  const unit = select([['auto', '자동 감지'], ['s', '초'], ['ms', '밀리초'], ['us', '마이크로초']], 'auto', () => conv());
  const tsOut = h('table', { class: 'kv' });
  const dateInput = h('input', { class: 'input grow', type: 'datetime-local', step: '1', 'aria-label': '날짜' });
  const isoInput = h('input', { class: 'input mono grow', placeholder: '2026-11-10T15:30:00+09:00 등 날짜 문자열', 'aria-label': '날짜 문자열' });
  const dateOut = h('table', { class: 'kv' });

  const rel = (ms: number) => {
    const diff = (ms - Date.now()) / 1000;
    const abs = Math.abs(diff);
    const [v, u] = abs < 60 ? [abs, '초'] : abs < 3600 ? [abs / 60, '분'] : abs < 86400 ? [abs / 3600, '시간'] : abs < 86400 * 365 ? [abs / 86400, '일'] : [abs / 86400 / 365, '년'];
    return `${Math.round(v)}${u} ${diff < 0 ? '전' : '후'}`;
  };
  const row = (k: string, v: string) => h('tr', null, h('th', null, k), h('td', null, copyButton(() => v), v));
  const rows = (d: Date) => [
    row('ISO 8601 (UTC)', d.toISOString()),
    row('로컬 시간', d.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'long' })),
    row('UTC', d.toUTCString()),
    row('Unix (초)', String(Math.floor(d.getTime() / 1000))),
    row('Unix (밀리초)', String(d.getTime())),
    row('상대 시간', rel(d.getTime())),
    row('요일 / 연중 일수', `${['일', '월', '화', '수', '목', '금', '토'][d.getDay()]}요일 · ${Math.ceil((d.getTime() - new Date(d.getFullYear(), 0, 1).getTime()) / 86400000) + 1}일째`),
  ];

  function conv() {
    store.set('tool:ts', tsInput.value);
    const raw = tsInput.value.trim();
    tsOut.replaceChildren();
    if (!raw) return;
    if (!/^-?\d+(\.\d+)?$/.test(raw)) return tsOut.append(h('tr', null, h('td', { class: 'note warn' }, '숫자만 입력하세요')));
    const n = Number(raw);
    let u = unit.value;
    if (u === 'auto') u = Math.abs(n) >= 1e14 ? 'us' : Math.abs(n) >= 1e11 ? 'ms' : 's';
    const d = new Date(u === 's' ? n * 1000 : u === 'ms' ? n : n / 1000);
    if (Number.isNaN(d.getTime())) return tsOut.append(h('tr', null, h('td', { class: 'note warn' }, '범위를 벗어난 값입니다')));
    tsOut.append(h('tr', null, h('th', null, '해석 단위'), h('td', null, { s: '초', ms: '밀리초', us: '마이크로초' }[u]!)), ...rows(d));
  }
  function fromDate(d: Date) {
    dateOut.replaceChildren(...(Number.isNaN(d.getTime()) ? [h('tr', null, h('td', { class: 'note warn' }, '날짜를 해석할 수 없습니다'))] : rows(d)));
  }
  tsInput.addEventListener('input', conv);
  dateInput.addEventListener('input', () => dateInput.value && fromDate(new Date(dateInput.value)));
  isoInput.addEventListener('input', () => isoInput.value.trim() && fromDate(new Date(isoInput.value.trim())));
  const pad = (n: number) => String(n).padStart(2, '0');
  const d0 = new Date();
  dateInput.value = `${d0.getFullYear()}-${pad(d0.getMonth() + 1)}-${pad(d0.getDate())}T${pad(d0.getHours())}:${pad(d0.getMinutes())}:${pad(d0.getSeconds())}`;
  conv();
  fromDate(d0);

  root.append(
    h('div', { class: 'stack' },
      panel('현재 Unix 타임스탬프', [copyButton(() => now.textContent ?? '')], h('div', { class: 'panel-body' }, now, nowMs)),
      h('div', { class: 'io-grid' },
        panel('타임스탬프 → 날짜', [], h('div', null, h('div', { class: 'panel-body row' }, tsInput, unit), tsOut)),
        panel('날짜 → 타임스탬프', [], h('div', null, h('div', { class: 'panel-body stack' }, field('날짜 선택 (로컬 시간)', dateInput), field('또는 문자열 입력', isoInput)), dateOut)),
      ),
    ),
  );
  return () => clearInterval(timer);
}

// ---------- number base ----------
function baseTool(root: HTMLElement) {
  const bases: [string, number, string][] = [['2진수 (BIN)', 2, '0b'], ['8진수 (OCT)', 8, '0o'], ['10진수 (DEC)', 10, ''], ['16진수 (HEX)', 16, '0x'], ['32진수', 32, ''], ['36진수', 36, '']];
  const inputs = bases.map(([label, b]) => {
    const inp = h('input', { class: 'input mono grow', 'aria-label': label, spellcheck: 'false' });
    inp.addEventListener('input', () => update(b, inp));
    return { label, b, inp };
  });
  const err = h('div', { class: 'error-box', hidden: true });
  const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz';
  const parse = (s: string, b: number): bigint => {
    // BigInt parsing is quadratic in length; 4096 digits is far beyond any practical value.
    if (s.length > 4096) throw new Error('입력이 너무 깁니다 (최대 4096자)');
    let t = s.trim().toLowerCase().replace(/[_\s,]/g, '');
    const neg = t.startsWith('-');
    if (neg) t = t.slice(1);
    t = t.replace(/^0[box]/, '');
    if (!t) throw new Error('값이 비어 있습니다');
    let v = 0n;
    for (const c of t) {
      const d = DIGITS.indexOf(c);
      if (d < 0 || d >= b) throw new Error(`"${c}" 는 ${b}진수에서 쓸 수 없는 숫자입니다`);
      v = v * BigInt(b) + BigInt(d);
    }
    return neg ? -v : v;
  };
  function update(from: number, src: HTMLInputElement) {
    if (!src.value.trim()) {
      inputs.forEach((x) => x !== inputs.find((y) => y.inp === src) && (x.inp.value = ''));
      err.hidden = true;
      return;
    }
    try {
      const v = parse(src.value, from);
      inputs.forEach((x) => x.inp !== src && (x.inp.value = v.toString(x.b).toUpperCase().replace(/^(-?)/, '$1')));
      err.hidden = true;
      store.set('tool:base', v.toString());
    } catch (e) {
      err.hidden = false;
      err.textContent = (e as Error).message;
    }
  }
  root.append(
    h('div', { class: 'stack', style: { maxWidth: '760px' } },
      err,
      ...inputs.map(({ label, inp }) => h('div', { class: 'result-row' }, h('span', { class: 'label' }, label), inp, copyButton(() => inp.value))),
      h('p', { class: 'note' }, '임의 크기 정수(BigInt)를 지원합니다. 0x, 0b, 0o 접두어와 _ 구분자를 자동으로 무시합니다.'),
    ),
  );
  inputs[2].inp.value = store.get('tool:base', '255');
  update(10, inputs[2].inp);
}

// ---------- color ----------
function colorTool(root: HTMLElement) {
  const picker = h('input', { type: 'color', style: { width: '56px', height: '40px', border: '0', background: 'none', padding: '0' }, 'aria-label': '색상 선택' });
  const text = h('input', { class: 'input mono grow', placeholder: '#0f766e, rgb(15,118,110), hsl(175 77% 26%)…', 'aria-label': '색상 값' });
  const swatch = h('div', { class: 'swatch' });
  const out = h('div', { class: 'result-list' });
  const err = h('div', { class: 'error-box', hidden: true });
  const ctx = document.createElement('canvas').getContext('2d')!;

  const parse = (s: string): [number, number, number, number] | null => {
    if (!CSS.supports('color', s.trim())) return null;
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillStyle = s.trim();
    ctx.fillRect(0, 0, 1, 1);
    const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data;
    return [r, g, b, a / 255];
  };
  const toHsl = (r: number, g: number, b: number) => {
    r /= 255; g /= 255; b /= 255;
    const max = Math.max(r, g, b), min = Math.min(r, g, b), l = (max + min) / 2;
    let hh = 0, s = 0;
    if (max !== min) {
      const d = max - min;
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
      hh = max === r ? (g - b) / d + (g < b ? 6 : 0) : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
      hh *= 60;
    }
    return [Math.round(hh), Math.round(s * 100), Math.round(l * 100)];
  };
  const lum = (r: number, g: number, b: number) => {
    const f = (c: number) => ((c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  function update(s: string) {
    store.set('tool:color', s);
    const c = s.trim() ? parse(s.trim().replace(/^([\da-f]{3}|[\da-f]{6}|[\da-f]{8})$/i, '#$1')) : null;
    if (!c) {
      err.hidden = !s.trim();
      err.textContent = '인식할 수 없는 색상입니다';
      out.replaceChildren();
      return;
    }
    err.hidden = true;
    const [r, g, b, a] = c;
    const hex = '#' + [r, g, b].map((x) => x.toString(16).padStart(2, '0')).join('');
    const [hh, ss, ll] = toHsl(r, g, b);
    const k = 1 - Math.max(r, g, b) / 255;
    const cmyk = k === 1 ? [0, 0, 0, 100] : [r, g, b].map((x) => Math.round(((1 - x / 255 - k) / (1 - k)) * 100)).concat(Math.round(k * 100));
    const L = lum(r, g, b);
    const cw = (1.05 / (L + 0.05)).toFixed(2), cb = ((L + 0.05) / 0.05).toFixed(2);
    swatch.style.background = `rgba(${r},${g},${b},${a})`;
    picker.value = hex;
    const items: [string, string][] = [
      ['HEX', a < 1 ? hex + Math.round(a * 255).toString(16).padStart(2, '0') : hex],
      ['RGB', a < 1 ? `rgba(${r}, ${g}, ${b}, ${+a.toFixed(2)})` : `rgb(${r}, ${g}, ${b})`],
      ['HSL', a < 1 ? `hsla(${hh}, ${ss}%, ${ll}%, ${+a.toFixed(2)})` : `hsl(${hh}, ${ss}%, ${ll}%)`],
      ['CMYK', `cmyk(${cmyk.map((x) => x + '%').join(', ')})`],
      ['Android / ARGB', `0x${Math.round(a * 255).toString(16).padStart(2, '0')}${hex.slice(1)}`.toUpperCase().replace('0X', '0x')],
      ['명도 대비', `흰색 대비 ${cw}:1 · 검정 대비 ${cb}:1 (WCAG AA 기준 4.5:1)`],
    ];
    out.replaceChildren(...items.map(([l, v]) => h('div', { class: 'result-row' }, h('span', { class: 'label' }, l), h('span', { class: 'value' }, v), copyButton(() => v))));
  }
  picker.addEventListener('input', () => ((text.value = picker.value), update(picker.value)));
  text.addEventListener('input', () => update(text.value));
  text.value = store.get('tool:color', '#0f766e');
  root.append(h('div', { class: 'stack', style: { maxWidth: '820px' } }, h('div', { class: 'row', style: { alignItems: 'center' } }, picker, text), err, swatch, out));
  update(text.value);
}

// ---------- case converter ----------
function words(s: string): string[] {
  return s
    .replace(/([a-z\d])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
}
const cap = (w: string) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
const CASES: [string, (s: string) => string][] = [
  ['camelCase', (s) => words(s).map((w, i) => (i ? cap(w) : w.toLowerCase())).join('')],
  ['PascalCase', (s) => words(s).map(cap).join('')],
  ['snake_case', (s) => words(s).map((w) => w.toLowerCase()).join('_')],
  ['SCREAMING_SNAKE', (s) => words(s).map((w) => w.toUpperCase()).join('_')],
  ['kebab-case', (s) => words(s).map((w) => w.toLowerCase()).join('-')],
  ['Train-Case', (s) => words(s).map(cap).join('-')],
  ['dot.case', (s) => words(s).map((w) => w.toLowerCase()).join('.')],
  ['path/case', (s) => words(s).map((w) => w.toLowerCase()).join('/')],
  ['Title Case', (s) => words(s).map(cap).join(' ')],
  ['Sentence case', (s) => { const w = words(s).map((x) => x.toLowerCase()).join(' '); return w.charAt(0).toUpperCase() + w.slice(1); }],
  ['lowercase', (s) => s.toLowerCase()],
  ['UPPERCASE', (s) => s.toUpperCase()],
  ['iNVERSE cASE', (s) => [...s].map((c) => (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())).join('')],
];
function caseTool(root: HTMLElement) {
  const input = h('input', { class: 'input mono', style: { width: '100%' }, value: store.get('tool:case', 'getUserProfile_by-ID'), 'aria-label': '변환할 텍스트' });
  const out = h('div', { class: 'result-list' });
  const update = () => {
    store.set('tool:case', input.value);
    out.replaceChildren(...CASES.map(([name, fn]) => { const v = fn(input.value); return h('div', { class: 'result-row' }, h('span', { class: 'label' }, name), h('span', { class: 'value' }, v), copyButton(() => v)); }));
  };
  input.addEventListener('input', update);
  root.append(h('div', { class: 'stack', style: { maxWidth: '820px' } }, input, out));
  update();
}

// ---------- cron ----------
function cronTool(root: HTMLElement) {
  const input = h('input', { class: 'input mono', style: { width: '100%', fontSize: '18px' }, value: store.get('tool:cron', '*/15 9-18 * * 1-5'), 'aria-label': 'Cron 표현식' });
  const desc = h('div', { class: 'big-time', style: { fontSize: '19px', fontFamily: 'var(--sans)' } });
  const descEn = h('div', { class: 'note' });
  const err = h('div', { class: 'error-box', hidden: true });
  const fields = h('table', { class: 'kv' });
  const NAMES = ['분 (0-59)', '시 (0-23)', '일 (1-31)', '월 (1-12)', '요일 (0-6, 일=0)'];
  const NAMES6 = ['초 (0-59)', ...NAMES];
  const update = () => {
    store.set('tool:cron', input.value);
    const v = input.value.trim();
    try {
      desc.textContent = cronstrue.toString(v, { locale: 'ko', use24HourTimeFormat: true });
      descEn.textContent = cronstrue.toString(v, { locale: 'en', use24HourTimeFormat: true });
      err.hidden = true;
      const parts = v.split(/\s+/);
      const names = parts.length >= 6 ? NAMES6 : NAMES;
      fields.replaceChildren(...parts.slice(0, names.length).map((p, i) => h('tr', null, h('th', null, names[i]), h('td', null, p))));
    } catch (e) {
      err.hidden = false;
      err.textContent = String(e).replace(/^Error:\s*/, '');
      desc.textContent = descEn.textContent = '';
      fields.replaceChildren();
    }
  };
  const presets: [string, string][] = [['매분', '* * * * *'], ['매시 정각', '0 * * * *'], ['매일 자정', '0 0 * * *'], ['평일 오전 9시', '0 9 * * 1-5'], ['매주 일요일', '0 0 * * 0'], ['매월 1일', '0 0 1 * *'], ['5분마다', '*/5 * * * *']];
  input.addEventListener('input', update);
  root.append(
    h('div', { class: 'stack', style: { maxWidth: '820px' } },
      input,
      h('div', { class: 'chips' }, ...presets.map(([n, c]) => h('button', { class: 'chip', type: 'button', onclick: () => ((input.value = c), update()) }, n))),
      err,
      panel('설명', [], h('div', { class: 'panel-body' }, desc, descEn)),
      panel('필드', [], fields),
      h('p', { class: 'note' }, '5필드(분 시 일 월 요일) 표준 cron과 6필드(초 포함) / Quartz 형식을 지원합니다.'),
    ),
  );
  update();
}

export const convertTools: Tool[] = [
  {
    id: 'json-yaml',
    name: 'JSON ↔ YAML',
    category: 'convert',
    description: 'JSON을 YAML로, YAML을 JSON으로 변환합니다.',
    keywords: ['yaml to json', 'json to yaml', 'yml', 'k8s'],
    render: (root) =>
      transformer(root, {
        id: 'json-yaml',
        swap: true,
        wrap: false,
        modes: [
          { id: 'j2y', label: 'JSON → YAML', run: (s) => { const t = YAML.stringify(parseJson(s), { lineWidth: 0 }); return { text: t, html: highlightYaml(t) }; } },
          {
            id: 'y2j',
            label: 'YAML → JSON',
            run: (s, o) => {
              const docs = YAML.parseAllDocuments(s);
              const errs = docs.flatMap((d) => d.errors);
              if (errs.length) throw new Error('YAML 오류: ' + errs.map((e) => e.message).join('\n'));
              const data = docs.length === 1 ? docs[0].toJS(YAML_JS_OPTS) : docs.map((d) => d.toJS(YAML_JS_OPTS));
              const t = JSON.stringify(data, null, Number(o.indent));
              return { text: t, html: highlightJson(t) };
            },
          },
        ],
        options: [{ id: 'indent', label: '들여쓰기', type: 'select', default: '2', modes: ['y2j'], choices: [['2', '2칸'], ['4', '4칸']] }],
        sample: (m) => (m === 'j2y' ? '{"apiVersion":"v1","kind":"Service","metadata":{"name":"devkit","labels":{"app":"web"}},"spec":{"ports":[{"port":80,"targetPort":8080}]}}' : 'name: devkit\nversion: 1.0\nfeatures:\n  - base64\n  - json\nconfig:\n  debug: false\n'),
      }),
  },
  {
    id: 'json-csv',
    name: 'JSON ↔ CSV',
    category: 'convert',
    description: 'JSON 배열을 CSV(엑셀)로, CSV를 JSON 배열로 변환합니다. 중첩 객체는 점(.) 표기로 펼칩니다.',
    keywords: ['csv to json', 'json to csv', 'excel', 'tsv', '엑셀', 'spreadsheet'],
    render: (root) =>
      transformer(root, {
        id: 'json-csv',
        swap: true,
        wrap: false,
        modes: [
          {
            id: 'j2c',
            label: 'JSON → CSV',
            run: (s, o) => {
              const data = parseJson(s);
              const arr: Record<string, unknown>[] = (Array.isArray(data) ? data : [data]).map((r) => (r && typeof r === 'object' && !Array.isArray(r) ? flatten(r as Record<string, unknown>) : { value: r }));
              const d = String(o.delim);
              const cols = [...new Set(arr.flatMap((r) => Object.keys(r)))];
              const g = Boolean(o.guard);
              return [cols.map((c) => csvCell(c, d, g)).join(d), ...arr.map((r) => cols.map((c) => csvCell(r[c], d, g)).join(d))].join('\n');
            },
          },
          {
            id: 'c2j',
            label: 'CSV → JSON',
            run: (s, o) => {
              const rows = parseCsv(s, String(o.delim));
              if (!rows.length) return '[]';
              const [head, ...body] = rows;
              const data = o.header ? body.map((r) => Object.fromEntries(head.map((k, i) => [k, o.types ? autoType(r[i] ?? '') : r[i] ?? '']))) : rows.map((r) => (o.types ? r.map(autoType) : r));
              const t = JSON.stringify(data, null, 2);
              return { text: t, html: highlightJson(t) };
            },
          },
        ],
        options: [
          { id: 'delim', label: '구분자', type: 'select', default: ',', choices: DELIMS },
          { id: 'header', label: '첫 줄을 헤더로', type: 'checkbox', default: true, modes: ['c2j'] },
          { id: 'types', label: '숫자/불리언 자동 변환', type: 'checkbox', default: true, modes: ['c2j'] },
          { id: 'guard', label: '엑셀 수식 주입 방지 (= + - @ 앞에 \')', type: 'checkbox', default: true, modes: ['j2c'] },
        ],
        sample: (m) => (m === 'j2c' ? '[{"id":1,"name":"홍길동","email":"hong@example.com","address":{"city":"서울"}},{"id":2,"name":"Kim, Jr.","email":"kim@example.com","address":{"city":"부산"}}]' : 'id,name,score,active\n1,홍길동,95.5,true\n2,"Kim, Jr.",88,false'),
      }),
  },
  {
    id: 'json-ts',
    name: 'JSON → TypeScript',
    category: 'convert',
    description: 'JSON 예시 데이터로부터 TypeScript 인터페이스(타입)를 생성합니다.',
    keywords: ['typescript', 'interface', 'type', 'quicktype', 'ts'],
    render: (root) =>
      transformer(root, {
        id: 'json-ts',
        wrap: false,
        modes: [{ id: 'ts', label: '변환', run: (s, o) => toTs(parseJson(s), 'Root', o.kind === 'type') }],
        options: [{ id: 'kind', label: '선언', type: 'select', default: 'interface', choices: [['interface', 'interface'], ['type', 'type']] }],
        sample: '{"id":1,"name":"DevKit","tags":["json","regex"],"owner":{"login":"hong","verified":true},"releases":[{"version":"1.0.0","date":"2026-11-10"},{"version":"1.1.0","date":"2026-12-01","notes":"bug fixes"}],"license":null}',
      }),
  },
  { id: 'timestamp', name: 'Unix 타임스탬프 변환', category: 'convert', description: 'Unix 타임스탬프(초/밀리초)와 날짜를 서로 변환합니다. 현재 시각을 실시간으로 보여줍니다.', keywords: ['epoch', 'unix time', 'date', '날짜', '시간', 'iso 8601'], render: timestampTool },
  { id: 'number-base', name: '진법 변환기', category: 'convert', description: '2진수, 8진수, 10진수, 16진수 등을 서로 변환합니다. 큰 정수도 지원합니다.', keywords: ['binary', 'hex', 'octal', 'decimal', 'radix', '진수'], render: baseTool },
  { id: 'color', name: '색상 변환기', category: 'convert', description: 'HEX, RGB, HSL, CMYK 색상 값을 서로 변환하고 명도 대비를 계산합니다.', keywords: ['hex to rgb', 'rgb', 'hsl', 'cmyk', 'color picker', '색상', 'contrast'], render: colorTool },
  { id: 'case', name: '대소문자/케이스 변환', category: 'convert', description: 'camelCase, snake_case, kebab-case, PascalCase 등 변수명 표기법을 한 번에 변환합니다.', keywords: ['camel', 'snake', 'kebab', 'pascal', 'upper', 'lower', '변수명'], render: caseTool },
  { id: 'cron', name: 'Cron 표현식 해석', category: 'convert', description: 'Cron 스케줄 표현식을 사람이 읽을 수 있는 한국어 문장으로 풀어줍니다.', keywords: ['crontab', 'schedule', 'quartz', '스케줄'], render: cronTool },
];
