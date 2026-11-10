// Small DOM helpers shared by every tool. No framework: tools build their UI with `h()`.
import { HIGHLIGHT_LIMIT, MAX_INPUT_CHARS, assertInputSize, escapeHtml, findSuspicious, safeUrl, setHtml, stripSuspicious } from './security';

export { escapeHtml, setHtml };

type Child = Node | string | number | null | undefined | false;
type Props = Record<string, unknown>;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props | null = null,
  ...children: (Child | Child[])[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      // Raw HTML / inline-handler props are never accepted here: use setHtml() for vetted markup.
      if (key === 'html' || key === 'innerHTML' || key === 'outerHTML' || key === 'srcdoc' || (key.startsWith('on') && typeof value !== 'function'))
        throw new Error(`h(): unsafe prop "${key}"`);
      if (key === 'class') el.className = String(value);
      else if (key === 'text') el.textContent = String(value);
      else if (key === 'href' || key === 'src') el.setAttribute(key, safeUrl(String(value), key));
      else if (key === 'style' && typeof value === 'object') Object.assign(el.style, value);
      else if (key.startsWith('on') && typeof value === 'function')
        el.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
      else if (key in el && typeof value !== 'string') (el as unknown as Props)[key] = value;
      else if (key === 'value' || key === 'checked') (el as unknown as Props)[key] = value;
      else el.setAttribute(key, value === true ? '' : String(value));
    }
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

// ---------- persistence (per-viewer convenience only) ----------
/** Tools whose input commonly holds credentials: never written to storage. */
const SENSITIVE_KEYS = new Set(['tool:jwt', 'tool:hash', 'tool:urlparse', 'tool:base64', 'tool:string-escape', 'tool:mask']);

/** Keep only fields whose type matches the fallback, so corrupted or tampered storage cannot inject odd values. */
function conform<T>(parsed: unknown, fallback: T): T {
  if (Array.isArray(fallback)) return (Array.isArray(parsed) ? parsed.filter((x) => typeof x === 'string').slice(0, 100) : fallback) as T;
  if (fallback !== null && typeof fallback === 'object') {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return fallback;
    const out = { ...fallback } as Record<string, unknown>;
    for (const k of Object.keys(fallback)) {
      if (!Object.prototype.hasOwnProperty.call(parsed, k)) continue;
      const v = (parsed as Record<string, unknown>)[k];
      const want = (fallback as Record<string, unknown>)[k];
      const ok = want === undefined ? v !== null && !Array.isArray(v) : typeof v === typeof want;
      if (ok) out[k] = v;
    }
    return out as T;
  }
  return typeof parsed === typeof fallback ? (parsed as T) : fallback;
}

export const store = {
  get<T>(key: string, fallback: T): T {
    try {
      const raw = localStorage.getItem('devkit:' + key);
      return raw === null ? fallback : conform(JSON.parse(raw), fallback);
    } catch {
      return fallback;
    }
  },
  set(key: string, value: unknown): void {
    if (key.startsWith('tool:') && (SENSITIVE_KEYS.has(key) || !rememberInputs())) return;
    try {
      localStorage.setItem('devkit:' + key, JSON.stringify(value));
    } catch {
      /* storage unavailable */
    }
  },
  /** Drop anything an older version may have saved for tools that are now never persisted. */
  purgeSensitive(): void {
    try {
      SENSITIVE_KEYS.forEach((k) => localStorage.removeItem('devkit:' + k));
    } catch {
      /* ignore */
    }
  },
  /** Remove every saved tool input (settings, favorites and theme are kept). */
  clearInputs(): number {
    let n = 0;
    try {
      for (const k of Object.keys(localStorage)) if (k.startsWith('devkit:tool:')) (localStorage.removeItem(k), n++);
    } catch {
      /* ignore */
    }
    return n;
  },
};

export function rememberInputs(): boolean {
  return store.get('settings:remember', true);
}

export function debounce<A extends unknown[]>(fn: (...a: A) => void, ms = 150) {
  let t: ReturnType<typeof setTimeout> | undefined;
  return (...a: A) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}

// ---------- feedback ----------
let toastTimer: ReturnType<typeof setTimeout> | undefined;
export function toast(message: string): void {
  let el = document.getElementById('toast');
  if (!el) {
    el = h('div', { id: 'toast', role: 'status', 'aria-live': 'polite' });
    document.body.append(el);
  }
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el!.classList.remove('show'), 1600);
}

export async function copyText(text: string): Promise<void> {
  if (!text) return toast('복사할 내용이 없습니다');
  try {
    await navigator.clipboard.writeText(text);
    toast('복사했습니다');
  } catch {
    toast('클립보드 접근이 거부되었습니다');
  }
}

export function copyButton(getText: () => string, label = '복사'): HTMLButtonElement {
  return h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => copyText(getText()) }, label);
}

export function button(label: string, onclick: () => void, cls = 'btn btn-ghost btn-sm'): HTMLButtonElement {
  return h('button', { class: cls, type: 'button', onclick }, label);
}

// ---------- layout primitives ----------
export function panel(title: string, actions: Child[], body: Node, extraClass = ''): HTMLElement {
  return h(
    'section',
    { class: 'panel ' + extraClass },
    h('header', { class: 'panel-head' }, h('span', { class: 'panel-title' }, title), h('div', { class: 'panel-actions' }, ...actions)),
    body,
  );
}

export function textarea(props: Props = {}): HTMLTextAreaElement {
  return h('textarea', { class: 'code', spellcheck: 'false', autocomplete: 'off', ...props });
}

export function segmented<T extends string>(
  choices: [T, string][],
  value: T,
  onChange: (v: T) => void,
): HTMLElement & { set(v: T): void } {
  const wrap = h('div', { class: 'segmented', role: 'tablist' }) as unknown as HTMLElement & { set(v: T): void };
  const buttons = choices.map(([id, label]) =>
    h('button', {
      type: 'button',
      role: 'tab',
      class: id === value ? 'active' : '',
      'aria-selected': String(id === value),
      onclick: () => {
        wrap.set(id);
        onChange(id);
      },
    }, label),
  );
  wrap.set = (v: T) =>
    buttons.forEach((b, i) => {
      const on = choices[i][0] === v;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', String(on));
    });
  wrap.append(...buttons);
  return wrap;
}

export function field(label: string, control: Node, cls = ''): HTMLLabelElement {
  return h('label', { class: 'field ' + cls }, h('span', { class: 'field-label' }, label), control);
}

export function checkbox(label: string, checked: boolean, onChange: (v: boolean) => void): HTMLLabelElement {
  const input = h('input', { type: 'checkbox', checked, onchange: () => onChange(input.checked) });
  return h('label', { class: 'check' }, input, h('span', null, label));
}

export function select(choices: [string, string][], value: string, onChange: (v: string) => void): HTMLSelectElement {
  const s = h('select', { class: 'input', onchange: () => onChange(s.value) },
    ...choices.map(([v, l]) => h('option', { value: v, selected: v === value }, l)));
  return s;
}

export function errorBox(): HTMLElement & { show(msg: string | null): void } {
  const el = h('div', { class: 'error-box', role: 'alert', hidden: true }) as unknown as HTMLElement & { show(msg: string | null): void };
  el.show = (msg) => {
    el.hidden = !msg;
    el.textContent = msg ?? '';
  };
  return el;
}

// ---------- syntax highlighting (lightweight, output-only) ----------
function wrapTokens(text: string, re: RegExp, classify: (m: RegExpExecArray) => string | null): string {
  let out = '';
  let last = 0;
  re.lastIndex = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (m[0] === '') {
      re.lastIndex++;
      continue;
    }
    const cls = classify(m);
    out += escapeHtml(text.slice(last, m.index));
    out += cls ? `<span class="tok-${cls}">${escapeHtml(m[0])}</span>` : escapeHtml(m[0]);
    last = m.index + m[0].length;
  }
  return out + escapeHtml(text.slice(last));
}

export function highlightJson(text: string): string {
  // Group 1 marks an object key (string followed by ':'), decided by the regex itself so highlighting stays linear.
  const re = /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*")(?=\s*:)|"(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}[\],:]/g;
  return wrapTokens(text, re, (m) => {
    const t = m[0];
    if (t[0] === '"') return m[1] !== undefined ? 'key' : 'string';
    if (t === 'true' || t === 'false') return 'bool';
    if (t === 'null') return 'null';
    if (/^[{}[\],:]$/.test(t)) return 'punct';
    return 'number';
  });
}

export function highlightYaml(text: string): string {
  return text
    .split('\n')
    .map((line) => {
      const comment = line.match(/^(\s*)(#.*)$/);
      if (comment) return escapeHtml(comment[1]) + `<span class="tok-comment">${escapeHtml(comment[2])}</span>`;
      const kv = line.match(/^(\s*(?:- )*)([^\s#][^:#]*?|"[^"]*"|'[^']*')(:)(\s+|$)(.*)$/);
      if (kv) return escapeHtml(kv[1]) + `<span class="tok-key">${escapeHtml(kv[2])}</span>` + `<span class="tok-punct">:</span>` + kv[4] + yamlScalar(kv[5]);
      const item = line.match(/^(\s*-\s+)(.*)$/);
      if (item) return `<span class="tok-punct">${escapeHtml(item[1])}</span>` + yamlScalar(item[2]);
      return escapeHtml(line);
    })
    .join('\n');
}

function yamlScalar(v: string): string {
  if (!v) return '';
  const [value, comment] = splitComment(v);
  let cls = 'string';
  if (/^(true|false|yes|no|on|off)$/i.test(value)) cls = 'bool';
  else if (/^(null|~)$/.test(value)) cls = 'null';
  else if (/^[-+]?(\d[\d_]*(\.\d+)?([eE][-+]?\d+)?|0x[\da-fA-F]+|\.inf|\.nan)$/.test(value)) cls = 'number';
  else if (/^[|>][-+]?$/.test(value) || /^[[{]/.test(value) || /^[&*!]/.test(value)) cls = 'punct';
  return `<span class="tok-${cls}">${escapeHtml(value)}</span>` + (comment ? `<span class="tok-comment">${escapeHtml(comment)}</span>` : '');
}

function splitComment(v: string): [string, string] {
  const i = v.search(/\s#/);
  return i === -1 ? [v, ''] : [v.slice(0, i), v.slice(i)];
}

export function highlightXml(text: string): string {
  const re = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\/?[\w:.-]+|\/?>|[\w:.-]+(?==)|"[^"]*"|'[^']*'/g;
  let inTag = false;
  return wrapTokens(text, re, (m) => {
    const t = m[0];
    if (t.startsWith('<!--')) return 'comment';
    if (t.startsWith('<![CDATA[')) return 'string';
    if (t.startsWith('<')) {
      inTag = true;
      return 'tag';
    }
    if (t === '>' || t === '/>') {
      const was = inTag;
      inTag = false;
      return was ? 'tag' : null;
    }
    if (!inTag) return null;
    return t[0] === '"' || t[0] === "'" ? 'string' : 'attr';
  });
}

// ---------- the common "input → output" tool ----------
export interface Output {
  text: string;
  html?: string;
}
export type RunResult = string | Output;
export type Opts = Record<string, string | number | boolean>;

export interface OptionDef {
  id: string;
  label: string;
  type: 'checkbox' | 'select' | 'number';
  choices?: [string, string][];
  default: string | number | boolean;
  min?: number;
  max?: number;
  /** Show only for these mode ids. */
  modes?: string[];
}

export interface Mode {
  id: string;
  label: string;
  run(input: string, opts: Opts): RunResult | Promise<RunResult>;
}

export interface TransformConfig {
  id: string;
  modes: Mode[];
  options?: OptionDef[];
  placeholder?: string;
  sample?: string | ((modeId: string) => string);
  inputLabel?: string;
  outputLabel?: string;
  /** Adds a "swap" button that moves output to input and flips between the first two modes. */
  swap?: boolean;
  /** Output wraps long lines (default true). */
  wrap?: boolean;
  /** Maximum accepted input length in characters. */
  maxInput?: number;
  /** Called with the active mode on start and whenever it changes. */
  onModeChange?: (mode: string) => void;
  extraActions?: (ctx: { input: HTMLTextAreaElement; refresh(): void }) => Child[];
}

export function transformer(root: HTMLElement, cfg: TransformConfig): { input: HTMLTextAreaElement; refresh(): void } {
  const saved = store.get<{ mode?: string; input?: string; opts?: Opts }>('tool:' + cfg.id, {});
  let mode = cfg.modes.find((m) => m.id === saved.mode)?.id ?? cfg.modes[0].id;
  const opts: Opts = {};
  for (const o of cfg.options ?? []) opts[o.id] = saved.opts?.[o.id] ?? o.default;

  const input = textarea({ placeholder: cfg.placeholder ?? '여기에 입력하세요', value: saved.input ?? '', 'aria-label': cfg.inputLabel ?? '입력' });
  const output = h('pre', { class: 'code output' + (cfg.wrap === false ? ' nowrap' : ''), tabindex: '0', 'aria-label': cfg.outputLabel ?? '결과' });
  const err = errorBox();
  const status = h('span', { class: 'panel-meta' });
  let lastText = '';
  let seq = 0;

  const persist = debounce(() => store.set('tool:' + cfg.id, { mode, input: input.value.length < 200_000 ? input.value : '', opts }), 400);
  async function refresh() {
    const my = ++seq;
    persist();
    const value = input.value;
    renderWarnings(value);
    if (!value) {
      lastText = '';
      output.textContent = '';
      status.textContent = '';
      err.show(null);
      return;
    }
    try {
      assertInputSize(value, cfg.maxInput ?? MAX_INPUT_CHARS);
      const m = cfg.modes.find((x) => x.id === mode)!;
      const res = await m.run(value, opts);
      if (my !== seq) return;
      const out: Output = typeof res === 'string' ? { text: res } : res;
      lastText = out.text;
      // Large outputs skip highlighting: plain text is both safer and far faster to render.
      if (out.html !== undefined && out.text.length <= HIGHLIGHT_LIMIT) setHtml(output, out.html);
      else output.textContent = out.text;
      status.textContent = `${out.text.length.toLocaleString()}자`;
      err.show(null);
    } catch (e) {
      if (my !== seq) return;
      lastText = '';
      output.textContent = '';
      status.textContent = '';
      err.show(e instanceof RangeError ? '데이터가 너무 크거나 너무 깊게 중첩되어 처리할 수 없습니다.' : (e as Error).message || String(e));
    }
  }

  const optionEls: { def: OptionDef; el: HTMLElement }[] = [];
  for (const def of cfg.options ?? []) {
    let control: HTMLElement;
    if (def.type === 'checkbox') control = checkbox(def.label, Boolean(opts[def.id]), (v) => ((opts[def.id] = v), refresh()));
    else if (def.type === 'select')
      control = field(def.label, select(def.choices!, String(opts[def.id]), (v) => ((opts[def.id] = v), refresh())), 'inline');
    else {
      const n = h('input', {
        class: 'input input-num', type: 'number', value: String(opts[def.id]), min: def.min, max: def.max,
        oninput: () => ((opts[def.id] = Number(n.value)), refresh()),
      });
      control = field(def.label, n, 'inline');
    }
    optionEls.push({ def, el: control });
  }
  const syncOptions = () => {
    optionEls.forEach(({ def, el }) => (el.hidden = !!def.modes && !def.modes.includes(mode)));
    cfg.onModeChange?.(mode);
  };
  syncOptions();

  const modeSwitch = cfg.modes.length > 1
    ? segmented(cfg.modes.map((m) => [m.id, m.label] as [string, string]), mode, (v) => {
        mode = v;
        syncOptions();
        refresh();
      })
    : null;

  const sample = () => (typeof cfg.sample === 'function' ? cfg.sample(mode) : cfg.sample ?? '');
  const ctx = { input, refresh: () => void refresh() };

  const inputActions: Child[] = [
    ...(cfg.extraActions?.(ctx) ?? []),
    cfg.sample ? button('예시', () => ((input.value = sample()), refresh())) : null,
    button('붙여넣기', async () => {
      try {
        input.value = await navigator.clipboard.readText();
        refresh();
      } catch {
        toast('클립보드 읽기 권한이 없습니다');
      }
    }),
    button('지우기', () => ((input.value = ''), refresh(), input.focus())),
  ];
  const outputActions: Child[] = [
    status,
    cfg.swap && cfg.modes.length >= 2
      ? button('⇅ 입력으로', () => {
          if (!lastText) return;
          input.value = lastText;
          mode = mode === cfg.modes[0].id ? cfg.modes[1].id : cfg.modes[0].id;
          modeSwitch?.set(mode);
          syncOptions();
          refresh();
        })
      : null,
    copyButton(() => lastText),
  ];

  const warnings = h('div', { class: 'warn-box', role: 'status', hidden: true });
  function renderWarnings(value: string) {
    const found = findSuspicious(value);
    warnings.hidden = !found.length;
    if (!found.length) return void warnings.replaceChildren();
    warnings.replaceChildren(
      h('span', null, '⚠ 보이지 않거나 텍스트 방향을 바꾸는 문자가 있습니다: ' + found.map((f) => `${f.label} ${f.count}개`).join(', ')),
      button('모두 제거', () => ((input.value = stripSuspicious(input.value)), refresh())),
    );
  }

  const toolbar = h('div', { class: 'toolbar' }, modeSwitch, ...optionEls.map((o) => o.el));
  root.append(
    (cfg.options?.length || modeSwitch) ? toolbar : '',
    h('div', { class: 'io-grid' },
      panel(cfg.inputLabel ?? '입력', inputActions, h('div', { class: 'output-wrap' }, warnings, input)),
      panel(cfg.outputLabel ?? '결과', outputActions, h('div', { class: 'output-wrap' }, err, output)),
    ),
  );
  input.addEventListener('input', debounce(() => refresh(), 120));
  refresh();
  return ctx;
}
