import type { Tool } from '../types';
import YAML from 'yaml';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import { YAML_JS_OPTS, parseJson } from '../json';
import { bareObject, parseInert } from '../security';
import { checkbox, copyButton, debounce, errorBox, escapeHtml, field, h, highlightJson, highlightXml, highlightYaml, panel, store, textarea, transformer } from '../ui';

// ---------- TOML ----------
const TOML_OPTS = { maxDepth: 100, unsafeKeyBehaviour: 'throw' as const, integersAsBigInt: 'asNeeded' as const };
/** BigInt and TOML dates are not JSON: render them as strings. */
const jsonSafe = (v: unknown): unknown =>
  typeof v === 'bigint' ? v.toString() : v instanceof Date ? v.toISOString() : Array.isArray(v) ? v.map(jsonSafe) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, jsonSafe(x)])) : v;
function readToml(s: string): unknown {
  try {
    return parseToml(s, TOML_OPTS);
  } catch (e) {
    throw new Error('TOML 오류: ' + (e as Error).message);
  }
}
function readYaml(s: string): unknown {
  const doc = YAML.parseDocument(s);
  if (doc.errors.length) throw new Error('YAML 오류: ' + doc.errors.map((e) => e.message).join('\n'));
  return doc.toJS(YAML_JS_OPTS);
}
function writeToml(v: unknown): string {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('TOML의 최상위는 객체(키-값 테이블)여야 합니다');
  try {
    return stringifyToml(v, { maxDepth: 100 });
  } catch (e) {
    throw new Error('TOML로 변환할 수 없습니다: ' + (e as Error).message + ' (TOML에는 null이 없습니다)');
  }
}
const tomlHl = (t: string) => t.split('\n').map((l) => {
  const sec = l.match(/^(\s*)(\[\[?[^\]]+\]\]?)(.*)$/);
  if (sec) return escapeHtml(sec[1]) + `<span class="tok-tag">${escapeHtml(sec[2])}</span>` + escapeHtml(sec[3]);
  if (/^\s*#/.test(l)) return `<span class="tok-comment">${escapeHtml(l)}</span>`;
  const kv = l.match(/^(\s*)([^=]+?)(\s*=\s*)(.*)$/);
  if (kv) return escapeHtml(kv[1]) + `<span class="tok-key">${escapeHtml(kv[2])}</span>` + escapeHtml(kv[3]) + `<span class="tok-string">${escapeHtml(kv[4])}</span>`;
  return escapeHtml(l);
}).join('\n');

// ---------- XML ↔ JSON ----------
const XML_NAME = /^[A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?$/;
function xmlToJson(src: string, attrPrefix: string): unknown {
  if (/<!ENTITY/i.test(src)) throw new Error('보안상 <!ENTITY> 선언이 포함된 XML은 처리하지 않습니다 (XXE / Billion Laughs 방지).');
  const doc = parseInert(src, 'application/xml');
  const err = doc.querySelector('parsererror');
  if (err) throw new Error('XML 오류: ' + (err.textContent ?? '').replace(/\s+/g, ' ').trim());
  let nodes = 0;
  const conv = (el: Element, depth: number): unknown => {
    if (depth > 200 || ++nodes > 200_000) throw new Error('XML이 너무 크거나 깊습니다');
    const obj = bareObject();
    for (const a of Array.from(el.attributes)) obj[attrPrefix + a.name] = a.value;
    const kids = Array.from(el.children);
    const text = Array.from(el.childNodes).filter((n) => n.nodeType === Node.TEXT_NODE || n.nodeType === Node.CDATA_SECTION_NODE).map((n) => n.textContent).join('').trim();
    for (const k of kids) {
      const v = conv(k, depth + 1);
      const prev = obj[k.tagName];
      obj[k.tagName] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [prev, v];
    }
    if (!kids.length && !el.attributes.length) return text;
    if (text) obj['#text'] = text;
    return obj;
  };
  const root = doc.documentElement;
  return { [root.tagName]: conv(root, 0) };
}
function jsonToXml(v: unknown, indent: string, attrPrefix: string): string {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escA = (s: string) => esc(s).replace(/"/g, '&quot;');
  const name = (n: string) => {
    if (!XML_NAME.test(n) || /^xml/i.test(n)) throw new Error(`"${n}"은(는) XML 요소/속성 이름으로 쓸 수 없습니다`);
    return n;
  };
  const scalar = (x: unknown) => (x === null ? '' : String(x));
  const out: string[] = [];
  const emit = (tag: string, val: unknown, lvl: number) => {
    const pad = indent.repeat(lvl);
    if (lvl > 200) throw new Error('중첩이 너무 깊습니다');
    if (Array.isArray(val)) return val.forEach((x) => emit(tag, x, lvl));
    if (val && typeof val === 'object') {
      const entries = Object.entries(val);
      const attrs = entries.filter(([k]) => k.startsWith(attrPrefix) && attrPrefix).map(([k, x]) => ` ${name(k.slice(attrPrefix.length))}="${escA(scalar(x))}"`).join('');
      const text = entries.find(([k]) => k === '#text')?.[1];
      const kids = entries.filter(([k]) => k !== '#text' && !(attrPrefix && k.startsWith(attrPrefix)));
      if (!kids.length) return out.push(`${pad}<${name(tag)}${attrs}${text === undefined ? '/>' : `>${esc(scalar(text))}</${tag}>`}`);
      out.push(`${pad}<${name(tag)}${attrs}>`);
      if (text !== undefined) out.push(pad + indent + esc(scalar(text)));
      kids.forEach(([k, x]) => emit(k, x, lvl + 1));
      return out.push(`${pad}</${tag}>`);
    }
    out.push(`${pad}<${name(tag)}>${esc(scalar(val))}</${tag}>`);
  };
  const entries = v && typeof v === 'object' && !Array.isArray(v) ? Object.entries(v) : [];
  if (entries.length === 1) emit(entries[0][0], entries[0][1], 0);
  else emit('root', v, 0);
  return '<?xml version="1.0" encoding="UTF-8"?>\n' + out.join(indent ? '\n' : '');
}

// ---------- Roman numerals ----------
const ROMAN: [number, string][] = [[1000, 'M'], [900, 'CM'], [500, 'D'], [400, 'CD'], [100, 'C'], [90, 'XC'], [50, 'L'], [40, 'XL'], [10, 'X'], [9, 'IX'], [5, 'V'], [4, 'IV'], [1, 'I']];
const toRoman = (n: number) => ROMAN.reduce((s, [v, r]) => { while (n >= v) (s += r), (n -= v); return s; }, '');
function romanTool(root: HTMLElement) {
  const num = h('input', { class: 'input mono grow', type: 'number', min: '1', max: '3999', value: '2026', 'aria-label': '숫자' });
  const rom = h('input', { class: 'input mono grow', value: 'MMXXVI', 'aria-label': '로마 숫자', spellcheck: 'false' });
  const err = errorBox();
  num.addEventListener('input', () => {
    const n = Number(num.value);
    if (!Number.isInteger(n) || n < 1 || n > 3999) return err.show('1부터 3999 사이의 정수만 변환할 수 있습니다');
    err.show(null);
    rom.value = toRoman(n);
  });
  rom.addEventListener('input', () => {
    const r = rom.value.trim().toUpperCase();
    if (!/^M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})$/.test(r) || !r) return err.show('올바른 로마 숫자가 아닙니다 (예: MCMXCIV)');
    err.show(null);
    let i = 0, n = 0;
    for (const [v, s] of ROMAN) while (r.startsWith(s, i)) (n += v), (i += s.length);
    num.value = String(n);
  });
  root.append(h('div', { class: 'stack', style: { maxWidth: '640px' } },
    h('div', { class: 'result-row' }, h('span', { class: 'label' }, '아라비아 숫자'), num, copyButton(() => num.value)),
    h('div', { class: 'result-row' }, h('span', { class: 'label' }, '로마 숫자'), rom, copyButton(() => rom.value)),
    err));
}

// ---------- NATO ----------
const NATO: Record<string, string> = { A: 'Alfa', B: 'Bravo', C: 'Charlie', D: 'Delta', E: 'Echo', F: 'Foxtrot', G: 'Golf', H: 'Hotel', I: 'India', J: 'Juliett', K: 'Kilo', L: 'Lima', M: 'Mike', N: 'November', O: 'Oscar', P: 'Papa', Q: 'Quebec', R: 'Romeo', S: 'Sierra', T: 'Tango', U: 'Uniform', V: 'Victor', W: 'Whiskey', X: 'X-ray', Y: 'Yankee', Z: 'Zulu', 0: 'Zero', 1: 'One', 2: 'Two', 3: 'Three', 4: 'Four', 5: 'Five', 6: 'Six', 7: 'Seven', 8: 'Eight', 9: 'Niner', '-': 'Dash', '.': 'Stop', '@': 'At', '_': 'Underscore', '/': 'Slash' };
const NATO_REV = new Map(Object.entries(NATO).map(([k, v]) => [v.toUpperCase().replace('-', ''), k]));

// ---------- chmod ----------
function chmodTool(root: HTMLElement) {
  const who = ['소유자 (u)', '그룹 (g)', '기타 (o)'];
  const perms = ['읽기 r', '쓰기 w', '실행 x'];
  const bits = [[true, true, true], [true, false, true], [true, false, true]];
  const special = [false, false, false]; // setuid, setgid, sticky
  const octal = h('input', { class: 'input mono', style: { width: '110px', fontSize: '20px' }, value: '755', 'aria-label': '8진수 권한' });
  const symbolic = h('input', { class: 'input mono', style: { width: '160px', fontSize: '20px' }, value: 'rwxr-xr-x', 'aria-label': '기호 권한' });
  const file = h('input', { class: 'input mono', value: 'script.sh', 'aria-label': '파일명', style: { width: '180px' } });
  const cmd = h('div', { class: 'big-time', style: { fontSize: '18px' } });
  const warn = h('div', { class: 'warn-box', hidden: true, style: { margin: '0' } });
  const err = errorBox();
  const boxes: HTMLInputElement[][] = bits.map((row, i) => row.map((on, j) => h('input', { type: 'checkbox', checked: on, 'aria-label': `${who[i]} ${perms[j]}`, onchange: () => ((bits[i][j] = boxes[i][j].checked), sync('grid')) })));
  const specBoxes = ['setuid (4)', 'setgid (2)', 'sticky (1)'].map((l, i) => checkbox(l, special[i], (v) => ((special[i] = v), sync('grid'))));

  function sync(from: 'grid' | 'octal' | 'symbolic') {
    err.show(null);
    if (from === 'octal') {
      const v = octal.value.trim();
      if (!/^[0-7]{3,4}$/.test(v)) return err.show('3~4자리 8진수를 입력하세요 (예: 755, 4755)');
      const d = v.padStart(4, '0').split('').map(Number);
      special.forEach((_, i) => (special[i] = !!(d[0] & (4 >> i))));
      bits.forEach((row, i) => row.forEach((_, j) => (row[j] = !!(d[i + 1] & (4 >> j)))));
    } else if (from === 'symbolic') {
      const v = symbolic.value.trim().replace(/^[-dlbcps]/, (m) => (symbolic.value.trim().length === 10 ? '' : m));
      if (!/^([r-][w-][xsS-])([r-][w-][xsS-])([r-][w-][xtT-])$/.test(v)) return err.show('기호 형식이 올바르지 않습니다 (예: rwxr-xr-x, -rwsr-xr-x)');
      for (let i = 0; i < 3; i++) {
        const c = v.slice(i * 3, i * 3 + 3);
        bits[i] = [c[0] === 'r', c[1] === 'w', /[xst]/.test(c[2])];
        special[i] = /[sStT]/.test(c[2]);
      }
    }
    const digit = (row: boolean[]) => (row[0] ? 4 : 0) + (row[1] ? 2 : 0) + (row[2] ? 1 : 0);
    const sp = (special[0] ? 4 : 0) + (special[1] ? 2 : 0) + (special[2] ? 1 : 0);
    const oct = (sp ? String(sp) : '') + bits.map(digit).join('');
    const sym = bits.map((row, i) => {
      const x = row[2], s = special[i];
      const exec = i === 2 ? (s ? (x ? 't' : 'T') : x ? 'x' : '-') : s ? (x ? 's' : 'S') : x ? 'x' : '-';
      return (row[0] ? 'r' : '-') + (row[1] ? 'w' : '-') + exec;
    }).join('');
    if (from !== 'octal') octal.value = oct;
    if (from !== 'symbolic') symbolic.value = sym;
    boxes.forEach((row, i) => row.forEach((b, j) => (b.checked = bits[i][j])));
    specBoxes.forEach((l, i) => ((l.querySelector('input') as HTMLInputElement).checked = special[i]));
    cmd.textContent = `chmod ${oct} ${file.value || 'file'}`;
    const w: string[] = [];
    if (bits[2][1]) w.push('모든 사용자(other)가 쓸 수 있습니다 (world-writable)');
    if (special[0] || special[1]) w.push('setuid/setgid는 실행 시 소유자/그룹 권한으로 동작하므로 권한 상승에 악용될 수 있습니다');
    if (oct.endsWith('777')) w.push('777은 거의 항상 과도한 권한입니다');
    warn.hidden = !w.length;
    warn.textContent = w.length ? '⚠ ' + w.join(' · ') : '';
  }
  octal.addEventListener('input', () => sync('octal'));
  symbolic.addEventListener('input', () => sync('symbolic'));
  file.addEventListener('input', () => sync('grid'));
  const grid = h('table', { class: 'kv', style: { width: 'auto' } },
    h('tr', null, h('th', null, ''), ...perms.map((p) => h('th', { style: { textAlign: 'center' } }, p))),
    ...who.map((w, i) => h('tr', null, h('th', null, w), ...boxes[i].map((b) => h('td', { style: { textAlign: 'center' } }, b)))));
  const presets: [string, string][] = [['644 파일', '644'], ['755 실행/디렉터리', '755'], ['600 비밀 파일', '600'], ['700 개인 디렉터리', '700'], ['775 그룹 공유', '775'], ['1777 /tmp', '1777']];
  root.append(h('div', { class: 'stack', style: { maxWidth: '760px' } },
    h('div', { class: 'row', style: { alignItems: 'center' } }, field('8진수', octal), field('기호', symbolic), field('파일', file)),
    h('div', { class: 'chips' }, ...presets.map(([l, v]) => h('button', { class: 'chip', type: 'button', onclick: () => ((octal.value = v), sync('octal')) }, l))),
    err,
    panel('권한', [], h('div', { class: 'panel-body stack' }, grid, h('div', { class: 'toolbar', style: { marginBottom: '0' } }, ...specBoxes))),
    panel('명령어', [copyButton(() => cmd.textContent ?? '')], h('div', { class: 'panel-body' }, cmd)),
    warn));
  sync('grid');
}

// ---------- docker run → compose ----------
/** POSIX-ish shell word splitting: quotes, escapes and line continuations. No expansion is performed. */
function shellSplit(s: string): string[] {
  const out: string[] = [];
  let cur = '', q: string | null = null, has = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === q) q = null;
      else if (c === '\\' && q === '"' && i + 1 < s.length && '"\\$`'.includes(s[i + 1])) cur += s[++i];
      else cur += c;
    } else if (c === '"' || c === "'") (q = c), (has = true);
    else if (c === '\\') {
      if (s[i + 1] === '\n' || (s[i + 1] === '\r' && s[i + 2] === '\n')) i += s[i + 1] === '\r' ? 2 : 1;
      else if (i + 1 < s.length) (cur += s[++i]), (has = true);
    } else if (/\s/.test(c)) {
      if (cur || has) out.push(cur), (cur = ''), (has = false);
    } else (cur += c), (has = true);
  }
  if (q) throw new Error('닫히지 않은 따옴표가 있습니다');
  if (cur || has) out.push(cur);
  return out;
}

function dockerToCompose(cmd: string): { yaml: string; notes: string[] } {
  const words = shellSplit(cmd.trim().replace(/^\$\s*/, ''));
  if (words[0] === 'sudo') words.shift();
  if (words[0] !== 'docker' || !['run', 'container'].includes(words[1] ?? '')) throw new Error('"docker run …" 명령어를 입력하세요');
  let i = words[1] === 'container' ? 3 : 2;
  const svc: Record<string, unknown> = {};
  const notes: string[] = [];
  const push = (k: string, v: unknown) => ((svc[k] ??= []) as unknown[]).push(v);
  const VALUE_FLAGS: Record<string, string> = {
    '-p': 'ports', '--publish': 'ports', '-v': 'volumes', '--volume': 'volumes', '-e': 'environment', '--env': 'environment', '--env-file': 'env_file',
    '--name': 'container_name', '--restart': 'restart', '--network': 'networks', '--net': 'networks', '-w': 'working_dir', '--workdir': 'working_dir',
    '-u': 'user', '--user': 'user', '-h': 'hostname', '--hostname': 'hostname', '--entrypoint': 'entrypoint', '-l': 'labels', '--label': 'labels',
    '--cpus': 'cpus', '-m': 'mem_limit', '--memory': 'mem_limit', '--cap-add': 'cap_add', '--cap-drop': 'cap_drop', '--device': 'devices',
    '--add-host': 'extra_hosts', '--dns': 'dns', '--expose': 'expose', '--log-driver': 'logging.driver', '--platform': 'platform',
    '--shm-size': 'shm_size', '--pid': 'pid', '--ipc': 'ipc', '--security-opt': 'security_opt', '--ulimit': 'ulimits', '--mount': 'volumes',
    '--tmpfs': 'tmpfs', '--stop-signal': 'stop_signal', '--health-cmd': 'healthcheck.test', '--health-interval': 'healthcheck.interval',
    '--health-retries': 'healthcheck.retries', '--health-timeout': 'healthcheck.timeout', '--gpus': 'gpus',
  };
  const LIST = new Set(['ports', 'volumes', 'environment', 'env_file', 'labels', 'cap_add', 'cap_drop', 'devices', 'extra_hosts', 'dns', 'expose', 'security_opt', 'tmpfs', 'networks']);
  for (; i < words.length; i++) {
    const w = words[i];
    if (!w.startsWith('-') || w === '-') break;
    let flag = w, val: string | undefined;
    const eq = w.indexOf('=');
    if (w.startsWith('--') && eq > 0) (flag = w.slice(0, eq)), (val = w.slice(eq + 1));
    // grouped short boolean flags such as -dit
    if (/^-[a-z]{2,}$/.test(flag) && !VALUE_FLAGS[flag]) {
      for (const c of flag.slice(1)) {
        if (c === 'd') notes.push('-d (백그라운드)는 compose에서 `docker compose up -d`로 지정합니다');
        else if (c === 'i') svc.stdin_open = true;
        else if (c === 't') svc.tty = true;
        else notes.push(`알 수 없는 옵션 -${c}`);
      }
      continue;
    }
    if (flag === '-d' || flag === '--detach') { notes.push('-d (백그라운드)는 compose에서 `docker compose up -d`로 지정합니다'); continue; }
    if (flag === '-i' || flag === '--interactive') { svc.stdin_open = true; continue; }
    if (flag === '-t' || flag === '--tty') { svc.tty = true; continue; }
    if (flag === '--rm') { notes.push('--rm 은 compose에 대응 항목이 없습니다 (`docker compose run --rm` 사용)'); continue; }
    if (flag === '--privileged') { svc.privileged = true; notes.push('⚠ --privileged 는 호스트 장치·커널 기능 전체에 접근하는 위험한 옵션입니다'); continue; }
    if (flag === '--read-only') { svc.read_only = true; continue; }
    if (flag === '--init') { svc.init = true; continue; }
    const key = VALUE_FLAGS[flag];
    if (!key) {
      notes.push(`지원하지 않는 옵션 ${flag} (직접 추가하세요)`);
      if (val === undefined && words[i + 1] && !words[i + 1].startsWith('-')) i++;
      continue;
    }
    if (val === undefined) val = words[++i];
    if (val === undefined) throw new Error(`${flag} 옵션에 값이 없습니다`);
    if (key.includes('.')) {
      const [a, b] = key.split('.');
      const obj = (svc[a] ??= {}) as Record<string, unknown>;
      obj[b] = b === 'test' ? ['CMD-SHELL', val] : b === 'retries' ? Number(val) : val;
    } else if (key === 'ulimits') {
      const [n, v] = val.split('=');
      ((svc.ulimits ??= {}) as Record<string, unknown>)[n] = v?.includes(':') ? { soft: Number(v.split(':')[0]), hard: Number(v.split(':')[1]) } : Number(v);
    } else if (LIST.has(key)) push(key, key === 'ports' || key === 'expose' ? val : val);
    else svc[key] = key === 'cpus' ? Number(val) : val;
    if (key === 'volumes' && /docker\.sock/.test(val)) notes.push('⚠ docker.sock 마운트는 컨테이너에 호스트의 루트 권한을 주는 것과 같습니다');
    if (key === 'cap_add' && /^(ALL|SYS_ADMIN)$/i.test(val)) notes.push(`⚠ --cap-add ${val} 는 매우 넓은 권한입니다`);
    if (key === 'ports' && /^\d+:\d+/.test(val)) notes.push(`포트 ${val.split(':')[0]}가 모든 인터페이스(0.0.0.0)에 열립니다. 로컬 전용이면 127.0.0.1:${val} 형식을 쓰세요`);
  }
  const image = words[i];
  if (!image) throw new Error('이미지 이름을 찾을 수 없습니다');
  const rest = words.slice(i + 1);
  const service: Record<string, unknown> = { image, ...svc };
  if (rest.length) service.command = rest;
  if (Array.isArray(service.networks)) {
    const nets = service.networks as string[];
    if (nets.length === 1 && ['host', 'none', 'bridge'].includes(nets[0])) (service.network_mode = nets[0]), delete service.networks;
  }
  const name = String(svc.container_name ?? image.split('/').pop()!.split(':')[0]).replace(/[^\w.-]/g, '-') || 'app';
  const compose: Record<string, unknown> = { services: { [name]: service } };
  if (Array.isArray(service.networks)) compose.networks = Object.fromEntries((service.networks as string[]).map((n) => [n, { external: true }]));
  const named = ((service.volumes as string[] | undefined) ?? []).map((v) => v.split(':')[0]).filter((v) => v && !/^[./~$]/.test(v) && !v.includes('/') && !v.includes('='));
  if (named.length) compose.volumes = Object.fromEntries(named.map((n) => [n, {}]));
  return { yaml: YAML.stringify(compose, { lineWidth: 0 }), notes: [...new Set(notes)] };
}

// ---------- safe math evaluator (no eval) ----------
type Tok = { t: 'num'; v: number } | { t: 'id'; v: string } | { t: 'op'; v: string };
const FUNCS: Record<string, (...a: number[]) => number> = {
  sqrt: Math.sqrt, cbrt: Math.cbrt, abs: Math.abs, sin: Math.sin, cos: Math.cos, tan: Math.tan, asin: Math.asin, acos: Math.acos, atan: Math.atan,
  sinh: Math.sinh, cosh: Math.cosh, tanh: Math.tanh, ln: Math.log, log: Math.log10, log2: Math.log2, exp: Math.exp, floor: Math.floor,
  ceil: Math.ceil, round: Math.round, trunc: Math.trunc, sign: Math.sign, min: Math.min, max: Math.max, pow: Math.pow, hypot: Math.hypot,
  deg: (r) => (r * 180) / Math.PI, rad: (d) => (d * Math.PI) / 180,
};
const CONSTS: Record<string, number> = { pi: Math.PI, e: Math.E, tau: Math.PI * 2, phi: (1 + Math.sqrt(5)) / 2 };

function tokenize(s: string): Tok[] {
  const out: Tok[] = [];
  const re = /\s*(?:(\d[\d_]*(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|0x[\da-fA-F]+|0b[01]+)|([A-Za-z_]\w*)|(\*\*|[-+*/%^(),!]))/y;
  let i = 0;
  while (i < s.length) {
    if (/^\s*$/.test(s.slice(i))) break;
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m) throw new Error(`알 수 없는 문자 "${s.slice(i).trim()[0]}" (위치 ${i + 1})`);
    if (m[1]) out.push({ t: 'num', v: /^0[xb]/i.test(m[1]) ? Number(m[1]) : Number(m[1].replace(/_/g, '')) });
    else if (m[2]) out.push({ t: 'id', v: m[2] });
    else out.push({ t: 'op', v: m[3] === '**' ? '^' : m[3] });
    i = re.lastIndex;
    if (out.length > 10_000) throw new Error('식이 너무 깁니다');
  }
  return out;
}

function evaluate(expr: string, vars: Map<string, number>): number {
  const toks = tokenize(expr);
  let p = 0, depth = 0;
  const peek = () => toks[p];
  const take = (v?: string) => {
    const t = toks[p];
    if (v !== undefined && (!t || t.t !== 'op' || t.v !== v)) throw new Error(`"${v}"가 필요합니다`);
    p++;
    return t;
  };
  const guard = () => { if (++depth > 500) throw new Error('괄호/함수 중첩이 너무 깊습니다'); };
  const factorial = (n: number) => {
    if (!Number.isInteger(n) || n < 0) throw new Error('팩토리얼은 0 이상의 정수에만 쓸 수 있습니다');
    if (n > 170) return Infinity;
    let r = 1;
    for (let i = 2; i <= n; i++) r *= i;
    return r;
  };
  const primary = (): number => {
    const t = take();
    if (!t) throw new Error('식이 예상보다 일찍 끝났습니다');
    if (t.t === 'num') return t.v;
    if (t.t === 'op' && t.v === '(') { guard(); const v = expr0(); take(')'); depth--; return v; }
    if (t.t === 'op' && (t.v === '-' || t.v === '+')) { const v = unary(); return t.v === '-' ? -v : v; }
    if (t.t === 'id') {
      const name = t.v.toLowerCase();
      if (peek()?.t === 'op' && (peek() as { v: string }).v === '(') {
        const fn = Object.prototype.hasOwnProperty.call(FUNCS, name) ? FUNCS[name] : undefined;
        if (!fn) throw new Error(`알 수 없는 함수 ${t.v}()`);
        guard();
        take('(');
        const args: number[] = [];
        if (!(peek()?.t === 'op' && (peek() as { v: string }).v === ')')) {
          args.push(expr0());
          while (peek()?.t === 'op' && (peek() as { v: string }).v === ',') take(','), args.push(expr0());
        }
        take(')');
        depth--;
        return fn(...args);
      }
      if (vars.has(t.v)) return vars.get(t.v)!;
      if (Object.prototype.hasOwnProperty.call(CONSTS, name)) return CONSTS[name];
      throw new Error(`정의되지 않은 이름 "${t.v}"`);
    }
    throw new Error(`예상하지 못한 "${t.v}"`);
  };
  const postfix = (): number => {
    let v = primary();
    while (peek()?.t === 'op' && (peek() as { v: string }).v === '!') take('!'), (v = factorial(v));
    return v;
  };
  const power = (): number => {
    const b = postfix();
    if (peek()?.t === 'op' && (peek() as { v: string }).v === '^') { take('^'); guard(); const e = unary(); depth--; return b ** e; }
    return b;
  };
  const unary = (): number => {
    const t = peek();
    if (t?.t === 'op' && (t.v === '-' || t.v === '+')) { take(); guard(); const v = unary(); depth--; return t.v === '-' ? -v : v; }
    return power();
  };
  const term = (): number => {
    let v = unary();
    for (let t = peek(); t?.t === 'op' && '*/%'.includes(t.v) && t.v.length === 1; t = peek()) {
      take();
      const r = unary();
      v = t.v === '*' ? v * r : t.v === '/' ? v / r : v % r;
    }
    return v;
  };
  const expr0 = (): number => {
    let v = term();
    for (let t = peek(); t?.t === 'op' && (t.v === '+' || t.v === '-'); t = peek()) {
      take();
      const r = term();
      v = t.v === '+' ? v + r : v - r;
    }
    return v;
  };
  if (!toks.length) throw new Error('빈 식');
  const v = expr0();
  if (p < toks.length) throw new Error(`예상하지 못한 "${(toks[p] as { v: string | number }).v}"`);
  return v;
}

function mathTool(root: HTMLElement) {
  const input = textarea({ value: store.get('tool:math', 'r = 5\npi * r ^ 2\nsqrt(2) * 10\n(1 + 0.05) ^ 10 * 1000000\n10!\nans / 2'), 'aria-label': '수식' });
  const out = h('pre', { class: 'code output' });
  const update = () => {
    store.set('tool:math', input.value.length < 50_000 ? input.value : '');
    const vars = new Map<string, number>();
    const lines = input.value.split('\n').slice(0, 2000);
    const res: string[] = [];
    for (const raw of lines) {
      const line = raw.replace(/(#|\/\/).*$/, '').trim();
      if (!line) { res.push(''); continue; }
      try {
        const asg = line.match(/^([A-Za-z_]\w*)\s*=(?!=)\s*(.+)$/);
        if (asg && (Object.prototype.hasOwnProperty.call(FUNCS, asg[1].toLowerCase()) || Object.prototype.hasOwnProperty.call(CONSTS, asg[1].toLowerCase()))) throw new Error(`"${asg[1]}"은(는) 예약된 이름입니다`);
        const v = evaluate(asg ? asg[2] : line, vars);
        if (asg) vars.set(asg[1], v);
        vars.set('ans', v);
        const shown = Number.isInteger(v) && Math.abs(v) < 1e21 ? v.toLocaleString('en-US') : String(+v.toPrecision(15));
        res.push(`${asg ? asg[1] + ' = ' : '= '}${shown}`);
      } catch (e) {
        res.push('⚠ ' + (e as Error).message);
      }
    }
    out.textContent = res.join('\n');
  };
  input.addEventListener('input', debounce(update, 120));
  update();
  root.append(
    h('div', { class: 'io-grid' }, panel('수식 (한 줄에 하나)', [], input), panel('결과', [copyButton(() => out.textContent ?? '')], out)),
    h('p', { class: 'note' }, `사칙연산, %, ^ 또는 **, !, 괄호, 변수(x = 3), ans(직전 결과). 함수: ${Object.keys(FUNCS).join(', ')}. 상수: pi, e, tau, phi. eval 없이 직접 해석하므로 코드가 실행되지 않습니다.`),
  );
}

// ---------- keycode ----------
function keycodeTool(root: HTMLElement): () => void {
  const big = h('div', { class: 'big-time', style: { fontSize: '56px', textAlign: 'center', padding: '24px 0' } }, '아무 키나 누르세요');
  const table = h('table', { class: 'kv' });
  const onKey = (e: KeyboardEvent) => {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
    if (!(e.ctrlKey || e.metaKey) || !['r', 'k'].includes(e.key.toLowerCase())) e.preventDefault();
    big.textContent = e.key === ' ' ? 'Space' : e.key;
    const row = (k: string, v: string) => h('tr', null, h('th', null, k), h('td', null, copyButton(() => v), v));
    table.replaceChildren(
      row('event.key', JSON.stringify(e.key)),
      row('event.code', e.code),
      row('event.keyCode (구식)', String(e.keyCode)),
      row('event.which (구식)', String(e.which)),
      row('event.location', `${e.location} (${['일반', '왼쪽', '오른쪽', '숫자 키패드'][e.location] ?? '?'})`),
      row('수식 키', [e.ctrlKey && 'Ctrl', e.shiftKey && 'Shift', e.altKey && 'Alt', e.metaKey && 'Meta'].filter(Boolean).join(' + ') || '없음'),
      row('repeat / isComposing', `${e.repeat} / ${e.isComposing}`),
    );
  };
  window.addEventListener('keydown', onKey);
  root.append(h('div', { class: 'stack', style: { maxWidth: '760px' } }, panel('눌린 키', [], big), table, h('p', { class: 'note' }, '한글 IME 입력 중에는 key가 "Process"로 표시될 수 있습니다. Ctrl+K / Ctrl+R은 브라우저 기능을 위해 막지 않습니다.')));
  return () => window.removeEventListener('keydown', onKey);
}

// ---------- git cheatsheet ----------
const GIT: [string, [string, string][]][] = [
  ['설정', [['git config --global user.name "이름"', '커밋 작성자 이름 설정'], ['git config --global user.email "메일"', '커밋 작성자 이메일 설정'], ['git config --global init.defaultBranch main', '기본 브랜치 이름을 main으로'], ['git config --list --show-origin', '설정값과 위치 보기']]],
  ['시작', [['git init', '현재 폴더를 저장소로 만들기'], ['git clone <url>', '원격 저장소 복제'], ['git clone --depth 1 <url>', '최신 커밋만 얕게 복제']]],
  ['변경 사항', [['git status -sb', '짧은 상태 보기'], ['git add -p', '변경 사항을 조각 단위로 골라 스테이징'], ['git diff', '스테이징 전 변경 내용'], ['git diff --staged', '스테이징된 변경 내용'], ['git restore <file>', '작업 중인 변경 되돌리기'], ['git restore --staged <file>', '스테이징 취소']]],
  ['커밋', [['git commit -m "메시지"', '커밋 만들기'], ['git commit --amend', '직전 커밋 수정 (푸시 전만)'], ['git commit --fixup <sha>', '특정 커밋을 고치는 fixup 커밋'], ['git log --oneline --graph --all', '전체 이력을 그래프로']]],
  ['브랜치', [['git switch -c <name>', '새 브랜치 만들고 이동'], ['git switch <name>', '브랜치 이동'], ['git branch -d <name>', '병합된 브랜치 삭제'], ['git branch -vv', '브랜치와 추적 정보'], ['git merge --no-ff <name>', '병합 커밋을 남기며 병합'], ['git rebase main', '현재 브랜치를 main 위로 재배치']]],
  ['원격', [['git remote -v', '원격 저장소 목록'], ['git fetch --prune', '원격 정보 갱신 + 삭제된 브랜치 정리'], ['git pull --rebase', '가져와서 내 커밋을 위로 재배치'], ['git push -u origin <branch>', '푸시하고 추적 설정'], ['git push --force-with-lease', '안전한 강제 푸시 (다른 사람 커밋 보호)']]],
  ['되돌리기', [['git revert <sha>', '커밋을 취소하는 새 커밋 (공유된 이력에 안전)'], ['git reset --soft HEAD~1', '마지막 커밋 취소, 변경은 스테이징 유지'], ['git reset --hard <sha>', '⚠ 해당 커밋으로 강제 이동 (변경 사항 삭제)'], ['git reflog', 'HEAD 이동 기록 (실수 복구용)'], ['git cherry-pick <sha>', '다른 브랜치의 커밋 가져오기']]],
  ['임시 저장', [['git stash push -m "메모"', '변경 사항 임시 저장'], ['git stash list', '임시 저장 목록'], ['git stash pop', '꺼내고 목록에서 삭제']]],
  ['태그 / 기타', [['git tag -a v1.0 -m "release"', '주석 태그 만들기'], ['git push --tags', '태그 푸시'], ['git blame -L 10,20 <file>', '줄별 마지막 수정자'], ['git bisect start', '이분 탐색으로 버그 커밋 찾기'], ['git clean -nd', '추적 안 되는 파일 미리보기 (-f로 삭제)']]],
];
function gitTool(root: HTMLElement) {
  const q = h('input', { class: 'input', style: { width: '100%' }, placeholder: '검색 (예: 되돌리기, stash, 브랜치)', 'aria-label': 'Git 명령 검색' });
  const list = h('div', { class: 'stack' });
  const update = () => {
    const t = q.value.trim().toLowerCase();
    list.replaceChildren(...GIT.map(([sec, items]) => {
      const rows = items.filter(([c, d]) => !t || c.toLowerCase().includes(t) || d.includes(t) || sec.includes(t));
      if (!rows.length) return '';
      return panel(sec, [], h('div', { class: 'result-list', style: { padding: '10px' } }, ...rows.map(([c, d]) => h('div', { class: 'result-row', style: { gridTemplateColumns: 'minmax(0,1.2fr) minmax(0,1fr) auto' } }, h('code', { class: 'value' }, c), h('span', { class: 'note' }, d), copyButton(() => c)))));
    }));
  };
  q.addEventListener('input', update);
  update();
  root.append(h('div', { class: 'stack' }, q, list));
}

export const devTools: Tool[] = [
  {
    id: 'toml',
    name: 'TOML ↔ JSON / YAML',
    category: 'convert',
    description: 'TOML을 JSON·YAML로, JSON·YAML을 TOML로 변환합니다. Cargo.toml, pyproject.toml 등에 유용합니다.',
    keywords: ['toml', 'cargo', 'pyproject', 'config'],
    render: (root) =>
      void transformer(root, {
        id: 'toml',
        swap: true,
        wrap: false,
        modes: [
          { id: 't2j', label: 'TOML → JSON', run: (s) => { const t = JSON.stringify(jsonSafe(readToml(s)), null, 2); return { text: t, html: highlightJson(t) }; } },
          { id: 'j2t', label: 'JSON → TOML', run: (s) => { const t = writeToml(parseJson(s)); return { text: t, html: tomlHl(t) }; } },
          { id: 't2y', label: 'TOML → YAML', run: (s) => { const t = YAML.stringify(jsonSafe(readToml(s)), { lineWidth: 0 }); return { text: t, html: highlightYaml(t) }; } },
          { id: 'y2t', label: 'YAML → TOML', run: (s) => { const t = writeToml(readYaml(s)); return { text: t, html: tomlHl(t) }; } },
        ],
        sample: (m) => m === 't2j' || m === 't2y'
          ? '# Cargo.toml\n[package]\nname = "devkit"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = { version = "1.0", features = ["derive"] }\ntokio = "1"\n\n[[bin]]\nname = "cli"\npath = "src/main.rs"\n'
          : m === 'j2t' ? '{"title":"DevKit","owner":{"name":"홍길동","since":2026},"database":{"ports":[8000,8001],"enabled":true}}' : 'title: DevKit\nserver:\n  host: 127.0.0.1\n  port: 8080\nfeatures: [json, toml]\n',
      }),
  },
  {
    id: 'xml-json',
    name: 'XML ↔ JSON',
    category: 'convert',
    description: 'XML을 JSON 객체로, JSON을 XML로 변환합니다. 속성은 @ 접두어, 텍스트는 #text로 표현합니다.',
    keywords: ['xml to json', 'json to xml', 'soap', 'rss'],
    render: (root) =>
      void transformer(root, {
        id: 'xml-json',
        swap: true,
        wrap: false,
        modes: [
          { id: 'x2j', label: 'XML → JSON', run: (s, o) => { const t = JSON.stringify(xmlToJson(s, String(o.prefix)), null, 2); return { text: t, html: highlightJson(t) }; } },
          { id: 'j2x', label: 'JSON → XML', run: (s, o) => { const t = jsonToXml(parseJson(s), '  ', String(o.prefix)); return { text: t, html: highlightXml(t) }; } },
        ],
        options: [{ id: 'prefix', label: '속성 접두어', type: 'select', default: '@', choices: [['@', '@'], ['_', '_'], ['$', '$']] }],
        sample: (m) => m === 'x2j' ? '<catalog><book id="bk101" lang="ko"><title>개발자 도구</title><price currency="KRW">25000</price></book><book id="bk102"><title>정규식</title></book></catalog>' : '{"catalog":{"book":[{"@id":"bk101","title":"개발자 도구","price":{"@currency":"KRW","#text":"25000"}},{"@id":"bk102","title":"정규식"}]}}',
      }),
  },
  { id: 'roman', name: '로마 숫자 변환', category: 'convert', description: '아라비아 숫자(1–3999)와 로마 숫자를 서로 변환합니다.', keywords: ['roman numeral', 'mmxxvi', '로마'], render: romanTool },
  {
    id: 'nato',
    name: 'NATO 음성 알파벳',
    category: 'encode',
    description: '영문·숫자를 Alfa, Bravo, Charlie… 같은 NATO 음성 알파벳으로 바꾸거나 되돌립니다. 전화로 코드를 불러줄 때 유용합니다.',
    keywords: ['nato', 'phonetic', 'alfa bravo', '음성 알파벳'],
    render: (root) =>
      void transformer(root, {
        id: 'nato',
        swap: true,
        modes: [
          { id: 'encode', label: '텍스트 → NATO', run: (s) => [...s.toUpperCase()].map((c) => (c === ' ' ? '/' : NATO[c] ?? c)).join(' ') },
          { id: 'decode', label: 'NATO → 텍스트', run: (s) => s.split(/\s+/).filter(Boolean).map((w) => (w === '/' ? ' ' : NATO_REV.get(w.toUpperCase().replace('-', '')) ?? w)).join('') },
        ],
        sample: (m) => (m === 'encode' ? 'AB12-XZ9' : 'Alfa Bravo One Two Dash X-ray Zulu Niner'),
      }),
  },
  { id: 'chmod', name: 'chmod 권한 계산기', category: 'dev', description: '리눅스 파일 권한을 체크박스로 고르고 755 같은 8진수와 rwxr-xr-x 기호 표기를 서로 변환합니다.', keywords: ['chmod', 'permission', 'linux', 'unix', 'rwx', '권한'], render: chmodTool },
  {
    id: 'docker-compose',
    name: 'docker run → compose',
    category: 'dev',
    description: 'docker run 명령어를 docker-compose.yml로 변환하고, 위험한 옵션(--privileged, docker.sock 등)을 경고합니다.',
    keywords: ['docker', 'compose', 'docker-compose', 'container', '도커'],
    render: (root) => {
      const notes = h('div', { class: 'stack', style: { gap: '6px', marginTop: '12px' } });
      transformer(root, {
        id: 'docker-compose',
        wrap: false,
        maxInput: 100_000,
        modes: [{
          id: 'convert',
          label: '변환',
          run: (s) => {
            const r = dockerToCompose(s);
            notes.replaceChildren(...r.notes.map((n) => h('div', { class: n.startsWith('⚠') ? 'error-box' : 'note', style: { margin: '0' } }, n)));
            return { text: r.yaml, html: highlightYaml(r.yaml) };
          },
        }],
        sample: 'docker run -d --name web \\\n  -p 8080:80 -p 127.0.0.1:8443:443 \\\n  -v ./html:/usr/share/nginx/html:ro -v nginx_logs:/var/log/nginx \\\n  -e TZ=Asia/Seoul -e "NGINX_HOST=example.com" \\\n  --restart unless-stopped --network app-net \\\n  nginx:1.27-alpine',
      });
      root.append(notes);
    },
  },
  { id: 'math', name: '수식 계산기', category: 'dev', description: '여러 줄의 수식을 계산합니다. 변수, 함수(sqrt, sin, log…), 거듭제곱, 팩토리얼을 지원합니다.', keywords: ['calculator', 'math', 'expression', '계산기', 'evaluate'], render: mathTool },
  { id: 'keycode', name: '키코드 정보', category: 'dev', description: '누른 키의 key, code, keyCode, 위치, 수식 키를 보여줍니다. 단축키 개발에 유용합니다.', keywords: ['keycode', 'keyboard', 'event.key', 'event.code', '키보드'], render: keycodeTool },
  { id: 'git', name: 'Git 치트시트', category: 'dev', description: '자주 쓰는 Git 명령어를 상황별로 정리했습니다. 검색하고 바로 복사할 수 있습니다.', keywords: ['git', 'cheatsheet', 'commands', '깃', '명령어'], render: gitTool },
];
