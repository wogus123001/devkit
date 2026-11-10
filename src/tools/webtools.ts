import type { Tool } from '../types';
import QRCode from 'qrcode';
import { bytesToBase64, bytesToDisplay, base64ToBytes, utf8 } from '../bytes';
import { parseJson } from '../json';
import { checkbox, copyButton, debounce, errorBox, field, h, panel, select, setHtml, escapeHtml, store, textarea, transformer } from '../ui';

const kvRow = (k: string, v: string) => h('tr', null, h('th', null, k), h('td', null, v ? copyButton(() => v) : null, v || h('span', { class: 'note' }, '-')));

// ---------- Basic auth ----------
function basicAuthTool(root: HTMLElement) {
  const user = h('input', { class: 'input mono grow', placeholder: 'username', 'aria-label': '사용자 이름', autocomplete: 'off' });
  const pass = h('input', { class: 'input mono grow', type: 'password', placeholder: 'password', 'aria-label': '비밀번호', autocomplete: 'off' });
  const header = h('input', { class: 'input mono', style: { width: '100%' }, placeholder: 'Authorization: Basic dXNlcjpwYXNz', 'aria-label': 'Authorization 헤더' });
  const out = h('table', { class: 'kv' });
  const err = errorBox();
  const encode = () => {
    err.show(null);
    if (user.value.includes(':')) return err.show('사용자 이름에는 콜론(:)을 쓸 수 없습니다 (RFC 7617)');
    const token = bytesToBase64(utf8(`${user.value}:${pass.value}`));
    header.value = `Authorization: Basic ${token}`;
    out.replaceChildren(kvRow('헤더', header.value), kvRow('토큰만', token), kvRow('curl', `curl -H "Authorization: Basic ${token}" https://example.com`));
  };
  const decode = () => {
    err.show(null);
    const m = header.value.trim().match(/^(?:authorization:\s*)?basic\s+([A-Za-z0-9+/=]+)$/i);
    if (!m) return err.show('"Authorization: Basic …" 형식이 아닙니다');
    try {
      const text = bytesToDisplay(base64ToBytes(m[1]));
      const i = text.indexOf(':');
      user.value = i < 0 ? text : text.slice(0, i);
      pass.value = i < 0 ? '' : text.slice(i + 1);
      out.replaceChildren(kvRow('사용자 이름', user.value), kvRow('비밀번호', '•'.repeat(Math.min(16, pass.value.length))));
    } catch (e) {
      err.show((e as Error).message);
    }
  };
  user.addEventListener('input', encode);
  pass.addEventListener('input', encode);
  header.addEventListener('input', decode);
  root.append(h('div', { class: 'stack', style: { maxWidth: '820px' } },
    h('div', { class: 'row' }, field('사용자 이름', user, 'grow'), field('비밀번호', pass, 'grow')),
    field('Authorization 헤더 (붙여넣으면 디코딩)', header),
    err, out,
    h('p', { class: 'note warn' }, '⚠ Basic 인증의 Base64는 암호화가 아닙니다. 누구나 디코딩할 수 있으므로 반드시 HTTPS에서만 사용하세요. 입력값은 저장되지 않습니다.')));
}

// ---------- User-Agent ----------
interface UA { browser: string; engine: string; os: string; device: string; bot: string }
function parseUA(ua: string): UA {
  const v = (re: RegExp) => ua.match(re)?.[1] ?? '';
  const bots: [RegExp, string][] = [[/Googlebot\/?([\d.]*)/, 'Googlebot'], [/bingbot\/?([\d.]*)/i, 'Bingbot'], [/Yeti\/?([\d.]*)/, 'Naver Yeti'], [/Daum(?:oa)?\/?([\d.]*)/, 'Daum'], [/GPTBot\/?([\d.]*)/, 'GPTBot'], [/ClaudeBot\/?([\d.]*)/, 'ClaudeBot'], [/facebookexternalhit\/?([\d.]*)/, 'Facebook'], [/Slackbot/, 'Slackbot'], [/Twitterbot/, 'Twitterbot'], [/curl\/([\d.]+)/, 'curl'], [/Wget\/([\d.]+)/, 'Wget'], [/python-requests\/([\d.]+)/, 'python-requests'], [/HeadlessChrome\/([\d.]+)/, 'Headless Chrome'], [/PostmanRuntime\/([\d.]+)/, 'Postman'], [/okhttp\/([\d.]+)/, 'OkHttp'], [/Go-http-client\/([\d.]+)/, 'Go http'], [/bot|crawler|spider|crawling/i, '기타 봇']];
  let bot = '';
  for (const [re, name] of bots) { const m = ua.match(re); if (m) { bot = `${name} ${m[1] ?? ''}`.trim(); break; } }
  const browsers: [RegExp, string][] = [
    [/KAKAOTALK\s([\d.]+)/i, 'KakaoTalk 인앱'], [/NAVER\(inapp[^)]*\)|NAVER\/([\d.]+)/, '네이버 앱'], [/Whale\/([\d.]+)/, 'Naver Whale'], [/SamsungBrowser\/([\d.]+)/, 'Samsung Internet'],
    [/Edg(?:e|A|iOS)?\/([\d.]+)/, 'Microsoft Edge'], [/OPR\/([\d.]+)|Opera\/([\d.]+)/, 'Opera'], [/YaBrowser\/([\d.]+)/, 'Yandex'], [/Vivaldi\/([\d.]+)/, 'Vivaldi'],
    [/Firefox\/([\d.]+)|FxiOS\/([\d.]+)/, 'Firefox'], [/CriOS\/([\d.]+)/, 'Chrome (iOS)'], [/Chrome\/([\d.]+)/, 'Chrome'], [/Version\/([\d.]+).*Safari/, 'Safari'], [/MSIE ([\d.]+)|Trident\/.*rv:([\d.]+)/, 'Internet Explorer'],
  ];
  let browser = '';
  for (const [re, name] of browsers) { const m = ua.match(re); if (m) { browser = `${name} ${m.slice(1).find(Boolean) ?? ''}`.trim(); break; } }
  const engine = /Gecko\/\d+.*Firefox/.test(ua) ? 'Gecko' : /Trident|MSIE/.test(ua) ? 'Trident' : /Edge\/\d/.test(ua) ? 'EdgeHTML' : /(?:iPhone|iPad|iPod).*AppleWebKit/.test(ua) ? 'WebKit (iOS)' : /Chrome|Chromium|CriOS/.test(ua) ? 'Blink' : /AppleWebKit/.test(ua) ? 'WebKit' : '';
  const WIN: Record<string, string> = { '10.0': '10 / 11', '6.3': '8.1', '6.2': '8', '6.1': '7', '6.0': 'Vista', '5.1': 'XP' };
  let os = '';
  if (/Windows NT ([\d.]+)/.test(ua)) os = `Windows ${WIN[v(/Windows NT ([\d.]+)/)] ?? v(/Windows NT ([\d.]+)/)}`;
  else if (/(?:iPhone|iPad|iPod).*OS ([\d_]+)/.test(ua)) os = `iOS ${v(/OS ([\d_]+)/).replace(/_/g, '.')}`;
  else if (/Android ([\d.]+)/.test(ua)) os = `Android ${v(/Android ([\d.]+)/)}`;
  else if (/Mac OS X ([\d_.]+)/.test(ua)) os = `macOS ${v(/Mac OS X ([\d_.]+)/).replace(/_/g, '.')}`;
  else if (/CrOS/.test(ua)) os = 'ChromeOS';
  else if (/Linux/.test(ua)) os = 'Linux';
  const device = bot ? '봇/도구' : /iPad|Tablet|SM-T|Tab(?!le)/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua)) ? '태블릿' : /Mobi|iPhone|iPod|Android/.test(ua) ? '모바일' : /SmartTV|Tizen|Web0S/.test(ua) ? 'TV' : '데스크톱';
  return { browser, engine, os, device, bot };
}

// ---------- MIME ----------
const MIME: [string, string, string][] = [
  ['html htm', 'text/html', '웹 페이지'], ['css', 'text/css', '스타일시트'], ['js mjs', 'text/javascript', 'JavaScript'], ['json', 'application/json', 'JSON'], ['jsonld', 'application/ld+json', 'JSON-LD'],
  ['xml', 'application/xml', 'XML'], ['txt', 'text/plain', '텍스트'], ['csv', 'text/csv', 'CSV'], ['md', 'text/markdown', '마크다운'], ['yaml yml', 'application/yaml', 'YAML'],
  ['toml', 'application/toml', 'TOML'], ['png', 'image/png', 'PNG 이미지'], ['jpg jpeg', 'image/jpeg', 'JPEG 이미지'], ['gif', 'image/gif', 'GIF'], ['webp', 'image/webp', 'WebP'], ['avif', 'image/avif', 'AVIF'],
  ['svg', 'image/svg+xml', 'SVG (스크립트 포함 가능)'], ['ico', 'image/vnd.microsoft.icon', '아이콘'], ['bmp', 'image/bmp', 'BMP'], ['tif tiff', 'image/tiff', 'TIFF'], ['heic', 'image/heic', 'HEIC'],
  ['mp3', 'audio/mpeg', 'MP3'], ['wav', 'audio/wav', 'WAV'], ['ogg oga', 'audio/ogg', 'Ogg 오디오'], ['m4a', 'audio/mp4', 'M4A'], ['flac', 'audio/flac', 'FLAC'], ['aac', 'audio/aac', 'AAC'],
  ['mp4', 'video/mp4', 'MP4'], ['webm', 'video/webm', 'WebM'], ['mov', 'video/quicktime', 'QuickTime'], ['avi', 'video/x-msvideo', 'AVI'], ['mkv', 'video/x-matroska', 'Matroska'], ['m3u8', 'application/vnd.apple.mpegurl', 'HLS 재생목록'],
  ['woff', 'font/woff', 'WOFF'], ['woff2', 'font/woff2', 'WOFF2'], ['ttf', 'font/ttf', 'TrueType'], ['otf', 'font/otf', 'OpenType'],
  ['pdf', 'application/pdf', 'PDF'], ['zip', 'application/zip', 'ZIP'], ['gz', 'application/gzip', 'Gzip'], ['tar', 'application/x-tar', 'Tar'], ['7z', 'application/x-7z-compressed', '7-Zip'], ['rar', 'application/vnd.rar', 'RAR'],
  ['doc', 'application/msword', 'Word 97-2003'], ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'Word'], ['xls', 'application/vnd.ms-excel', 'Excel 97-2003'],
  ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Excel'], ['ppt', 'application/vnd.ms-powerpoint', 'PowerPoint 97-2003'], ['pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'PowerPoint'],
  ['hwp', 'application/x-hwp', '한글'], ['hwpx', 'application/hwp+zip', '한글 (HWPX)'], ['epub', 'application/epub+zip', 'EPUB'], ['rtf', 'application/rtf', 'RTF'],
  ['wasm', 'application/wasm', 'WebAssembly'], ['bin', 'application/octet-stream', '임의의 바이너리'], ['exe', 'application/vnd.microsoft.portable-executable', '실행 파일'], ['apk', 'application/vnd.android.package-archive', 'Android 앱'],
  ['webmanifest', 'application/manifest+json', '웹 앱 매니페스트'], ['ics', 'text/calendar', '캘린더'], ['vcf', 'text/vcard', '연락처'], ['proto', 'text/plain', 'Protobuf 스키마'], ['pb', 'application/x-protobuf', 'Protobuf 바이너리'],
  ['', 'multipart/form-data', '폼 업로드'], ['', 'application/x-www-form-urlencoded', '폼 전송'], ['', 'text/event-stream', 'Server-Sent Events'], ['', 'application/graphql-response+json', 'GraphQL 응답'],
];
function mimeTool(root: HTMLElement) {
  const q = h('input', { class: 'input', style: { width: '100%' }, placeholder: '확장자나 MIME 검색 (예: .png, application/json, 엑셀)', 'aria-label': 'MIME 검색' });
  const list = h('div', { class: 'result-list' });
  const update = () => {
    const t = q.value.trim().toLowerCase().replace(/^\./, '');
    const rows = MIME.filter(([e, m, d]) => !t || e.split(' ').some((x) => x.startsWith(t)) || m.includes(t) || d.toLowerCase().includes(t)).slice(0, 80);
    list.replaceChildren(...rows.map(([e, m, d]) => h('div', { class: 'result-row', style: { gridTemplateColumns: '110px minmax(0,1fr) auto' } }, h('span', { class: 'label' }, e ? e.split(' ').map((x) => '.' + x).join(' ') : '—'), h('div', null, h('div', { class: 'value' }, m), h('div', { class: 'note' }, d)), copyButton(() => m))));
    if (!rows.length) list.append(h('div', { class: 'note' }, '결과가 없습니다'));
  };
  q.addEventListener('input', update);
  update();
  root.append(h('div', { class: 'stack', style: { maxWidth: '860px' } }, q, list));
}

// ---------- Device info ----------
function deviceTool(root: HTMLElement): () => void {
  const table = h('table', { class: 'kv' });
  const nav = navigator as Navigator & { deviceMemory?: number; userAgentData?: { platform?: string; mobile?: boolean; brands?: { brand: string; version: string }[] } };
  const update = () => {
    const mq = (q: string) => matchMedia(q).matches;
    const ua = parseUA(navigator.userAgent);
    const rows: [string, string][] = [
      ['브라우저', ua.browser], ['운영체제', nav.userAgentData?.platform || ua.os], ['기기 유형', ua.device],
      ['화면 해상도', `${screen.width} × ${screen.height}`], ['사용 가능 영역', `${screen.availWidth} × ${screen.availHeight}`], ['브라우저 창 (viewport)', `${innerWidth} × ${innerHeight}`],
      ['픽셀 비율 (DPR)', String(devicePixelRatio)], ['색 깊이', `${screen.colorDepth}비트`], ['화면 방향', screen.orientation?.type ?? '-'],
      ['언어', navigator.languages?.join(', ') ?? navigator.language], ['시간대', Intl.DateTimeFormat().resolvedOptions().timeZone], ['CPU 코어 (논리)', String(navigator.hardwareConcurrency ?? '-')],
      ['메모리 (대략)', nav.deviceMemory ? `${nav.deviceMemory}GB 이상` : '-'], ['터치 포인트', String(navigator.maxTouchPoints)], ['온라인', navigator.onLine ? '예' : '아니요'],
      ['쿠키 허용', navigator.cookieEnabled ? '예' : '아니요'], ['다크 모드 선호', mq('(prefers-color-scheme: dark)') ? '예' : '아니요'], ['동작 줄이기 선호', mq('(prefers-reduced-motion: reduce)') ? '예' : '아니요'],
      ['포인터', mq('(pointer: coarse)') ? '손가락 (coarse)' : mq('(pointer: fine)') ? '마우스 (fine)' : '-'], ['User-Agent', navigator.userAgent],
    ];
    table.replaceChildren(...rows.map(([k, v]) => kvRow(k, v)));
  };
  update();
  addEventListener('resize', update);
  root.append(h('div', { class: 'stack', style: { maxWidth: '860px' } }, table, h('p', { class: 'note' }, '이 정보는 브라우저가 페이지에 제공하는 값이며, 어디에도 전송되지 않습니다. 창 크기를 바꾸면 실시간으로 갱신됩니다.')));
  return () => removeEventListener('resize', update);
}

// ---------- IPv4 subnet ----------
const ipToInt = (s: string): number => {
  const p = s.trim().split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255 || (x.length > 1 && x[0] === '0'))) throw new Error(`올바른 IPv4 주소가 아닙니다: ${s}`);
  return p.reduce((a, x) => a * 256 + Number(x), 0);
};
const intToIp = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
const maskOf = (bits: number) => (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
function classify(n: number): string {
  const inR = (a: string, b: number) => (n & maskOf(b)) >>> 0 === ipToInt(a);
  if (inR('10.0.0.0', 8) || inR('172.16.0.0', 12) || inR('192.168.0.0', 16)) return '사설 (RFC 1918)';
  if (inR('127.0.0.0', 8)) return '루프백';
  if (inR('169.254.0.0', 16)) return '링크 로컬';
  if (inR('100.64.0.0', 10)) return 'CGNAT (RFC 6598)';
  if (inR('224.0.0.0', 4)) return '멀티캐스트';
  if (inR('192.0.2.0', 24) || inR('198.51.100.0', 24) || inR('203.0.113.0', 24)) return '문서용 예제 (TEST-NET)';
  if (inR('0.0.0.0', 8) || inR('240.0.0.0', 4)) return '예약됨';
  return '공인';
}
/** Smallest list of CIDR blocks covering start..end (inclusive). */
function rangeToCidrs(start: number, end: number): string[] {
  const out: string[] = [];
  let cur = start;
  while (cur <= end && out.length < 64) {
    let size = 32;
    while (size > 0) {
      const m = maskOf(size - 1);
      if ((cur & m) >>> 0 !== cur || cur + 2 ** (32 - size + 1) - 1 > end) break;
      size--;
    }
    out.push(`${intToIp(cur)}/${size}`);
    cur += 2 ** (32 - size);
  }
  return out;
}
function subnetTool(root: HTMLElement) {
  const input = h('input', { class: 'input mono', style: { width: '100%', fontSize: '16px' }, value: store.get('tool:subnet', '192.168.10.37/26'), 'aria-label': 'CIDR 또는 범위' });
  const table = h('table', { class: 'kv' });
  const err = errorBox();
  const update = () => {
    store.set('tool:subnet', input.value);
    err.show(null);
    table.replaceChildren();
    const v = input.value.trim();
    if (!v) return;
    try {
      const range = v.match(/^([\d.]+)\s*[-~]\s*([\d.]+)$/);
      if (range) {
        const a = ipToInt(range[1]), b = ipToInt(range[2]);
        if (a > b) throw new Error('시작 주소가 끝 주소보다 큽니다');
        const cidrs = rangeToCidrs(a, b);
        table.append(kvRow('주소 개수', (b - a + 1).toLocaleString()), kvRow('CIDR 블록', cidrs.join(', ')));
        return;
      }
      const m = v.match(/^([\d.]+)(?:\s*\/\s*(\d{1,2})|\s+([\d.]+))?$/);
      if (!m) throw new Error('"192.168.0.1/24", "192.168.0.1 255.255.255.0", 또는 "10.0.0.1 - 10.0.0.50" 형식으로 입력하세요');
      const ip = ipToInt(m[1]);
      let bits = m[2] !== undefined ? Number(m[2]) : 32;
      if (m[3]) {
        const mk = ipToInt(m[3]);
        bits = (mk >>> 0).toString(2).replace(/0+$/, '').length;
        if (maskOf(bits) !== mk) throw new Error('서브넷 마스크가 연속된 1비트가 아닙니다');
      }
      if (bits > 32) throw new Error('프리픽스 길이는 0~32입니다');
      const mask = maskOf(bits);
      const net = (ip & mask) >>> 0;
      const bc = (net | (~mask >>> 0)) >>> 0;
      const total = 2 ** (32 - bits);
      const hosts = bits >= 31 ? total : total - 2;
      const first = bits >= 31 ? net : net + 1, last = bits >= 31 ? bc : bc - 1;
      const bin = (n: number) => (n >>> 0).toString(2).padStart(32, '0').replace(/(.{8})(?!$)/g, '$1.');
      table.append(
        kvRow('CIDR', `${intToIp(net)}/${bits}`), kvRow('네트워크 주소', intToIp(net)), kvRow('브로드캐스트', bits >= 31 ? '없음 (/31·/32)' : intToIp(bc)),
        kvRow('사용 가능 호스트 범위', `${intToIp(first)} – ${intToIp(last)}`), kvRow('사용 가능 호스트 수', hosts.toLocaleString()), kvRow('전체 주소 수', total.toLocaleString()),
        kvRow('서브넷 마스크', intToIp(mask)), kvRow('와일드카드 마스크', intToIp(~mask >>> 0)), kvRow('주소 유형', classify(ip)),
        kvRow('IP (10진 정수)', String(ip)), kvRow('IP (16진)', '0x' + ip.toString(16).padStart(8, '0')), kvRow('IP (2진)', bin(ip)), kvRow('마스크 (2진)', bin(mask)),
        kvRow('IPv4-mapped IPv6', `::ffff:${intToIp(ip)}`),
      );
    } catch (e) {
      err.show((e as Error).message);
    }
  };
  input.addEventListener('input', update);
  update();
  root.append(h('div', { class: 'stack', style: { maxWidth: '860px' } }, input,
    h('div', { class: 'chips' }, ...['10.0.0.0/8', '172.16.5.4/20', '192.168.1.130 255.255.255.192', '203.0.113.7/32', '10.0.0.0 - 10.0.3.255'].map((x) => h('button', { class: 'chip', type: 'button', onclick: () => ((input.value = x), update()) }, x))),
    err, table));
}

// ---------- JSON diff ----------
type Change = { path: string; kind: 'add' | 'del' | 'mod' | 'type'; a?: unknown; b?: unknown };
function jsonDiff(a: unknown, b: unknown, path: string, out: Change[], depth = 0): void {
  if (out.length > 5000) return;
  if (depth > 500) throw new Error('중첩이 너무 깊습니다');
  const ta = Array.isArray(a) ? 'array' : a === null ? 'null' : typeof a;
  const tb = Array.isArray(b) ? 'array' : b === null ? 'null' : typeof b;
  if (ta !== tb) return void out.push({ path, kind: 'type', a, b });
  if (ta === 'array') {
    const x = a as unknown[], y = b as unknown[];
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const p = `${path}[${i}]`;
      if (i >= x.length) out.push({ path: p, kind: 'add', b: y[i] });
      else if (i >= y.length) out.push({ path: p, kind: 'del', a: x[i] });
      else jsonDiff(x[i], y[i], p, out, depth + 1);
    }
  } else if (ta === 'object') {
    const x = a as Record<string, unknown>, y = b as Record<string, unknown>;
    const keys = new Set([...Object.keys(x), ...Object.keys(y)]);
    for (const k of keys) {
      const p = /^[A-Za-z_$][\w$]*$/.test(k) ? `${path}.${k}` : `${path}[${JSON.stringify(k)}]`;
      const inA = Object.prototype.hasOwnProperty.call(x, k), inB = Object.prototype.hasOwnProperty.call(y, k);
      if (!inA) out.push({ path: p, kind: 'add', b: y[k] });
      else if (!inB) out.push({ path: p, kind: 'del', a: x[k] });
      else jsonDiff(x[k], y[k], p, out, depth + 1);
    }
  } else if (!Object.is(a, b)) out.push({ path, kind: 'mod', a, b });
}
function jsonDiffTool(root: HTMLElement) {
  const a = textarea({ class: 'code short', value: '{"name":"DevKit","version":"1.0.0","tools":["json","regex"],"config":{"theme":"light","limit":100}}', 'aria-label': '원본 JSON' });
  const b = textarea({ class: 'code short', value: '{"name":"DevKit","version":"1.1.0","tools":["json","regex","protobuf"],"config":{"theme":"dark"},"license":"MIT"}', 'aria-label': '비교 JSON' });
  const out = h('div', { class: 'diff' });
  const stats = h('div', { class: 'diff-stats' });
  const err = errorBox();
  const fmt = (v: unknown) => { const s = JSON.stringify(v); return s.length > 200 ? s.slice(0, 200) + '…' : s; };
  const update = () => {
    err.show(null);
    try {
      const changes: Change[] = [];
      jsonDiff(parseJson(a.value), parseJson(b.value), '$', changes);
      const icon = { add: '+', del: '−', mod: '~', type: '~' };
      const cls = { add: 'add', del: 'del', mod: '', type: '' };
      setHtml(out, changes.map((c) => `<div class="line ${cls[c.kind]}"><span>${icon[c.kind]} <span class="tok-key">${escapeHtml(c.path)}</span>${c.kind === 'add' ? ': ' + escapeHtml(fmt(c.b)) : c.kind === 'del' ? ': ' + escapeHtml(fmt(c.a)) : `: <del>${escapeHtml(fmt(c.a))}</del> → <ins>${escapeHtml(fmt(c.b))}</ins>${c.kind === 'type' ? ' <span class="tok-comment">(타입 변경)</span>' : ''}`}</span></div>`).join('') || '<div class="line"><span>두 JSON이 동일합니다 (키 순서 무시)</span></div>');
      const n = (k: Change['kind']) => changes.filter((c) => c.kind === k).length;
      stats.replaceChildren(h('span', { class: 'plus' }, `+${n('add')} 추가`), h('span', { class: 'minus' }, `−${n('del')} 삭제`), h('span', null, `~${n('mod') + n('type')} 변경`));
    } catch (e) {
      err.show((e as Error).message);
      out.replaceChildren();
      stats.replaceChildren();
    }
  };
  const run = debounce(update, 200);
  a.addEventListener('input', run);
  b.addEventListener('input', run);
  update();
  root.append(h('div', { class: 'stack' }, h('div', { class: 'io-grid' }, panel('원본 (A)', [], a), panel('비교 (B)', [], b)), err, panel('차이 (JSONPath)', [stats], out)));
}

// ---------- Slugify ----------
function slugify(s: string, sep: string, lower: boolean, keepHangul: boolean): string {
  let t = s.normalize('NFKD').replace(/[̀-ͯ]/g, '').normalize('NFC');
  t = t.replace(/[&]/g, ' and ').replace(/[@]/g, ' at ');
  const allowed = keepHangul ? /[^A-Za-z0-9가-힣]+/g : /[^A-Za-z0-9]+/g;
  t = t.replace(allowed, sep).replace(new RegExp(`\\${sep}{2,}`, 'g'), sep).replace(new RegExp(`^\\${sep}|\\${sep}$`, 'g'), '');
  return lower ? t.toLowerCase() : t;
}

// ---------- WiFi QR ----------
function wifiTool(root: HTMLElement) {
  const ssid = h('input', { class: 'input grow', value: 'MyHomeWiFi', 'aria-label': 'SSID' });
  const pass = h('input', { class: 'input mono grow', type: 'password', 'aria-label': 'Wi-Fi 비밀번호', autocomplete: 'off' });
  const enc = select([['WPA', 'WPA/WPA2/WPA3'], ['WEP', 'WEP (취약)'], ['nopass', '암호 없음']], 'WPA', () => render());
  let hidden = false;
  const canvas = h('canvas');
  const err = errorBox();
  const note = h('div', { class: 'note' });
  // Escape \ ; , : " per the de-facto WIFI: URI format.
  const esc = (s: string) => s.replace(/([\\;,:"])/g, '\\$1');
  const render = async () => {
    err.show(null);
    if (!ssid.value) return err.show('SSID를 입력하세요');
    if (enc.value !== 'nopass' && !pass.value) return err.show('비밀번호를 입력하세요');
    if (enc.value === 'WPA' && pass.value && (pass.value.length < 8 || pass.value.length > 63)) err.show('WPA 비밀번호는 8~63자입니다');
    const payload = `WIFI:T:${enc.value};S:${esc(ssid.value)};${enc.value !== 'nopass' ? `P:${esc(pass.value)};` : ''}${hidden ? 'H:true;' : ''};`;
    await QRCode.toCanvas(canvas, payload, { width: 280, margin: 2, errorCorrectionLevel: 'M' });
    note.textContent = enc.value === 'WEP' ? '⚠ WEP는 몇 분 안에 해독될 수 있습니다. WPA2 이상을 사용하세요.' : '휴대폰 카메라로 스캔하면 바로 연결됩니다. QR에는 비밀번호가 그대로 들어 있으니 공개된 곳에 붙이지 마세요.';
  };
  const run = debounce(render, 150);
  ssid.addEventListener('input', run);
  pass.addEventListener('input', run);
  root.append(h('div', { class: 'io-grid' },
    h('div', { class: 'stack' }, field('네트워크 이름 (SSID)', ssid), field('비밀번호', pass), h('div', { class: 'toolbar' }, field('보안', enc, 'inline'), checkbox('숨겨진 네트워크', hidden, (v) => ((hidden = v), render()))), err, note),
    panel('Wi-Fi QR', [h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => { const a = h('a', { href: canvas.toDataURL('image/png'), download: 'wifi-qr.png' }); a.click(); } }, 'PNG 저장')], h('div', { class: 'qr-out' }, canvas))));
  render();
}

export const webTools2: Tool[] = [
  { id: 'basic-auth', name: 'Basic Auth 생성기', category: 'web', description: '사용자 이름과 비밀번호로 HTTP Basic 인증 헤더를 만들거나, 헤더를 디코딩합니다.', keywords: ['basic auth', 'authorization', 'http header', '인증 헤더'], render: basicAuthTool },
  {
    id: 'user-agent',
    name: 'User-Agent 파서',
    category: 'web',
    description: 'User-Agent 문자열에서 브라우저, 엔진, OS, 기기 종류, 봇 여부를 분석합니다. 카카오톡·네이버 인앱 브라우저도 인식합니다.',
    keywords: ['user agent', 'ua', 'browser detect', '브라우저', 'bot'],
    render: (root) => {
      const input = textarea({ class: 'code short', value: navigator.userAgent, 'aria-label': 'User-Agent' });
      const table = h('table', { class: 'kv' });
      const update = () => {
        const r = parseUA(input.value.slice(0, 4000));
        table.replaceChildren(kvRow('브라우저', r.browser), kvRow('렌더링 엔진', r.engine), kvRow('운영체제', r.os), kvRow('기기 유형', r.device), kvRow('봇 / 도구', r.bot));
      };
      input.addEventListener('input', update);
      update();
      root.append(h('div', { class: 'stack', style: { maxWidth: '860px' } }, panel('User-Agent (기본값: 현재 브라우저)', [h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => ((input.value = navigator.userAgent), update()) }, '내 브라우저')], input), table,
        h('p', { class: 'note' }, 'User-Agent는 누구나 바꿀 수 있으므로 보안 판단(차단·권한)에 사용하면 안 됩니다.')));
    },
  },
  { id: 'mime', name: 'MIME 타입 조회', category: 'web', description: '파일 확장자와 MIME 타입(Content-Type)을 서로 찾아봅니다.', keywords: ['mime', 'content-type', 'media type', '확장자'], render: mimeTool },
  { id: 'device', name: '기기 정보', category: 'web', description: '현재 기기의 화면 크기, 픽셀 비율, 브라우저, 언어, 시간대 등 정보를 보여줍니다.', keywords: ['device', 'screen', 'viewport', 'dpr', '해상도', '기기'], render: deviceTool },
  { id: 'subnet', name: 'IPv4 서브넷 계산기', category: 'web', description: 'CIDR로 네트워크·브로드캐스트 주소, 호스트 범위, 마스크를 계산하고 IP 범위를 CIDR로 바꿉니다.', keywords: ['subnet', 'cidr', 'ipv4', 'netmask', '서브넷', 'ip'], render: subnetTool },
  { id: 'json-diff', name: 'JSON 비교', category: 'format', description: '두 JSON의 구조를 비교해 추가·삭제·변경된 값을 JSONPath와 함께 보여줍니다. 키 순서는 무시합니다.', keywords: ['json diff', 'compare', '비교'], render: jsonDiffTool },
  {
    id: 'slugify',
    name: 'Slug 변환',
    category: 'text',
    description: '제목을 URL·파일명에 쓸 수 있는 slug(my-blog-post)로 바꿉니다. 한글 유지 옵션을 지원합니다.',
    keywords: ['slug', 'url friendly', 'permalink', '퍼머링크'],
    render: (root) =>
      void transformer(root, {
        id: 'slugify',
        modes: [{ id: 'run', label: '변환', run: (s, o) => s.split('\n').map((l) => slugify(l, String(o.sep), Boolean(o.lower), Boolean(o.hangul))).join('\n') }],
        options: [
          { id: 'sep', label: '구분자', type: 'select', default: '-', choices: [['-', '하이픈 -'], ['_', '밑줄 _'], ['.', '점 .']] },
          { id: 'lower', label: '소문자로', type: 'checkbox', default: true },
          { id: 'hangul', label: '한글 유지', type: 'checkbox', default: true },
        ],
        sample: 'Hello, World! 개발자 도구 모음 2026\nCafé & Crème Brûlée @ Seoul',
      }),
  },
  { id: 'wifi-qr', name: 'Wi-Fi QR 생성기', category: 'generate', description: 'Wi-Fi 이름과 비밀번호로 스캔하면 바로 연결되는 QR 코드를 만듭니다.', keywords: ['wifi', 'qr', 'wireless', '와이파이'], render: wifiTool },
];
