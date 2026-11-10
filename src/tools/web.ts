import type { Tool } from '../types';
import { button, copyButton, h, panel, store } from '../ui';
import { findSuspicious } from '../security';

/** decodeURIComponent that never throws on malformed % sequences. */
function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Heuristic checks for URLs commonly used in phishing, open-redirect and SSRF attacks. */
function auditUrl(raw: string, url: URL): { level: 'danger' | 'warn' | 'info'; text: string }[] {
  const out: { level: 'danger' | 'warn' | 'info'; text: string }[] = [];
  const scheme = url.protocol.toLowerCase();
  if (['javascript:', 'vbscript:', 'data:'].includes(scheme)) out.push({ level: 'danger', text: `${scheme} URL은 클릭 시 코드를 실행하거나 위조 페이지를 띄울 수 있습니다.` });
  else if (scheme === 'file:') out.push({ level: 'warn', text: 'file: URL은 로컬 파일에 접근합니다.' });
  else if (scheme === 'http:') out.push({ level: 'info', text: '암호화되지 않은 http 연결입니다.' });

  if (url.username || url.password) {
    out.push({ level: 'danger', text: `"@" 앞부분(${safeDecode(url.username)}${url.password ? ':…' : ''})은 사용자 정보일 뿐이며, 실제 접속하는 호스트는 "${url.hostname}"입니다. 피싱에 자주 쓰이는 형태입니다.` });
  }
  const typedHost = raw.replace(/^[a-z][\w+.-]*:\/\/(?:[^@/?#]*@)?/i, '').split(/[/:?#]/)[0].toLowerCase();
  if (url.hostname.includes('xn--') || /[^\x00-\x7f]/.test(typedHost)) {
    out.push({ level: 'danger', text: `국제화 도메인(IDN)입니다. 실제 도메인은 "${url.hostname}"입니다. 라틴 문자와 비슷하게 생긴 키릴/그리스 문자로 다른 사이트를 흉내 내는 호모그래프 공격일 수 있습니다.` });
  }
  if (typedHost && typedHost !== url.hostname && /^[\d.x]+$|^0x/i.test(typedHost))
    out.push({ level: 'warn', text: `호스트 "${typedHost}"가 "${url.hostname}"로 해석됩니다 (16진수/8진수/정수 표기로 IP를 숨기는 기법).` });
  if (/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0$|localhost$|\[::1?\]$|\[f[cd])/i.test(url.hostname))
    out.push({ level: 'warn', text: '내부망/루프백 주소입니다. 서버가 이 URL을 대신 요청하면 SSRF가 될 수 있습니다.' });
  for (const [k, v] of url.searchParams) {
    if (/^(redirect|redirect_uri|redirect_url|url|next|return|returnurl|return_to|continue|dest|destination|goto|target|callback|r|u)$/i.test(k) && /^(https?:)?\/\/|^[a-z]+:/i.test(v.trim()))
      out.push({ level: 'warn', text: `파라미터 "${k}"에 외부 URL(${v.slice(0, 80)})이 들어 있습니다. 오픈 리다이렉트에 악용될 수 있습니다.` });
    if (/<script|javascript:|on\w+\s*=|<svg|<img/i.test(v))
      out.push({ level: 'danger', text: `파라미터 "${k}" 값에 스크립트/HTML 주입 시도로 보이는 문자열이 있습니다.` });
    if (/('|%27)\s*(or|and|union|--|;)|union\s+select|sleep\(|benchmark\(/i.test(v))
      out.push({ level: 'danger', text: `파라미터 "${k}" 값에 SQL 인젝션 시도로 보이는 문자열이 있습니다.` });
    if (/\.\.[/\\]/.test(v)) out.push({ level: 'warn', text: `파라미터 "${k}" 값에 경로 탐색(../) 패턴이 있습니다.` });
  }
  if (/%25[0-9a-f]{2}/i.test(raw)) out.push({ level: 'warn', text: '이중 인코딩(%25XX)이 있습니다. 필터 우회에 쓰이는 경우가 있습니다.' });
  const odd = findSuspicious(raw);
  if (odd.length) out.push({ level: 'danger', text: '보이지 않는 문자가 있습니다: ' + odd.map((f) => `${f.label} ${f.count}개`).join(', ') });
  if (raw.length > 2048) out.push({ level: 'info', text: `URL이 ${raw.length.toLocaleString()}자로 매우 깁니다 (일부 서버/브라우저 제한 2048자 초과).` });
  return out;
}

// ---------- URL parser / builder ----------
function urlTool(root: HTMLElement) {
  const audit = h('div', { class: 'stack', style: { gap: '6px' } });
  const input = h('input', { class: 'input mono', style: { width: '100%' }, value: store.get('tool:urlparse', 'https://user:pass@devkit.example.com:8080/tools/json?tab=format&lang=ko&tag=a&tag=b#section-2'), 'aria-label': 'URL' });
  const parts = h('table', { class: 'kv' });
  const paramsBody = h('tbody');
  const err = h('div', { class: 'error-box', hidden: true });
  let url: URL | null = null;

  const row = (k: string, v: string) => h('tr', null, h('th', null, k), h('td', null, v ? copyButton(() => v) : null, v || h('span', { class: 'note' }, '(없음)')));
  function parse() {
    store.set('tool:urlparse', input.value);
    try {
      url = new URL(input.value.trim());
    } catch {
      url = null;
      err.hidden = !input.value.trim();
      err.textContent = '올바른 절대 URL이 아닙니다 (예: https://example.com/path)';
      parts.replaceChildren();
      paramsBody.replaceChildren();
      audit.replaceChildren();
      return;
    }
    err.hidden = true;
    const findings = auditUrl(input.value.trim(), url);
    audit.replaceChildren(
      ...(findings.length
        ? findings.map((f) => h('div', { class: f.level === 'danger' ? 'error-box' : f.level === 'warn' ? 'warn-box' : 'note', style: { margin: '0' } }, (f.level === 'info' ? 'ℹ ' : '⚠ ') + f.text))
        : [h('div', { class: 'note', style: { color: 'var(--ok)' } }, '✓ 알려진 위험 패턴이 발견되지 않았습니다.')]),
    );
    parts.replaceChildren(
      row('프로토콜', url.protocol),
      row('사용자 이름', safeDecode(url.username)),
      row('비밀번호', url.password ? '•'.repeat(Math.min(12, safeDecode(url.password).length)) : ''),
      row('호스트', url.hostname),
      row('포트', url.port || (url.protocol === 'https:' ? '443 (기본)' : url.protocol === 'http:' ? '80 (기본)' : '')),
      row('경로', safeDecode(url.pathname)),
      row('쿼리 문자열', url.search),
      row('해시', safeDecode(url.hash)),
      row('Origin', url.origin),
    );
    renderParams();
  }
  function renderParams() {
    if (!url) return;
    const entries = [...url.searchParams.entries()];
    paramsBody.replaceChildren(
      ...entries.map(([k, v], i) => {
        const kIn = h('input', { class: 'input mono', value: k, style: { width: '100%' }, 'aria-label': '키' });
        const vIn = h('input', { class: 'input mono', value: v, style: { width: '100%' }, 'aria-label': '값' });
        const commit = () => {
          entries[i] = [kIn.value, vIn.value];
          rebuild(entries);
        };
        kIn.addEventListener('change', commit);
        vIn.addEventListener('change', commit);
        return h('tr', null, h('td', null, kIn), h('td', null, vIn), h('td', { style: { width: '1%' } }, button('삭제', () => (entries.splice(i, 1), rebuild(entries)))));
      }),
    );
    if (!entries.length) paramsBody.append(h('tr', null, h('td', { class: 'note', colspan: '3' }, '쿼리 파라미터가 없습니다')));
  }
  function rebuild(entries: [string, string][]) {
    if (!url) return;
    url.search = new URLSearchParams(entries).toString();
    input.value = url.toString();
    parse();
  }
  input.addEventListener('input', parse);
  root.append(
    h('div', { class: 'stack' },
      input, err,
      panel('보안 점검', [], h('div', { class: 'panel-body' }, audit)),
      h('div', { class: 'io-grid' },
        panel('구성 요소', [], parts),
        panel('쿼리 파라미터 (편집 가능)', [
          button('+ 추가', () => url && rebuild([...url.searchParams.entries(), ['key', 'value']])),
          copyButton(() => input.value, 'URL 복사'),
        ], h('table', { class: 'kv' }, paramsBody)),
      ),
    ),
  );
  parse();
}

// ---------- HTTP status codes ----------
const STATUS: [number, string, string][] = [
  [100, 'Continue', '요청의 첫 부분을 받았으니 계속 보내도 됩니다.'],
  [101, 'Switching Protocols', '프로토콜 전환 (예: WebSocket 업그레이드).'],
  [103, 'Early Hints', '최종 응답 전에 미리 리소스 힌트(Link 헤더)를 보냅니다.'],
  [200, 'OK', '요청 성공.'],
  [201, 'Created', '요청 성공으로 새 리소스가 생성됨 (주로 POST).'],
  [202, 'Accepted', '요청은 접수됐지만 처리가 아직 끝나지 않음 (비동기 작업).'],
  [204, 'No Content', '성공했지만 응답 본문이 없음 (주로 DELETE, PUT).'],
  [206, 'Partial Content', 'Range 요청에 대한 부분 응답 (이어받기, 스트리밍).'],
  [301, 'Moved Permanently', '리소스가 영구적으로 이동함. 검색엔진도 새 주소로 갱신.'],
  [302, 'Found', '임시 이동. 브라우저는 GET으로 바꿔 재요청하는 경우가 많음.'],
  [303, 'See Other', '다른 URL을 GET으로 조회하라 (POST 후 리다이렉트).'],
  [304, 'Not Modified', '캐시된 버전을 그대로 사용 (ETag / If-Modified-Since).'],
  [307, 'Temporary Redirect', '임시 이동. 메서드와 본문을 유지한 채 재요청.'],
  [308, 'Permanent Redirect', '영구 이동. 메서드와 본문을 유지한 채 재요청.'],
  [400, 'Bad Request', '요청 형식이 잘못됨 (잘못된 JSON, 파라미터 누락 등).'],
  [401, 'Unauthorized', '인증 필요 또는 인증 실패 (토큰 없음/만료).'],
  [403, 'Forbidden', '인증은 됐지만 권한이 없음.'],
  [404, 'Not Found', '리소스를 찾을 수 없음.'],
  [405, 'Method Not Allowed', '해당 리소스가 이 HTTP 메서드를 지원하지 않음.'],
  [406, 'Not Acceptable', 'Accept 헤더에 맞는 응답 형식을 제공할 수 없음.'],
  [408, 'Request Timeout', '클라이언트가 요청을 너무 늦게 보냄.'],
  [409, 'Conflict', '현재 리소스 상태와 충돌 (중복 생성, 버전 충돌).'],
  [410, 'Gone', '리소스가 영구적으로 삭제됨.'],
  [411, 'Length Required', 'Content-Length 헤더가 필요함.'],
  [412, 'Precondition Failed', 'If-Match 등 조건부 헤더 조건이 맞지 않음.'],
  [413, 'Content Too Large', '요청 본문이 너무 큼 (업로드 크기 제한).'],
  [414, 'URI Too Long', 'URL이 너무 김.'],
  [415, 'Unsupported Media Type', '지원하지 않는 Content-Type.'],
  [418, "I'm a teapot", '만우절 농담으로 만들어진 코드 (RFC 2324).'],
  [422, 'Unprocessable Content', '형식은 맞지만 내용 검증에 실패 (유효성 검사 오류).'],
  [425, 'Too Early', '재전송 공격 위험으로 처리하지 않음.'],
  [428, 'Precondition Required', '조건부 요청 헤더가 필요함.'],
  [429, 'Too Many Requests', '요청 횟수 제한(Rate limit) 초과. Retry-After 확인.'],
  [431, 'Request Header Fields Too Large', '요청 헤더가 너무 큼 (쿠키 과다 등).'],
  [451, 'Unavailable For Legal Reasons', '법적 이유로 제공할 수 없음.'],
  [500, 'Internal Server Error', '서버 내부 오류.'],
  [501, 'Not Implemented', '서버가 해당 기능을 지원하지 않음.'],
  [502, 'Bad Gateway', '게이트웨이/프록시가 상위 서버로부터 잘못된 응답을 받음.'],
  [503, 'Service Unavailable', '서버 과부하 또는 점검 중.'],
  [504, 'Gateway Timeout', '게이트웨이/프록시가 상위 서버 응답을 기다리다 시간 초과.'],
  [505, 'HTTP Version Not Supported', '지원하지 않는 HTTP 버전.'],
];
function statusTool(root: HTMLElement) {
  const q = h('input', { class: 'input', style: { width: '100%' }, placeholder: '코드나 키워드로 검색 (예: 4, 404, 권한, redirect)', 'aria-label': '상태 코드 검색' });
  const list = h('div', { class: 'result-list' });
  const GROUP: Record<number, [string, string]> = { 1: ['정보', 'var(--muted)'], 2: ['성공', 'var(--ok)'], 3: ['리다이렉트', 'var(--tok-bool)'], 4: ['클라이언트 오류', 'var(--tok-number)'], 5: ['서버 오류', 'var(--danger)'] };
  const update = () => {
    const t = q.value.trim().toLowerCase();
    const items = STATUS.filter(([c, n, d]) => !t || String(c).startsWith(t) || n.toLowerCase().includes(t) || d.includes(t));
    list.replaceChildren(...items.map(([c, n, d]) => {
      const [g, color] = GROUP[Math.floor(c / 100)];
      return h('div', { class: 'result-row', style: { gridTemplateColumns: '70px minmax(0,1fr) auto' } },
        h('strong', { style: { font: '600 18px var(--mono)', color } }, String(c)),
        h('div', null, h('div', { style: { fontWeight: '600' } }, n), h('div', { class: 'note' }, d)),
        h('span', { class: 'note' }, g));
    }));
    if (!items.length) list.append(h('div', { class: 'note' }, '일치하는 상태 코드가 없습니다.'));
  };
  q.addEventListener('input', update);
  root.append(h('div', { class: 'stack', style: { maxWidth: '900px' } }, q, list));
  update();
}

export const webTools: Tool[] = [
  { id: 'url-parser', name: 'URL 파서', category: 'web', description: 'URL을 프로토콜, 호스트, 경로, 쿼리 파라미터로 분해하고 파라미터를 편집해 다시 조합합니다.', keywords: ['query string', 'querystring', 'parse url', '쿼리'], render: urlTool },
  { id: 'http-status', name: 'HTTP 상태 코드', category: 'web', description: '200, 404, 500 등 HTTP 상태 코드의 의미를 한국어로 검색합니다.', keywords: ['status code', '404', '500', 'response', '응답 코드'], render: statusTool },
];
