import type { Tool } from '../types';
import YAML from 'yaml';
import { format as formatSql, type SqlLanguage } from 'sql-formatter';
import { marked } from 'marked';
import { copyButton, debounce, escapeHtml, h, highlightJson, highlightXml, highlightYaml, panel, store, textarea, transformer } from '../ui';
import { findSuspicious, parseInert, setUntrustedHtml } from '../security';

/** YAML aliases are capped so "billion laughs" style anchors cannot expand into gigabytes. */
export const YAML_JS_OPTS = { maxAliasCount: 100 };
const MAX_DEPTH = 1000;

// ---------- JSON ----------
/** Validating scanner used only to locate the first error offset when JSON.parse omits it. */
function findJsonError(s: string): [number, string] {
  let i = 0;
  let depth = 0;
  const LIT = /true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y; // sticky: matches at i without copying the rest
  const ws = () => { while (/\s/.test(s[i] ?? '')) i++; };
  const fail = (what: string): never => { throw [i, what]; };
  const value = (): void => {
    ws();
    const c = s[i];
    if ((c === '{' || c === '[') && ++depth > MAX_DEPTH) fail(`중첩 깊이가 ${MAX_DEPTH}단계를 넘습니다`);
    if (c === '{') {
      i++; ws();
      if (s[i] === '}') return void (i++, depth--);
      for (;;) {
        ws();
        if (s[i] !== '"') fail(s[i] === '}' ? '마지막 쉼표 뒤에 키가 없습니다' : '키는 큰따옴표 문자열이어야 합니다');
        str(); ws();
        if (s[i] !== ':') fail('":" 이 필요합니다');
        i++; value(); ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') return void (i++, depth--);
        fail('"," 또는 "}" 가 필요합니다');
      }
    }
    if (c === '[') {
      i++; ws();
      if (s[i] === ']') return void (i++, depth--);
      for (;;) {
        ws();
        if (s[i] === ']') fail('마지막 쉼표 뒤에 값이 없습니다');
        value(); ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') return void (i++, depth--);
        fail('"," 또는 "]" 가 필요합니다');
      }
    }
    if (c === '"') return str();
    LIT.lastIndex = i;
    const lit = LIT.exec(s);
    if (lit) return void (i += lit[0].length);
    fail(c === undefined ? '입력이 예상보다 일찍 끝났습니다' : c === "'" ? '작은따옴표는 사용할 수 없습니다' : `예상하지 못한 문자 "${c}"`);
  };
  const str = () => {
    i++;
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\') i++;
      else if (s[i] < ' ') fail('문자열 안에 줄바꿈 등 제어문자가 있습니다');
      i++;
    }
    if (s[i] !== '"') fail('닫히지 않은 문자열');
    i++;
  };
  try {
    value(); ws();
    if (i < s.length) fail('값 뒤에 불필요한 내용이 있습니다');
  } catch (e) {
    if (Array.isArray(e)) return e as [number, string];
    throw e;
  }
  return [0, ''];
}

/** JSON.parse with an error that always names line, column and the surrounding text. */
export function parseJson(text: string): unknown {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    const [pos, reason] = findJsonError(text);
    const msg = reason || (e as Error).message;
    const before = text.slice(0, pos);
    const line = before.split('\n').length;
    const col = pos - before.lastIndexOf('\n');
    const lineText = text.split('\n')[line - 1] ?? '';
    const hint = /,\s*[}\]]/.test(text.slice(Math.max(0, pos - 20), pos + 2)) ? '\n힌트: 마지막 항목 뒤 쉼표(trailing comma)는 JSON에서 허용되지 않습니다.' : /'/.test(text.slice(pos, pos + 1)) ? '\n힌트: JSON 문자열은 큰따옴표(")만 사용할 수 있습니다.' : '';
    const shown = lineText.length > 200 ? lineText.slice(Math.max(0, col - 100), col + 100) : lineText;
    const caret = lineText.length > 200 ? Math.min(col - 1, 100) : col - 1;
    throw new Error(`JSON 오류 (${line}행 ${col}열): ${msg.replace(/ in JSON at position \d+.*$/, '')}\n${shown}\n${' '.repeat(Math.max(0, caret))}^${hint}`);
  }
  // Deep nesting is valid JSON but makes every recursive consumer (stringify, tree, converters) overflow the stack.
  if (nestingDepth(text) > MAX_DEPTH) throw new Error(`JSON 중첩 깊이가 ${MAX_DEPTH}단계를 넘어 처리하지 않습니다.`);
  return value;
}

/** Maximum bracket depth outside of strings. Linear time. */
function nestingDepth(s: string): number {
  let d = 0, max = 0, inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++; // backslash
      else if (c === 34) inStr = false;
    } else if (c === 34) inStr = true;
    else if (c === 123 || c === 91) max = Math.max(max, ++d);
    else if (c === 125 || c === 93) d--;
  }
  return max;
}

export function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]));
  return v;
}

const indentOf = (o: string | number | boolean) => (o === 'tab' ? '\t' : Number(o));

const TREE_NODE_LIMIT = 5000;
/** Builds the collapsible tree. Stops after TREE_NODE_LIMIT nodes so huge documents cannot freeze the page. */
function treeHtml(value: unknown, key: string | null, depth: number, budget = { left: TREE_NODE_LIMIT }): string {
  if (budget.left-- <= 0) return budget.left === -1 ? `<div class="leaf"><span class="count">… ${TREE_NODE_LIMIT.toLocaleString()}개 노드까지만 표시합니다. 전체는 "정렬" 모드에서 확인하세요.</span></div>` : '';
  const label = key === null ? '' : `<span class="tok-key">${escapeHtml(JSON.stringify(key))}</span><span class="tok-punct">: </span>`;
  if (value && typeof value === 'object') {
    const isArr = Array.isArray(value);
    const entries = isArr ? (value as unknown[]).map((v, i) => [String(i), v] as const) : Object.entries(value);
    const [o, c] = isArr ? ['[', ']'] : ['{', '}'];
    const count = `<span class="count"> ${entries.length}${isArr ? '개 항목' : '개 키'}</span>`;
    if (!entries.length) return `<div class="leaf">${label}<span class="tok-punct">${o}${c}</span></div>`;
    const children = entries.map(([k, v]) => treeHtml(v, isArr ? null : k, depth + 1, budget)).join('');
    return `<details${depth < 2 ? ' open' : ''}><summary>${label}<span class="tok-punct">${o}</span>${count}</summary>${children}<div><span class="tok-punct">${c}</span></div></details>`;
  }
  return `<div class="leaf">${label}${highlightJson(JSON.stringify(value))}</div>`;
}

// ---------- XML ----------
function formatXml(src: string, indent: string, minify: boolean): string {
  // Entity declarations enable XXE and "billion laughs" expansion. A formatter never needs them.
  if (/<!ENTITY/i.test(src)) throw new Error('보안상 <!ENTITY> 선언이 포함된 XML은 처리하지 않습니다 (XXE / Billion Laughs 방지).');
  const doc = parseInert(src, 'application/xml');
  const err = doc.querySelector('parsererror');
  if (err) throw new Error('XML 오류: ' + (err.textContent ?? '').replace(/\s+/g, ' ').trim());
  const decl = src.match(/^\s*(<\?xml[^?]*\?>)/)?.[1];
  const nl = minify ? '' : '\n';
  const pad = (n: number) => (minify ? '' : indent.repeat(n));
  const attrs = (el: Element) => Array.from(el.attributes).map((a) => ` ${a.name}="${a.value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')}"`).join('');
  const esc = (t: string) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const walk = (node: Node, level: number): string => {
    switch (node.nodeType) {
      case Node.ELEMENT_NODE: {
        const el = node as Element;
        const kids = Array.from(el.childNodes).filter((n) => !(n.nodeType === Node.TEXT_NODE && !n.textContent!.trim()));
        if (!kids.length) return `${pad(level)}<${el.tagName}${attrs(el)}/>`;
        if (kids.length === 1 && kids[0].nodeType === Node.TEXT_NODE) return `${pad(level)}<${el.tagName}${attrs(el)}>${esc(kids[0].textContent!.trim())}</${el.tagName}>`;
        return `${pad(level)}<${el.tagName}${attrs(el)}>${nl}${kids.map((k) => walk(k, level + 1)).join(nl)}${nl}${pad(level)}</${el.tagName}>`;
      }
      case Node.TEXT_NODE:
        return pad(level) + esc(node.textContent!.trim());
      case Node.CDATA_SECTION_NODE:
        return `${pad(level)}<![CDATA[${node.textContent}]]>`;
      case Node.COMMENT_NODE:
        return minify ? '' : `${pad(level)}<!--${node.textContent}-->`;
      case Node.PROCESSING_INSTRUCTION_NODE:
        return `${pad(level)}<?${(node as ProcessingInstruction).target} ${(node as ProcessingInstruction).data}?>`;
      case Node.DOCUMENT_TYPE_NODE: {
        const d = node as DocumentType;
        return `<!DOCTYPE ${d.name}${d.publicId ? ` PUBLIC "${d.publicId}"` : ''}${d.systemId ? ` "${d.systemId}"` : ''}>`;
      }
      default:
        return '';
    }
  };
  const body = Array.from(doc.childNodes).map((n) => walk(n, 0)).filter(Boolean).join(nl);
  return (decl ? decl + nl : '') + body;
}

// ---------- SQL highlight ----------
const SQL_KW = new Set('SELECT FROM WHERE AND OR NOT IN IS NULL AS ON JOIN LEFT RIGHT INNER OUTER FULL CROSS GROUP BY ORDER HAVING LIMIT OFFSET INSERT INTO VALUES UPDATE SET DELETE CREATE TABLE ALTER DROP INDEX VIEW PRIMARY KEY FOREIGN REFERENCES UNIQUE DEFAULT DISTINCT UNION ALL CASE WHEN THEN ELSE END EXISTS BETWEEN LIKE ILIKE ASC DESC WITH RETURNING TRUE FALSE COUNT SUM AVG MIN MAX COALESCE CAST OVER PARTITION ROW_NUMBER IF REPLACE TRUNCATE BEGIN COMMIT ROLLBACK GRANT REVOKE INTERVAL USING NATURAL LATERAL ANY SOME TOP FETCH NEXT ROWS ONLY'.split(' '));
function highlightSql(text: string): string {
  const re = /--[^\n]*|\/\*[\s\S]*?\*\/|'(?:''|[^'])*'|"(?:""|[^"])*"|`[^`]*`|\b\d+(?:\.\d+)?\b|\b[A-Za-z_]+\b/g;
  let out = '', last = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const t = m[0];
    let cls: string | null = null;
    if (t.startsWith('--') || t.startsWith('/*')) cls = 'comment';
    else if (t[0] === "'") cls = 'string';
    else if (t[0] === '"' || t[0] === '`') cls = 'attr';
    else if (/^\d/.test(t)) cls = 'number';
    else if (SQL_KW.has(t.toUpperCase())) cls = 'key';
    out += escapeHtml(text.slice(last, m.index)) + (cls ? `<span class="tok-${cls}">${escapeHtml(t)}</span>` : escapeHtml(t));
    last = m.index + t.length;
  }
  return out + escapeHtml(text.slice(last));
}

// ---------- Markdown ----------
function markdownTool(root: HTMLElement) {
  const SAMPLE = `# DevKit 마크다운 미리보기

**굵게**, *기울임*, ~~취소선~~, \`인라인 코드\`

## 목록
- 항목 1
- 항목 2
  - 하위 항목

1. 첫째
2. 둘째

> 인용문입니다.

\`\`\`js
console.log('Hello, DevKit');
\`\`\`

| 도구 | 설명 |
| --- | --- |
| JSON | 포맷터 |
| Regex | 테스터 |

[링크](https://example.com)
`;
  const input = textarea({ value: store.get('tool:markdown', SAMPLE) });
  const view = h('div', { class: 'md-preview' });
  const notice = h('div', { class: 'warn-box', hidden: true });
  const update = () => {
    const src = input.value;
    store.set('tool:markdown', src.length < 200_000 ? src : '');
    if (src.length > 1_000_000) {
      view.replaceChildren(h('div', { class: 'error-box' }, '마크다운이 너무 큽니다 (최대 1,000,000자).'));
      return;
    }
    // marked output is untrusted HTML (markdown allows raw tags): sanitize, block remote images, harden links.
    const { blockedImages } = setUntrustedHtml(view, marked.parse(src, { async: false, gfm: true, breaks: false }));
    const odd = findSuspicious(src);
    const msgs = [
      blockedImages ? `외부 이미지 ${blockedImages}개를 차단했습니다 (열람자 IP 추적 방지).` : '',
      odd.length ? `보이지 않는 문자: ${odd.map((f) => `${f.label} ${f.count}개`).join(', ')}` : '',
    ].filter(Boolean);
    notice.hidden = !msgs.length;
    notice.textContent = msgs.join(' · ');
  };
  input.addEventListener('input', debounce(update, 120));
  update();
  root.append(
    h('div', { class: 'io-grid' },
      panel('마크다운', [copyButton(() => input.value, 'MD 복사')], input),
      panel('미리보기', [copyButton(() => view.innerHTML, '정제된 HTML 복사')], h('div', { class: 'output-wrap' }, notice, view)),
    ),
  );
}

export const formatTools: Tool[] = [
  {
    id: 'json',
    name: 'JSON 포맷터',
    category: 'format',
    description: 'JSON을 보기 좋게 정렬하고 색으로 구분합니다. 압축, 키 정렬, 트리 보기, 오류 위치 표시를 지원합니다.',
    keywords: ['json beautify', 'pretty', 'minify', 'validator', 'lint', '검증', '정렬', 'tree'],
    render: (root) =>
      transformer(root, {
        id: 'json',
        wrap: false,
        modes: [
          { id: 'pretty', label: '정렬', run: (s, o) => { let v = parseJson(s); if (o.sort) v = sortKeys(v); const t = JSON.stringify(v, null, indentOf(o.indent)); return { text: t, html: highlightJson(t) }; } },
          { id: 'tree', label: '트리', run: (s, o) => { let v = parseJson(s); if (o.sort) v = sortKeys(v); return { text: JSON.stringify(v, null, 2), html: `<div class="tree">${treeHtml(v, null, 0)}</div>` }; } },
          { id: 'minify', label: '압축', run: (s, o) => { let v = parseJson(s); if (o.sort) v = sortKeys(v); const t = JSON.stringify(v); return { text: t, html: highlightJson(t) }; } },
        ],
        options: [
          { id: 'indent', label: '들여쓰기', type: 'select', default: '2', modes: ['pretty'], choices: [['2', '공백 2칸'], ['4', '공백 4칸'], ['tab', '탭']] },
          { id: 'sort', label: '키 알파벳순 정렬', type: 'checkbox', default: false },
        ],
        placeholder: '{"hello": "world"}',
        sample: '{"name":"DevKit","version":"1.0.0","tools":["base64","json","regex"],"author":{"name":"홍길동","email":"dev@example.com"},"stars":1234,"price":12.5,"public":true,"license":null}',
      }),
  },
  {
    id: 'yaml',
    name: 'YAML 포맷터',
    category: 'format',
    description: 'YAML을 검증하고 일관된 들여쓰기로 다시 정렬합니다. 여러 문서(---)도 지원합니다.',
    keywords: ['yml', 'yaml lint', 'validator', 'kubernetes', 'k8s', 'docker compose'],
    render: (root) =>
      transformer(root, {
        id: 'yaml',
        wrap: false,
        modes: [
          {
            id: 'pretty',
            label: '정렬',
            run: (s, o) => {
              const docs = YAML.parseAllDocuments(s);
              const errs = docs.flatMap((d) => d.errors);
              if (errs.length) throw new Error('YAML 오류: ' + errs.map((e) => e.message).join('\n'));
              const t = docs.map((d) => { if (o.sort) d.contents = d.createNode(sortKeys(d.toJS(YAML_JS_OPTS))) as never; return d.toString({ indent: Number(o.indent), lineWidth: 0 }); }).join('---\n');
              return { text: t, html: highlightYaml(t) };
            },
          },
        ],
        options: [
          { id: 'indent', label: '들여쓰기', type: 'select', default: '2', choices: [['2', '공백 2칸'], ['4', '공백 4칸']] },
          { id: 'sort', label: '키 알파벳순 정렬', type: 'checkbox', default: false },
        ],
        sample: `# 서비스 설정
service:
    name: devkit
    replicas: 3
    ports: [80, 443]
    env:
      - name: NODE_ENV
        value: production
      - {name: DEBUG, value: "false"}
    enabled: true
    timeout: null
`,
      }),
  },
  {
    id: 'xml',
    name: 'XML 포맷터',
    category: 'format',
    description: 'XML을 검증하고 들여쓰기해서 보기 좋게 정렬하거나 한 줄로 압축합니다.',
    keywords: ['xml beautify', 'pretty', 'minify', 'svg', 'soap', 'rss'],
    render: (root) =>
      transformer(root, {
        id: 'xml',
        wrap: false,
        modes: [
          { id: 'pretty', label: '정렬', run: (s, o) => { const t = formatXml(s, o.indent === 'tab' ? '\t' : ' '.repeat(Number(o.indent)), false); return { text: t, html: highlightXml(t) }; } },
          { id: 'minify', label: '압축', run: (s) => { const t = formatXml(s, '', true); return { text: t, html: highlightXml(t) }; } },
        ],
        options: [{ id: 'indent', label: '들여쓰기', type: 'select', default: '2', modes: ['pretty'], choices: [['2', '공백 2칸'], ['4', '공백 4칸'], ['tab', '탭']] }],
        sample: '<?xml version="1.0" encoding="UTF-8"?><catalog><!-- 도서 목록 --><book id="bk101" lang="ko"><title>개발자 도구</title><price currency="KRW">25000</price><tags><tag>dev</tag><tag>tools</tag></tags></book><book id="bk102"/></catalog>',
      }),
  },
  {
    id: 'sql',
    name: 'SQL 포맷터',
    category: 'format',
    description: 'SQL 쿼리를 읽기 쉽게 줄바꿈하고 들여씁니다. MySQL, PostgreSQL 등 방언을 지원합니다.',
    keywords: ['sql beautify', 'query', 'mysql', 'postgres', 'oracle', '쿼리'],
    render: (root) =>
      transformer(root, {
        id: 'sql',
        wrap: false,
        maxInput: 500_000, // formatter + highlighter are superlinear on pathological input
        modes: [
          {
            id: 'pretty',
            label: '정렬',
            run: (s, o) => {
              const t = formatSql(s, { language: o.lang as SqlLanguage, keywordCase: o.kw as 'upper' | 'lower' | 'preserve', tabWidth: Number(o.indent) });
              return { text: t, html: highlightSql(t) };
            },
          },
        ],
        options: [
          { id: 'lang', label: '방언', type: 'select', default: 'sql', choices: [['sql', '표준 SQL'], ['mysql', 'MySQL'], ['mariadb', 'MariaDB'], ['postgresql', 'PostgreSQL'], ['sqlite', 'SQLite'], ['tsql', 'SQL Server'], ['plsql', 'Oracle PL/SQL'], ['bigquery', 'BigQuery'], ['snowflake', 'Snowflake']] },
          { id: 'kw', label: '키워드', type: 'select', default: 'upper', choices: [['upper', '대문자'], ['lower', '소문자'], ['preserve', '유지']] },
          { id: 'indent', label: '들여쓰기', type: 'select', default: '2', choices: [['2', '2칸'], ['4', '4칸']] },
        ],
        sample: "select u.id, u.name, count(o.id) as orders from users u left join orders o on o.user_id = u.id where u.created_at > '2026-01-01' and u.status in ('active','pending') group by u.id, u.name having count(o.id) > 3 order by orders desc limit 10;",
      }),
  },
  {
    id: 'markdown',
    name: '마크다운 미리보기',
    category: 'format',
    description: '마크다운(GFM)을 실시간으로 렌더링하고 HTML로 복사합니다.',
    keywords: ['md', 'markdown', 'gfm', 'readme', 'preview'],
    render: markdownTool,
  },
];
