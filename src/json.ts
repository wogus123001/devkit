// JSON parsing shared by many tools. Kept apart from tools/format.ts so tools that only need
// parseJson do not pull in the formatter libraries (sql-formatter, marked).

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
