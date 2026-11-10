// Runs user regexes off the main thread so catastrophic backtracking can be killed by a timeout.

export interface RegexRequest {
  id: number;
  pattern: string;
  flags: string;
  text: string;
  replacement: string | null;
}
export interface RegexMatch {
  index: number;
  end: number;
  text: string;
  groups: (string | undefined)[];
  named: Record<string, string | undefined> | null;
}
export interface RegexResponse {
  id: number;
  error?: string;
  matches?: RegexMatch[];
  total?: number;
  replaced?: string | null;
}

const LIMIT = 5000;

self.onmessage = (e: MessageEvent<RegexRequest>) => {
  const { id, pattern, flags, text, replacement } = e.data;
  try {
    const re = new RegExp(pattern, flags);
    const matches: RegexMatch[] = [];
    let total = 0;
    const scan = new RegExp(pattern, flags.includes('g') ? flags : flags + 'g');
    for (let m = scan.exec(text); m; m = scan.exec(text)) {
      total++;
      if (matches.length < LIMIT)
        matches.push({ index: m.index, end: m.index + m[0].length, text: m[0], groups: m.slice(1), named: m.groups ? { ...m.groups } : null });
      if (m[0] === '') scan.lastIndex += flags.includes('u') || flags.includes('v') ? (text.codePointAt(scan.lastIndex)! > 0xffff ? 2 : 1) : 1;
      if (!flags.includes('g')) break;
    }
    // "$`" and "$'" insert the text before/after each match, so output can grow quadratically.
    if (replacement !== null && /\$[`']/.test(replacement) && total * text.length > 50_000_000)
      throw new Error("치환 결과가 너무 커집니다 ($` 또는 $' 를 많은 매치에 사용).");
    const replaced = replacement === null ? null : text.replace(re, replacement);
    (self as unknown as Worker).postMessage({ id, matches, total, replaced } satisfies RegexResponse);
  } catch (err) {
    (self as unknown as Worker).postMessage({ id, error: (err as Error).message } satisfies RegexResponse);
  }
};
