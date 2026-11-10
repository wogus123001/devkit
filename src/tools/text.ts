import type { Tool } from '../types';
import { diffChars, diffLines, diffWordsWithSpace } from 'diff';
import { checkbox, debounce, escapeHtml, h, panel, segmented, setHtml, store, textarea, transformer } from '../ui';

// ---------- diff ----------
function diffTool(root: HTMLElement) {
  const s = store.get('tool:diff', {
    a: 'const name = "DevKit";\nconst version = 1;\nfunction hello() {\n  console.log("hi");\n}\n',
    b: 'const name = "DevKit";\nconst version = 2;\nfunction hello(user) {\n  console.log("hi", user);\n}\nexport default hello;\n',
    mode: 'lines', ignoreWs: false, ignoreCase: false,
  });
  const a = textarea({ class: 'code short', value: s.a, 'aria-label': '원본' });
  const b = textarea({ class: 'code short', value: s.b, 'aria-label': '변경본' });
  const out = h('div', { class: 'diff' });
  const stats = h('div', { class: 'diff-stats' });
  const update = () => {
    Object.assign(s, { a: a.value.length < 100_000 ? a.value : '', b: b.value.length < 100_000 ? b.value : '' });
    store.set('tool:diff', s);
    let added = 0, removed = 0;
    // Diff is O(N·D): two large, very different texts can lock the tab, so size and time are both capped.
    const limit = s.mode === 'lines' ? 2_000_000 : 200_000;
    if (a.value.length > limit || b.value.length > limit) {
      out.replaceChildren(h('div', { class: 'error-box' }, `${s.mode === 'lines' ? '줄' : '단어/글자'} 단위 비교는 각 ${limit.toLocaleString()}자까지 지원합니다.`));
      stats.replaceChildren();
      return;
    }
    const timedOut = () => {
      out.replaceChildren(h('div', { class: 'error-box' }, '차이가 너무 많아 1.5초 안에 비교를 끝내지 못했습니다. 줄 단위 비교를 사용하거나 텍스트를 나눠 보세요.'));
      stats.replaceChildren();
    };
    if (s.mode === 'lines') {
      const parts = diffLines(a.value, b.value, { ignoreWhitespace: s.ignoreWs, stripTrailingCr: true, timeout: 1500 });
      if (!parts) return timedOut();
      let la = 1, lb = 1;
      const rows: string[] = [];
      for (const p of parts) {
        const lines = p.value.replace(/\n$/, '').split('\n');
        for (const line of lines) {
          if (p.added) (rows.push(`<div class="line add"><span class="ln"></span><span class="ln">${lb++}</span><span>+ ${escapeHtml(line)}</span></div>`), added++);
          else if (p.removed) (rows.push(`<div class="line del"><span class="ln">${la++}</span><span class="ln"></span><span>- ${escapeHtml(line)}</span></div>`), removed++);
          else rows.push(`<div class="line"><span class="ln">${la++}</span><span class="ln">${lb++}</span><span>  ${escapeHtml(line)}</span></div>`);
        }
      }
      setHtml(out, rows.join(''));
    } else {
      const parts = s.mode === 'words' ? diffWordsWithSpace(a.value, b.value, { ignoreCase: s.ignoreCase, timeout: 1500 }) : diffChars(a.value, b.value, { ignoreCase: s.ignoreCase, timeout: 1500 });
      if (!parts) return timedOut();
      setHtml(out, '<div class="line"><span>' + parts.map((p) => {
        if (p.added) return (added += p.count ?? 1), `<ins>${escapeHtml(p.value)}</ins>`;
        if (p.removed) return (removed += p.count ?? 1), `<del>${escapeHtml(p.value)}</del>`;
        return escapeHtml(p.value);
      }).join('') + '</span></div>');
    }
    const unit = s.mode === 'lines' ? '줄' : s.mode === 'words' ? '단어' : '글자';
    stats.replaceChildren(
      a.value === b.value ? h('span', null, '두 텍스트가 동일합니다') : h('span', { class: 'plus' }, `+${added}${unit} 추가`),
      a.value === b.value ? '' : h('span', { class: 'minus' }, `−${removed}${unit} 삭제`),
    );
  };
  const run = debounce(update, 200);
  a.addEventListener('input', run);
  b.addEventListener('input', run);
  root.append(
    h('div', { class: 'stack' },
      h('div', { class: 'toolbar', style: { marginBottom: '0' } },
        segmented([['lines', '줄 단위'], ['words', '단어 단위'], ['chars', '글자 단위']], s.mode, (v) => ((s.mode = v), update())),
        checkbox('공백 무시', s.ignoreWs, (v) => ((s.ignoreWs = v), update())),
        checkbox("대소문자 무시 (단어·글자)", s.ignoreCase, (v) => ((s.ignoreCase = v), update())),
      ),
      h('div', { class: 'io-grid' }, panel('원본 (A)', [], a), panel('변경본 (B)', [], b)),
      panel('차이', [stats], out),
    ),
  );
  update();
}

// ---------- counter ----------
function counterTool(root: HTMLElement) {
  const input = textarea({ value: store.get('tool:counter', ''), placeholder: '글자 수를 셀 텍스트를 입력하세요' });
  const grid = h('div', { class: 'stats' });
  const seg = typeof Intl !== 'undefined' && 'Segmenter' in Intl ? new Intl.Segmenter('ko', { granularity: 'grapheme' }) : null;
  const update = () => {
    const t = input.value;
    store.set('tool:counter', t.length < 100_000 ? t : '');
    const graphemes = seg ? [...seg.segment(t)].length : [...t].length;
    const bytes = new TextEncoder().encode(t).length;
    // EUC-KR style count: Hangul/CJK = 2 bytes, ASCII = 1 (common for SMS/legacy DB limits)
    const legacy = [...t].reduce((n, c) => n + (c.charCodeAt(0) > 127 ? 2 : 1), 0);
    const words = t.trim() ? t.trim().split(/\s+/).length : 0;
    const items: [string, string | number][] = [
      ['글자 수 (공백 포함)', graphemes],
      ['글자 수 (공백 제외)', seg ? [...seg.segment(t.replace(/\s/g, ''))].length : t.replace(/\s/g, '').length],
      ['단어', words],
      ['줄', t ? t.split('\n').length : 0],
      ['문장', (t.match(/[^.!?。！？\n]+[.!?。！？]+/g) ?? []).length],
      ['문단', t.split(/\n\s*\n/).filter((x) => x.trim()).length],
      ['UTF-8 바이트', bytes],
      ['EUC-KR 바이트', legacy],
      ['한글', (t.match(/[가-힣]/g) ?? []).length],
      ['영문', (t.match(/[a-zA-Z]/g) ?? []).length],
      ['숫자', (t.match(/\d/g) ?? []).length],
      ['읽기 시간', `${Math.max(t ? 1 : 0, Math.round(graphemes / 500))}분`],
    ];
    grid.replaceChildren(...items.map(([l, v]) => h('div', { class: 'stat' }, h('div', { class: 'stat-value' }, typeof v === 'number' ? v.toLocaleString() : v), h('div', { class: 'stat-label' }, l))));
  };
  input.addEventListener('input', update);
  root.append(h('div', { class: 'stack' }, grid, panel('텍스트', [], input)));
  update();
}

// ---------- line tools ----------
const collator = new Intl.Collator('ko', { numeric: true, sensitivity: 'base' });
export const textTools: Tool[] = [
  { id: 'diff', name: '텍스트 비교 (Diff)', category: 'text', description: '두 텍스트의 차이를 줄/단어/글자 단위로 비교해 추가·삭제된 부분을 표시합니다.', keywords: ['diff', 'compare', 'merge', '비교', 'changes'], render: diffTool },
  { id: 'counter', name: '글자 수 세기', category: 'text', description: '글자, 단어, 줄, 바이트 수를 실시간으로 셉니다. 공백 제외, UTF-8/EUC-KR 바이트를 지원합니다.', keywords: ['word count', 'character count', '글자수', '바이트', 'length'], render: counterTool },
  {
    id: 'lines',
    name: '줄 정리 도구',
    category: 'text',
    description: '여러 줄 텍스트를 정렬, 중복 제거, 공백 제거, 뒤집기, 번호 매기기 등으로 정리합니다.',
    keywords: ['sort', 'unique', 'dedupe', 'trim', '정렬', '중복 제거', 'shuffle'],
    render: (root) =>
      transformer(root, {
        id: 'lines',
        modes: [
          {
            id: 'run',
            label: '적용',
            run: (s, o) => {
              let lines = s.split(/\r?\n/);
              if (o.trim) lines = lines.map((l) => l.trim());
              if (o.empty) lines = lines.filter((l) => l.trim());
              if (o.unique) {
                const seen = new Set<string>();
                lines = lines.filter((l) => { const k = o.ci ? l.toLowerCase() : l; return seen.has(k) ? false : (seen.add(k), true); });
              }
              if (o.sort === 'asc') lines.sort(collator.compare);
              else if (o.sort === 'desc') lines.sort((x, y) => collator.compare(y, x));
              else if (o.sort === 'len') lines.sort((x, y) => x.length - y.length);
              else if (o.sort === 'reverse') lines.reverse();
              else if (o.sort === 'shuffle') for (let i = lines.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [lines[i], lines[j]] = [lines[j], lines[i]]; }
              if (o.number) lines = lines.map((l, i) => `${i + 1}. ${l}`);
              return o.join === 'newline' ? lines.join('\n') : lines.join(o.join === 'comma' ? ', ' : o.join === 'space' ? ' ' : '\t');
            },
          },
        ],
        options: [
          { id: 'sort', label: '정렬', type: 'select', default: 'none', choices: [['none', '그대로'], ['asc', '오름차순'], ['desc', '내림차순'], ['len', '길이순'], ['reverse', '뒤집기'], ['shuffle', '무작위']] },
          { id: 'unique', label: '중복 제거', type: 'checkbox', default: true },
          { id: 'ci', label: '대소문자 무시', type: 'checkbox', default: false },
          { id: 'trim', label: '앞뒤 공백 제거', type: 'checkbox', default: true },
          { id: 'empty', label: '빈 줄 제거', type: 'checkbox', default: true },
          { id: 'number', label: '번호 매기기', type: 'checkbox', default: false },
          { id: 'join', label: '구분', type: 'select', default: 'newline', choices: [['newline', '줄바꿈'], ['comma', '쉼표'], ['space', '공백'], ['tab', '탭']] },
        ],
        sample: 'banana\napple\n  cherry  \napple\n\n바나나\n사과\nBanana\n',
      }),
  },
];
