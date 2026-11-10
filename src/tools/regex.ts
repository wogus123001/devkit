import type { Tool } from '../types';
import type { RegexRequest, RegexResponse } from '../regex.worker';
import regexWorkerUrl from '../regex.worker.ts?worker&url';
import { button, checkbox, copyButton, debounce, escapeHtml, h, panel, setHtml, store, textarea } from '../ui';
import { HIGHLIGHT_LIMIT, MAX_INPUT_CHARS, createWorker, findSuspicious } from '../security';

const MAX_PATTERN = 10_000;

const FLAGS: [string, string][] = [
  ['g', '전체 검색 (global)'],
  ['i', '대소문자 무시'],
  ['m', '여러 줄 (^ $ 줄 단위)'],
  ['s', '. 이 줄바꿈 포함'],
  ['u', '유니코드'],
  ['y', '고정 위치 (sticky)'],
];

const PRESETS: [string, string, string][] = [
  ['이메일', '[\\w.+-]+@[\\w-]+\\.[\\w.-]+', 'g'],
  ['URL', 'https?:\\/\\/[^\\s/$.?#].[^\\s]*', 'gi'],
  ['IPv4', '\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b', 'g'],
  ['휴대폰 번호', '01[016789]-?\\d{3,4}-?\\d{4}', 'g'],
  ['날짜 YYYY-MM-DD', '(?<year>\\d{4})-(?<month>0[1-9]|1[0-2])-(?<day>0[1-9]|[12]\\d|3[01])', 'g'],
  ['한글', '[가-힣]+', 'g'],
  ['HEX 색상', '#(?:[0-9a-fA-F]{3}){1,2}\\b', 'g'],
  ['UUID', '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'gi'],
  ['HTML 태그', '<\\/?([a-z][a-z0-9]*)\\b[^>]*>', 'gi'],
  ['숫자 (천 단위 콤마)', '-?\\d{1,3}(?:,\\d{3})*(?:\\.\\d+)?', 'g'],
];

const CHEATS: [string, string][] = [
  ['.', '아무 문자 1개'], ['\\d \\D', '숫자 / 숫자 아님'], ['\\w \\W', '단어 문자 / 아님'], ['\\s \\S', '공백 / 공백 아님'],
  ['[abc]', 'a, b, c 중 하나'], ['[^abc]', 'a, b, c 제외'], ['[a-z]', '범위'], ['^ $', '시작 / 끝'],
  ['\\b', '단어 경계'], ['* + ?', '0+ / 1+ / 0~1회'], ['{n,m}', 'n~m회 반복'], ['*? +?', '최소 매칭 (lazy)'],
  ['(abc)', '캡처 그룹'], ['(?<name>…)', '이름 있는 그룹'], ['(?:abc)', '비캡처 그룹'], ['a|b', 'a 또는 b'],
  ['(?=…)', '전방 탐색'], ['(?!…)', '부정 전방 탐색'], ['(?<=…)', '후방 탐색'], ['\\1', '역참조'],
  ['$1 $<name>', '치환: 그룹'], ['$&', '치환: 전체 매치'],
];

const SAMPLE_TEXT = `연락처: dev@example.com, hong.gildong+test@devkit.co.kr
홈페이지: https://devkit.example.com/tools?id=42
서버 IP: 192.168.0.1 / 10.0.0.255
전화: 010-1234-5678, 01098765432
배포일: 2026-11-10, 마감: 2026-12-31
색상: #0f766e #fff`;

function regexTool(root: HTMLElement): () => void {
  const saved = store.get('tool:regex', { pattern: '(?<year>\\d{4})-(?<month>\\d{2})-(?<day>\\d{2})', flags: 'g', text: SAMPLE_TEXT, replacement: '$<day>/$<month>/$<year>', replaceOn: false });
  let flags = saved.flags;

  const patternInput = h('input', { value: saved.pattern, placeholder: '정규식 입력', 'aria-label': '정규식 패턴', spellcheck: 'false', autocomplete: 'off' });
  const flagsText = h('span', { class: 'flags-text' }, flags);
  const text = textarea({ value: saved.text, placeholder: '테스트할 문자열', 'aria-label': '테스트 문자열' });
  const highlighted = h('pre', { class: 'code output highlight', 'aria-label': '매치 결과' });
  const matchesBox = h('div', { class: 'matches' });
  const matchMeta = h('span', { class: 'panel-meta' });
  const status = h('div', { class: 'error-box', hidden: true });
  const hiddenChars = h('div', { class: 'warn-box', hidden: true, style: { margin: '0' } });
  const replaceInput = h('input', { class: 'input mono grow', value: saved.replacement, placeholder: '치환 문자열 ($1, $<name>, $&)', 'aria-label': '치환 문자열' });
  const replaceOut = h('pre', { class: 'code output short' });
  let replaceOn = saved.replaceOn;
  let replacedText = '';

  let worker: Worker | null = null;
  let seq = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const spawn = () => createWorker(new URL(regexWorkerUrl, location.href));

  const flagBoxes = FLAGS.map(([f, label]) =>
    checkbox(`${f} · ${label}`, flags.includes(f), (on) => {
      flags = FLAGS.map(([x]) => x).filter((x) => (x === f ? on : flags.includes(x))).join('');
      flagsText.textContent = flags;
      run();
    }),
  );

  function render(res: RegexResponse, value: string) {
    if (res.error) {
      status.hidden = false;
      status.textContent = '정규식 오류: ' + res.error;
      highlighted.textContent = value;
      matchesBox.replaceChildren();
      matchMeta.textContent = '';
      return;
    }
    status.hidden = true;
    const ms = res.matches!;
    let html = '', last = 0;
    ms.forEach((m, i) => {
      html += escapeHtml(value.slice(last, m.index));
      html += m.text === '' ? '<mark class="zero"></mark>' : `<mark class="m${i % 2}" title="#${i + 1}">${escapeHtml(m.text)}</mark>`;
      last = m.end;
    });
    if (value.length > HIGHLIGHT_LIMIT) highlighted.textContent = value; // too large to mark up quickly
    else setHtml(highlighted, html + escapeHtml(value.slice(last)) + '\n');
    matchMeta.textContent = res.total ? `${res.total.toLocaleString()}개 일치${res.total > ms.length ? ` (처음 ${ms.length}개 표시)` : ''}` : '일치 없음';
    matchesBox.replaceChildren(
      ...ms.slice(0, 300).map((m, i) => {
        const groupRows: Node[] = [];
        m.groups.forEach((g, gi) => groupRows.push(h('span', null, `$${gi + 1}`), h('div', null, g === undefined ? h('em', { class: 'note' }, '(매치 안 됨)') : h('code', null, g))));
        for (const [k, v] of Object.entries(m.named ?? {})) groupRows.push(h('span', null, `<${k}>`), h('div', null, v === undefined ? h('em', { class: 'note' }, '(매치 안 됨)') : h('code', null, v)));
        return h('div', { class: 'match' },
          h('div', { class: 'match-head' }, h('span', null, `#${i + 1}`), h('span', null, `위치 ${m.index}–${m.end}`)),
          h('code', null, m.text === '' ? '(빈 문자열)' : m.text),
          groupRows.length ? h('div', { class: 'groups' }, ...groupRows) : null,
        );
      }),
    );
    if (!ms.length) matchesBox.append(h('div', { class: 'note' }, '일치하는 부분이 없습니다.'));
    replacedText = res.replaced ?? '';
    replaceOut.textContent = replacedText;
  }

  function run() {
    store.set('tool:regex', { pattern: patternInput.value, flags, text: text.value.length < 200_000 ? text.value : '', replacement: replaceInput.value, replaceOn });
    const id = ++seq;
    const value = text.value;
    const odd = findSuspicious(patternInput.value + value);
    hiddenChars.hidden = !odd.length;
    hiddenChars.textContent = odd.length ? '⚠ 패턴 또는 문자열에 보이지 않는 문자가 있습니다: ' + odd.map((f) => `${f.label} ${f.count}개`).join(', ') : '';
    if (patternInput.value.length > MAX_PATTERN || value.length > MAX_INPUT_CHARS) {
      render({ id, error: `입력이 너무 큽니다 (패턴 최대 ${MAX_PATTERN.toLocaleString()}자, 문자열 최대 ${MAX_INPUT_CHARS.toLocaleString()}자)` }, value.slice(0, 10_000));
      return;
    }
    if (!patternInput.value) {
      status.hidden = true;
      highlighted.textContent = value;
      matchesBox.replaceChildren(h('div', { class: 'note' }, '정규식을 입력하세요.'));
      matchMeta.textContent = '';
      replaceOut.textContent = '';
      return;
    }
    worker ??= spawn();
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (id !== seq) return;
      worker?.terminate();
      worker = null;
      render({ id, error: '실행 시간이 1.5초를 넘어 중단했습니다. 과도한 백트래킹(예: (a+)+)이 있는지 확인하세요.' }, value);
    }, 1500);
    worker.onmessage = (e: MessageEvent<RegexResponse>) => {
      if (e.data.id !== seq) return;
      clearTimeout(timer);
      render(e.data, value);
    };
    worker.postMessage({ id, pattern: patternInput.value, flags, text: value, replacement: replaceOn ? replaceInput.value : null } satisfies RegexRequest);
  }
  const runSoon = debounce(run, 120);
  patternInput.addEventListener('input', runSoon);
  text.addEventListener('input', runSoon);
  replaceInput.addEventListener('input', runSoon);

  const replacePanel = panel('치환 결과', [copyButton(() => replacedText)], replaceOut);
  replacePanel.hidden = !replaceOn;
  const replaceRow = h('div', { class: 'row' }, replaceInput);
  replaceRow.hidden = !replaceOn;

  root.append(
    h('div', { class: 'stack' },
      h('div', { class: 'regex-input' }, h('span', null, '/'), patternInput, h('span', null, '/'), flagsText),
      hiddenChars,
      h('div', { class: 'toolbar', style: { marginBottom: '0' } }, ...flagBoxes),
      h('div', { class: 'row', style: { alignItems: 'center' } },
        h('span', { class: 'field-label' }, '자주 쓰는 패턴'),
        h('div', { class: 'chips' }, ...PRESETS.map(([name, p, f]) => h('button', {
          class: 'chip', type: 'button',
          onclick: () => {
            patternInput.value = p;
            flags = f;
            flagsText.textContent = f;
            flagBoxes.forEach((b, i) => ((b.querySelector('input') as HTMLInputElement).checked = f.includes(FLAGS[i][0])));
            run();
          },
        }, name))),
      ),
      h('div', { class: 'io-grid' },
        panel('테스트 문자열', [button('예시', () => ((text.value = SAMPLE_TEXT), run())), button('지우기', () => ((text.value = ''), run()))], text),
        panel('매치 하이라이트', [matchMeta, copyButton(() => `/${patternInput.value}/${flags}`, '정규식 복사')], h('div', { class: 'output-wrap' }, status, highlighted)),
      ),
      h('div', { class: 'row', style: { alignItems: 'center' } },
        checkbox('치환(Replace) 사용', replaceOn, (on) => {
          replaceOn = on;
          replacePanel.hidden = replaceRow.hidden = !on;
          run();
        }),
      ),
      replaceRow,
      replacePanel,
      h('div', { class: 'io-grid' },
        panel('매치 목록 · 그룹', [], matchesBox),
        panel('빠른 참고', [], h('div', { class: 'cheats' }, ...CHEATS.map(([c, d]) => h('div', null, h('code', null, c), h('span', null, d))))),
      ),
    ),
  );
  run();
  return () => {
    clearTimeout(timer);
    worker?.terminate();
  };
}

export const regexTools: Tool[] = [
  {
    id: 'regex',
    name: '정규식 테스터',
    category: 'regex',
    description: 'JavaScript 정규식을 실시간으로 테스트합니다. 매치 하이라이트, 캡처 그룹, 치환, 자주 쓰는 패턴을 제공합니다.',
    keywords: ['regexp', 'regular expression', 'regex101', 'match', 'replace', '정규표현식'],
    render: regexTool,
  },
];
