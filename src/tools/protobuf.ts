import type { Tool } from '../types';
import { MAX_BYTES, decodeRaw, decodeWithSchema, encodeWithSchema, formatBinary, lookupType, parseBinary, parseSchema, rawToText, type Schema } from '../protobuf';
import { parseJson } from '../json';
import { button, debounce, errorBox, escapeHtml, field, h, highlightJson, panel, store, textarea, transformer } from '../ui';

const SAMPLE_SCHEMA = `syntax = "proto3";
package demo;

message Person {
  string name = 1;
  int32 id = 2;
  string email = 3;
  enum PhoneType { MOBILE = 0; HOME = 1; WORK = 2; }
  message PhoneNumber {
    string number = 1;
    PhoneType type = 2;
  }
  repeated PhoneNumber phones = 4;
  map<string, int64> scores = 5;
  bool active = 6;
  double rating = 7;
  sint32 delta = 8;
  bytes avatar = 9;
  repeated int32 tags = 10;
}
`;
// Produced by upstream protobufjs from SAMPLE_JSON with SAMPLE_SCHEMA.
const SAMPLE_HEX =
  '0a09ed998deab8b8eb8f9910d2091a10686f6e67406578616d706c652e636f6d220f0a0d3031302d313233342d35363738220f0a0b30322d3132332d3435363710022a080a046d617468105f2a0e0a03656e67108180808080808010300139000000000000124040534a04deadbeef520e0102ac02ffffffffffffffffff01';
const SAMPLE_JSON = `{
  "name": "홍길동",
  "id": 1234,
  "email": "hong@example.com",
  "phones": [
    { "number": "010-1234-5678", "type": "MOBILE" },
    { "number": "02-123-4567", "type": "WORK" }
  ],
  "scores": { "math": 95, "eng": "9007199254740993" },
  "active": true,
  "rating": 4.5,
  "delta": -42,
  "avatar": "3q2+7w==",
  "tags": [1, 2, 300, -1]
}`;

/** Colorize the schema-less tree text. Every piece is escaped before wrapping. */
function rawHtml(text: string): string {
  return text
    .split('\n')
    .map((line) => {
      const m = line.match(/^(\s*)(\d+): <([\w-]+)> (.*)$/);
      if (m) {
        const cls = m[3] === 'string' ? 'string' : m[3] === 'message' || m[3] === 'group' ? 'punct' : m[3] === 'bytes' ? 'attr' : 'number';
        return `${m[1]}<span class="tok-key">${m[2]}</span><span class="tok-punct">: &lt;${escapeHtml(m[3])}&gt;</span> <span class="tok-${cls}">${escapeHtml(m[4])}</span>`;
      }
      return `<span class="tok-comment">${escapeHtml(line)}</span>`;
    })
    .join('\n');
}

function protobufTool(root: HTMLElement) {
  const saved = store.get('tool:protobuf-schema', { schema: SAMPLE_SCHEMA, type: 'demo.Person' });
  let schema: Schema | null = null;
  let msgType = saved.type;

  const schemaInput = textarea({ class: 'code short', value: saved.schema, 'aria-label': '.proto 스키마', placeholder: 'syntax = "proto3";\nmessage MyMessage { … }' });
  const typeSelect = h('select', { class: 'input', 'aria-label': '메시지 타입', onchange: () => ((msgType = typeSelect.value), persist(), ctx.refresh()) });
  const schemaErr = errorBox();
  const schemaMeta = h('span', { class: 'panel-meta' });
  const schemaPanel = panel('스키마 (.proto)', [
    schemaMeta,
    button('예시 스키마', () => {
      schemaInput.value = SAMPLE_SCHEMA;
      msgType = 'demo.Person';
      compile();
      ctx.refresh();
    }),
    field('메시지 타입', typeSelect, 'inline'),
  ], h('div', { class: 'output-wrap' }, schemaErr, schemaInput));
  schemaPanel.style.marginBottom = '14px';
  const persist = () => store.set('tool:protobuf-schema', { schema: schemaInput.value.length < 200_000 ? schemaInput.value : '', type: msgType });

  function compile() {
    persist();
    try {
      schema = parseSchema(schemaInput.value);
      if (!schema.types.includes(msgType)) msgType = schema.types[0];
      typeSelect.replaceChildren(...schema.types.map((t) => h('option', { value: t, selected: t === msgType }, t)));
      schemaMeta.textContent = `메시지 ${schema.types.length}개`;
      schemaErr.show(null);
    } catch (e) {
      schema = null;
      typeSelect.replaceChildren();
      schemaMeta.textContent = '';
      schemaErr.show((e as Error).message);
    }
  }
  const needType = () => {
    if (!schema) throw new Error('먼저 위에 올바른 .proto 스키마를 입력하세요.');
    return lookupType(schema, msgType);
  };

  root.append(schemaPanel);
  compile();
  const ctx = transformer(root, {
    id: 'protobuf',
    swap: true,
    wrap: false,
    maxInput: MAX_BYTES * 2 + 1000,
    onModeChange: (m) => (schemaPanel.hidden = m === 'raw'),
    modes: [
      {
        id: 'decode',
        label: '디코딩 → JSON',
        run: (s, o) => {
          const json = decodeWithSchema(needType(), parseBinary(s, String(o.informat)), { enumsAsNames: Boolean(o.enums) });
          const t = JSON.stringify(json, null, 2);
          return { text: t, html: highlightJson(t) };
        },
      },
      {
        id: 'encode',
        label: '인코딩 → 바이너리',
        run: (s, o) => formatBinary(encodeWithSchema(needType(), parseJson(s)), String(o.outformat)),
      },
      {
        id: 'raw',
        label: '스키마 없이',
        run: (s, o) => {
          const bytes = parseBinary(s, String(o.informat));
          if (bytes.length > 2 * 1024 * 1024) throw new Error('스키마 없는 분석은 2MB까지 지원합니다');
          const t = `총 ${bytes.length}바이트\n` + rawToText(decodeRaw(bytes));
          return { text: t, html: rawHtml(t) };
        },
      },
    ],
    options: [
      { id: 'informat', label: '입력 형식', type: 'select', default: 'auto', modes: ['decode', 'raw'], choices: [['auto', '자동 감지'], ['hex', 'Hex'], ['base64', 'Base64']] },
      { id: 'outformat', label: '출력 형식', type: 'select', default: 'hexsp', modes: ['encode'], choices: [['hexsp', 'Hex (공백)'], ['hex', 'Hex'], ['base64', 'Base64'], ['c', '0x.. 배열']] },
      { id: 'enums', label: 'enum을 이름으로', type: 'checkbox', default: true, modes: ['decode'] },
    ],
    placeholder: 'Hex(0a 09 ed …) 또는 Base64 바이너리, 인코딩 모드에서는 JSON',
    sample: (m) => (m === 'encode' ? SAMPLE_JSON : SAMPLE_HEX),
  });
  schemaInput.addEventListener('input', debounce(() => (compile(), ctx.refresh()), 250));
}

export const protobufTools: Tool[] = [
  {
    id: 'protobuf',
    name: 'Protobuf 디코더/인코더',
    category: 'encode',
    description: 'Protocol Buffers 바이너리를 .proto 스키마로 JSON 디코딩/인코딩하거나, 스키마 없이 필드 구조를 분석합니다.',
    keywords: ['protocol buffers', 'proto', 'protobuf', 'grpc', 'wire format', 'pb', '프로토버프'],
    render: protobufTool,
  },
];
