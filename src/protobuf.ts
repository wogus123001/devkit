// Protocol Buffers wire-format codec.
//
// protobufjs is used ONLY to parse .proto text into reflection objects. Its own encode/decode
// generate code with Function(), which the production CSP forbids, so (de)serialization is done
// here by walking the reflection tree. Every read is bounds-checked; depth and output size are capped.
import protobuf from 'protobufjs';
import { bareObject } from './security';
import { base64ToBytes, bytesToBase64, fromHex, toHex } from './bytes';

export const MAX_BYTES = 10 * 1024 * 1024;
const MAX_DEPTH = 64; // protobuf's own default recursion limit is 100
const MAX_NODES = 50_000;

// ---------- input parsing ----------
/** Parse hex or base64 (auto-detected) into bytes. */
export function parseBinary(input: string, format: string): Uint8Array {
  const s = input.trim();
  if (!s) return new Uint8Array();
  let fmt = format;
  if (fmt === 'auto') {
    const compact = s.replace(/0x/gi, '').replace(/[\s,:\\x-]/g, '');
    fmt = /^[\da-fA-F]+$/.test(compact) && compact.length % 2 === 0 ? 'hex' : 'base64';
  }
  const bytes = fmt === 'hex' ? fromHex(s.replace(/\\x/gi, '')) : base64ToBytes(s);
  if (bytes.length > MAX_BYTES) throw new Error(`데이터가 너무 큽니다 (최대 ${MAX_BYTES / 1024 / 1024}MB)`);
  return bytes;
}

// ---------- reader ----------
const WIRE_NAMES = ['varint', 'fixed64', 'len', 'group-start', 'group-end', 'fixed32'];

class Reader {
  pos: number;
  private view: DataView;
  constructor(readonly buf: Uint8Array, pos = 0, readonly end = buf.length) {
    this.pos = pos;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  done() {
    return this.pos >= this.end;
  }
  varint(): bigint {
    let result = 0n;
    for (let i = 0; i < 10; i++) {
      if (this.pos >= this.end) throw new Error(`varint가 ${this.pos}번째 바이트에서 잘렸습니다`);
      const b = this.buf[this.pos++];
      result |= BigInt(b & 0x7f) << BigInt(7 * i);
      if (!(b & 0x80)) return result & 0xffffffffffffffffn;
    }
    throw new Error(`varint가 10바이트를 넘습니다 (${this.pos}번째 바이트)`);
  }
  need(n: number) {
    if (n < 0 || this.pos + n > this.end) throw new Error(`데이터가 부족합니다: ${this.pos}번째 바이트에서 ${n}바이트가 필요하지만 ${this.end - this.pos}바이트 남음`);
  }
  fixed32(): number {
    this.need(4);
    const v = this.view.getUint32(this.pos, true);
    this.pos += 4;
    return v;
  }
  fixed64(): bigint {
    this.need(8);
    const v = this.view.getBigUint64(this.pos, true);
    this.pos += 8;
    return v;
  }
  float(): number {
    this.need(4);
    const v = this.view.getFloat32(this.pos, true);
    this.pos += 4;
    return v;
  }
  double(): number {
    this.need(8);
    const v = this.view.getFloat64(this.pos, true);
    this.pos += 8;
    return v;
  }
  lenBytes(): Uint8Array {
    const n = this.varint();
    if (n > BigInt(this.end - this.pos)) throw new Error(`길이 ${n}이(가) 남은 데이터(${this.end - this.pos}바이트)보다 큽니다`);
    const len = Number(n);
    const out = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }
  tag(): { no: number; wire: number } {
    const t = this.varint();
    const no = Number(t >> 3n);
    const wire = Number(t & 7n);
    if (no < 1 || no > 0x1fffffff) throw new Error(`잘못된 필드 번호 ${no} (${this.pos}번째 바이트 근처)`);
    if (wire > 5) throw new Error(`잘못된 와이어 타입 ${wire} (필드 ${no})`);
    return { no, wire };
  }
  skip(wire: number, no: number, depth = 0) {
    if (wire === 0) this.varint();
    else if (wire === 1) this.need(8), (this.pos += 8);
    else if (wire === 2) this.lenBytes();
    else if (wire === 5) this.need(4), (this.pos += 4);
    else if (wire === 3) {
      if (depth > MAX_DEPTH) throw new Error('그룹 중첩이 너무 깊습니다');
      for (;;) {
        const t = this.tag();
        if (t.wire === 4) {
          if (t.no !== no) throw new Error(`그룹 종료 필드 번호가 맞지 않습니다 (${no} ≠ ${t.no})`);
          return;
        }
        this.skip(t.wire, t.no, depth + 1);
      }
    } else throw new Error(`예상하지 못한 그룹 종료 (필드 ${no})`);
  }
}

const zigzag = (v: bigint) => (v >> 1n) ^ -(v & 1n);
const toInt64 = (v: bigint) => BigInt.asIntN(64, v);
const isPrintable = (s: string) => s.length > 0 && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F�]/.test(s);

// ---------- schema-less decoding ----------
export interface RawNode {
  no: number;
  wire: string;
  /** Primary rendering, plus alternate readings of the same bytes. */
  value: string;
  alt?: string;
  children?: RawNode[];
}

function tryDecodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Decode bytes with no schema. Throws if the bytes are not a well-formed message. */
export function decodeRaw(buf: Uint8Array, depth = 0, budget = { left: MAX_NODES }): RawNode[] {
  if (depth > MAX_DEPTH) throw new Error(`메시지 중첩이 ${MAX_DEPTH}단계를 넘습니다`);
  const r = new Reader(buf);
  const out: RawNode[] = [];
  while (!r.done()) {
    if (--budget.left < 0) throw new Error(`필드가 너무 많습니다 (최대 ${MAX_NODES.toLocaleString()}개)`);
    const { no, wire } = r.tag();
    if (wire === 0) {
      const v = r.varint();
      const alts: string[] = [];
      if (toInt64(v) !== v) alts.push(`int64 ${toInt64(v)}`);
      alts.push(`sint ${zigzag(v)}`);
      if (v <= 1n) alts.push(`bool ${v === 1n}`);
      out.push({ no, wire: 'varint', value: v.toString(), alt: alts.join(' · ') });
    } else if (wire === 1) {
      const start = r.pos;
      const v = r.fixed64();
      r.pos = start;
      const d = r.double();
      out.push({ no, wire: 'fixed64', value: v.toString(), alt: `int64 ${toInt64(v)} · double ${d} · hex 0x${v.toString(16).padStart(16, '0')}` });
    } else if (wire === 5) {
      const start = r.pos;
      const v = r.fixed32();
      r.pos = start;
      const f = r.float();
      out.push({ no, wire: 'fixed32', value: String(v), alt: `int32 ${v | 0} · float ${f} · hex 0x${v.toString(16).padStart(8, '0')}` });
    } else if (wire === 2) {
      const bytes = r.lenBytes();
      out.push(describeLen(no, bytes, depth, budget));
    } else if (wire === 3) {
      const start = r.pos;
      r.skip(3, no, depth);
      const inner = buf.subarray(start, r.pos);
      // inner ends with the END_GROUP tag; decode the body only
      const children = decodeRaw(stripGroupEnd(inner, no), depth + 1, budget);
      out.push({ no, wire: 'group', value: `${children.length}개 필드`, children });
    } else throw new Error(`예상하지 못한 그룹 종료 태그 (필드 ${no})`);
  }
  return out;
}

function stripGroupEnd(inner: Uint8Array, no: number): Uint8Array {
  // The END_GROUP tag is the varint (no << 3 | 4) at the end.
  let tag = (BigInt(no) << 3n) | 4n;
  let len = 1;
  while (tag >= 0x80n) (tag >>= 7n), len++;
  return inner.subarray(0, inner.length - len);
}

function describeLen(no: number, bytes: Uint8Array, depth: number, budget: { left: number }): RawNode {
  const text = tryDecodeUtf8(bytes);
  let children: RawNode[] | null = null;
  if (bytes.length) {
    const saved = budget.left;
    try {
      children = decodeRaw(bytes, depth + 1, budget);
    } catch {
      children = null;
      budget.left = saved;
    }
  }
  // A nested message normally starts with a small tag byte (0x08, 0x0a, 0x12 …) that is a control
  // character as text; real strings almost never do. Prefer the message reading in that case.
  const looksLikeMessage = !!children?.length && bytes[0] < 0x20;
  if (text !== null && isPrintable(text) && !looksLikeMessage && (!children || isMostlyText(text)))
    return { no, wire: 'string', value: JSON.stringify(text), alt: children ? `중첩 메시지로도 해석 가능 (${children.length}개 필드)` : undefined };
  if (children && children.length)
    return { no, wire: 'message', value: `${children.length}개 필드 · ${bytes.length}바이트`, alt: text !== null && isPrintable(text) ? `문자열로도 해석 가능: ${JSON.stringify(text.slice(0, 60))}` : undefined, children };
  if (!bytes.length) return { no, wire: 'bytes', value: '(빈 값)' };
  const packed = tryPacked(bytes);
  return {
    no,
    wire: 'bytes',
    value: `[${bytes.length}] ${toHex(bytes.subarray(0, 64), ' ')}${bytes.length > 64 ? ' …' : ''}`,
    alt: [text !== null && text ? `UTF-8 ${JSON.stringify(text.slice(0, 80))}` : '', packed ? `packed varint [${packed}]` : '', `base64 ${bytesToBase64(bytes.subarray(0, 48))}${bytes.length > 48 ? '…' : ''}`].filter(Boolean).join(' · '),
  };
}

function isMostlyText(s: string): boolean {
  const letters = s.match(/[\p{L}\p{N}\s.,:;!?'"()\-_/@#]/gu)?.length ?? 0;
  return letters / s.length > 0.85;
}

function tryPacked(bytes: Uint8Array): string | null {
  if (!bytes.length || bytes.length > 4096) return null;
  try {
    const r = new Reader(bytes);
    const vals: string[] = [];
    while (!r.done()) vals.push(r.varint().toString());
    return vals.length > 1 ? vals.slice(0, 20).join(', ') + (vals.length > 20 ? ', …' : '') : null;
  } catch {
    return null;
  }
}

export function rawToText(nodes: RawNode[], indent = ''): string {
  return nodes
    .map((n) => {
      const head = `${indent}${n.no}: <${n.wire}> ${n.value}`;
      const alt = n.alt ? `${indent}    ↳ ${n.alt}` : '';
      const kids = n.children ? `\n${rawToText(n.children, indent + '  ')}` : '';
      return [head, alt].filter(Boolean).join('\n') + kids;
    })
    .join('\n');
}

// ---------- schema ----------
const WELL_KNOWN = /^google\/protobuf\/[\w]+\.proto$/;

export interface Schema {
  root: protobuf.Root;
  types: string[];
}

export function parseSchema(source: string): Schema {
  if (source.length > 1_000_000) throw new Error('스키마가 너무 큽니다 (최대 1MB)');
  const root = new protobuf.Root();
  let parsed: protobuf.IParserResult;
  try {
    parsed = protobuf.parse(source, root, { keepCase: true, alternateCommentMode: true });
  } catch (e) {
    throw new Error('.proto 문법 오류: ' + (e as Error).message);
  }
  for (const imp of [...(parsed.imports ?? []), ...(parsed.weakImports ?? [])]) {
    const def = WELL_KNOWN.test(imp) ? (protobuf.common as unknown as { get(f: string): { nested: Record<string, unknown> } | null }).get(imp) : null;
    if (!def) throw new Error(`import "${imp}"는 불러올 수 없습니다. google/protobuf 기본 타입만 지원하므로, 다른 파일의 메시지는 이 스키마에 함께 붙여 넣으세요.`);
    root.addJSON(def.nested as never);
  }
  try {
    root.resolveAll();
  } catch (e) {
    throw new Error('타입을 해석할 수 없습니다: ' + (e as Error).message);
  }
  const types: string[] = [];
  const walk = (ns: protobuf.NamespaceBase) => {
    for (const obj of ns.nestedArray) {
      if (obj instanceof protobuf.Type && !obj.fullName.startsWith('.google.protobuf.')) types.push(obj.fullName.replace(/^\./, ''));
      if (obj instanceof protobuf.Namespace || obj instanceof protobuf.Type) walk(obj as protobuf.NamespaceBase);
    }
  };
  walk(root);
  if (!types.length) throw new Error('스키마에 message 정의가 없습니다');
  return { root, types };
}

export function lookupType(schema: Schema, name: string): protobuf.Type {
  const t = schema.root.lookup(name);
  if (!(t instanceof protobuf.Type)) throw new Error(`메시지 타입 "${name}"을(를) 찾을 수 없습니다`);
  return t;
}

const INT_TYPES = new Set(['int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'bool']);
const F32 = new Set(['fixed32', 'sfixed32', 'float']);
const F64 = new Set(['fixed64', 'sfixed64', 'double']);

function wireTypeOf(type: string, resolved: protobuf.ReflectionObject | null): number {
  if (resolved instanceof protobuf.Enum) return 0;
  if (resolved instanceof protobuf.Type) return 2;
  if (INT_TYPES.has(type)) return 0;
  if (F32.has(type)) return 5;
  if (F64.has(type)) return 1;
  return 2; // string, bytes
}

interface FieldLike {
  name: string;
  id: number;
  type: string;
  repeated: boolean;
  resolvedType: protobuf.Type | protobuf.Enum | null;
  packed?: boolean;
  keyType?: string;
  hasPresence?: boolean;
}

/** proto3 implicit-presence fields holding their default value are not serialized (matches protoc/protobufjs). */
function isImplicitDefault(f: FieldLike, v: unknown): boolean {
  if (f.hasPresence !== false || f.repeated || isMap(f) || f.resolvedType instanceof protobuf.Type) return false;
  if (f.resolvedType instanceof protobuf.Enum) return v === 0 || v === '0' || (typeof v === 'string' && f.resolvedType.values[v] === 0 && Object.prototype.hasOwnProperty.call(f.resolvedType.values, v));
  if (typeof v === 'boolean') return v === false;
  if (typeof v === 'number') return v === 0 && !Object.is(v, -0);
  if (typeof v === 'string') return f.type === 'string' || f.type === 'bytes' ? v === '' : /^-?0+$/.test(v.trim());
  return false;
}
const isMap = (f: FieldLike) => typeof f.keyType === 'string';

// ---------- schema decode (binary → JSON) ----------
function readScalar(r: Reader, type: string, resolved: protobuf.ReflectionObject | null, enumsAsNames: boolean): unknown {
  if (resolved instanceof protobuf.Enum) {
    const n = Number(toInt64(r.varint()));
    return enumsAsNames ? resolved.valuesById[n] ?? n : n;
  }
  switch (type) {
    case 'int32': return Number(BigInt.asIntN(32, r.varint()));
    case 'uint32': return Number(BigInt.asUintN(32, r.varint()));
    case 'sint32': return Number(BigInt.asIntN(32, zigzag(r.varint())));
    case 'int64': return toInt64(r.varint()).toString();
    case 'uint64': return r.varint().toString();
    case 'sint64': return zigzag(r.varint()).toString();
    case 'bool': return r.varint() !== 0n;
    case 'fixed32': return r.fixed32();
    case 'sfixed32': return r.fixed32() | 0;
    case 'float': return r.float();
    case 'fixed64': return r.fixed64().toString();
    case 'sfixed64': return toInt64(r.fixed64()).toString();
    case 'double': return r.double();
    case 'string': {
      const b = r.lenBytes();
      const s = tryDecodeUtf8(b);
      if (s === null) throw new Error('string 필드에 올바르지 않은 UTF-8이 있습니다');
      return s;
    }
    case 'bytes': return bytesToBase64(r.lenBytes());
    default: throw new Error(`지원하지 않는 타입 ${type}`);
  }
}

const jsonNum = (v: number) => (Number.isFinite(v) ? v : String(v)); // NaN/Infinity → "NaN"/"Infinity" (JSON mapping)

export function decodeWithSchema(type: protobuf.Type, buf: Uint8Array, opts: { enumsAsNames: boolean }, depth = 0, budget = { left: MAX_NODES }): Record<string, unknown> {
  if (depth > MAX_DEPTH) throw new Error(`메시지 중첩이 ${MAX_DEPTH}단계를 넘습니다`);
  const r = new Reader(buf);
  const out = bareObject();
  const unknown: RawNode[] = [];
  while (!r.done()) {
    if (--budget.left < 0) throw new Error(`필드가 너무 많습니다 (최대 ${MAX_NODES.toLocaleString()}개)`);
    const start = r.pos;
    const { no, wire } = r.tag();
    const field = type.fieldsById[no] as unknown as FieldLike | undefined;
    if (!field) {
      r.skip(wire, no);
      try {
        unknown.push(...decodeRaw(buf.subarray(start, r.pos), depth + 1, budget));
      } catch {
        unknown.push({ no, wire: WIRE_NAMES[wire], value: toHex(buf.subarray(start, r.pos), ' ') });
      }
      continue;
    }
    const readOne = (rr: Reader): unknown => {
      if (field.resolvedType instanceof protobuf.Type) return decodeWithSchema(field.resolvedType, rr.lenBytes(), opts, depth + 1, budget);
      const v = readScalar(rr, field.type, field.resolvedType, opts.enumsAsNames);
      return typeof v === 'number' ? jsonNum(v) : v;
    };
    if (isMap(field)) {
      if (wire !== 2) throw new Error(`map 필드 "${field.name}"의 와이어 타입이 잘못되었습니다`);
      const entry = new Reader(r.lenBytes());
      let key: unknown = field.keyType === 'string' ? '' : field.keyType === 'bool' ? false : 0;
      let value: unknown = null;
      while (!entry.done()) {
        const t = entry.tag();
        if (t.no === 1) key = readScalar(entry, field.keyType!, null, false);
        else if (t.no === 2) value = readOne(entry);
        else entry.skip(t.wire, t.no);
      }
      const m = (out[field.name] ??= bareObject()) as Record<string, unknown>;
      m[String(key)] = value;
      continue;
    }
    const expected = wireTypeOf(field.type, field.resolvedType);
    if (field.repeated && wire === 2 && expected !== 2) {
      // packed repeated scalars
      const packed = new Reader(r.lenBytes());
      const arr = (out[field.name] ??= []) as unknown[];
      while (!packed.done()) arr.push(readOne(packed));
      continue;
    }
    if (wire !== expected) throw new Error(`필드 "${field.name}"(${no})의 와이어 타입 ${WIRE_NAMES[wire]}이(가) 스키마의 ${field.type}(${WIRE_NAMES[expected]})와 맞지 않습니다. 다른 메시지 타입을 선택해 보세요.`);
    const v = readOne(r);
    if (field.repeated) ((out[field.name] ??= []) as unknown[]).push(v);
    else out[field.name] = v;
  }
  if (unknown.length) out['@unknownFields'] = unknown.map((u) => ({ field: u.no, wire: u.wire, value: u.value }));
  return out;
}

// ---------- schema encode (JSON → binary) ----------
class Writer {
  private chunks: number[] = [];
  bytes(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
  get length() {
    return this.chunks.length;
  }
  varint(v: bigint) {
    let x = BigInt.asUintN(64, v);
    while (x >= 0x80n) {
      this.chunks.push(Number(x & 0x7fn) | 0x80);
      x >>= 7n;
    }
    this.chunks.push(Number(x));
  }
  tag(no: number, wire: number) {
    this.varint((BigInt(no) << 3n) | BigInt(wire));
  }
  raw(b: Uint8Array) {
    if (this.chunks.length + b.length > MAX_BYTES) throw new Error('인코딩 결과가 너무 큽니다');
    for (const x of b) this.chunks.push(x);
  }
  fixed(n: number, setter: (dv: DataView) => void) {
    const dv = new DataView(new ArrayBuffer(n));
    setter(dv);
    this.raw(new Uint8Array(dv.buffer));
  }
  lenDelimited(b: Uint8Array) {
    this.varint(BigInt(b.length));
    this.raw(b);
  }
}

function toBigInt(v: unknown, path: string): bigint {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error(`${path}: 정수가 아닙니다 (${v})`);
    if (!Number.isSafeInteger(v)) throw new Error(`${path}: ${v}는 JS 숫자 정밀도를 넘습니다. 64비트 값은 "문자열"로 적어 주세요.`);
    return BigInt(v);
  }
  if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) return BigInt(v.trim());
  if (typeof v === 'boolean') return v ? 1n : 0n;
  throw new Error(`${path}: 정수가 필요합니다 (받은 값: ${JSON.stringify(v)})`);
}

function checkRange(v: bigint, min: bigint, max: bigint, path: string, type: string): bigint {
  if (v < min || v > max) throw new Error(`${path}: ${v}는 ${type} 범위(${min} ~ ${max})를 벗어납니다`);
  return v;
}

function toFloat(v: unknown, path: string): number {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && ['NaN', 'Infinity', '-Infinity'].includes(v)) return Number(v);
  if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  throw new Error(`${path}: 숫자가 필요합니다 (받은 값: ${JSON.stringify(v)})`);
}

function writeScalar(w: Writer, type: string, resolved: protobuf.ReflectionObject | null, v: unknown, path: string) {
  if (resolved instanceof protobuf.Enum) {
    let n: number | undefined;
    if (typeof v === 'string' && !/^-?\d+$/.test(v)) {
      n = resolved.values[v];
      if (n === undefined || !Object.prototype.hasOwnProperty.call(resolved.values, v)) throw new Error(`${path}: enum ${resolved.name}에 "${v}" 값이 없습니다 (가능: ${Object.keys(resolved.values).join(', ')})`);
    } else n = Number(checkRange(toBigInt(v, path), -(2n ** 31n), 2n ** 31n - 1n, path, 'enum'));
    return w.varint(BigInt(n));
  }
  const I32: [bigint, bigint] = [-(2n ** 31n), 2n ** 31n - 1n];
  const U32: [bigint, bigint] = [0n, 2n ** 32n - 1n];
  const I64: [bigint, bigint] = [-(2n ** 63n), 2n ** 63n - 1n];
  const U64: [bigint, bigint] = [0n, 2n ** 64n - 1n];
  switch (type) {
    case 'int32': return w.varint(checkRange(toBigInt(v, path), ...I32, path, type));
    case 'uint32': return w.varint(checkRange(toBigInt(v, path), ...U32, path, type));
    case 'sint32': { const x = checkRange(toBigInt(v, path), ...I32, path, type); return w.varint((x << 1n) ^ (x >> 31n)); }
    case 'int64': return w.varint(checkRange(toBigInt(v, path), ...I64, path, type));
    case 'uint64': return w.varint(checkRange(toBigInt(v, path), ...U64, path, type));
    case 'sint64': { const x = checkRange(toBigInt(v, path), ...I64, path, type); return w.varint((x << 1n) ^ (x >> 63n)); }
    case 'bool':
      if (typeof v !== 'boolean') throw new Error(`${path}: true/false가 필요합니다`);
      return w.varint(v ? 1n : 0n);
    case 'fixed32': { const x = checkRange(toBigInt(v, path), ...U32, path, type); return w.fixed(4, (d) => d.setUint32(0, Number(x), true)); }
    case 'sfixed32': { const x = checkRange(toBigInt(v, path), ...I32, path, type); return w.fixed(4, (d) => d.setInt32(0, Number(x), true)); }
    case 'fixed64': { const x = checkRange(toBigInt(v, path), ...U64, path, type); return w.fixed(8, (d) => d.setBigUint64(0, x, true)); }
    case 'sfixed64': { const x = checkRange(toBigInt(v, path), ...I64, path, type); return w.fixed(8, (d) => d.setBigInt64(0, x, true)); }
    case 'float': { const x = toFloat(v, path); return w.fixed(4, (d) => d.setFloat32(0, x, true)); }
    case 'double': { const x = toFloat(v, path); return w.fixed(8, (d) => d.setFloat64(0, x, true)); }
    case 'string':
      if (typeof v !== 'string') throw new Error(`${path}: 문자열이 필요합니다`);
      return w.lenDelimited(new TextEncoder().encode(v));
    case 'bytes':
      if (typeof v !== 'string') throw new Error(`${path}: bytes는 Base64 문자열로 적어 주세요`);
      return w.lenDelimited(base64ToBytes(v));
    default:
      throw new Error(`${path}: 지원하지 않는 타입 ${type}`);
  }
}

const camel = (s: string) => s.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());

export function encodeWithSchema(type: protobuf.Type, obj: unknown, path = type.name, depth = 0): Uint8Array {
  if (depth > MAX_DEPTH) throw new Error(`${path}: 중첩이 ${MAX_DEPTH}단계를 넘습니다`);
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error(`${path}: 객체({ … })가 필요합니다`);
  const input = obj as Record<string, unknown>;
  const fields = type.fieldsArray as unknown as FieldLike[];
  const byName = new Map<string, FieldLike>();
  for (const f of fields) byName.set(f.name, f), byName.set(camel(f.name), f);
  for (const k of Object.keys(input)) if (!byName.has(k) && k !== '@unknownFields') throw new Error(`${path}: 스키마에 없는 필드 "${k}" (가능: ${fields.map((f) => f.name).join(', ')})`);

  const w = new Writer();
  for (const f of [...fields].sort((a, b) => a.id - b.id)) {
    const key = Object.prototype.hasOwnProperty.call(input, f.name) ? f.name : Object.prototype.hasOwnProperty.call(input, camel(f.name)) ? camel(f.name) : null;
    if (key === null) continue;
    const v = input[key];
    if (v === null || v === undefined) continue;
    const p = `${path}.${f.name}`;
    if (isImplicitDefault(f, v)) {
      writeScalar(new Writer(), f.type, f.resolvedType, v, p); // still validate the value
      continue;
    }
    const writeOne = (wr: Writer, val: unknown, pp: string, fieldNo: number) => {
      if (f.resolvedType instanceof protobuf.Type) {
        wr.tag(fieldNo, 2);
        wr.lenDelimited(encodeWithSchema(f.resolvedType, val, pp, depth + 1));
      } else {
        wr.tag(fieldNo, wireTypeOf(f.type, f.resolvedType));
        writeScalar(wr, f.type, f.resolvedType, val, pp);
      }
    };
    if (isMap(f)) {
      if (typeof v !== 'object' || Array.isArray(v)) throw new Error(`${p}: map은 객체({ "키": 값 })로 적어 주세요`);
      for (const [mk, mv] of Object.entries(v as object)) {
        const entry = new Writer();
        entry.tag(1, wireTypeOf(f.keyType!, null));
        writeScalar(entry, f.keyType!, null, f.keyType === 'bool' ? mk === 'true' : f.keyType === 'string' ? mk : mk, `${p}[${mk}]`);
        writeOne(entry, mv, `${p}[${mk}]`, 2);
        w.tag(f.id, 2);
        w.lenDelimited(entry.bytes());
      }
    } else if (f.repeated) {
      if (!Array.isArray(v)) throw new Error(`${p}: repeated 필드는 배열([ … ])이어야 합니다`);
      const scalarWire = f.resolvedType instanceof protobuf.Type ? 2 : wireTypeOf(f.type, f.resolvedType);
      if (f.packed && scalarWire !== 2 && v.length) {
        const inner = new Writer();
        v.forEach((x, i) => writeScalar(inner, f.type, f.resolvedType, x, `${p}[${i}]`));
        w.tag(f.id, 2);
        w.lenDelimited(inner.bytes());
      } else v.forEach((x, i) => writeOne(w, x, `${p}[${i}]`, f.id));
    } else writeOne(w, v, p, f.id);
  }
  return w.bytes();
}

export function formatBinary(bytes: Uint8Array, format: string): string {
  if (format === 'base64') return bytesToBase64(bytes);
  if (format === 'hex') return toHex(bytes);
  if (format === 'c') return Array.from(bytes, (b) => '0x' + b.toString(16).padStart(2, '0')).join(', ');
  return toHex(bytes, ' ');
}
