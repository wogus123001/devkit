// Byte-level helpers shared by encoders and hash tools.

const enc = new TextEncoder();
export const utf8 = (s: string): Uint8Array => enc.encode(s);

/** Strict UTF-8 decode; throws when the bytes are not valid text. */
export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function toHex(bytes: Uint8Array, sep = ''): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(sep);
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/0x/gi, '').replace(/[\s,:;-]/g, '');
  if (!/^[\da-fA-F]*$/.test(clean)) throw new Error('16진수가 아닌 문자가 포함되어 있습니다');
  if (clean.length % 2) throw new Error('16진수 자릿수가 홀수입니다 (바이트당 2자리 필요)');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function bytesToBase64(bytes: Uint8Array, urlSafe = false): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  const b64 = btoa(bin);
  return urlSafe ? b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : b64;
}

export function base64ToBytes(input: string): Uint8Array {
  let s = input.replace(/^data:[^,]*,/, '').replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('Base64에 사용할 수 없는 문자가 포함되어 있습니다');
  s = s.replace(/=+$/, '');
  if (s.length % 4 === 1) throw new Error('Base64 길이가 올바르지 않습니다');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decode bytes as UTF-8 when possible, otherwise describe them as hex. */
export function bytesToDisplay(bytes: Uint8Array): string {
  try {
    return fromUtf8(bytes);
  } catch {
    throw new Error(`결과가 UTF-8 텍스트가 아닌 바이너리입니다 (${bytes.length} bytes).\nHEX: ${toHex(bytes.subarray(0, 256), ' ')}${bytes.length > 256 ? ' …' : ''}`);
  }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(2)} MB`;
}
