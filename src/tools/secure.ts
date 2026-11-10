import type { Tool } from '../types';
import bcrypt from 'bcryptjs';
import QRCode from 'qrcode';
import { base64ToBytes, bytesToBase64, utf8 } from '../bytes';
import { button, copyButton, debounce, errorBox, field, h, panel, segmented, select, textarea, transformer } from '../ui';

// ---------- shared ----------
function secretInput(placeholder: string, label: string): { wrap: HTMLElement; input: HTMLInputElement } {
  const input = h('input', { class: 'input mono grow', type: 'password', placeholder, 'aria-label': label, autocomplete: 'off', spellcheck: 'false' });
  const toggle = button('보기', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
    toggle.textContent = input.type === 'password' ? '보기' : '숨기기';
  });
  return { wrap: h('div', { class: 'row', style: { alignItems: 'center', flexWrap: 'nowrap' } }, input, toggle), input };
}

function downloadText(name: string, text: string) {
  // octet-stream so the blob (same origin) is always saved, never rendered.
  const url = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function humanDuration(sec: number): string {
  if (!Number.isFinite(sec) || sec > 1e15) return '사실상 불가능 (수억 년 이상)';
  if (sec < 1) return '즉시 (1초 미만)';
  const units: [number, string][] = [[31536000 * 100, '세기'], [31536000, '년'], [2592000, '개월'], [86400, '일'], [3600, '시간'], [60, '분'], [1, '초']];
  for (const [s, u] of units) if (sec >= s) return `약 ${Math.round(sec / s).toLocaleString()}${u}`;
  return '즉시';
}

// ---------- bcrypt ----------
const BCRYPT_RE = /^\$2[abxy]\$(\d{2})\$[./A-Za-z0-9]{53}$/;
function bcryptTool(root: HTMLElement) {
  let mode: 'hash' | 'verify' = 'hash';
  const pw = secretInput('비밀번호', '비밀번호');
  const rounds = select([['8', '8 (빠름)'], ['10', '10 (기본)'], ['12', '12 (권장)'], ['13', '13'], ['14', '14 (느림)']], '12', () => {});
  const hashIn = h('input', { class: 'input mono grow', placeholder: '$2b$12$…', 'aria-label': '검증할 bcrypt 해시', spellcheck: 'false' });
  const out = h('div', { class: 'result-list' });
  const err = errorBox();
  const hashRow = field('라운드(cost)', rounds, 'inline');
  const verifyRow = field('bcrypt 해시', hashIn, 'grow');
  verifyRow.hidden = true;
  const run = h('button', { class: 'btn btn-primary', type: 'button' }, '해시 생성');
  let busy = false;

  run.addEventListener('click', async () => {
    if (busy) return;
    err.show(null);
    out.replaceChildren();
    const p = pw.input.value;
    if (!p) return err.show('비밀번호를 입력하세요');
    const warn = bcrypt.truncates(p) ? h('div', { class: 'warn-box', style: { margin: '0' } }, '⚠ bcrypt는 앞 72바이트만 사용합니다. 이 비밀번호의 나머지 부분은 해시에 반영되지 않습니다.') : null;
    busy = true;
    run.disabled = true;
    const t0 = performance.now();
    try {
      if (mode === 'hash') {
        const hsh = await bcrypt.hash(p, Number(rounds.value));
        out.append(h('div', { class: 'result-row' }, h('span', { class: 'label' }, '해시'), h('span', { class: 'value' }, hsh), copyButton(() => hsh)));
      } else {
        const hv = hashIn.value.trim();
        const m = hv.match(BCRYPT_RE);
        if (!m) throw new Error('올바른 bcrypt 해시 형식이 아닙니다 ($2a$/$2b$/$2y$ + cost + 53자)');
        // A hostile hash with cost 31 would spin for days; real systems use 10–14.
        if (Number(m[1]) > 15) throw new Error(`cost ${m[1]}는 너무 큽니다 (최대 15까지 검증)`);
        const ok = await bcrypt.compare(p, hv);
        out.append(h('div', { class: ok ? 'note' : 'error-box', style: ok ? { color: 'var(--ok)', fontWeight: '600', fontSize: '16px' } : { margin: '0' } }, ok ? '✓ 일치합니다' : '✗ 일치하지 않습니다'));
      }
      out.append(h('div', { class: 'note' }, `처리 시간 ${Math.round(performance.now() - t0)}ms`));
      if (warn) out.prepend(warn);
    } catch (e) {
      err.show((e as Error).message);
    } finally {
      busy = false;
      run.disabled = false;
    }
  });

  root.append(
    h('div', { class: 'stack', style: { maxWidth: '820px' } },
      segmented([['hash', '해시 생성'], ['verify', '검증']], mode, (v) => {
        mode = v;
        hashRow.hidden = v !== 'hash';
        verifyRow.hidden = v !== 'verify';
        run.textContent = v === 'hash' ? '해시 생성' : '검증';
        out.replaceChildren();
      }),
      field('비밀번호', pw.wrap),
      hashRow,
      verifyRow,
      h('div', { class: 'row' }, run),
      err,
      out,
      h('p', { class: 'note' }, '라운드가 1 늘 때마다 계산 시간이 2배가 됩니다. 비밀번호는 저장되거나 전송되지 않습니다.'),
    ),
  );
}

// ---------- AES-GCM ----------
// Payload: "DKA1" | iterations (u32 BE) | salt(16) | iv(12) | ciphertext+tag, then Base64.
const MAGIC = [0x44, 0x4b, 0x41, 0x31];
const DEFAULT_ITER = 600_000; // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
const MAX_ITER = 5_000_000;

async function deriveKey(pass: string, salt: Uint8Array, iter: number): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', utf8(pass) as BufferSource, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function aesEncrypt(text: string, pass: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pass, salt, DEFAULT_ITER);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(text) as BufferSource));
  const head = new Uint8Array(8);
  head.set(MAGIC);
  new DataView(head.buffer).setUint32(4, DEFAULT_ITER);
  const all = new Uint8Array(head.length + 16 + 12 + ct.length);
  all.set(head);
  all.set(salt, 8);
  all.set(iv, 24);
  all.set(ct, 36);
  return bytesToBase64(all);
}

async function aesDecrypt(b64: string, pass: string): Promise<string> {
  const all = base64ToBytes(b64.trim());
  if (all.length < 36 + 16 || MAGIC.some((b, i) => all[i] !== b)) throw new Error('DevKit AES 형식(DKA1)의 암호문이 아닙니다');
  const iter = new DataView(all.buffer, all.byteOffset).getUint32(4);
  if (iter < 1000 || iter > MAX_ITER) throw new Error(`반복 횟수 ${iter}가 허용 범위를 벗어납니다`);
  const key = await deriveKey(pass, all.subarray(8, 24), iter);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.subarray(24, 36) as BufferSource }, key, all.subarray(36) as BufferSource);
    return new TextDecoder().decode(pt);
  } catch {
    throw new Error('복호화 실패: 비밀번호가 틀렸거나 암호문이 변조되었습니다');
  }
}

function aesTool(root: HTMLElement) {
  let mode: 'enc' | 'dec' = 'enc';
  const pass = secretInput('비밀번호 (passphrase)', '비밀번호');
  const input = textarea({ class: 'code short', placeholder: '암호화할 텍스트', 'aria-label': '입력' });
  const output = textarea({ class: 'code short', readonly: true, 'aria-label': '결과' });
  const err = errorBox();
  const go = h('button', { class: 'btn btn-primary', type: 'button' }, '암호화');
  go.addEventListener('click', async () => {
    err.show(null);
    output.value = '';
    if (!pass.input.value) return err.show('비밀번호를 입력하세요');
    if (!input.value) return err.show('입력이 비어 있습니다');
    if (input.value.length > 5_000_000) return err.show('입력이 너무 큽니다');
    go.disabled = true;
    try {
      output.value = mode === 'enc' ? await aesEncrypt(input.value, pass.input.value) : await aesDecrypt(input.value, pass.input.value);
    } catch (e) {
      err.show((e as Error).message);
    } finally {
      go.disabled = false;
    }
  });
  root.append(
    h('div', { class: 'stack' },
      h('div', { class: 'toolbar', style: { marginBottom: '0' } },
        segmented([['enc', '암호화'], ['dec', '복호화']], mode, (v) => {
          mode = v;
          go.textContent = v === 'enc' ? '암호화' : '복호화';
          input.placeholder = v === 'enc' ? '암호화할 텍스트' : 'DKA1 암호문 (Base64)';
          [input.value, output.value] = [output.value, ''];
        }),
      ),
      field('비밀번호', pass.wrap),
      h('div', { class: 'io-grid' }, panel('입력', [], input), panel('결과', [copyButton(() => output.value)], output)),
      h('div', { class: 'row' }, go),
      err,
      h('p', { class: 'note' }, `AES-256-GCM과 PBKDF2-SHA256(${DEFAULT_ITER.toLocaleString()}회, 랜덤 salt·IV)을 사용합니다. GCM 인증 태그로 변조를 감지합니다. 결과 형식은 DevKit 전용(DKA1)이므로 다른 도구의 AES 결과와는 호환되지 않습니다. 비밀번호를 잊으면 복구할 수 없습니다.`),
    ),
  );
}

// ---------- RSA key pair ----------
function toPem(der: ArrayBuffer, label: string): string {
  const b64 = bytesToBase64(new Uint8Array(der));
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----\n`;
}

function rsaTool(root: HTMLElement) {
  const bits = select([['2048', '2048비트'], ['3072', '3072비트 (권장)'], ['4096', '4096비트']], '3072', () => {});
  const usage = select([['RSA-OAEP', '암호화 (RSA-OAEP)'], ['RSASSA-PKCS1-v1_5', '서명 (RS256)'], ['RSA-PSS', '서명 (PS256)']], 'RSA-OAEP', () => {});
  const fmt = select([['pem', 'PEM'], ['jwk', 'JWK (JSON)']], 'pem', () => {});
  const pub = textarea({ class: 'code short', readonly: true, 'aria-label': '공개키' });
  const priv = textarea({ class: 'code short', readonly: true, 'aria-label': '개인키' });
  const status = h('span', { class: 'note' });
  const gen = h('button', { class: 'btn btn-primary', type: 'button' }, '키 생성');
  gen.addEventListener('click', async () => {
    gen.disabled = true;
    status.textContent = '생성 중…';
    const t0 = performance.now();
    try {
      const alg = usage.value;
      const kp = await crypto.subtle.generateKey(
        { name: alg, modulusLength: Number(bits.value), publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        alg === 'RSA-OAEP' ? ['encrypt', 'decrypt'] : ['sign', 'verify'],
      );
      if (fmt.value === 'jwk') {
        pub.value = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.publicKey), null, 2);
        priv.value = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey), null, 2);
      } else {
        pub.value = toPem(await crypto.subtle.exportKey('spki', kp.publicKey), 'PUBLIC KEY');
        priv.value = toPem(await crypto.subtle.exportKey('pkcs8', kp.privateKey), 'PRIVATE KEY');
      }
      status.textContent = `${bits.value}비트 키 생성 완료 (${Math.round(performance.now() - t0)}ms)`;
    } catch (e) {
      status.textContent = '생성 실패: ' + (e as Error).message;
    } finally {
      gen.disabled = false;
    }
  });
  const ext = () => (fmt.value === 'jwk' ? 'json' : 'pem');
  root.append(
    h('div', { class: 'stack' },
      h('div', { class: 'toolbar', style: { marginBottom: '0' } }, field('크기', bits, 'inline'), field('용도', usage, 'inline'), field('형식', fmt, 'inline'), gen, status),
      h('div', { class: 'io-grid' },
        panel('공개키 (public)', [button('저장', () => pub.value && downloadText(`public.${ext()}`, pub.value)), copyButton(() => pub.value)], pub),
        panel('개인키 (private)', [button('저장', () => priv.value && downloadText(`private.${ext()}`, priv.value)), copyButton(() => priv.value)], priv),
      ),
      h('p', { class: 'note' }, '브라우저의 Web Crypto API로 이 기기에서만 생성되며, 키는 저장되거나 전송되지 않습니다. 개인키는 절대 공유하지 마세요.'),
    ),
  );
}

// ---------- TOTP ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let bits = 0, value = 0;
  for (const c of clean) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error(`Base32에 사용할 수 없는 문자: "${c}"`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
function base32Encode(b: Uint8Array): string {
  let bits = 0, value = 0, out = '';
  for (const x of b) {
    value = (value << 8) | x;
    bits += 8;
    while (bits >= 5) (out += B32[(value >>> (bits - 5)) & 31]), (bits -= 5);
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

async function hotp(key: Uint8Array, counter: number, digits: number, hash: string): Promise<string> {
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const k = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
  const off = mac[mac.length - 1] & 0xf;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

function totpTool(root: HTMLElement): () => void {
  const secret = h('input', { class: 'input mono grow', value: base32Encode(crypto.getRandomValues(new Uint8Array(20))), 'aria-label': 'Base32 시크릿', spellcheck: 'false', autocomplete: 'off' });
  const issuer = h('input', { class: 'input grow', value: 'DevKit', 'aria-label': '발급자' });
  const account = h('input', { class: 'input grow', value: 'user@example.com', 'aria-label': '계정' });
  const digits = select([['6', '6자리'], ['8', '8자리']], '6', () => tick());
  const period = select([['30', '30초'], ['60', '60초']], '30', () => tick());
  const algo = select([['SHA-1', 'SHA1 (표준)'], ['SHA-256', 'SHA256'], ['SHA-512', 'SHA512']], 'SHA-1', () => tick());
  const code = h('div', { class: 'big-time', style: { fontSize: '40px', letterSpacing: '0.12em' } });
  const remain = h('div', { class: 'note' });
  const bar = h('div', { class: 'strength' }, h('div', { style: { background: 'var(--accent)' } }));
  const neighbours = h('div', { class: 'note' });
  const err = errorBox();
  const canvas = h('canvas');
  const uriOut = h('div', { class: 'value', style: { fontFamily: 'var(--mono)', fontSize: '12px', wordBreak: 'break-all' } });
  const verify = h('input', { class: 'input mono', placeholder: '코드 검증', 'aria-label': '검증할 코드', style: { width: '140px' } });
  const verifyOut = h('span', { class: 'note' });
  let uri = '';

  async function tick() {
    try {
      const key = base32Decode(secret.value);
      if (key.length < 10) throw new Error('시크릿이 너무 짧습니다 (최소 80비트 = Base32 16자 권장)');
      const p = Number(period.value), d = Number(digits.value);
      const now = Date.now() / 1000;
      const ctr = Math.floor(now / p);
      const [prev, cur, next] = await Promise.all([hotp(key, ctr - 1, d, algo.value), hotp(key, ctr, d, algo.value), hotp(key, ctr + 1, d, algo.value)]);
      code.textContent = cur.replace(/(\d{3})(?=\d)/g, '$1 ');
      const left = p - (now % p);
      remain.textContent = `${Math.ceil(left)}초 후 변경`;
      (bar.firstElementChild as HTMLElement).style.width = `${(left / p) * 100}%`;
      neighbours.textContent = `이전 ${prev} · 다음 ${next}`;
      const v = verify.value.replace(/\s/g, '');
      verifyOut.textContent = v ? ([prev, cur, next].includes(v) ? '✓ 유효 (±1 구간 허용)' : '✗ 일치하지 않음') : '';
      err.show(null);
    } catch (e) {
      code.textContent = '------';
      err.show((e as Error).message);
    }
  }
  const renderQr = debounce(async () => {
    const label = encodeURIComponent(`${issuer.value}:${account.value}`);
    uri = `otpauth://totp/${label}?secret=${secret.value.replace(/[\s=]/g, '').toUpperCase()}&issuer=${encodeURIComponent(issuer.value)}&algorithm=${algo.value.replace('-', '')}&digits=${digits.value}&period=${period.value}`;
    uriOut.textContent = uri;
    try {
      await QRCode.toCanvas(canvas, uri, { width: 220, margin: 2, errorCorrectionLevel: 'M' });
    } catch {
      /* invalid secret is reported by tick() */
    }
  }, 200);
  [secret, issuer, account].forEach((el) => el.addEventListener('input', () => (tick(), renderQr())));
  [digits, period, algo].forEach((el) => el.addEventListener('change', () => renderQr()));
  verify.addEventListener('input', tick);
  const timer = setInterval(tick, 1000);
  tick();
  renderQr();

  root.append(
    h('div', { class: 'io-grid' },
      h('div', { class: 'stack' },
        field('시크릿 (Base32)', h('div', { class: 'row', style: { flexWrap: 'nowrap' } }, secret, button('새로 생성', () => ((secret.value = base32Encode(crypto.getRandomValues(new Uint8Array(20)))), tick(), renderQr())))),
        h('div', { class: 'row' }, field('발급자', issuer, 'grow'), field('계정', account, 'grow')),
        h('div', { class: 'toolbar' }, field('자릿수', digits, 'inline'), field('주기', period, 'inline'), field('알고리즘', algo, 'inline')),
        err,
        panel('현재 코드', [copyButton(() => (code.textContent ?? '').replace(/\s/g, ''))], h('div', { class: 'panel-body stack', style: { gap: '8px' } }, code, bar, remain, neighbours, h('div', { class: 'row', style: { alignItems: 'center' } }, verify, verifyOut))),
      ),
      panel('인증 앱 등록 QR', [copyButton(() => uri, 'URI 복사')], h('div', { class: 'qr-out stack' }, canvas, uriOut)),
    ),
    h('p', { class: 'note' }, 'RFC 6238 TOTP. Google Authenticator 등 인증 앱과 호환됩니다. 시크릿은 저장되지 않으므로 실제 서비스용 시크릿은 다른 곳에 안전하게 보관하세요.'),
  );
  return () => clearInterval(timer);
}

// ---------- password strength ----------
const COMMON = 'password,123456,123456789,12345678,12345,qwerty,abc123,football,1234567,monkey,111111,letmein,1234,1234567890,dragon,baseball,sunshine,iloveyou,trustno1,princess,adobe123,123123,welcome,login,admin,qwerty123,solo,1q2w3e4r,master,666666,photoshop,1qaz2wsx,qwertyuiop,ashley,mustang,121212,starwars,654321,bailey,access,flower,555555,passw0rd,shadow,lovely,7777777,michael,!@#$%^&*,jesus,password1,superman,hello,charlie,888888,696969,hottie,freedom,aa123456,qazwsx,ninja,azerty,loveme,whatever,donald,batman,zaq1zaq1,000000,qwer1234,asdf1234,q1w2e3r4,zxcvbnm,asdfgh,1q2w3e,gkswlsdl,dkssud,tkfkdgo,qwe123,a123456,abcd1234,p@ssw0rd,admin123,root,toor,test,guest,changeme'.split(',');
const KEYBOARD = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', '1qaz2wsx3edc', 'qazwsxedc'];

function analyse(pw: string) {
  const notes: string[] = [];
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^\w\s]|_/.test(pw)) pool += 33;
  if (/\s/.test(pw)) pool += 1;
  if (/[^\x00-\x7f]/.test(pw)) pool += 100;
  // Compress predictable structure before counting length.
  let s = pw.toLowerCase();
  const lowered = s.replace(/[0-9!@#$%^&*._-]+$/, '').replace(/[@4]/g, 'a').replace(/0/g, 'o').replace(/[1!]/g, 'i').replace(/3/g, 'e').replace(/\$/g, 's');
  if (COMMON.includes(pw.toLowerCase()) || COMMON.includes(lowered)) notes.push('자주 쓰이는 비밀번호 목록에 있습니다');
  if (/(.)\1{2,}/.test(s)) notes.push('같은 문자가 반복됩니다');
  s = s.replace(/(.)\1{2,}/g, '$1');
  let seqFound = false;
  for (const row of KEYBOARD)
    for (let len = row.length; len >= 4; len--)
      for (let i = 0; i + len <= row.length; i++) {
        const frag = row.slice(i, i + len);
        if (s.includes(frag) || s.includes([...frag].reverse().join(''))) {
          s = s.replace(frag, frag[0]);
          seqFound = true;
        }
      }
  s = s.replace(/(?:abc|bcd|cde|def|efg|fgh|xyz|012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210)+/g, (m) => ((seqFound = true), m[0]));
  if (seqFound) notes.push('키보드 배열이나 연속된 문자/숫자가 있습니다');
  if (/(19|20)\d{2}|\d{6}/.test(pw)) notes.push('연도나 생년월일로 보이는 숫자가 있습니다');
  if (pw.length < 12) notes.push('12자 이상을 권장합니다');
  if (pool && pool <= 26) notes.push('한 종류의 문자만 사용합니다');
  let bits = s.length * Math.log2(Math.max(pool, 1));
  if (notes[0]?.startsWith('자주')) bits = Math.min(bits, 10);
  return { bits: Math.max(0, Math.round(bits)), notes };
}

function strengthTool(root: HTMLElement) {
  const pw = secretInput('분석할 비밀번호', '비밀번호');
  const meter = h('div', { class: 'strength', style: { height: '10px' } }, h('div'));
  const label = h('div', { style: { fontWeight: '600', fontSize: '18px' } });
  const table = h('table', { class: 'kv' });
  const notes = h('ul', { class: 'note', style: { margin: '0', paddingLeft: '20px' } });
  const update = () => {
    const v = pw.input.value;
    if (!v) return label.replaceChildren(), table.replaceChildren(), notes.replaceChildren(), ((meter.firstElementChild as HTMLElement).style.width = '0');
    const { bits, notes: n } = analyse(v);
    const guesses = 2 ** Math.min(bits, 300) / 2;
    const [txt, color, pct] = bits < 28 ? ['매우 약함', '#dc2626', 10] : bits < 40 ? ['약함', '#ea580c', 30] : bits < 60 ? ['보통', '#ca8a04', 55] : bits < 80 ? ['강함', '#16a34a', 80] : ['매우 강함', '#0f766e', 100];
    const bar = meter.firstElementChild as HTMLElement;
    bar.style.width = pct + '%';
    bar.style.background = color;
    label.textContent = txt;
    label.style.color = color;
    const row = (k: string, val: string) => h('tr', null, h('th', null, k), h('td', null, val));
    table.replaceChildren(
      row('길이', `${[...v].length}자`),
      row('추정 엔트로피', `약 ${bits}비트`),
      row('온라인 공격 (초당 100회)', humanDuration(guesses / 100)),
      row('오프라인 – bcrypt 해시 (초당 1만 회)', humanDuration(guesses / 1e4)),
      row('오프라인 – 빠른 해시 (초당 100억 회)', humanDuration(guesses / 1e10)),
    );
    notes.replaceChildren(...(n.length ? n : ['특별한 약점이 발견되지 않았습니다']).map((t) => h('li', null, t)));
  };
  pw.input.addEventListener('input', update);
  root.append(
    h('div', { class: 'stack', style: { maxWidth: '760px' } },
      field('비밀번호', pw.wrap), meter, label, table, notes,
      h('p', { class: 'note' }, '입력값은 이 브라우저 안에서만 분석되며 저장·전송되지 않습니다. 추정치는 참고용이며, 서비스마다 다른 비밀번호를 쓰는 것이 가장 중요합니다.'),
    ),
  );
}

// ---------- sensitive data masking ----------
const luhn = (d: string) => {
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2) n = n * 2 > 9 ? n * 2 - 9 : n * 2;
    sum += n;
  }
  return sum % 10 === 0;
};
const RULES: { id: string; label: string; re: RegExp; mask: (m: string, ...g: string[]) => string | null }[] = [
  { id: 'pem', label: '개인키 블록', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, mask: () => '-----[개인키 삭제됨]-----' },
  { id: 'jwt', label: 'JWT', re: /\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]*/g, mask: (m) => m.slice(0, 10) + '…[JWT 마스킹]' },
  { id: 'aws', label: 'AWS 액세스 키', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, mask: (m) => m.slice(0, 4) + '*'.repeat(12) + m.slice(-4) },
  {
    id: 'secret',
    label: '키/토큰/비밀번호 값',
    re: /\b(api[_-]?key|secret|token|access[_-]?token|password|passwd|pwd|authorization)(["']?\s*[:=]\s*["']?)((?:bearer|basic)\s+)?([^\s"',;&]{4,})/gi,
    // Values already masked by an earlier rule (e.g. JWT) are left alone.
    mask: (_m, k, sep, scheme, v) => (v.includes('[') || /^\*+$|\*{4}/.test(v) ? null : `${k}${sep}${scheme ?? ''}${v.slice(0, 2)}${'*'.repeat(Math.min(12, Math.max(4, v.length - 2)))}`),
  },
  { id: 'bearer', label: 'Bearer 토큰', re: /\bBearer\s+[\w\-.~+/]{10,}=*/g, mask: (m) => 'Bearer ' + m.slice(7, 11) + '****' },
  { id: 'rrn', label: '주민등록번호', re: /\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))-?([1-8])\d{6}\b/g, mask: (_m, a, b) => `${a}-${b}******` },
  { id: 'card', label: '카드 번호', re: /\b(?:\d[ -]?){13,19}\b/g, mask: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d) ? m.replace(/\d(?=(?:\D*\d){4})/g, '*') : null; } },
  { id: 'phone', label: '전화번호', re: /\b(01[016789]|0[2-6]\d?)[-. ]?(\d{3,4})[-. ]?(\d{4})\b/g, mask: (_m, a, _b, c) => `${a}-****-${c}` },
  { id: 'email', label: '이메일', re: /\b([\w.+-])([\w.+-]*)@([\w-]+(?:\.[\w-]+)+)\b/g, mask: (_m, f, rest, d) => `${f}${'*'.repeat(Math.min(6, Math.max(2, rest.length)))}@${d}` },
  { id: 'ip', label: 'IPv4 주소', re: /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, mask: (_m, a, b) => `${a}.${b}.*.*` },
];

export const secureTools: Tool[] = [
  { id: 'bcrypt', name: 'Bcrypt 해시/검증', category: 'crypto', description: '비밀번호를 bcrypt로 해시하거나, 비밀번호와 bcrypt 해시가 일치하는지 검증합니다.', keywords: ['bcrypt', 'password hash', '비밀번호 해시', 'blowfish'], render: bcryptTool },
  { id: 'aes', name: 'AES 암호화/복호화', category: 'crypto', description: '비밀번호로 텍스트를 AES-256-GCM 암호화하고 복호화합니다. PBKDF2로 키를 만들고 변조를 감지합니다.', keywords: ['aes', 'encrypt', 'decrypt', '암호화', '복호화', 'gcm', 'pbkdf2'], render: aesTool },
  { id: 'rsa', name: 'RSA 키 쌍 생성', category: 'crypto', description: 'RSA 공개키/개인키 쌍을 브라우저에서 생성하고 PEM 또는 JWK로 내보냅니다.', keywords: ['rsa', 'key pair', 'pem', 'jwk', 'public key', 'private key', '공개키', '개인키'], render: rsaTool },
  { id: 'totp', name: 'OTP (TOTP) 생성기', category: 'crypto', description: '2단계 인증용 TOTP 코드를 생성·검증하고, 인증 앱 등록용 QR 코드를 만듭니다.', keywords: ['otp', 'totp', '2fa', 'mfa', 'google authenticator', '2단계 인증', 'otpauth'], render: totpTool },
  { id: 'password-strength', name: '비밀번호 강도 분석', category: 'crypto', description: '비밀번호의 엔트로피와 공격 유형별 예상 해독 시간을 계산하고 약점을 알려줍니다.', keywords: ['password strength', 'entropy', 'crack time', '비밀번호 강도'], render: strengthTool },
  {
    id: 'mask',
    name: '민감정보 마스킹',
    category: 'crypto',
    description: '로그나 텍스트에서 이메일, 전화번호, 주민등록번호, 카드 번호, 토큰, 키 등을 찾아 가립니다.',
    keywords: ['mask', 'redact', 'obfuscate', 'pii', '개인정보', '마스킹', 'secret'],
    render: (root) => {
      const counts = h('div', { class: 'note' });
      transformer(root, {
        id: 'mask',
        modes: [
          {
            id: 'auto',
            label: '자동 감지',
            run: (s, o) => {
              const found: string[] = [];
              let out = s;
              for (const r of RULES) {
                if (!o[r.id]) continue;
                let n = 0;
                out = out.replace(r.re, (...args) => {
                  const m = args[0] as string;
                  const res = r.mask(m, ...(args.slice(1, -2) as string[]));
                  if (res === null) return m;
                  n++;
                  return res;
                });
                if (n) found.push(`${r.label} ${n}`);
              }
              counts.textContent = found.length ? '가린 항목: ' + found.join(', ') : '감지된 민감정보가 없습니다';
              return out;
            },
          },
          {
            id: 'manual',
            label: '앞뒤만 남기기',
            run: (s, o) => {
              counts.textContent = '';
              return s.split('\n').map((line) => {
                const chars = [...line];
                const keepS = Number(o.start), keepE = Number(o.end);
                if (chars.length <= keepS + keepE) return line;
                return chars.map((c, i) => (i < keepS || i >= chars.length - keepE || (o.spaces && /\s/.test(c)) ? c : String(o.char || '*'))).join('');
              }).join('\n');
            },
          },
        ],
        options: [
          ...RULES.map((r) => ({ id: r.id, label: r.label, type: 'checkbox' as const, default: r.id !== 'ip', modes: ['auto'] })),
          { id: 'start', label: '앞', type: 'number', default: 4, min: 0, max: 100, modes: ['manual'] },
          { id: 'end', label: '뒤', type: 'number', default: 4, min: 0, max: 100, modes: ['manual'] },
          { id: 'char', label: '문자', type: 'select', default: '*', choices: [['*', '*'], ['•', '•'], ['x', 'x'], ['#', '#']], modes: ['manual'] },
          { id: 'spaces', label: '공백 유지', type: 'checkbox', default: true, modes: ['manual'] },
        ],
        sample: `2026-11-10 12:00:01 INFO login user=hong.gildong@example.com phone=010-1234-5678 ip=203.0.113.42
2026-11-10 12:00:02 DEBUG Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123def
2026-11-10 12:00:03 WARN payment card=4111 1111 1111 1111 rrn=900101-1234567 api_key="sk_live_51HxYzAbCdEf"
aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
      });
      root.querySelector('.io-grid')?.after(counts);
    },
  },
];

