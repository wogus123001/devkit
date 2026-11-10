// Static pages (about, privacy, licenses, 404). Text only, built with h() like every tool.
import { h } from './ui';
import { CONTACT, SITE_NAME } from './site';

const EFFECTIVE_DATE = '2026년 11월 10일';

const LICENSES: [name: string, license: string, url: string][] = [
  ['@noble/hashes', 'MIT', 'https://github.com/paulmillr/noble-hashes'],
  ['bcryptjs', 'BSD-3-Clause', 'https://github.com/dcodeIO/bcrypt.js'],
  ['cronstrue', 'MIT', 'https://github.com/bradymholt/cRonstrue'],
  ['diff (jsdiff)', 'BSD-3-Clause', 'https://github.com/kpdecker/jsdiff'],
  ['DOMPurify', 'MPL-2.0 또는 Apache-2.0', 'https://github.com/cure53/DOMPurify'],
  ['js-md5', 'MIT', 'https://github.com/emn178/js-md5'],
  ['marked', 'MIT', 'https://github.com/markedjs/marked'],
  ['protobuf.js', 'BSD-3-Clause', 'https://github.com/protobufjs/protobuf.js'],
  ['node-qrcode', 'MIT', 'https://github.com/soldair/node-qrcode'],
  ['smol-toml', 'BSD-3-Clause', 'https://github.com/squirrelchat/smol-toml'],
  ['sql-formatter', 'MIT', 'https://github.com/sql-formatter-org/sql-formatter'],
  ['yaml', 'ISC', 'https://github.com/eemeli/yaml'],
];

const ext = (href: string, text: string) => h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);

function head(title: string, lead?: string) {
  return h('div', { class: 'hero' }, h('h1', null, title), lead ? h('p', null, lead) : null);
}

function about(): Node[] {
  return [
    head(`${SITE_NAME} 소개`, '개발자가 자주 찾는 도구를 한곳에 모았습니다.'),
    h('div', { class: 'prose' },
      h('h2', null, '무엇을 할 수 있나요'),
      h('p', null, 'Base64·URL·JWT 디코딩, JSON/YAML/SQL 포맷팅, 정규식 테스트, 해시 계산, UUID·QR 코드 생성 등 개발 중에 자주 필요한 작업을 설치 없이 바로 할 수 있습니다.'),
      h('h2', null, '데이터는 브라우저 밖으로 나가지 않습니다'),
      h('p', null, '모든 도구는 브라우저 안에서만 동작합니다. 입력한 값은 서버로 전송되지 않으며, 페이지의 보안 정책(CSP)이 외부로의 네트워크 요청 자체를 막고 있습니다.'),
      h('h2', null, '면책'),
      h('p', null, '도구의 결과는 정확하도록 노력하지만 보장하지는 않습니다. 중요한 작업에는 결과를 한 번 더 확인해 주세요.'),
      CONTACT ? h('h2', null, '문의') : null,
      CONTACT ? h('p', null, ext(CONTACT.href, CONTACT.label)) : null,
      h('p', null, h('a', { href: '/privacy' }, '개인정보처리방침'), ' · ', h('a', { href: '/licenses' }, '오픈소스 라이선스')),
    ),
  ];
}

function privacy(): Node[] {
  return [
    head('개인정보처리방침', `시행일: ${EFFECTIVE_DATE}`),
    h('div', { class: 'prose' },
      h('h2', null, '1. 수집하는 개인정보'),
      h('p', null, `${SITE_NAME}은 회원가입이 없으며 이름, 이메일 등 개인정보를 수집하지 않습니다.`),
      h('h2', null, '2. 도구 입력값'),
      h('p', null, '도구에 입력한 값은 브라우저 안에서만 처리되고 서버로 전송되지 않습니다.'),
      h('h2', null, '3. 브라우저 저장소(localStorage)'),
      h('p', null, '편의를 위해 테마, 즐겨찾기, 최근 사용 도구, 일부 도구의 입력값을 사용자의 브라우저에만 저장합니다. 이 정보는 운영자에게 전송되지 않습니다. JWT·해시·URL·Base64 등 민감할 수 있는 입력은 저장하지 않으며, 사이드바의 "입력값 기억"을 끄거나 "저장 데이터 삭제"로 언제든 지울 수 있습니다.'),
      h('h2', null, '4. 호스팅'),
      h('p', null, '이 사이트는 Cloudflare Pages에서 제공됩니다. 페이지를 전달하고 보안을 유지하는 과정에서 Cloudflare가 IP 주소 등 접속 정보를 처리할 수 있으며, 이는 ', ext('https://www.cloudflare.com/privacypolicy/', 'Cloudflare 개인정보처리방침'), '을 따릅니다.'),
      h('h2', null, '5. 변경'),
      h('p', null, '이 방침이 바뀌면 이 페이지에 시행일과 함께 공지합니다.'),
    ),
  ];
}

function licenses(): Node[] {
  return [
    head('오픈소스 라이선스', `${SITE_NAME}은 다음 오픈소스 라이브러리를 사용합니다. 각 라이브러리의 저작권은 해당 저작자에게 있습니다.`),
    h('div', { class: 'prose' },
      h('table', null,
        h('thead', null, h('tr', null, h('th', null, '라이브러리'), h('th', null, '라이선스'))),
        h('tbody', null, ...LICENSES.map(([name, lic, url]) => h('tr', null, h('td', null, ext(url, name)), h('td', null, lic)))),
      ),
    ),
  ];
}

export function notFound(): Node[] {
  return [head('페이지를 찾을 수 없습니다', '주소가 바뀌었거나 없는 도구입니다.'), h('p', null, h('a', { class: 'btn', href: '/' }, '전체 도구 보기'))];
}

export const PAGE_RENDERERS: Record<string, () => Node[]> = { about, privacy, licenses };
