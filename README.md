# DevKit

개발자가 자주 찾는 도구를 한곳에 모은 웹사이트입니다. 모든 처리는 브라우저 안에서만 이루어지며 입력값은 서버로 전송되지 않습니다.

## 실행

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # 타입 검사 후 dist/ 에 정적 파일 생성
```

`dist/`는 정적 파일이므로 GitHub Pages, Netlify, Vercel, S3 등 어디에나 올릴 수 있습니다.

## 도구 (60개)

| 분류 | 도구 |
| --- | --- |
| 인코딩 / 디코딩 | Protobuf (스키마로 디코딩·인코딩, 스키마 없이 분석), Base64, Base64 파일/이미지, URL, HTML 엔티티, 유니코드 이스케이프, 문자열 이스케이프, JWT 디코더, Hex, 2진수, Base32, ROT13/시저, 모스 부호, NATO 음성 알파벳 |
| 포맷터 / 뷰어 | JSON (정렬·트리·압축·오류 위치), JSON 비교, YAML, XML, SQL (9개 방언), 마크다운 미리보기 |
| 정규식 | 정규식 테스터 (하이라이트, 캡처/이름 그룹, 치환, 프리셋, 치트시트, 무한 백트래킹 차단) |
| 변환기 | JSON↔YAML, JSON↔CSV, JSON→TypeScript, TOML↔JSON/YAML, XML↔JSON, Unix 타임스탬프, 진법, 색상, 케이스, Cron 해석, 로마 숫자 |
| 해시 / 보안 | 해시 (MD5·SHA-1/2/3·RIPEMD-160·HMAC, 파일 지원), 비밀번호 생성기, 비밀번호 강도 분석, Bcrypt 해시/검증, AES-256-GCM 암호화, RSA 키 쌍 생성, OTP(TOTP) 생성기, 민감정보 마스킹 |
| 생성기 | UUID v4/v7·ULID, QR 코드, Wi-Fi QR, Lorem Ipsum |
| 텍스트 | Diff 비교, 글자 수 세기, 줄 정리, Slug 변환 |
| 웹 / 네트워크 | URL 파서 (보안 점검), HTTP 상태 코드, Basic Auth, User-Agent 파서, MIME 타입, 기기 정보, IPv4 서브넷 계산기 |
| 개발 / 시스템 | chmod 계산기, docker run → compose, 수식 계산기, 키코드 정보, Git 치트시트 |

도구 목록은 [rea](https://github.com/morluto/rea)의 `capture_browser_scenario`로 it-tools.tech의 접근성 트리를 수집해 빠진 기능을 비교한 뒤 보강했습니다 (코드는 가져오지 않고 기능 목록만 참고).

공통 기능: `Ctrl+K` 검색, 즐겨찾기, 최근 사용, 다크 모드, 모바일 레이아웃, 도구별 입력값 자동 저장(브라우저 localStorage).

## 보안

모든 입력은 신뢰할 수 없는 데이터로 취급합니다.

| 위협 | 대응 |
| --- | --- |
| XSS (스크립트/HTML 주입) | 결과는 `escapeHtml` 후 `setHtml()`에서 DOMPurify 허용목록(span/mark 등)으로 한 번 더 정제. 마크다운은 별도의 엄격한 프로필(form·style·svg·math·iframe 금지, `javascript:` 링크 제거) |
| 잊어버린 innerHTML | 배포 빌드에 CSP `require-trusted-types-for 'script'` 적용. 정제 정책을 거치지 않은 innerHTML·Worker URL은 브라우저가 차단 (Chromium) |
| 외부 스크립트·데이터 유출 | CSP `script-src 'self'`, `connect-src 'self'`, 인라인 스크립트 없음, eval 없음 |
| DOM Clobbering | DOMPurify `SANITIZE_NAMED_PROPS` |
| 추적 이미지 | 마크다운의 외부 이미지는 대체 텍스트로 바꾸고 CSP `img-src`로도 차단 |
| 탭내빙 | 외부 링크에 `rel="noopener noreferrer"` |
| 동일 출처 Blob 실행 | Base64→파일 저장은 `application/octet-stream`으로 생성, SVG 미리보기는 불투명 출처 data: URL로만 |
| XXE / Billion Laughs | `<!ENTITY>` 선언 XML 거부, YAML 별칭 확장 100회 제한 |
| ReDoS | 정규식은 Web Worker에서 1.5초 제한. 내부 하이라이터는 선형 시간 정규식 |
| 리소스 고갈 (DoS) | 입력 500만 자 제한, JSON 중첩 1000단계, 트리 5000노드, Diff 1.5초 제한, 큰 결과는 하이라이트 생략, BigInt 4096자 |
| 프로토타입 오염 | 키 병합에 `Map`/`Object.create(null)` 사용 (`__proto__`, `constructor` 키 안전) |
| CSV(수식) 주입 | JSON→CSV에서 `= + - @`로 시작하는 텍스트 앞에 `'` 추가 (기본 켬) |
| Trojan Source / 숨은 문자 | 양방향 제어·폭 없는 문자·유니코드 태그 문자 감지 및 일괄 제거 |
| 피싱 URL | URL 파서가 `user@host` 속임수, IDN 호모그래프, 난독화된 IP, 오픈 리다이렉트, SQLi/XSS 파라미터, 내부망(SSRF) 주소를 경고 |
| JWT 공격 | `alg: none`, 빈 서명, `jku`/`x5u`/`jwk` 헤더, 조작된 `kid` 경고 |
| 클릭재킹 | `frame-ancestors 'none'`/`X-Frame-Options`(public/_headers) + 프레임 안에서는 렌더링 거부 |
| 민감정보 저장 | JWT·해시·URL·Base64·문자열 이스케이프 입력은 저장하지 않음. 사이드바에서 입력 기억 끄기·삭제 가능. 저장값은 타입 검증 후 사용 |
| Protobuf | protobufjs는 .proto 파싱에만 사용(코드 생성·eval 없음, CSP 호환). 바이너리 읽기는 모두 범위 검사, varint 10바이트·중첩 64단계·필드 5만 개·10MB 제한, 정수 범위·enum 이름 검증 |
| 새 보안 도구 | bcrypt cost 15 초과 해시 검증 거부(DoS 방지)·72바이트 절단 경고, AES는 PBKDF2 60만 회 + GCM 변조 감지·반복 횟수 상한, 수식 계산기는 eval 없는 자체 파서(중첩 500단계), TOML은 `__proto__`·`constructor` 키 거부, docker 변환기는 `--privileged`·docker.sock·전체 포트 공개 경고 |
| 공급망 | 의존성 정확한 버전 고정, `.npmrc`에서 `ignore-scripts=true`, `npm run audit` |

배포 시 `public/_headers`의 헤더(CSP, HSTS, X-Frame-Options 등)를 서버/CDN에 적용하세요. Netlify·Cloudflare Pages는 이 파일을 자동으로 읽습니다. GitHub Pages처럼 헤더를 설정할 수 없는 곳에서는 `<meta>` CSP와 프레임 차단 코드만 적용됩니다.

## 구조

```
src/
  main.ts            앱 셸: 사이드바, 검색, 해시 라우팅, 홈, 즐겨찾기
  security.ts        HTML 정제, Trusted Types, URL 검증, 숨은 문자 감지, 입력 제한
  ui.ts              DOM 헬퍼, 공통 "입력 → 결과" 도구(transformer), 구문 강조
  tools/secure.ts    bcrypt, AES, RSA, TOTP, 비밀번호 강도, 마스킹
  tools/devtools.ts  TOML, XML↔JSON, chmod, docker, 수식, Git 등
  tools/webtools.ts  서브넷, User-Agent, MIME, JSON 비교, Wi-Fi QR 등
  protobuf.ts        Protobuf 와이어 포맷 리더/라이터, 스키마 기반 인코딩/디코딩
  bytes.ts           UTF-8 / Base64 / Hex 바이트 유틸
  regex.worker.ts    정규식을 별도 스레드에서 실행 (1.5초 타임아웃)
  tools/*.ts         분류별 도구 정의
  tools/index.ts     도구 목록
```

새 도구 추가: `tools/` 파일에 `Tool` 객체(`id`, `name`, `category`, `description`, `keywords`, `render`)를 추가하면 사이드바·검색·홈에 자동으로 나타납니다. 단순 변환 도구는 `transformer()`에 `modes`와 `options`만 넘기면 됩니다.
