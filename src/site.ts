// Site-wide metadata shared by the app (runtime <head> updates) and scripts/prerender.mjs (static HTML per route).
// Keep this file free of DOM access: it is also loaded in Node at build time.

export const SITE_URL = 'https://devkit-ahl.pages.dev';
export const SITE_NAME = 'DevKit';
export const SITE_TITLE = 'DevKit — 개발자 도구 모음';
export const SITE_DESCRIPTION = 'Base64, URL, JWT, JSON, YAML, 정규식 등 개발자 도구를 한곳에. 모든 처리는 브라우저에서만 이루어집니다.';

/** Contact shown on the about page. null hides the contact section. */
export const CONTACT: { label: string; href: string } | null = null;

export interface StaticPage {
  id: string;
  title: string;
  description: string;
}

export const PAGES: StaticPage[] = [
  { id: 'about', title: '소개', description: 'DevKit은 개발자가 자주 쓰는 도구를 모은 웹사이트입니다. 입력한 데이터는 서버로 전송되지 않고 브라우저 안에서만 처리됩니다.' },
  { id: 'privacy', title: '개인정보처리방침', description: 'DevKit의 개인정보처리방침입니다. DevKit은 개인정보를 수집하지 않으며, 입력값은 브라우저 안에서만 처리됩니다.' },
  { id: 'licenses', title: '오픈소스 라이선스', description: 'DevKit이 사용하는 오픈소스 라이브러리와 라이선스 목록입니다.' },
];

export const toolTitle = (name: string) => `${name} — ${SITE_NAME}`;
export const pageTitle = (title: string) => `${title} — ${SITE_NAME}`;
export const canonical = (id: string) => (id ? `${SITE_URL}/${id}` : `${SITE_URL}/`);
