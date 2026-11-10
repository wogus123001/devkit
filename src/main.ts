import './style.css';
import { CATEGORIES, type Tool } from './types';
import { TOOLS } from './tools';
import { h, rememberInputs, store, toast } from './ui';
import { PAGES, SITE_DESCRIPTION, SITE_TITLE, canonical, pageTitle, toolTitle } from './site';
import { PAGE_RENDERERS, notFound } from './pages';

const byId = new Map(TOOLS.map((t) => [t.id, t]));
const app = document.getElementById('app')!;
app.replaceChildren(); // drop the prerendered static content; the app renders the live UI

// Clickjacking guard for hosts that cannot send `frame-ancestors` / X-Frame-Options (e.g. GitHub Pages):
// refuse to render inside another site's frame, where hidden overlays could trick clicks or capture input.
if (window.top !== window.self) {
  app.append(h('div', { class: 'main' }, h('p', null, '보안을 위해 DevKit은 다른 페이지 안에서 실행되지 않습니다. '), h('a', { href: location.href, target: '_top', rel: 'noopener' }, '새 창에서 열기')));
  throw new Error('framed: rendering stopped');
}
store.purgeSensitive();

// ---------- favorites & recents ----------
let favorites = store.get<string[]>('favorites', []).filter((id) => byId.has(id));
let recents = store.get<string[]>('recents', []).filter((id) => byId.has(id));
const isFav = (id: string) => favorites.includes(id);
function toggleFav(id: string) {
  favorites = isFav(id) ? favorites.filter((x) => x !== id) : [...favorites, id];
  store.set('favorites', favorites);
}
function pushRecent(id: string) {
  recents = [id, ...recents.filter((x) => x !== id)].slice(0, 8);
  store.set('recents', recents);
}

// ---------- search ----------
const norm = (s: string) => s.toLowerCase().replace(/[\s\-_/]+/g, '');
function matches(tool: Tool, q: string): boolean {
  if (!q) return true;
  const hay = norm([tool.name, tool.description, tool.id, ...(tool.keywords ?? [])].join(' '));
  return q.split(/\s+/).filter(Boolean).every((w) => hay.includes(norm(w)));
}

// ---------- theme ----------
function currentTheme(): 'light' | 'dark' {
  const set = document.documentElement.dataset.theme;
  if (set === 'light' || set === 'dark') return set;
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try {
    localStorage.setItem('devkit:theme', next);
  } catch {
    /* ignore */
  }
  themeBtn.textContent = next === 'dark' ? '☀ 라이트' : '☾ 다크';
}

// ---------- shell ----------
const searchInput = h('input', { type: 'search', placeholder: '도구 검색…', 'aria-label': '도구 검색' });
const nav = h('nav', { class: 'nav', 'aria-label': '도구 목록' });
const themeBtn = h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: toggleTheme }, currentTheme() === 'dark' ? '☀ 라이트' : '☾ 다크');
const main = h('main', { class: 'main', id: 'main' });
const shell = h('div', { class: 'app' });

const sidebar = h('aside', { class: 'sidebar' },
  h('a', { class: 'brand', href: '/' },
    h('span', { class: 'brand-logo' }, '</>'),
    h('span', null, h('div', { class: 'brand-name' }, 'DevKit'), h('div', { class: 'brand-sub' }, `개발자 도구 ${TOOLS.length}개`)),
  ),
  h('div', { class: 'search' }, searchInput, h('kbd', null, 'Ctrl K')),
  nav,
  h('div', { class: 'sidebar-foot' }, h('span', null, '모든 처리는 브라우저 안에서'), themeBtn),
  h('div', { class: 'sidebar-foot', style: { paddingTop: '0', borderTop: '0' } },
    h('label', { class: 'check', title: '끄면 도구 입력값을 브라우저에 저장하지 않습니다. JWT·해시·URL·Base64·문자열 이스케이프 입력은 항상 저장하지 않습니다.' },
      h('input', {
        type: 'checkbox',
        checked: rememberInputs(),
        onchange: (e: Event) => {
          const on = (e.target as HTMLInputElement).checked;
          store.set('settings:remember', on);
          if (!on) store.clearInputs();
          toast(on ? '입력값을 이 브라우저에 저장합니다' : '입력값을 저장하지 않으며, 저장된 값을 지웠습니다');
        },
      }),
      h('span', null, '입력값 기억'),
    ),
    h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => toast(`저장된 입력 ${store.clearInputs()}개를 지웠습니다`) }, '저장 데이터 삭제'),
  ),
  h('div', { class: 'sidebar-links' }, ...PAGES.map((p) => h('a', { href: '/' + p.id }, p.title))),
);
const topbar = h('div', { class: 'topbar' },
  h('button', { class: 'btn btn-sm', type: 'button', 'aria-label': '메뉴', onclick: () => shell.classList.toggle('nav-open') }, '☰'),
  h('a', { href: '/', style: { fontWeight: '700', color: 'var(--text)', textDecoration: 'none' } }, 'DevKit'),
);
shell.append(sidebar, h('div', { style: { minWidth: '0' } }, topbar, main));
app.append(shell);

function renderNav() {
  const q = searchInput.value.trim();
  const active = currentRoute();
  nav.replaceChildren();
  let count = 0;
  for (const cat of CATEGORIES) {
    const tools = TOOLS.filter((t) => t.category === cat.id && matches(t, q));
    if (!tools.length) continue;
    count += tools.length;
    nav.append(
      h('div', { class: 'nav-group' },
        h('div', { class: 'nav-group-title' }, h('span', { class: 'nav-group-icon' }, cat.icon), cat.name),
        ...tools.map((t) => h('a', { href: '/' + t.id, class: t.id === active ? 'active' : '' }, t.name, isFav(t.id) ? h('span', { 'aria-label': '즐겨찾기' }, '★') : null)),
      ),
    );
  }
  if (!count) nav.append(h('div', { class: 'nav-empty' }, '검색 결과가 없습니다'));
}

searchInput.addEventListener('input', renderNav);
searchInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const first = nav.querySelector('a');
    if (first) navigate(first.getAttribute('href')!);
  } else if (e.key === 'Escape') {
    searchInput.value = '';
    renderNav();
  }
});
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    shell.classList.add('nav-open');
    searchInput.focus();
    searchInput.select();
  }
});

// ---------- routing ----------
// Real paths (/base64) instead of hash URLs so every tool is its own indexable page.
// scripts/prerender.mjs writes a static HTML file per path; the app takes over after load.
const pageById = new Map(PAGES.map((p) => [p.id, p]));

function currentRoute(): string {
  let path = location.pathname;
  try {
    path = decodeURIComponent(path);
  } catch {
    /* malformed escape: use as-is */
  }
  return path.replace(/^\/+|\/+$/g, '').replace(/\.html$/, '').replace(/^index$/, '');
}

function navigate(href: string) {
  const url = new URL(href, location.href);
  if (url.pathname !== location.pathname) history.pushState(null, '', url.pathname);
  route();
}

// Old links used #/tool-id: move them to the matching path.
{
  const legacy = location.hash.match(/^#\/([a-z0-9-]*)/);
  if (legacy) history.replaceState(null, '', '/' + legacy[1]);
}

document.addEventListener('click', (e) => {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = (e.target as Element).closest?.('a');
  if (!a || a.target || a.hasAttribute('download')) return;
  const href = a.getAttribute('href');
  if (!href || !href.startsWith('/') || href.startsWith('//')) return;
  e.preventDefault();
  navigate(href);
});

function setMeta(title: string, description: string, id: string, indexable = true) {
  document.title = title;
  document.querySelector('meta[name="description"]')?.setAttribute('content', description);
  document.querySelector('link[rel="canonical"]')?.setAttribute('href', canonical(id));
  document.querySelector('meta[name="robots"]')?.setAttribute('content', indexable ? 'index,follow' : 'noindex');
}

let cleanup: (() => void) | void;
function route() {
  if (typeof cleanup === 'function') cleanup();
  cleanup = undefined;
  shell.classList.remove('nav-open');
  const id = currentRoute();
  const tool = byId.get(id);
  const page = pageById.get(id);
  main.replaceChildren();
  if (!id) {
    renderHome();
    setMeta(SITE_TITLE, SITE_DESCRIPTION, '');
  } else if (tool) {
    pushRecent(tool.id);
    renderTool(tool);
    setMeta(toolTitle(tool.name), tool.description, tool.id);
  } else if (page) {
    main.append(...PAGE_RENDERERS[page.id]());
    setMeta(pageTitle(page.title), page.description, page.id);
  } else {
    main.append(...notFound());
    setMeta(pageTitle('페이지를 찾을 수 없음'), SITE_DESCRIPTION, id, false);
  }
  renderNav();
  window.scrollTo(0, 0);
}

function card(t: Tool) {
  return h('a', { class: 'card', href: '/' + t.id }, h('div', { class: 'card-name' }, t.name), h('div', { class: 'card-desc' }, t.description));
}

function renderHome() {
  main.append(
    h('div', { class: 'hero' },
      h('h1', null, '개발자 도구, 한곳에'),
      h('p', null, '인코딩·디코딩, JSON/YAML 포맷팅, 정규식 테스트까지. 입력한 데이터는 서버로 전송되지 않고 브라우저 안에서만 처리됩니다.'),
    ),
  );
  if (favorites.length)
    main.append(h('section', { class: 'home-section' }, h('h2', null, '★ 즐겨찾기'), h('div', { class: 'cards' }, ...favorites.map((id) => card(byId.get(id)!)))));
  if (recents.length)
    main.append(h('section', { class: 'home-section' }, h('h2', null, '최근 사용'), h('div', { class: 'cards' }, ...recents.slice(0, 4).map((id) => card(byId.get(id)!)))));
  for (const cat of CATEGORIES) {
    const tools = TOOLS.filter((t) => t.category === cat.id);
    main.append(
      h('section', { class: 'home-section' },
        h('h2', null, h('span', { class: 'nav-group-icon' }, cat.icon), cat.name),
        h('div', { class: 'cards' }, ...tools.map(card)),
      ),
    );
  }
}

function renderTool(tool: Tool) {
  const cat = CATEGORIES.find((c) => c.id === tool.category)!;
  const star = h('button', {
    class: 'btn star' + (isFav(tool.id) ? ' on' : ''),
    type: 'button',
    title: '즐겨찾기',
    'aria-pressed': String(isFav(tool.id)),
    onclick: () => {
      toggleFav(tool.id);
      star.classList.toggle('on', isFav(tool.id));
      star.textContent = isFav(tool.id) ? '★' : '☆';
      star.setAttribute('aria-pressed', String(isFav(tool.id)));
      renderNav();
    },
  }, isFav(tool.id) ? '★' : '☆');
  const body = h('div', { class: 'tool-body' });
  main.append(
    h('div', { class: 'tool-head' },
      h('div', null, h('div', { class: 'crumb' }, cat.name), h('h1', { class: 'tool-title' }, tool.name), h('p', { class: 'tool-desc' }, tool.description)),
      star,
    ),
    body,
  );
  try {
    cleanup = tool.render(body);
  } catch (e) {
    body.append(h('div', { class: 'error-box' }, '도구를 불러오지 못했습니다: ' + (e as Error).message));
  }
}

window.addEventListener('popstate', route);
route();
