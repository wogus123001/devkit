// Runs after `vite build`. For every route it writes dist/<id>.html: a copy of the built index.html with
// that route's <title>, description, canonical URL and Open Graph tags, plus static content (heading,
// description, links to every tool) so crawlers that do not run JavaScript still see a real page.
// Cloudflare Pages serves dist/base64.html at /base64. Also writes 404.html, sitemap.xml and robots.txt.
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'vite';

const DIST = new URL('../dist/', import.meta.url);

const vite = await createServer({ server: { middlewareMode: true, hmr: false }, appType: 'custom', logLevel: 'error' });
let TOOLS, CATEGORIES, site;
try {
  ({ TOOLS } = await vite.ssrLoadModule('/src/tools/index.ts'));
  ({ CATEGORIES } = await vite.ssrLoadModule('/src/types.ts'));
  site = await vite.ssrLoadModule('/src/site.ts');
} finally {
  await vite.close();
}
const { SITE_URL, SITE_NAME, SITE_TITLE, SITE_DESCRIPTION, PAGES, toolTitle, pageTitle, canonical } = site;

// ---------- route table ----------
const RESERVED = new Set(['index', '404', 'assets', 'robots', 'sitemap', 'theme', 'favicon']);
const routes = [
  { id: '', title: SITE_TITLE, description: SITE_DESCRIPTION, heading: '개발자 도구, 한곳에' },
  ...TOOLS.map((t) => ({ id: t.id, title: toolTitle(t.name), description: t.description, heading: t.name, crumb: CATEGORIES.find((c) => c.id === t.category)?.name })),
  ...PAGES.map((p) => ({ id: p.id, title: pageTitle(p.title), description: p.description, heading: p.title })),
];
const seen = new Set();
for (const r of routes) {
  if (r.id && (!/^[a-z0-9-]+$/.test(r.id) || RESERVED.has(r.id))) throw new Error(`prerender: unusable route id "${r.id}"`);
  if (seen.has(r.id)) throw new Error(`prerender: duplicate route id "${r.id}"`);
  seen.add(r.id);
}

// ---------- html ----------
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const toolIndex = CATEGORIES.map((c) => {
  const items = TOOLS.filter((t) => t.category === c.id).map((t) => `<li><a href="/${t.id}">${esc(t.name)}</a></li>`).join('');
  return items ? `<h2>${esc(c.name)}</h2><ul>${items}</ul>` : '';
}).join('');
const footer = `<p>${PAGES.map((p) => `<a href="/${p.id}">${esc(p.title)}</a>`).join(' · ')}</p>`;

function staticBody(r) {
  return `<div class="prerender"><p><a href="/">${esc(SITE_NAME)}</a>${r.crumb ? ` › ${esc(r.crumb)}` : ''}</p>` +
    `<h1>${esc(r.heading)}</h1><p>${esc(r.description)}</p>` +
    `<noscript><p>이 도구는 JavaScript가 필요합니다.</p></noscript>` +
    `<nav aria-label="도구 목록">${toolIndex}</nav>${footer}</div>`;
}

const template = await readFile(new URL('index.html', DIST), 'utf8');

function setTag(html, pattern, replacement) {
  if (!pattern.test(html)) throw new Error(`prerender: index.html is missing ${pattern}`);
  return html.replace(pattern, () => replacement);
}

function render(r, { indexable = true } = {}) {
  const url = canonical(r.id);
  let html = template;
  html = setTag(html, /<title>[^<]*<\/title>/, `<title>${esc(r.title)}</title>`);
  html = setTag(html, /<meta name="description" content="[^"]*" \/>/, `<meta name="description" content="${esc(r.description)}" />`);
  html = setTag(html, /<meta name="robots" content="[^"]*" \/>/, `<meta name="robots" content="${indexable ? 'index,follow' : 'noindex'}" />`);
  html = setTag(html, /<link rel="canonical" href="[^"]*" \/>/, indexable ? `<link rel="canonical" href="${esc(url)}" />` : '');
  html = setTag(html, /<meta property="og:title" content="[^"]*" \/>/, `<meta property="og:title" content="${esc(r.title)}" />`);
  html = setTag(html, /<meta property="og:description" content="[^"]*" \/>/, `<meta property="og:description" content="${esc(r.description)}" />`);
  html = setTag(html, /<meta property="og:url" content="[^"]*" \/>/, `<meta property="og:url" content="${esc(url)}" />`);
  html = setTag(html, /<div id="app"><\/div>/, `<div id="app">${staticBody(r)}</div>`);
  return html;
}

for (const r of routes) await writeFile(new URL(`${r.id || 'index'}.html`, DIST), render(r));
await writeFile(
  new URL('404.html', DIST),
  render({ id: '404', title: pageTitle('페이지를 찾을 수 없음'), description: '주소가 바뀌었거나 없는 도구입니다.', heading: '페이지를 찾을 수 없습니다' }, { indexable: false }),
);

const today = new Date().toISOString().slice(0, 10);
const sitemap = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
  routes.map((r) => `  <url><loc>${esc(canonical(r.id))}</loc><lastmod>${today}</lastmod></url>`).join('\n') + '\n</urlset>\n';
await writeFile(new URL('sitemap.xml', DIST), sitemap);
await writeFile(new URL('robots.txt', DIST), `User-agent: *\nAllow: /\n\nSitemap: ${SITE_URL}/sitemap.xml\n`);

console.log(`prerender: ${routes.length} pages + 404.html, sitemap.xml, robots.txt`);
