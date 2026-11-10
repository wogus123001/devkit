// Writes src/tools/meta.json: every tool's id, name, category, description and keywords, plus the module
// that implements it. The app loads this small list up front (navigation, search, home cards) and imports
// a tool's module only when that tool is opened, so heavy libraries stay out of the first download.
// Runs before `dev` and `build`; rerun it (npm run meta) after adding or renaming a tool.
import { readdir, writeFile } from 'node:fs/promises';
import { createServer } from 'vite';

const TOOLS_DIR = new URL('../src/tools/', import.meta.url);
const SKIP = new Set(['index.ts', 'lazy.ts']);

const vite = await createServer({ server: { middlewareMode: true, hmr: false }, appType: 'custom', logLevel: 'error' });
const moduleOf = new Map();
let TOOLS;
try {
  ({ TOOLS } = await vite.ssrLoadModule('/src/tools/index.ts'));
  for (const file of (await readdir(TOOLS_DIR)).filter((f) => f.endsWith('.ts') && !SKIP.has(f)).sort()) {
    const mod = await vite.ssrLoadModule(`/src/tools/${file}`);
    for (const value of Object.values(mod)) {
      if (!Array.isArray(value)) continue;
      for (const t of value) {
        if (!t || typeof t.id !== 'string' || typeof t.render !== 'function') continue;
        if (moduleOf.has(t.id) && moduleOf.get(t.id) !== file) throw new Error(`tool "${t.id}" is exported from both ${moduleOf.get(t.id)} and ${file}`);
        moduleOf.set(t.id, file);
      }
    }
  }
} finally {
  await vite.close();
}

const meta = TOOLS.map((t) => {
  const module = moduleOf.get(t.id);
  if (!module) throw new Error(`tool "${t.id}" is listed in tools/index.ts but no module exports it`);
  return { id: t.id, name: t.name, category: t.category, description: t.description, ...(t.keywords?.length ? { keywords: t.keywords } : {}), module: module.replace(/\.ts$/, '') };
});
await writeFile(new URL('meta.json', TOOLS_DIR), JSON.stringify(meta, null, 2) + '\n');
console.log(`tool meta: ${meta.length} tools from ${new Set(meta.map((m) => m.module)).size} modules`);
