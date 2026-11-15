/**
 * Behaviour for the documentation page: one section at a time (hash routing),
 * "On this page" with the current heading, search across every section, copy
 * buttons, the mobile menu, and the theme shared with the console. Without
 * script the page still reads top to bottom.
 */
import './docs.css';

const $ = <T extends HTMLElement = HTMLElement>(sel: string, root: ParentNode = document) => root.querySelector(sel) as T | null;
const $$ = <T extends HTMLElement = HTMLElement>(sel: string, root: ParentNode = document) => [...root.querySelectorAll(sel)] as T[];

document.documentElement.classList.add('js');

// ---------------------------------------------------------------- theme (same key as the console)
const THEME_KEY = 'pinhole-theme';
function stored(): string | null {
  try {
    return localStorage.getItem(THEME_KEY);
  } catch {
    return null;
  }
}
function applyTheme(t: string) {
  document.documentElement.dataset.theme = t;
  const btn = $('#theme');
  if (btn) btn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
}
applyTheme(stored() ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
$('#theme')?.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    /* private window: the choice lasts for this page only */
  }
});

// ---------------------------------------------------------------- sections and routing
const pages = $$<HTMLElement>('section.page');
const navLinks = $$<HTMLAnchorElement>('.nav a[data-page]');
const toc = $('#toc-list');
const pager = $('#pager');
const baseTitle = document.title;
let tocObserver: IntersectionObserver | undefined;

function pageOf(id: string): HTMLElement | undefined {
  if (!id) return pages[0];
  const el = document.getElementById(id);
  if (!el) return undefined;
  return el.matches('section.page') ? el : (el.closest('section.page') as HTMLElement | null) ?? undefined;
}

function show(hash: string, scroll = true) {
  const id = decodeURIComponent(hash.replace(/^#/, ''));
  const page = pageOf(id) ?? pages[0]!;
  const changed = !page.classList.contains('active');
  pages.forEach((p) => p.classList.toggle('active', p === page));
  navLinks.forEach((a) => (a.dataset.page === page.id ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  const title = page.dataset.title ?? '';
  document.title = page === pages[0] ? baseTitle : `${title}: ${baseTitle}`;
  buildToc(page);
  buildPager(page);
  closeMenu();
  if (!scroll) return;
  const target = id && id !== page.id ? document.getElementById(id) : null;
  if (target) target.scrollIntoView({ block: 'start' });
  else if (changed) window.scrollTo({ top: 0 });
  if (changed) (page.querySelector('h1, h2') as HTMLElement | null)?.focus({ preventScroll: true });
  if (page.id === 'overview') replayTrace();
}

function buildToc(page: HTMLElement) {
  if (!toc) return;
  const heads = $$<HTMLHeadingElement>('h3[id]', page);
  toc.replaceChildren(
    ...heads.map((h) => {
      const a = document.createElement('a');
      a.href = `#${h.id}`;
      a.textContent = h.firstChild?.textContent ?? h.textContent ?? '';
      return a;
    }),
  );
  ($('#toc') as HTMLElement).hidden = heads.length === 0;
  tocObserver?.disconnect();
  if (!('IntersectionObserver' in window) || !heads.length) return;
  const links = $$<HTMLAnchorElement>('a', toc);
  const visible = new Set<Element>();
  tocObserver = new IntersectionObserver(
    (entries) => {
      for (const e of entries) e.isIntersecting ? visible.add(e.target) : visible.delete(e.target);
      const first = heads.find((h) => visible.has(h)) ?? [...heads].reverse().find((h) => h.getBoundingClientRect().top < 120);
      links.forEach((l) => l.classList.toggle('on', !!first && l.getAttribute('href') === `#${first.id}`));
    },
    { rootMargin: '-64px 0px -60% 0px' },
  );
  heads.forEach((h) => tocObserver!.observe(h));
}

function buildPager(page: HTMLElement) {
  if (!pager) return;
  const i = pages.indexOf(page);
  const link = (p: HTMLElement | undefined, cls: string, label: string) => {
    if (!p) return null;
    const a = document.createElement('a');
    a.href = `#${p.id}`;
    a.className = cls;
    a.innerHTML = `<small>${label}</small><b></b>`;
    a.querySelector('b')!.textContent = p.dataset.title ?? '';
    return a;
  };
  pager.replaceChildren(...[link(pages[i - 1], 'prev', 'Previous'), link(pages[i + 1], 'next', 'Next')].filter((x): x is HTMLAnchorElement => !!x));
}

window.addEventListener('hashchange', () => show(location.hash));
show(location.hash, !!location.hash);

// Section headings get a link to themselves.
for (const h of $$<HTMLHeadingElement>('.doc h3[id]')) {
  const a = document.createElement('a');
  a.className = 'anchor';
  a.href = `#${h.id}`;
  a.setAttribute('aria-label', `Link to ${h.textContent}`);
  a.textContent = '#';
  h.append(a);
}

// ---------------------------------------------------------------- the example trace
function replayTrace() {
  const t = $('.trace');
  if (!t || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  t.classList.remove('reveal');
  void t.offsetWidth;
  t.classList.add('reveal');
}
$$<HTMLLIElement>('.trace li').forEach((li, i) => li.style.setProperty('--i', String(i)));

// ---------------------------------------------------------------- copy buttons
for (const pre of $$<HTMLPreElement>('pre')) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'copy';
  b.textContent = 'Copy';
  b.addEventListener('click', async () => {
    const code = pre.querySelector('code');
    // For real output, copy the command, not what it printed.
    const text = pre.classList.contains('term') ? (pre.querySelector('.prompt')?.textContent ?? '').trim() : (code?.textContent ?? '');
    try {
      await navigator.clipboard.writeText(text);
      b.textContent = 'Copied';
    } catch {
      b.textContent = 'Select and copy';
    }
    setTimeout(() => (b.textContent = 'Copy'), 1600);
  });
  pre.append(b);
}

// ---------------------------------------------------------------- mobile menu
const nav = $('#nav');
const scrim = $('#scrim');
const menuBtn = $('#menu');
function closeMenu() {
  nav?.classList.remove('open');
  if (scrim) scrim.hidden = true;
  menuBtn?.setAttribute('aria-expanded', 'false');
}
menuBtn?.addEventListener('click', () => {
  const open = !nav?.classList.contains('open');
  nav?.classList.toggle('open', open);
  if (scrim) scrim.hidden = !open;
  menuBtn.setAttribute('aria-expanded', String(open));
  if (open) (nav?.querySelector('a[aria-current]') as HTMLElement | null)?.focus();
});
scrim?.addEventListener('click', closeMenu);

// ---------------------------------------------------------------- search
interface Entry { href: string; title: string; where: string; text: string }
const index: Entry[] = [];
for (const p of pages) {
  const title = p.dataset.title ?? '';
  // The section's own text up to its first h3, then one entry per h3.
  let current: Entry = { href: `#${p.id}`, title, where: p.dataset.group ?? '', text: '' };
  index.push(current);
  const walker = document.createTreeWalker(p, NodeFilter.SHOW_ELEMENT);
  for (let n = walker.nextNode() as HTMLElement | null; n; n = walker.nextNode() as HTMLElement | null) {
    if (n.tagName === 'H3' && n.id) {
      current = { href: `#${n.id}`, title: n.firstChild?.textContent ?? '', where: title, text: '' };
      index.push(current);
    } else if (/^(P|LI|DD|TD|H4|SUMMARY)$/.test(n.tagName)) current.text += ` ${n.textContent ?? ''}`;
  }
}
const input = $<HTMLInputElement>('#q');
const results = $('#results');
let sel = 0;
function snippet(text: string, words: string[]): string {
  const t = text.replace(/\s+/g, ' ').trim();
  const at = Math.max(0, ...words.map((w) => t.toLowerCase().indexOf(w)).filter((i) => i >= 0).slice(0, 1));
  const start = Math.max(0, at - 40);
  return `${start ? '…' : ''}${t.slice(start, start + 120)}${t.length > start + 120 ? '…' : ''}`;
}
function search() {
  if (!input || !results) return;
  const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) {
    results.hidden = true;
    input.setAttribute('aria-expanded', 'false');
    return;
  }
  const scored = index
    .map((e) => {
      const title = e.title.toLowerCase();
      const body = e.text.toLowerCase();
      if (!words.every((w) => title.includes(w) || body.includes(w))) return null;
      return { e, s: words.reduce((n, w) => n + (title.includes(w) ? 10 : 0) + (body.split(w).length - 1), 0) };
    })
    .filter((x): x is { e: Entry; s: number } => !!x)
    .sort((a, b) => b.s - a.s)
    .slice(0, 8);
  sel = 0;
  results.replaceChildren();
  if (!scored.length) {
    const p = document.createElement('p');
    p.textContent = 'Nothing matches. Try fewer words.';
    results.append(p);
  }
  scored.forEach(({ e }, i) => {
    const a = document.createElement('a');
    a.href = e.href;
    a.id = `r${i}`;
    a.setAttribute('role', 'option');
    a.setAttribute('aria-selected', String(i === 0));
    const b = document.createElement('b');
    b.textContent = e.title;
    const w = document.createElement('small');
    w.textContent = e.where;
    const s = document.createElement('span');
    s.textContent = snippet(e.text, words);
    a.append(b, w, s);
    a.addEventListener('click', () => {
      results.hidden = true;
      input.value = '';
    });
    results.append(a);
  });
  results.hidden = false;
  input.setAttribute('aria-expanded', 'true');
}
input?.addEventListener('input', search);
input?.addEventListener('keydown', (e) => {
  const items = $$<HTMLAnchorElement>('a', results!);
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    if (!items.length) return;
    sel = (sel + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
    items.forEach((a, i) => a.setAttribute('aria-selected', String(i === sel)));
    input.setAttribute('aria-activedescendant', items[sel]!.id);
    items[sel]!.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter' && items[sel]) {
    e.preventDefault();
    items[sel]!.click();
    location.hash = items[sel]!.getAttribute('href')!;
    input.blur();
  } else if (e.key === 'Escape') {
    input.value = '';
    search();
    input.blur();
  }
});
document.addEventListener('click', (e) => {
  if (results && !results.hidden && !(e.target as HTMLElement).closest('.search')) results.hidden = true;
});
document.addEventListener('keydown', (e) => {
  const typing = (e.target as HTMLElement).closest('input, textarea, select');
  if (((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') || (e.key === '/' && !typing)) {
    e.preventDefault();
    input?.focus();
    input?.select();
  } else if (e.key === 'Escape') closeMenu();
});
