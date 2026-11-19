/** Tiny DOM helpers shared by the vanilla prototypes. Text is always inserted as text. */
export type Child = Node | string | number | null | undefined | false;
export function h(tag: string, attrs: Record<string, string | number | boolean | undefined> = {}, ...children: Child[]): HTMLElement {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== false) e.setAttribute(k, v === true ? '' : String(v));
  for (const c of children) if (c !== null && c !== undefined && c !== false) e.append(typeof c === 'object' ? c : document.createTextNode(String(c)));
  return e;
}
const SVGNS = 'http://www.w3.org/2000/svg';
export function s(tag: string, attrs: Record<string, string | number> = {}, ...children: (Node | string)[]): SVGElement {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  for (const c of children) e.append(typeof c === 'string' ? document.createTextNode(c) : c);
  return e;
}
export function on<K extends keyof HTMLElementEventMap>(el: HTMLElement, ev: K, fn: (e: HTMLElementEventMap[K]) => void): HTMLElement {
  el.addEventListener(ev, fn);
  return el;
}
export function filePicker(onFiles: (f: FileList) => void): () => void {
  // JSON, gzip and the .txt PowerShell sometimes writes; the reader works out what each file is.
  const input = h('input', { type: 'file', accept: '.json,.gz,.txt,application/json,application/gzip', multiple: true, hidden: true }) as HTMLInputElement;
  input.addEventListener('change', () => {
    if (input.files?.length) onFiles(input.files);
    input.value = '';
  });
  document.body.append(input);
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => {
    e.preventDefault();
    if (e.dataTransfer?.files.length) onFiles(e.dataTransfer.files);
  });
  return () => input.click();
}
/** A short message at the bottom of the screen; with an action (Undo), it stays longer and offers a button. */
export function toast(msg: string, cls = 'toast', action?: { label: string; run: () => void }) {
  let t = document.querySelector<HTMLElement>(`.${cls}`);
  if (!t) {
    t = h('div', { class: cls, role: 'status' });
    document.body.append(t);
  }
  t.replaceChildren(msg);
  if (action) {
    const b = h('button', { type: 'button', class: 'toast-act' }, action.label);
    b.addEventListener('click', () => {
      t!.classList.remove('show');
      action.run();
    });
    t.append(b);
  }
  t.classList.add('show');
  clearTimeout((t as unknown as { _t?: number })._t);
  (t as unknown as { _t?: number })._t = window.setTimeout(() => t!.classList.remove('show'), action ? 7000 : 1800);
}
