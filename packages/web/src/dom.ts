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
  const input = h('input', { type: 'file', accept: '.json', multiple: true, hidden: true }) as HTMLInputElement;
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
export function toast(msg: string, cls = 'toast') {
  let t = document.querySelector<HTMLElement>(`.${cls}`);
  if (!t) {
    t = h('div', { class: cls, role: 'status' });
    document.body.append(t);
  }
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout((t as unknown as { _t?: number })._t);
  (t as unknown as { _t?: number })._t = window.setTimeout(() => t!.classList.remove('show'), 1800);
}
