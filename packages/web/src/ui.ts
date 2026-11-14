/**
 * Small UI pieces shared by every page: severity markers, buttons, panel
 * headers, empty states and the icon set.
 */
import { h, on, toast } from './dom.js';
import type { Child } from './dom.js';
import * as D from './data.js';
import type { Severity } from './data.js';
import { ICON } from './graph.js';

Object.assign(ICON, {
  chev: 'M9 6l6 6-6 6',
  chevl: 'M15 6l-6 6 6 6',
  compare: 'M7 4v13M4 14l3 3 3-3M17 20V7M14 10l3-3 3 3',
  home: 'M4 11 12 4l8 7v9h-5v-6H9v6H4z',
  graph: 'M6 6m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0M18 6m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0M12 18m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0M7.5 7.5l3.5 8.5M16.5 7.5 13 16M8 6h8',
  list: 'M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01',
  box: 'M12 3 4 7v10l8 4 8-4V7zM4 7l8 4 8-4M12 11v10',
  shield: 'M12 3 5 6v6c0 4.5 3 7.7 7 9 4-1.3 7-4.5 7-9V6zM9 12l2 2 4-4',
  plug: 'M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0zM12 17v4',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM20 20l-4-4',
  upload: 'M12 16V4M7 9l5-5 5 5M4 20h16',
  download: 'M12 4v12M7 11l5 5 5-5M4 20h16',
  check: 'M5 12.5 10 17l9-10',
  x: 'M6 6l12 12M18 6 6 18',
  file: 'M14 3H6v18h12V7zM14 3v4h4',
  info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM12 11v5M12 8h.01',
  open: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
  blast: 'M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z',
  flask: 'M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4a2 2 0 0 0 1.8-3l-5-9V3M7.5 15h9',
  route: 'M6 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM18 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM6 15V9a4 4 0 0 1 4-4h6M18 9v6a4 4 0 0 1-4 4H8',
  broom: 'M14 4l6 6M12 6l6 6-7 7H5v-6zM5 13l6 6',
  wrench: 'M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.1-.4-.4-2.1z',
  command: 'M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z',
  play: 'M7 5v14l11-7z',
  undo: 'M9 14 4 9l5-5M4 9h11a5 5 0 0 1 0 10h-3',
  copy: 'M9 9h10v10H9zM5 15V5h10',
});

export const sevVar = (sv: Severity) => `var(--${sv})`;
export const softVar = (sv: Severity) => `var(--${sv}-soft)`;
export const sevPill = (sv: Severity, text?: string) => h('span', { class: `sev ${sv}` }, text ?? D.SEV_LABEL[sv]);
export const btn = (label: Child | Child[], cls: string, act: () => void, attrs: Record<string, string> = {}) =>
  on(h('button', { type: 'button', class: `btn ${cls}`, ...attrs }, ...(Array.isArray(label) ? label : [label])), 'click', act);
export const linkBtn = (label: string, act: () => void) => on(h('button', { type: 'button', class: 'link' }, label), 'click', act);
export function boxHead(title: string, note?: string, ...end: Child[]): HTMLElement {
  return h('header', {}, h('h2', {}, title), note ? h('span', { class: 'note' }, note) : null, end.length ? h('span', { class: 'end' }, ...end) : null);
}
export const empty = (title: string, body: string, ...acts: Child[]) =>
  h('div', { class: 'empty' }, h('h3', {}, title), h('p', {}, body), acts.length ? h('div', { style: 'display:flex;gap:0.5rem;justify-content:center' }, ...acts) : null);
export const ALL = () => new Set<Severity>(D.SEVERITY_ORDER);

/** Short display name: "orders-db (i-db, eni-db)" becomes "orders-db". */
export const short = (name: string) => name.replace(/ \(.*\)$/, '');

/** A labelled code block with a copy button, for AWS CLI commands. */
export function cmdBlock(lines: string[], copyLabel = 'Copy'): HTMLElement {
  const text = lines.join('\n');
  return h(
    'div',
    { class: 'cmd' },
    h('pre', {}, ...lines.flatMap((l, i) => [i ? '\n' : '', l.startsWith('#') ? h('span', { class: 'c' }, l) : [h('span', { class: 'p' }, '$ '), l]].flat())),
    on(h('button', { type: 'button' }, copyLabel), 'click', async () => {
      await D.copyText(text);
      toast('Copied');
    }),
  );
}
