/** Trash page: snapshots removed from the console, restorable for 30 days, and what this browser keeps. */
import { h, on } from './dom.js';
import * as D from './data.js';
import type { Stored } from './store.js';
import { TRASH_DAYS } from './store.js';
import { boxHead, btn, empty, stacked } from './ui.js';

export interface TrashCtx {
  trash: Stored[];
  savedCount: number;
  persistent: boolean;
  restore: (ids: string[]) => void;
  purge: (ids: string[]) => void;
  forgetAll: () => void;
}

const DAY = 864e5;
const when = (t: number) => {
  const days = Math.floor((Date.now() - t) / DAY);
  return days <= 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`;
};
const left = (t: number) => Math.max(1, Math.ceil(TRASH_DAYS - (Date.now() - t) / DAY));
const scopeOf = (r: Stored) => r.id.split('/').slice(0, 2).join(' / ');

/** A button that asks once more in place before doing something that cannot be undone. */
function confirmBtn(label: string, question: string, cls: string, run: () => void): HTMLElement {
  const host = h('span', { class: 'confirm' });
  const ask = () =>
    host.replaceChildren(
      h('span', { class: 'confirm-q', role: 'alert' }, question),
      btn('Yes, delete', `${cls} danger`, run),
      on(h('button', { type: 'button', class: `btn ${cls} ghost` }, 'Cancel'), 'click', () => reset()),
    );
  const reset = () => host.replaceChildren(btn(label, cls, ask));
  reset();
  return host;
}

export function trashPage(c: TrashCtx): HTMLElement {
  const list = [...c.trash].sort((a, b) => (b.deletedAt ?? 0) - (a.deletedAt ?? 0));
  const table = h(
    'table',
    { class: 't trash-t' },
    h('thead', {}, h('tr', {}, h('th', { class: 'first' }, 'Snapshot'), h('th', {}, 'Account and Region'), h('th', {}, 'Removed'), h('th', {}, 'Deleted in'), h('th', { class: 'last' }, h('span', { class: 'sr-only' }, 'Actions')))),
    h(
      'tbody',
      {},
      ...list.map((r) =>
        h(
          'tr',
          {},
          h('td', { class: 'first' }, h('strong', { class: 'break' }, r.name)),
          h('td', {}, scopeOf(r)),
          h('td', {}, when(r.deletedAt ?? r.addedAt)),
          h('td', {}, D.plural(left(r.deletedAt ?? r.addedAt), 'day')),
          h('td', { class: 'last' }, h('div', { class: 'row-actions' }, btn('Restore', 'sm', () => c.restore([r.id])), confirmBtn('Delete forever', `Delete ${r.name} for good?`, 'sm', () => c.purge([r.id])))),
        ),
      ),
    ),
  );
  return h(
    'div',
    { class: 'page' },
    h('div', { class: 'ph' }, h('div', {}, h('h1', {}, 'Trash'), h('p', {}, `Snapshots you remove stay here for ${TRASH_DAYS} days and can be restored, then they are deleted. Everything is kept in this browser only.`))),
    c.persistent ? null : h('div', { class: 'warn-bar', style: 'margin:0 0 1rem' }, 'This browser is not letting Pinhole keep data (a private window, or storage turned off), so snapshots and the trash last only until this tab is closed.'),
    list.length
      ? h(
          'section',
          { class: 'box', style: 'margin-bottom:1rem' },
          boxHead(D.plural(list.length, 'snapshot') + ' in the trash', '', h('div', { class: 'row-actions' }, btn('Restore all', 'sm', () => c.restore(list.map((r) => r.id))), confirmBtn('Empty trash', `Delete ${D.plural(list.length, 'snapshot')} for good?`, 'sm', () => c.purge(list.map((r) => r.id))))),
          h('div', { class: 'table-wrap' }, stacked(table)),
        )
      : empty('The trash is empty', 'Remove a snapshot with the × next to its account in the top bar; it comes here and can be restored.'),
    h(
      'section',
      { class: 'box' },
      boxHead('Kept in this browser', ''),
      h(
        'div',
        { class: 'pad' },
        h('p', { style: 'margin:0 0 0.75rem' }, `${D.plural(c.savedCount, 'snapshot')} loaded and ${D.plural(list.length, 'snapshot')} in the trash are kept in this browser's storage on this device, so they are still here after a refresh. They are never uploaded. What is kept is the snapshot after reading: VPN keys and any credentials are removed before it is stored.`),
        c.savedCount || list.length ? confirmBtn('Forget everything', 'Delete every snapshot in this browser, the trash included?', '', c.forgetAll) : null,
      ),
    ),
  );
}
