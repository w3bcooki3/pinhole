/**
 * Snapshots kept in this browser, so a refresh does not lose them, and a
 * trash for removed ones (restorable for 30 days).
 *
 * Stored in IndexedDB on this device only; nothing is uploaded. What is kept
 * is the snapshot after reading and cleaning (secrets removed, fields
 * validated), not the file as loaded, and it is analysed again on each load,
 * so a newer Pinhole reads it with its newer rules. When the browser refuses
 * storage (private windows in some browsers, storage turned off), everything
 * works for the session and the console says it will not be kept.
 */
export interface Stored {
  /** Snapshot key: account/region/collectedAt (or name). */
  id: string;
  name: string;
  /** The cleaned snapshot as JSON. */
  json: string;
  addedAt: number;
  /** Set while in the trash. */
  deletedAt?: number;
}

export const TRASH_DAYS = 30;
const DB = 'pinhole';
const STORE = 'snapshots';

let db: Promise<IDBDatabase | undefined> | undefined;
/** False once the browser has refused storage; the console says so. */
export let persistent = true;

function open(): Promise<IDBDatabase | undefined> {
  db ??= new Promise((resolve) => {
    try {
      if (typeof indexedDB === 'undefined') throw new Error('no IndexedDB');
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: 'id' });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => {
        persistent = false;
        resolve(undefined);
      };
      req.onblocked = () => {
        persistent = false;
        resolve(undefined);
      };
    } catch {
      persistent = false;
      resolve(undefined);
    }
  });
  return db;
}

function run<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T> | void): Promise<T | undefined> {
  return open().then(
    (d) =>
      new Promise<T | undefined>((resolve) => {
        if (!d) return resolve(undefined);
        try {
          const tx = d.transaction(STORE, mode);
          const req = fn(tx.objectStore(STORE));
          tx.oncomplete = () => resolve(req ? req.result : undefined);
          tx.onerror = () => {
            persistent = false;
            resolve(undefined);
          };
          tx.onabort = () => {
            // Most often the storage quota: keep working for the session.
            persistent = false;
            resolve(undefined);
          };
        } catch {
          persistent = false;
          resolve(undefined);
        }
      }),
  );
}

/** Every record, trash included. Records past their 30 days in the trash are removed first. */
export async function all(): Promise<Stored[]> {
  const list = ((await run<Stored[]>('readonly', (s) => s.getAll())) ?? []).filter(valid);
  const cutoff = Date.now() - TRASH_DAYS * 864e5;
  const expired = list.filter((r) => r.deletedAt !== undefined && r.deletedAt < cutoff);
  if (expired.length) await run('readwrite', (s) => void expired.forEach((r) => s.delete(r.id)));
  return list.filter((r) => !expired.includes(r)).sort((a, b) => a.addedAt - b.addedAt);
}

/** A stored record that is not ours or is damaged is ignored rather than breaking the console. */
function valid(r: unknown): r is Stored {
  const o = r as Stored;
  return !!o && typeof o.id === 'string' && typeof o.name === 'string' && typeof o.json === 'string' && typeof o.addedAt === 'number' && (o.deletedAt === undefined || typeof o.deletedAt === 'number');
}

export const put = (list: Stored[]) => run('readwrite', (s) => void list.forEach((r) => s.put(r)));
export const remove = (ids: string[]) => run('readwrite', (s) => void ids.forEach((id) => s.delete(id)));
export const clear = () => run('readwrite', (s) => s.clear());

/** Moves records to the trash, or back out of it. */
export async function setDeleted(ids: string[], deleted: boolean): Promise<void> {
  const list = (await all()).filter((r) => ids.includes(r.id));
  const now = Date.now();
  await put(list.map((r) => {
    const out: Stored = { ...r };
    if (deleted) out.deletedAt = now;
    else delete out.deletedAt;
    return out;
  }));
}

/** Asks the browser not to clear this site's storage under pressure. Best effort; no prompt in most browsers. */
export function keep(): void {
  try {
    void navigator.storage?.persist?.();
  } catch {
    /* not offered */
  }
}
