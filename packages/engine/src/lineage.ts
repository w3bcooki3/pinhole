/**
 * Which model a model was made from, and by which changes: set by
 * applyChanges, so analyses of a changed copy can reuse what is unchanged.
 */
import type { Change } from './whatif.js';
import type { NetworkModel } from './types.js';

export const LINEAGE = new WeakMap<NetworkModel, { base: NetworkModel; changes: Change[] }>();
