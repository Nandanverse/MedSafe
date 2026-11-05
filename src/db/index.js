/**
 * Store factory. Returns the in-memory twin for the mock stack (and tests) and
 * the PostgreSQL driver for production, chosen by the same FABRIC_MOCK switch
 * that selects the ledger — so "mock" means the whole stack has no external
 * infrastructure, and "real" means ledger + database + cache together.
 */

import { MemoryStore } from './memory-store.js';
import { PostgresStore } from './postgres.js';

/**
 * @param {object} config  the frozen app config
 * @param {import('../utils/logger.js').Logger} logger
 * @param {{clock?: () => Date}} [opts]  injected clock for the in-memory store
 * @returns {MemoryStore|PostgresStore}
 */
export function createStore(config, logger, opts = {}) {
  if (config.fabric.mock) {
    logger?.info('store driver: in-memory (mock stack)');
    return new MemoryStore({ clock: opts.clock, logger });
  }
  return new PostgresStore(config.db, logger);
}

export { MemoryStore, PostgresStore };
