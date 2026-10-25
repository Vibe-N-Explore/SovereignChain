/* storage.h - Persistence and crash-recovery for SovereignChain ledger.
 *
 * Phase 8: Persistence and recovery.
 *
 * Provides atomic, durable persistence of the ledger state to data_dir:
 *   - Atomic write: writes to state.dat.tmp, fsync, then renames to state.dat
 *   - Checksummed state file: validates SHA-256 state root hash on recovery
 *   - Crash recovery: detects corrupted writes, restores last known good state
 */
#ifndef SC_STORAGE_H
#define SC_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "err.h"
#include "ledger.h"

#define SC_STORAGE_MAGIC 0x53435354 /* "SCST" - SovereignChain STate */
#define SC_STORAGE_VERSION 1

/* Save entire ledger state to data_dir/state.dat atomically */
sc_err_t storage_save_state(const sc_ledger_t *ledger, const char *data_dir,
                            char *errbuf, size_t errlen);

/* Load ledger state from data_dir/state.dat with state root checksum verification */
sc_err_t storage_load_state(sc_ledger_t *ledger, const char *data_dir,
                            char *errbuf, size_t errlen);

/* Check if persistent state exists in data_dir */
bool storage_state_exists(const char *data_dir);

#endif /* SC_STORAGE_H */
