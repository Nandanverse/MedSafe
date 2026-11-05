/**
 * The trust bundle: loading it, refreshing it, and serving `GET /api/public-keys`.
 *
 * The bundle maps `mfg_licence_no` to a manufacturer's ECDSA public key, and it is
 * the root of every signature decision in the system. The API needs it to verify a
 * scanned payload; the phone downloads it so it can verify one with no network at
 * all. Both uses are served from the same object here.
 *
 * Three decisions in this file are worth stating, because each one is a place where
 * the obvious implementation is wrong.
 *
 * **A reload failure must never break verification.** The bundle is re-read from
 * disk periodically so a newly onboarded manufacturer does not require a restart.
 * If that re-read fails — a half-written file caught mid-deploy, a bad signature, a
 * permissions change — the previous bundle keeps serving and the failure is logged.
 * A refresh that could take verification offline would make the whole API only as
 * reliable as the least careful file copy anyone ever performs on it, and a slightly
 * stale bundle of known-good keys is enormously safer than no keys at all. The one
 * thing that does hard-fail is the *initial* load, at startup: an API that cannot
 * verify anything should refuse to start rather than answer every scan UNVERIFIABLE.
 *
 * **Refreshing is lazy, not timed.** There is no `setInterval` here. A background
 * timer would hold the event loop open — breaking both graceful shutdown and
 * `node --test`, which does not exit while a timer is pending — and it would keep
 * re-reading the file on an idle server for no benefit. Instead staleness is checked
 * when the bundle is actually used, and `mtime` is consulted before parsing, so an
 * unchanged file costs one `stat` rather than a parse and a signature verification.
 *
 * **Verification reads through a live view, not a captured reference.** `verify.js`
 * and `reports.js` are handed `liveView()` rather than the bundle itself. They only
 * ever call `publicKeyFor`, so a one-method delegate is enough — and it means a
 * reload is actually visible to them. Passing the bundle object directly would
 * compile, pass tests, and quietly pin those services to whatever was on disk at
 * startup, which is exactly the bug this endpoint exists to avoid.
 */

import { readFile, stat } from 'node:fs/promises';

import { TrueMedError, CODES } from '../core/errors.js';
import { loadPublicKey } from '../core/ecdsa.js';
import { TrustBundle } from '../core/trust-bundle.js';

/**
 * Read and parse a trust bundle from disk.
 *
 * Exported because `app.js` performs the initial load before any service exists —
 * the whole app is refused if this throws — and `scripts/seed-demo.js` needs the
 * same loader.
 *
 * @param {{bundlePath: string, rootPublicKeyPath: string, requireSignature: boolean}} cfg
 * @returns {Promise<TrustBundle>}
 */
export async function loadTrustBundle(cfg) {
  let blob;
  try {
    blob = await readFile(cfg.bundlePath, 'utf8');
  } catch (cause) {
    throw new TrueMedError(
      CODES.INTERNAL_ERROR,
      `the trust bundle could not be read from ${cfg.bundlePath}. The API cannot ` +
        'verify any medicine without it.',
      { cause, expose: false },
    );
  }

  // The root key is only needed to check the bundle's own signature, so it is
  // loaded here rather than held anywhere: nothing else in the API has any use for
  // it, and the server holds no root *private* key at all by design (§5).
  let rootPublicKey = null;
  if (cfg.requireSignature) {
    let pem;
    try {
      pem = await readFile(cfg.rootPublicKeyPath, 'utf8');
    } catch (cause) {
      throw new TrueMedError(
        CODES.INTERNAL_ERROR,
        `the trust root public key could not be read from ${cfg.rootPublicKeyPath}, ` +
          'so the trust bundle signature cannot be checked. Set ' +
          'TRUST_REQUIRE_SIGNATURE=0 only in development.',
        { cause, expose: false },
      );
    }
    rootPublicKey = loadPublicKey(pem);
  }

  return TrustBundle.fromJSON(blob, {
    rootPublicKey,
    requireSignature: cfg.requireSignature,
  });
}

/**
 * @param {{config: object, bundle: TrustBundle,
 *          logger?: import('../utils/logger.js').Logger,
 *          clock?: () => Date,
 *          load?: (cfg: object) => Promise<TrustBundle>}} deps
 */
export function makeTrustService({
  config,
  bundle,
  logger,
  clock = () => new Date(),
  load = loadTrustBundle,
}) {
  const cfg = config.trust;
  let current = bundle;
  let loadedAtMs = clock().getTime();
  let loadedMtimeMs = null;
  // One in-flight reload at a time. Without this, a burst of requests arriving the
  // moment the bundle goes stale would each start their own read, parse and
  // signature verification of the same file.
  let inFlight = null;

  /** True when enough time has passed to be worth a `stat`. 0 disables refreshing. */
  function isStale() {
    const interval = Number(cfg.reloadIntervalMs ?? 0);
    if (!Number.isFinite(interval) || interval <= 0) return false;
    return clock().getTime() - loadedAtMs >= interval;
  }

  /**
   * Re-read the bundle if the file has changed. Never throws.
   *
   * @returns {Promise<TrustBundle>} the current bundle, new or previous
   */
  async function refresh() {
    if (inFlight) return inFlight;
    inFlight = (async () => {
      try {
        // Cheap gate: an untouched file is the overwhelmingly common case, and
        // re-verifying its root signature every few minutes buys nothing.
        let mtimeMs = null;
        try {
          mtimeMs = (await stat(cfg.bundlePath)).mtimeMs;
        } catch {
          // A stat failure alone is not grounds to discard a working bundle; fall
          // through to the read, which will produce a properly logged failure.
          mtimeMs = null;
        }
        if (mtimeMs !== null && mtimeMs === loadedMtimeMs) {
          // Reset the clock, or a never-changing file is stat-ed on every request.
          loadedAtMs = clock().getTime();
          return current;
        }

        const next = await load(cfg);
        const before = current.summary();
        current = next;
        loadedMtimeMs = mtimeMs;
        loadedAtMs = clock().getTime();
        const after = next.summary();
        if (before.issued_at !== after.issued_at || before.key_count !== after.key_count) {
          logger?.info?.('trust bundle reloaded', {
            issued_at: after.issued_at,
            key_count: after.key_count,
            active_key_count: after.active_key_count,
            previous_issued_at: before.issued_at,
          });
        }
        return current;
      } catch (err) {
        // Deliberately swallowed: the previous bundle is still good. Logged at warn
        // rather than error because verification is unaffected — but it is logged
        // every interval, so a bundle left broken cannot go unnoticed.
        loadedAtMs = clock().getTime();
        logger?.warn?.('trust bundle reload failed; continuing with the previous one', {
          path: cfg.bundlePath,
          error: err?.message ?? String(err),
        });
        return current;
      } finally {
        inFlight = null;
      }
    })();
    return inFlight;
  }

  /** The bundle to use now, refreshed first if it has gone stale. */
  async function activeBundle() {
    if (isStale()) return refresh();
    return current;
  }

  /**
   * `GET /api/public-keys` → 200.
   *
   * The bundle's parsed contents are returned as the envelope's `data`, which is
   * what the Dart client reads (`fetchTrustBundle` re-encodes `result.data` and
   * hands it to `TrustBundle.fromJson`). Re-encoding is safe here and *only* here:
   * the root signature covers `canonicalJSONBytes({version, issued_at, keys})`, a
   * canonical re-serialisation of the parsed fields by definition, so whitespace and
   * key order cannot change what gets verified. The opposite rule holds one layer
   * down — a QR payload must be verified over its received bytes (§1.5), and
   * re-serialising one of those is a signature bypass.
   *
   * `rawJSON()` is the source rather than `toDict()` so that every field the file
   * carried reaches the client verbatim in content, `root_signature` included. A
   * bundle rebuilt from the class's own view of itself would silently drop any field
   * the class does not model, and the client verifies the signature over what it
   * receives — so a dropped field would present as a corrupt bundle on the phone
   * while looking perfectly healthy on the server.
   *
   * @returns {Promise<object>} the bundle, ready to be wrapped in the §4.1 envelope
   */
  async function publicKeys() {
    const active = await activeBundle();
    return JSON.parse(active.rawJSON());
  }

  /**
   * A one-method delegate over whatever bundle is current.
   *
   * Handed to `verify.js` and `reports.js` in place of the bundle so that a reload
   * reaches them. `publicKeyFor` is the only member `verifyWire` touches.
   *
   * It is deliberately synchronous, and therefore does not itself trigger a refresh:
   * a signature check sits on the patient's critical path, and making it wait on a
   * file read would put disk latency between a scan and its verdict. The refresh
   * happens on the endpoints that can afford it, and a bundle at most one interval
   * stale is precisely what the offline-capable design already tolerates.
   */
  function liveView() {
    return {
      publicKeyFor: (mfgLicenceNo, when) => current.publicKeyFor(mfgLicenceNo, when),
    };
  }

  /** For `/readyz` and startup logging. */
  function summary() {
    return current.summary();
  }

  return { publicKeys, liveView, summary, refresh, activeBundle };
}
