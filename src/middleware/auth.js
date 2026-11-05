/**
 * API-key authentication and role authorisation.
 *
 * Writers (manufacturer, distributor, sensor, regulator, pharmacy) and dashboard
 * readers (pharma) present an opaque bearer key in the `X-API-Key` header. The
 * store holds only the SHA-256 hash of each key, so authentication is: hash the
 * presented key, look up the live row, attach `{ role, scope }` to the request. A
 * leaked key table therefore yields no usable credentials, and there is no
 * per-request secret comparison to get wrong — the hash is the lookup key.
 *
 * The public routes (patient verify, patient report, public keys) use none of
 * this; they are deliberately unauthenticated so a patient never needs an account
 * to check a medicine. Authorisation is a separate step from authentication:
 * `requireRole` first proves identity, then checks the role, so a valid key for
 * the wrong role gets a clear 403, not a confusing 401.
 *
 * `scope` is carried but never interpreted here. For a `pharma` key it holds the
 * holder's `mfg_licence_no`, and the dashboard service filters on it so one
 * manufacturer cannot read another's batches (§4.4a). It stays out of this file
 * because a role check and a tenancy check are different questions: this
 * middleware answers "who are you", and only the endpoint knows what its own data
 * is scoped by.
 */

import { createHash } from 'node:crypto';

import { forbidden, unauthorized } from '../core/errors.js';

const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

/**
 * @param {{store: {findApiKey: Function, touchApiKey?: Function},
 *          logger?: import('../utils/logger.js').Logger}} deps
 */
export function makeAuth({ store, logger }) {
  /**
   * Resolve and attach the caller's identity, or throw 401. Shared by both
   * middlewares so a role check never does a second store lookup.
   */
  async function resolve(req) {
    const presented = req.get('X-API-Key');
    if (typeof presented !== 'string' || presented.trim() === '') {
      throw unauthorized('missing X-API-Key header');
    }
    const keyHash = sha256hex(presented);
    const row = await store.findApiKey(keyHash);
    if (!row) {
      // Same message whether the key is unknown or revoked — telling them apart
      // only helps an attacker probe which keys once existed.
      throw unauthorized('invalid or revoked API key');
    }
    req.auth = { role: row.role, keyId: row.id, keyHash, scope: row.scope ?? '' };
    // Record last-used without blocking or failing the request on a write error.
    if (store.touchApiKey) {
      Promise.resolve(store.touchApiKey(keyHash)).catch((err) =>
        logger?.debug?.('touchApiKey failed', { error: err?.message }),
      );
    }
    return row;
  }

  /** Require any valid key (role-agnostic). */
  const authenticate = (req, res, next) => resolve(req).then(() => next()).catch(next);

  /**
   * Require a valid key whose role is one of `roles`.
   * @param {...string} roles
   */
  const requireRole = (...roles) => (req, res, next) =>
    resolve(req)
      .then(() => {
        if (!roles.includes(req.auth.role)) {
          throw forbidden(
            `this action requires role ${roles.join(' or ')}; your key has role ${req.auth.role}`,
          );
        }
        next();
      })
      .catch(next);

  return { authenticate, requireRole };
}

export { sha256hex };
