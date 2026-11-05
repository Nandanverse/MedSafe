/**
 * Fabric driver factory and the API-role → Fabric-MSP mapping.
 *
 * `createFabric` returns the in-memory ledger under FABRIC_MOCK=1 and the real
 * gateway client otherwise — the config layer already refuses to let FABRIC_MOCK=1
 * reach production, so this switch cannot silently ship a mock to prod.
 *
 * The role→MSP mapping deserves a word. API callers authenticate with a role
 * (manufacturer, distributor, sensor, regulator, pharma, pharmacy); the chaincode
 * enforces §3.4 by the *submitting identity's* MSP. The mock ledger honours this
 * mapping directly, which is what makes the §3.4 rules testable here.
 *
 * On the real network there is a genuine limitation, stated plainly rather than
 * hidden: this client connects with a single Fabric identity (config.fabric.mspId).
 * A deployment that needs the API to submit as more than one org must run one
 * gateway identity per writing MSP; the single-identity setup shipped here covers
 * the manufacturer mint/custody flow, which is the demonstrated path. Where the
 * requested role's MSP differs from the connected identity, the mock enforces the
 * rule and the real chaincode will reject the transaction — either way the caller
 * gets a clear 403 rather than a silent wrong-org write.
 */

import { MockLedger, MSP } from './mock-ledger.js';
import { FabricGatewayClient } from './gateway-client.js';

/** API role → the Fabric MSP a submission is attributed to. */
const ROLE_TO_MSP = Object.freeze({
  manufacturer: MSP.MANUFACTURER,
  distributor: MSP.DISTRIBUTOR,
  // The cold-box sensor sits with the distributor in the chain, so its readings
  // are attributed to DistributorMSP (§3.4 permits Manufacturer or Distributor).
  sensor: MSP.DISTRIBUTOR,
  regulator: MSP.REGULATOR,
  // A retail chemist is the last custody holder before the patient. §3.4 admits
  // only ManufacturerMSP or DistributorMSP to UpdateLocation, and adding a fourth
  // org to the Fabric network for every pharmacy in India is not a deployment
  // anyone would run — so a pharmacy submits under DistributorMSP, the org that
  // already covers downstream distribution.
  //
  // That widening is safe only because the *status* restriction sits above it:
  // the location service confines a pharmacy key to `at_pharmacy` and `dispensed`
  // (§4.3). Without that check this line alone would let a chemist's key rewind a
  // unit to `in_transit`, which is exactly the attack §4.3 spells out. Role gates
  // the endpoint, the status list gates the transition, §3.1's ordering gates the
  // direction. Never remove one and keep the other two.
  pharmacy: MSP.DISTRIBUTOR,
  // pharma is read-only (dashboards); it never submits a write. Note that `pharma`
  // and `pharmacy` are different roles with deliberately different rights — §4.2.
});

/** @returns {string|null} the MSP for a role, or null for read-only/public roles. */
export function mspForRole(role) {
  return ROLE_TO_MSP[role] ?? null;
}

/**
 * @param {object} config  the frozen app config
 * @param {import('../utils/logger.js').Logger} logger
 * @param {{clock?: () => Date}} [opts]  injected clock for the mock (tests pin it)
 */
export function createFabric(config, logger, opts = {}) {
  if (config.fabric.mock) {
    logger?.info('fabric driver: MOCK (in-memory ledger)');
    return new MockLedger({ clock: opts.clock, logger });
  }
  return new FabricGatewayClient(config.fabric, logger);
}

export { MSP };
