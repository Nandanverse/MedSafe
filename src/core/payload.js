/**
 * The signed data elements of one sellable unit.
 *
 * Port of qr-generator/truemed_qr/payload.py. Everything here is
 * security-relevant: if signer and verifier disagree by one byte about how a
 * payload serialises, either every signature check fails (obvious, survivable)
 * or a canonicalisation gap opens that lets an attacker mutate fields while
 * keeping a valid signature (silent, not survivable).
 *
 * **This module is validation of a signed field, so it must not be stricter than
 * the signer.** That asymmetry is the governing rule of the whole file. Being
 * stricter than Python here does not make TrueMed safer — it makes genuine
 * medicine read as COUNTERFEIT, which is the single worst outcome the system can
 * produce. Anywhere a limit or pattern looks oddly permissive, it is matching
 * payload.py on purpose. Stricter rules belong on API *input* (rules.js), where
 * a rejection lands on whoever typed the data.
 *
 * Wire keys are short (`bn`, not `brand_name`) because QR capacity is the
 * binding constraint on a 10-tablet blister strip. Full names are used
 * everywhere off the wire. Mapping: DATA-CONTRACT.md §1.3.
 */

import { TrueMedError, CODES } from './errors.js';
import { canonicalJSONBytes, canonicalJSONString } from './canonical.js';
import {
  LIMITS,
  TYPE,
  TYPE_WIRE,
  WIRE_TYPE,
  asCodePointLabel,
  daysToExpiry as daysToExpiryOf,
  findControlChar,
  isExpired as isExpiredOn,
  parseDate,
} from './rules.js';

export const CONTRACT_VERSION = 1;

/**
 * Maximum bytes a QR code can carry at error-correction level H (version 40).
 * Level H is chosen because a blister strip in a patient's pocket gets creased,
 * and H tolerates 30% damage.
 */
export const QR_MAX_BYTES_ECC_H = 1273;

/** `TM1` + two `.` + 86 base64url characters of a 64-byte signature. */
const WIRE_OVERHEAD = 3 + 1 + 1 + 86;

/**
 * Hard ceiling on the canonical payload **in bytes**, derived from QR capacity
 * rather than guessed. `((1273 - 91) / 4) * 3 = 885`.
 *
 * Bytes, not characters, and that distinction is the point. The per-field limits
 * count characters, which is right for data quality and wrong for capacity: a
 * 64-character Devanagari generic name occupies 192 bytes in UTF-8. Enforcing
 * only character limits therefore permits payloads that cannot physically be
 * printed. Checking the budget at construction means an unprintable payload
 * cannot be built at all, so the failure lands on whoever typed the data rather
 * than stopping a production line at print time.
 */
export const MAX_PAYLOAD_BYTES =
  Math.floor((QR_MAX_BYTES_ECC_H - WIRE_OVERHEAD) / 4) * 3;

const MAX_EXCIPIENTS = 12;

/** Identical to `_PRODUCT_ID_RE` in payload.py. See the note in rules.js. */
const PRODUCT_ID_RE = /^[A-Z0-9]+_[A-Z0-9]+_\d{4}_\d{6}$/;

/** Required short keys, in the order payload.py lists them. */
export const REQUIRED_WIRE_KEYS = Object.freeze([
  'v', 'id', 'gn', 'bn', 'mf', 'ml', 'bt', 'md', 'ed', 'qt', 'ex', 'tp',
]);

export const REQUIRED_FULL_KEYS = Object.freeze([
  'product_id', 'generic_name', 'brand_name', 'manufacturer', 'mfg_licence_no',
  'batch_no', 'mfg_date', 'expiry_date', 'quantity', 'excipients', 'type',
]);

const payloadError = (message) => new TrueMedError(CODES.PAYLOAD_INVALID, message);

/**
 * `_require_str` from payload.py: a string, trimmed, non-empty, no control
 * characters, within its character limit.
 */
function requireStr(raw, fieldName, maxLen) {
  if (typeof raw !== 'string') {
    throw payloadError(`${fieldName} must be a string, got ${typeOf(raw)}`);
  }
  const value = raw.trim();
  if (!value) throw payloadError(`${fieldName} must not be empty`);
  const control = findControlChar(value);
  if (control) {
    throw payloadError(
      `${fieldName} contains a control character ` +
        `(${asCodePointLabel(control.codePoint)}); control characters are not ` +
        'permitted in signed fields',
    );
  }
  const limit = maxLen ?? LIMITS[fieldName];
  // Code points, not UTF-16 units, so `len()` in Python and this agree on the
  // length of Devanagari and emoji alike.
  const length = [...value].length;
  if (limit !== undefined && length > limit) {
    throw payloadError(
      `${fieldName} is ${length} characters, exceeding the ${limit}-character ` +
        'limit that keeps the QR code scannable',
    );
  }
  return value;
}

/** Python-style type name, for error messages that match payload.py's. */
function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'list';
  return typeof value;
}

/**
 * One sellable unit's signed data.
 *
 * Frozen after construction because a payload must not be mutated between
 * signing and encoding — precisely the window in which a tampering bug hides.
 *
 * `productId` is the primary key across all of TrueMed: the QR field, the Fabric
 * world-state key, the API path parameter, and the PostgreSQL foreign key.
 */
export class MedicineData {
  /**
   * @param {{
   *   product_id: string, generic_name: string, brand_name: string,
   *   manufacturer: string, mfg_licence_no: string, batch_no: string,
   *   mfg_date: string, expiry_date: string, quantity: string,
   *   excipients?: string[], med_type?: string, contract_version?: number
   * }} fields
   */
  constructor(fields) {
    const {
      product_id: productID,
      generic_name: genericName,
      brand_name: brandName,
      manufacturer,
      mfg_licence_no: mfgLicenceNo,
      batch_no: batchNo,
      mfg_date: mfgDate,
      expiry_date: expiryDate,
      quantity,
      excipients = [],
      med_type: medType = TYPE.MEDICINE,
      contract_version: contractVersion = CONTRACT_VERSION,
    } = fields ?? {};

    this.productID = requireStr(productID, 'product_id');
    this.genericName = requireStr(genericName, 'generic_name');
    this.brandName = requireStr(brandName, 'brand_name');
    this.manufacturer = requireStr(manufacturer, 'manufacturer');
    this.mfgLicenceNo = requireStr(mfgLicenceNo, 'mfg_licence_no');
    this.batchNo = requireStr(batchNo, 'batch_no');
    this.quantity = requireStr(quantity, 'quantity');

    if (!PRODUCT_ID_RE.test(this.productID)) {
      throw payloadError(
        `product_id ${JSON.stringify(this.productID)} does not match ` +
          '{GENERIC}_{BRAND}_{YEAR}_{SERIAL} with a 4-digit year and 6-digit ' +
          'serial; build it with makeProductID()',
      );
    }

    if (contractVersion !== CONTRACT_VERSION) {
      throw payloadError(
        `contract_version must be ${CONTRACT_VERSION} for prefix TM1, got ` +
          JSON.stringify(contractVersion),
      );
    }
    this.contractVersion = contractVersion;

    if (!Object.hasOwn(TYPE_WIRE, medType)) {
      throw payloadError(
        `type must be one of ${Object.keys(TYPE_WIRE).sort().join(', ')}, got ` +
          JSON.stringify(medType),
      );
    }
    this.medType = medType;

    // parseDate throws PAYLOAD_INVALID and rejects rollover dates like
    // 2026-02-31, so both languages refuse the same set of dates.
    const mfg = parseDate('mfg_date', mfgDate);
    const exp = parseDate('expiry_date', expiryDate);
    if (exp <= mfg) {
      throw payloadError(
        `expiry_date (${expiryDate}) must be after mfg_date (${mfgDate})`,
      );
    }
    this.mfgDate = mfgDate;
    this.expiryDate = expiryDate;

    if (!Array.isArray(excipients)) {
      throw payloadError(
        'excipients must be a JSON array of strings, not ' +
          `${typeOf(excipients)}; a comma-joined string is unparseable because ` +
          'excipient names may themselves contain commas',
      );
    }
    if (excipients.length > MAX_EXCIPIENTS) {
      throw payloadError(
        `excipients has ${excipients.length} entries, over the ` +
          `${MAX_EXCIPIENTS} limit; list only the declared inactive ingredients`,
      );
    }
    this.excipients = excipients.map((item) =>
      requireStr(item, 'excipient', LIMITS.excipient),
    );

    // Capacity gate last, because it needs every field in its final form.
    const size = this.canonicalJSON().length;
    if (size > MAX_PAYLOAD_BYTES) {
      throw payloadError(
        `payload encodes to ${size} bytes, over the ${MAX_PAYLOAD_BYTES}-byte ` +
          'budget that fits a QR code at error-correction level H (overflow: ' +
          `${size - MAX_PAYLOAD_BYTES} bytes). Shorten the manufacturer address ` +
          'or trim the excipient list. Note that non-Latin text costs up to 3 ' +
          'bytes per character, so a Devanagari field uses far more of the ' +
          'budget than its character count suggests.',
      );
    }

    Object.freeze(this.excipients);
    Object.freeze(this);
  }

  get isVaccine() {
    return this.medType === TYPE.VACCINE;
  }

  /** Days remaining; negative once expired, 0 on the expiry day itself. */
  daysToExpiry(today) {
    return daysToExpiryOf(this.expiryDate, today ?? new Date());
  }

  /** The expiry day itself still counts as usable, as a pharmacist reads it. */
  isExpired(today) {
    return isExpiredOn(this.expiryDate, today ?? new Date());
  }

  /** Short-key representation that goes inside the QR. */
  toWireDict() {
    return {
      v: this.contractVersion,
      id: this.productID,
      gn: this.genericName,
      bn: this.brandName,
      mf: this.manufacturer,
      ml: this.mfgLicenceNo,
      bt: this.batchNo,
      md: this.mfgDate,
      ed: this.expiryDate,
      qt: this.quantity,
      ex: [...this.excipients],
      tp: TYPE_WIRE[this.medType],
    };
  }

  /** Full-name representation used by the API, chaincode, and app. */
  toDict() {
    return {
      contract_version: this.contractVersion,
      product_id: this.productID,
      generic_name: this.genericName,
      brand_name: this.brandName,
      manufacturer: this.manufacturer,
      mfg_licence_no: this.mfgLicenceNo,
      batch_no: this.batchNo,
      mfg_date: this.mfgDate,
      expiry_date: this.expiryDate,
      quantity: this.quantity,
      excipients: [...this.excipients],
      type: this.medType,
    };
  }

  /**
   * The exact bytes that get signed: sorted keys, no whitespace, UTF-8, no
   * trailing newline. The only payload-to-bytes function in the backend.
   *
   * @returns {Buffer}
   */
  canonicalJSON() {
    return canonicalJSONBytes(this.toWireDict());
  }

  /** Same bytes as a string, for logging and fixtures. */
  canonicalJSONString() {
    return canonicalJSONString(this.toWireDict());
  }

  /** Rebuild from the short-key form found inside a QR code. */
  static fromWireDict(raw) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      throw payloadError(`QR payload must be a JSON object, got ${typeOf(raw)}`);
    }

    const missing = REQUIRED_WIRE_KEYS.filter((k) => !Object.hasOwn(raw, k));
    if (missing.length) {
      throw payloadError(
        `QR payload is missing required keys: ${missing.join(', ')}`,
      );
    }

    const version = raw.v;
    // `typeof true === 'boolean'`, so JS needs no explicit bool guard the way
    // Python does (where bool is a subclass of int) — but it does need the
    // integer check, since JSON has one number type and `1.5` would pass here.
    if (typeof version !== 'number' || !Number.isInteger(version)) {
      throw payloadError(
        `payload key 'v' must be an integer, got ${JSON.stringify(raw.v)}`,
      );
    }

    if (!Object.hasOwn(WIRE_TYPE, raw.tp)) {
      throw payloadError(
        `payload key 'tp' must be one of ${Object.keys(WIRE_TYPE).sort().join(', ')}, ` +
          `got ${JSON.stringify(raw.tp)}`,
      );
    }

    return new MedicineData({
      product_id: raw.id,
      generic_name: raw.gn,
      brand_name: raw.bn,
      manufacturer: raw.mf,
      mfg_licence_no: raw.ml,
      batch_no: raw.bt,
      mfg_date: raw.md,
      expiry_date: raw.ed,
      quantity: raw.qt,
      excipients: raw.ex,
      med_type: WIRE_TYPE[raw.tp],
      contract_version: version,
    });
  }

  /**
   * Parse signed payload bytes.
   *
   * Note the asymmetry with `canonicalJSON()`: this does *not* require that
   * `blob` was canonically encoded. Verification signs over the received bytes,
   * so a non-canonical but correctly-signed payload is still authentic — it just
   * could not have come from our generator.
   *
   * @param {Uint8Array|Buffer} blob
   */
  static fromCanonicalJSON(blob) {
    let text;
    try {
      // `fatal: true` matters. Buffer.toString('utf8') replaces malformed
      // sequences with U+FFFD without complaint, so a payload containing invalid
      // UTF-8 would parse into subtly different text than the bytes that were
      // signed. Python raises UnicodeDecodeError here; so do we.
      text = new TextDecoder('utf-8', { fatal: true }).decode(blob);
    } catch {
      throw payloadError('QR payload is not valid UTF-8');
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw payloadError(`QR payload is not valid JSON: ${err.message}`);
    }
    return MedicineData.fromWireDict(parsed);
  }

  /** Rebuild from the full-name form used by the API. */
  static fromDict(raw) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      throw payloadError(`expected an object, got ${typeOf(raw)}`);
    }
    const missing = REQUIRED_FULL_KEYS.filter((k) => !Object.hasOwn(raw, k));
    if (missing.length) {
      throw payloadError(`missing required fields: ${missing.join(', ')}`);
    }
    return new MedicineData({
      product_id: raw.product_id,
      generic_name: raw.generic_name,
      brand_name: raw.brand_name,
      manufacturer: raw.manufacturer,
      mfg_licence_no: raw.mfg_licence_no,
      batch_no: raw.batch_no,
      mfg_date: raw.mfg_date,
      expiry_date: raw.expiry_date,
      quantity: raw.quantity,
      excipients: raw.excipients,
      med_type: raw.type,
      contract_version: raw.contract_version ?? CONTRACT_VERSION,
    });
  }
}

/**
 * Build a `{GENERIC}_{BRAND}_{YEAR}_{SERIAL}` product identifier.
 *
 * Non-alphanumerics are *removed* rather than replaced with underscores, so the
 * four-segment structure stays unambiguous — `Paracetamol 500mg` becoming
 * `PARACETAMOL_500MG` would introduce a fifth segment and break parsing.
 *
 * makeProductID('Paracetamol 500mg', 'Paracip 500', 2026, 1)
 *   → 'PARACETAMOL500MG_PARACIP500_2026_000001'
 */
export function makeProductID(genericName, brandName, year, serial) {
  if (!Number.isInteger(year) || year < 1900 || year > 2999) {
    throw payloadError(`year must be a 4-digit integer, got ${JSON.stringify(year)}`);
  }
  if (!Number.isInteger(serial) || serial <= 0 || serial > 999999) {
    throw payloadError(
      `serial must be an integer in 1..999999, got ${JSON.stringify(serial)}; ` +
        'a batch larger than that needs a second brand-year namespace',
    );
  }

  const squash = (text, label) => {
    if (typeof text !== 'string') throw payloadError(`${label} must be a string`);
    const out = text.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!out) {
      throw payloadError(
        `${label} ${JSON.stringify(text)} has no alphanumeric characters to ` +
          'build an ID from',
      );
    }
    return out;
  };

  const productID =
    `${squash(genericName, 'generic_name')}_${squash(brandName, 'brand_name')}_` +
    `${String(year).padStart(4, '0')}_${String(serial).padStart(6, '0')}`;

  if (productID.length > LIMITS.product_id) {
    throw payloadError(
      `generated product_id is ${productID.length} characters, over the ` +
        `${LIMITS.product_id} limit; shorten the generic or brand name`,
    );
  }
  return productID;
}
