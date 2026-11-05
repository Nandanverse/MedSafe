/**
 * `POST /api/report` — a patient reporting suspected counterfeit medicine.
 *
 * Public and unauthenticated, by design: a patient holding a fake strip must be
 * able to say so without an account, and requiring one would silence exactly the
 * reports the system exists to collect. That makes this the most exposed write in
 * the API, so what it accepts is bounded tightly, and what it stores is bounded by
 * the DPDP Act rather than by what a client happens to send.
 *
 * **A report is never rejected for failing verification.** The report is evidence,
 * not a claim to be adjudicated. A payload that will not decode, a product ID
 * absent from the ledger, a signature that fails — each of those makes a report
 * *more* interesting to a regulator, not less. So when `raw_payload` is present and
 * readable, it is used to recover the `product_id` a client omitted and its offline
 * verdict is logged as a triage hint; when it is unreadable, the report is still
 * accepted. Nothing about the verdict can turn a submission away.
 *
 * **Personal data is minimised, then sealed.** `reporter_contact` is optional and
 * nullable — §4.5 says anonymous reporting must be possible — and when present it is
 * encrypted with the report's own id as AEAD context, so a stolen row cannot be
 * opened without the app's key and cannot be transplanted onto another report. The
 * client IP is kept for abuse triage and never returned. The photo is size-capped
 * and its declared type checked against its actual magic bytes.
 *
 * The response is deliberately thin (§4.5a is silent on it, so §4.1 governs): a
 * report id and a timestamp. A patient does not need their own submission read back,
 * and echoing the stored row would hand back the contact ciphertext and the IP.
 */

import { randomUUID } from 'node:crypto';

import { validationError } from '../core/errors.js';
import { verifyWire } from '../core/verifier.js';
import { LIMITS, stamp, validateProductID, validateText } from '../core/rules.js';
import { reportContext } from '../utils/secret-box.js';

/**
 * Photo ceiling, in decoded bytes.
 *
 * A phone camera JPEG at reasonable quality is 200–800 kB, so 2 MiB accepts a
 * genuine photo without argument while bounding what one unauthenticated request
 * can push into storage. The check is on decoded length, not the base64 text: an
 * attacker controls the encoding and base64 inflates by a third, so limiting the
 * string would leave the real figure a third higher than intended.
 */
const MAX_PHOTO_BYTES = 2 * 1024 * 1024;

/**
 * Upper bound on the base64 field before it is decoded at all.
 *
 * Without this the decode happens first and a 100 MB string is materialised in
 * memory just to be measured and thrown away — the cheap denial of service against
 * a public endpoint. Base64 is 4 bytes per 3, plus padding and any whitespace a
 * client inserts, so this is the byte ceiling scaled up with room to spare.
 */
const MAX_PHOTO_BASE64_CHARS = Math.ceil((MAX_PHOTO_BYTES * 4) / 3) + 1024;

/**
 * Accepted image types, by magic bytes.
 *
 * Sniffed rather than trusted from a `data:` prefix or a filename, because the
 * stored bytes are what a regulator will eventually open. A file claiming to be a
 * JPEG that is actually HTML is the setup for a stored-XSS payload delivered
 * through whatever viewer a CDSCO officer uses, and this endpoint takes uploads
 * from anyone at all.
 */
const IMAGE_MAGIC = [
  { type: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },
  { type: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: 'image/webp', bytes: [0x52, 0x49, 0x46, 0x46], at8: [0x57, 0x45, 0x42, 0x50] },
];

/** Match a decoded buffer against the accepted magic-byte signatures. */
function sniffImage(buf) {
  for (const sig of IMAGE_MAGIC) {
    if (buf.length < sig.bytes.length) continue;
    if (!sig.bytes.every((b, i) => buf[i] === b)) continue;
    // WebP is `RIFF....WEBP`, so the first four bytes alone would also match a WAV.
    if (sig.at8) {
      if (buf.length < 12) continue;
      if (!sig.at8.every((b, i) => buf[8 + i] === b)) continue;
    }
    return sig.type;
  }
  return null;
}

/**
 * Decode and validate `photo_base64`.
 *
 * @returns {{photo: Buffer, mime: string}|null}
 */
function decodePhoto(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') {
    throw validationError('photo_base64 must be a base64-encoded string');
  }

  // A `data:` URL is what a browser's FileReader produces, so accept it rather than
  // storing the header as if it were image data — but the declared type in it is
  // ignored in favour of the magic bytes below.
  let text = value.trim();
  const comma = text.startsWith('data:') ? text.indexOf(',') : -1;
  if (comma !== -1) text = text.slice(comma + 1);

  if (text.length > MAX_PHOTO_BASE64_CHARS) {
    throw validationError(
      `photo_base64 is too large; the limit is ${MAX_PHOTO_BYTES / 1024 / 1024} MB ` +
        'of image data — send a single compressed photo of the strip and its packaging',
    );
  }

  // Node's base64 decoder silently ignores characters outside the alphabet, so a
  // corrupt upload would otherwise be stored as a shorter, broken image. Re-encoding
  // and comparing is the reliable way to tell a valid encoding from a tolerated one.
  const compact = text.replace(/\s+/g, '');
  const photo = Buffer.from(compact, 'base64');
  if (!photo.length || photo.toString('base64').replace(/=+$/, '') !== compact.replace(/=+$/, '')) {
    throw validationError('photo_base64 is not valid base64');
  }
  if (photo.length > MAX_PHOTO_BYTES) {
    throw validationError(
      `the photo decodes to ${photo.length} bytes, over the ` +
        `${MAX_PHOTO_BYTES / 1024 / 1024} MB limit`,
    );
  }

  const mime = sniffImage(photo);
  if (!mime) {
    throw validationError(
      'the photo is not a JPEG, PNG or WebP image; its contents do not match any ' +
        'of those formats regardless of what it is named',
    );
  }
  return { photo, mime };
}

/**
 * Optional short text, trimmed and length-checked, or `''`.
 *
 * `validateText` rejects an empty string, which is right for a required field and
 * wrong here: a client sending `district: ""` means "not provided", and failing the
 * whole report over it would lose evidence to a formatting detail.
 */
function optionalText(field, value) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') {
    throw validationError(`${field} must be a string when provided`);
  }
  if (value.trim() === '') return '';
  return validateText(field, value, LIMITS[field]);
}

/**
 * A coarse coordinate, or null.
 *
 * Rounded to three decimals — about 100 m — because the district is what drives the
 * heat map and a precise fix on a patient reporting their own pharmacy is personal
 * data the system has no use for. Under the DPDP Act, collecting less is the
 * default, and a truncated coordinate cannot be un-truncated after a breach.
 */
function coarseCoord(field, value, limit) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n < -limit || n > limit) {
    throw validationError(`${field} must be a number between -${limit} and ${limit}`);
  }
  return Math.round(n * 1000) / 1000;
}

/**
 * @param {{store: object, trust: object, secrets: object,
 *          logger?: import('../utils/logger.js').Logger,
 *          clock?: () => Date}} deps
 */
export function makeReportsService({ store, trust, secrets, logger, clock = () => new Date() }) {
  /**
   * `POST /api/report` (§4.5) → 201.
   *
   * @param {object} input     the request body
   * @param {{ip?: string|null}} [meta]  transport facts the route supplies
   * @returns {Promise<{report_id: string, received_at: string}>}
   */
  async function submit(input, meta = {}) {
    const rawPayload = typeof input?.raw_payload === 'string' ? input.raw_payload : '';

    // A product ID is required, but it may be recovered from the payload when the
    // client sent only the scan. Between them there must be something identifying
    // the medicine, or the report cannot be attached to anything.
    let productID = null;
    if (input?.product_id !== undefined && input.product_id !== null && input.product_id !== '') {
      productID = validateProductID(input.product_id);
    }

    // Best-effort, and never fatal: an unreadable payload is itself worth reporting.
    //
    // `verifyWire` is used rather than `decode` because it returns the parsed
    // `medicine` even when the verdict is COUNTERFEIT — a forged signature over
    // well-formed fields still tells us which product is being impersonated, which
    // is exactly the report a regulator wants attached to that product ID.
    let payloadVerdict = null;
    if (rawPayload) {
      try {
        // `liveView()` supplies the `publicKeyFor` that `verifyWire` needs; the
        // service itself does not have one. Getting this wrong is silent here,
        // because the catch below turns it into "payload unreadable" — and a report
        // sent with only a scan would then be refused for having no product_id.
        const offline = verifyWire(rawPayload, trust.liveView(), { today: clock() });
        payloadVerdict = offline.verdict;
        if (!productID && offline.medicine) productID = offline.medicine.productID;
      } catch {
        // Left null. `verifyWire` reports a bad payload as a verdict rather than by
        // throwing, so this catches only an unexpected fault — and even then the
        // report proceeds, because refusing it would discard the evidence.
        payloadVerdict = null;
      }
    }

    if (!productID) {
      throw validationError(
        'a report needs either product_id or a raw_payload the server can read a ' +
          'product_id out of, so the report can be attached to a medicine',
      );
    }

    const photo = decodePhoto(input?.photo_base64);

    // The id is generated here rather than left to the store, because it is the AEAD
    // context binding the sealed contact to this row and must exist before the seal.
    const id = randomUUID();
    let contactEnc = null;
    const contact = optionalText('reporter_contact', input?.reporter_contact);
    if (contact) contactEnc = secrets.seal(contact, reportContext(id));

    const row = await store.insertReport({
      id,
      product_id: productID,
      pharmacy_name: optionalText('pharmacy_name', input?.pharmacy_name),
      district: optionalText('district', input?.district),
      state: optionalText('state', input?.state),
      lat: coarseCoord('lat', input?.lat, 90),
      lon: coarseCoord('lon', input?.lon, 180),
      notes: optionalText('notes', input?.notes),
      photo: photo?.photo ?? null,
      photo_bytes: photo?.photo.length ?? 0,
      reporter_contact_enc: contactEnc,
      client_ip: meta.ip ?? null,
    });

    // Logged without the contact, the photo or the IP: this line goes to whatever
    // aggregates logs, and personal data in it would outlive the sealing above.
    logger?.info?.('counterfeit report accepted', {
      report_id: row.id,
      product_id: productID,
      district: row.district || null,
      has_photo: Boolean(photo),
      payload_verdict: payloadVerdict,
    });

    // §4.1 shape only — the stored row holds ciphertext and an IP the reporter must
    // not be handed back.
    return { report_id: row.id, received_at: row.created_at ?? stamp(clock()) };
  }

  return { submit };
}
