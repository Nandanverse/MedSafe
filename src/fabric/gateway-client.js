/**
 * The real Hyperledger Fabric Gateway client, used when FABRIC_MOCK=0.
 *
 * It presents the identical interface to the mock ledger, so the service layer
 * never branches on which driver is behind it: createMedicine, updateLocation,
 * addTemperatureReading, recordPatientScan, recallBatch, verifyMedicine,
 * getMedicine, medicineExists, allMedicines, ping, close.
 *
 * Two implementation choices are worth stating:
 *
 * **The heavy dependencies are imported lazily, inside connect().** `@grpc/grpc-js`
 * and `@hyperledger/fabric-gateway` are only needed on the real path. Importing
 * them at module top would mean the mock path — the one the tests, the app and
 * the dashboards run on — could not even load the file without those packages
 * installed. A dynamic import keeps `node --test` green on a machine that has
 * never run `npm install` for production, and turns a missing dependency into a
 * clear startup error instead of an import crash.
 *
 * **Chaincode errors carry their contract code as a prefix.** Fabric surfaces a
 * chaincode's returned error as an opaque gRPC/endorse failure. So the Go
 * contract formats business errors as `CODE: message` (e.g. `VALIDATION_ERROR:
 * cannot move backwards`), and this client parses that prefix back into a
 * TrueMedError with the right HTTP status. Anything it cannot parse is a genuine
 * transport or endorsement failure and becomes UPSTREAM_UNAVAILABLE (503), never
 * a 500 that leaks peer hostnames. Component 2's chaincode must honour this
 * convention — it is part of the API↔chaincode contract.
 */

import { readFile } from 'node:fs/promises';
import { createPrivateKey } from 'node:crypto';

import { CODES, TrueMedError, isTrueMedError, upstreamUnavailable } from '../core/errors.js';
import { MAX_PAGE_SIZE } from '../core/rules.js';

const decoder = new TextDecoder('utf-8', { fatal: true });

/** Recognised `CODE:` prefixes a chaincode may return, mapped to our codes. */
const CHAINCODE_CODE_RE = /^([A-Z][A-Z0-9_]{2,40}):\s*(.*)$/s;

/**
 * Page size for the full-ledger scan behind allMedicines(). The chaincode clamps
 * anything above MAX_PAGE_SIZE (§3.7) to it, so asking for the maximum minimises
 * round trips without relying on the peer to be generous.
 */
const SCAN_PAGE_SIZE = MAX_PAGE_SIZE;

/**
 * Hard ceiling on pages per scan: 200 × 500 = 100,000 units.
 *
 * A dashboard request has to terminate. Without this a channel large enough to
 * outpace the page size would hold a request handler open indefinitely, and one
 * dashboard refresh could exhaust the peer's query capacity for everyone else.
 */
const MAX_SCAN_PAGES = 200;

export class FabricGatewayClient {
  /**
   * @param {object} cfg     config.fabric
   * @param {import('../utils/logger.js').Logger} logger
   */
  constructor(cfg, logger) {
    this.mock = false;
    this.cfg = cfg;
    this.log = logger;
    this.gateway = null;
    this.client = null; // the grpc.Client, closed separately from the gateway
    this.contract = null;
  }

  /**
   * Establish the gRPC channel and gateway connection. Idempotent: a second call
   * is a no-op once connected.
   */
  async connect() {
    if (this.contract) return;

    // Lazy, so the mock path never needs these installed. A missing package here
    // is a deployment mistake with an actionable message, not an import crash.
    let grpc;
    let fabric;
    try {
      grpc = (await import('@grpc/grpc-js')).default ?? (await import('@grpc/grpc-js'));
      fabric = await import('@hyperledger/fabric-gateway');
    } catch (cause) {
      throw new TrueMedError(
        CODES.INTERNAL_ERROR,
        'FABRIC_MOCK=0 but the Fabric client libraries are not installed. Run ' +
          '`npm ci` in backend/ so @hyperledger/fabric-gateway and @grpc/grpc-js ' +
          'are present.',
        { cause, expose: false },
      );
    }

    const { connect, signers, hash } = fabric;

    let tlsRootCert;
    let certPem;
    let keyPem;
    try {
      [tlsRootCert, certPem, keyPem] = await Promise.all([
        readFile(this.cfg.tlsCaPath),
        readFile(this.cfg.certPath),
        readFile(this.cfg.keyPath),
      ]);
    } catch (cause) {
      throw new TrueMedError(
        CODES.INTERNAL_ERROR,
        'could not read Fabric TLS CA, certificate or private key from the ' +
          'configured paths',
        { cause, expose: false },
      );
    }

    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);
    const grpcOptions = {};
    // The peer's certificate names it e.g. peer0.manufacturer.truemed.in while the
    // endpoint is localhost:7051; the override lets TLS verification succeed
    // against the certificate's name rather than being switched off.
    if (this.cfg.peerHostAlias) {
      grpcOptions['grpc.ssl_target_name_override'] = this.cfg.peerHostAlias;
    }
    this.client = new grpc.Client(this.cfg.peerEndpoint, tlsCredentials, grpcOptions);

    const identity = { mspId: this.cfg.mspId, credentials: certPem };
    const privateKey = createPrivateKey(keyPem);
    const signer = signers.newPrivateKeySigner(privateKey);

    const asMs = (ms) => ({ deadline: Date.now() + ms });
    this.gateway = connect({
      client: this.client,
      identity,
      signer,
      hash: hash.sha256,
      evaluateOptions: () => asMs(this.cfg.evaluateTimeoutMs),
      endorseOptions: () => asMs(this.cfg.submitTimeoutMs),
      submitOptions: () => asMs(this.cfg.submitTimeoutMs),
      commitStatusOptions: () => asMs(this.cfg.submitTimeoutMs),
    });

    const network = this.gateway.getNetwork(this.cfg.channel);
    this.contract = network.getContract(this.cfg.chaincode);
    this.log?.info('connected to Fabric', {
      channel: this.cfg.channel,
      chaincode: this.cfg.chaincode,
      msp: this.cfg.mspId,
      peer: this.cfg.peerEndpoint,
    });
  }

  async #ensure() {
    if (!this.contract) await this.connect();
  }

  /** Parse a chaincode result: bytes → utf8 → JSON, tolerating an empty body. */
  #parse(bytes) {
    if (!bytes || bytes.length === 0) return null;
    const text = decoder.decode(bytes);
    if (text.trim() === '') return null;
    try {
      return JSON.parse(text);
    } catch (cause) {
      throw new TrueMedError(
        CODES.INTERNAL_ERROR,
        'chaincode returned a non-JSON payload',
        { cause, expose: false },
      );
    }
  }

  /**
   * Translate a gateway/gRPC failure into a contract-shaped error.
   *
   * A chaincode business error arrives with its `CODE:` prefix somewhere in the
   * endorse details; parse it back so a distributor minting gets 403 FORBIDDEN,
   * not 503. A transport failure has no such prefix and becomes
   * UPSTREAM_UNAVAILABLE with the internal detail withheld from the client.
   */
  #translate(what, cause) {
    if (isTrueMedError(cause)) return cause;

    // fabric-gateway errors expose `details: [{ address, mspId, message }]`.
    const messages = [];
    if (cause && Array.isArray(cause.details)) {
      for (const d of cause.details) if (d && typeof d.message === 'string') messages.push(d.message);
    }
    if (cause && typeof cause.message === 'string') messages.push(cause.message);

    for (const message of messages) {
      const m = CHAINCODE_CODE_RE.exec(message.trim());
      if (m && CODES[m[1]]) {
        return new TrueMedError(m[1], m[2] || message, { expose: true });
      }
    }
    return upstreamUnavailable(`the blockchain (${what})`, cause);
  }

  async #evaluate(fn, args, what) {
    await this.#ensure();
    try {
      return this.#parse(await this.contract.evaluateTransaction(fn, ...args));
    } catch (cause) {
      throw this.#translate(what, cause);
    }
  }

  /**
   * Submit a write and capture its transaction id into `ctx.receipt` (§4.5a).
   *
   * This uses the explicit propose → endorse → submit → status flow rather than
   * the one-line `submitTransaction`, for one reason: `submitTransaction` returns
   * only the chaincode's bytes and discards the transaction id, and §4.5a calls
   * that id "the only field here that lets a dispute be settled". Recovering it
   * afterwards is impossible — it is a hash of the proposal, not something the
   * peer will tell you later — so it has to be taken from the object that has it.
   *
   * `getStatus()` is awaited rather than assumed. Endorsement succeeding means the
   * peers *would* accept the transaction; it does not mean the orderer committed
   * it. A transaction can endorse cleanly and then fail validation at commit —
   * MVCC_READ_CONFLICT is the common one, when two writes touch the same unit in
   * the same block. Without this check that unit silently did not move while the
   * API reported 200, which is the worst failure mode a custody trail can have.
   */
  async #submit(fn, args, what, ctx) {
    await this.#ensure();
    try {
      const proposal = this.contract.newProposal(fn, { arguments: args });
      const transaction = await proposal.endorse();
      const commit = await transaction.submit();
      const status = await commit.getStatus();

      const txId = commit.getTransactionId();
      if (!status.successful) {
        throw new TrueMedError(
          CODES.UPSTREAM_UNAVAILABLE,
          `the blockchain accepted but did not commit this ${what} ` +
            `(validation code ${status.code}); nothing was written, so it is safe ` +
            `to retry. Transaction ${txId}.`,
          { expose: true },
        );
      }

      const receipt = ctx?.receipt;
      if (receipt && typeof receipt === 'object') receipt.tx_id = txId;
      return this.#parse(commit.getResult());
    } catch (cause) {
      throw this.#translate(what, cause);
    }
  }

  /**
   * Submit a write, then read the unit back so the caller gets the record.
   *
   * The mock driver's writes return the record they wrote; the Go contract's four
   * unit-level writes return only `error`, so `#parse` yields null. §4.5a needs the
   * committed `status`, `location` and chaincode `timestamp` in the response, and
   * the service layer is written against one driver interface — so the difference
   * is reconciled here, inside the driver, rather than leaking a "which backend am
   * I on" branch into every write endpoint.
   *
   * The read-back is safe to do immediately: `#submit` awaits the commit status, so
   * the transaction is committed on this peer before the query runs. If the Go
   * contract is later changed to return the record, the `returned` short-circuit
   * means this stops doing a second round trip on its own.
   *
   * A read-back failure is reported as a failure *of confirmation*, not of the
   * write, and carries the transaction id. The distinction is practical: the unit
   * did move, so a client that treats this as "it didn't work" and retries will get
   * CONFLICT on a mint or a rejected backward transition on a hop. The message says
   * so, and the tx id lets the client record the custody action anyway.
   */
  async #submitAndRead(fn, args, what, ctx, productID) {
    const returned = await this.#submit(fn, args, what, ctx);
    if (returned && typeof returned === 'object') return returned;
    try {
      return await this.#evaluate('GetMedicine', [productID], `${what} read-back`);
    } catch (cause) {
      const txId = ctx?.receipt?.tx_id ?? 'unknown';
      throw new TrueMedError(
        CODES.UPSTREAM_UNAVAILABLE,
        `${what} committed as transaction ${txId}, but reading ${productID} back to ` +
          'confirm it failed. The write did land — do not retry it; read the unit ' +
          'again in a moment to see its new state.',
        { cause, expose: true },
      );
    }
  }

  // ── Reads ───────────────────────────────────────────────────────────────────

  async medicineExists(productID) {
    const res = await this.#evaluate('MedicineExists', [productID], 'MedicineExists');
    return res === true || res === 'true';
  }

  async getMedicine(productID) {
    // GetMedicine returns the record, or an empty body when absent.
    return this.#evaluate('GetMedicine', [productID], 'GetMedicine');
  }

  async verifyMedicine(productID) {
    const res = await this.#evaluate('VerifyMedicine', [productID], 'VerifyMedicine');
    // Chaincode returns { found, verdict, medicine }.
    if (res && typeof res === 'object') return res;
    return { found: false, verdict: 'NOT_ON_CHAIN', medicine: null };
  }

  /**
   * Every medicine on the channel, assembled by paging the chaincode.
   *
   * `GetAllMedicines` is paginated — it must be, or the peer would build a
   * response proportional to the whole ledger in memory — but the mock driver's
   * `allMedicines()` hands back a plain array, and the service layer is written
   * against that one interface. So the paging lives here rather than leaking into
   * every dashboard query.
   *
   * Two guards make this safe to call from a request handler. A bookmark that
   * stops advancing ends the loop: CouchDB returns the same bookmark once a scan
   * is exhausted, and without that check a stale bookmark would spin forever.
   * MAX_PAGES then bounds the work absolutely, and a truncated scan is logged as
   * a warning rather than passed off as a complete ledger — a dashboard showing
   * 500,000 of 2,000,000 units without saying so is worse than one that admits
   * the limit.
   */
  async allMedicines() {
    const all = [];
    let bookmark = '';
    for (let page = 0; page < MAX_SCAN_PAGES; page += 1) {
      const res = await this.#evaluate(
        'GetAllMedicines',
        [String(SCAN_PAGE_SIZE), bookmark],
        'GetAllMedicines',
      );
      const batch = Array.isArray(res?.medicines) ? res.medicines : [];
      all.push(...batch);
      const next = typeof res?.bookmark === 'string' ? res.bookmark : '';
      // An empty bookmark means the scan is done; an unchanged one means CouchDB
      // has nothing further to give and would otherwise loop.
      if (batch.length === 0 || next === '' || next === bookmark) return all;
      bookmark = next;
    }
    this.log?.warn(
      'GetAllMedicines hit the page ceiling; dashboard aggregates are computed ' +
        'over a truncated ledger scan',
      {
        returned: all.length,
        max_pages: MAX_SCAN_PAGES,
        page_size: SCAN_PAGE_SIZE,
      },
    );
    return all;
  }

  // ── Writes ────────────────────────────────────────────────────────────────
  // One JSON string argument per write, so adding a field never shifts a
  // positional argument between the API and the Go contract. Each takes the same
  // `ctx` the mock driver takes: `mspId` identifies the submitter (here it is
  // implicit in the gateway's own signing identity, so it is unused) and an
  // optional `receipt` collects the transaction id.

  async createMedicine(input, ctx) {
    return this.#submitAndRead(
      'CreateMedicine',
      [JSON.stringify(input)],
      'CreateMedicine',
      ctx,
      input.product_id,
    );
  }

  async updateLocation(input, ctx) {
    return this.#submitAndRead(
      'UpdateLocation',
      [JSON.stringify(input)],
      'UpdateLocation',
      ctx,
      input.product_id,
    );
  }

  async addTemperatureReading(input, ctx) {
    return this.#submitAndRead(
      'AddTemperatureReading',
      [JSON.stringify(input)],
      'AddTemperatureReading',
      ctx,
      input.product_id,
    );
  }

  async recordPatientScan(input, ctx) {
    return this.#submitAndRead(
      'RecordPatientScan',
      [JSON.stringify(input)],
      'RecordPatientScan',
      ctx,
      input.product_id,
    );
  }

  /**
   * RecallBatch is the one write whose chaincode function returns a value of its
   * own — `RecallResult`, not a medicine — so it submits without a read-back.
   */
  async recallBatch(input, ctx) {
    return this.#submit('RecallBatch', [JSON.stringify(input)], 'RecallBatch', ctx);
  }

  async ping() {
    // A cheap read proves the channel is reachable and the identity is accepted.
    await this.#evaluate('MedicineExists', ['__healthcheck__'], 'ping');
    return { ok: true, driver: 'fabric' };
  }

  async close() {
    try {
      this.gateway?.close();
    } finally {
      this.client?.close();
      this.gateway = null;
      this.client = null;
      this.contract = null;
    }
  }
}
