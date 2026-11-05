# TrueMed backend — module interface map

Every exported symbol in `backend/src/`, the exact shape of what each function takes
and returns, and the places where two interfaces look interchangeable and are not.

This is a map of the code as it stands, not a specification. `DATA-CONTRACT.md` is
the specification, and where the two disagree the contract wins and this file is
wrong. Its purpose is narrower: to let a new module be written against these
interfaces without reading every file, and without rediscovering the traps in §9 the
expensive way.

**How it was produced, and how it stays true.** The symbol lists were extracted
mechanically from the sources. Every request and response shape in §6 was captured by
executing the real services over the mock ledger, the in-memory store and the in-memory
cache — they are recorded output, not inferred from reading. §10 describes the twenty-one
tests in `backend/tests/docs/interface-map.test.js` that hold this file to the code and
go red when the two disagree. Nothing here describes a Fabric network, a Postgres
database or a Redis instance in operation; none of those has been run in this
environment.

---

## 1. Layer map

Dependencies point downward only. Nothing in `core/` imports anything above it, which
is what allows the whole of verification to be tested with no infrastructure at all.

```
server.js            process: env, signals, sockets     (the only reader of process.env)
  └── app.js         createServices() + createApp()     (dependency injection seam)
        ├── routes/        Express adapters: parse, delegate, envelope
        ├── middleware/    auth, rate limiting, envelope, errors
        ├── services/      all business logic, no Express, no process.env
        │     ├── db/      MemoryStore | PostgresStore   (identical method set)
        │     ├── cache/   MemoryCache | RedisCache | NullCache
        │     └── fabric/  MockLedger  | FabricGatewayClient (identical method set)
        └── core/          pure functions and value objects, zero I/O
```

The seam that matters is `createServices` / `createApp` in `app.js`: both take every
dependency as an argument, so a test builds the same services the server builds. The
487-test suite never imports Express and never opens a socket.

---

## 2. `core/` — pure, no I/O

| Module | Exports |
| --- | --- |
| `core/payload.js` | `MedicineData`, `makeProductID(genericName, brandName, year, serial)`, `CONTRACT_VERSION`, `MAX_PAYLOAD_BYTES`, `QR_MAX_BYTES_ECC_H`, `REQUIRED_WIRE_KEYS`, `REQUIRED_FULL_KEYS` |
| `core/codec.js` | `encode(payloadBytes, signature)`, `decode(wire)` → `{prefix, payloadBytes, signature}`, `looksLikeTrueMed`, `WIRE_PREFIX`, `SEPARATOR`, `SIG_LEN`, `MAX_WIRE_LEN` |
| `core/canonical.js` | `canonicalJSONString(value)`, `canonicalJSONBytes(value)` |
| `core/ecdsa.js` | `loadPublicKey(pem)`, `fingerprint(key)`, `verify(publicKey, data, signature)`, `verifyOrThrow(...)`, `hashAPIKey`, `COORD_LEN`, `SIGNATURE_LEN` |
| `core/base64url.js` | `encodeB64u(raw)`, `decodeB64u(text, what)`, `isB64u` |
| `core/trust-bundle.js` | `TrustBundle`, `TrustedKey`, `KEY_STATUS`, `TRUST_BUNDLE_VERSION` |
| `core/verifier.js` | `verifyWire(wire, bundle, opts)`, `mergeOnlineEvidence(offline, evidence)`, `toResponseBody(verification)` |
| `core/rules.js` | the enums, limits and validators listed in §3 |
| `core/errors.js` | `CODES`, `TrueMedError`, `httpStatusFor`, and the throw helpers in §3.1 |
| `core/envelope.js` | `success(data, meta)`, `failure(err)`, `toTrueMedError(err)`, `startTimer` |

### `MedicineData`

```js
new MedicineData(fields)
  .productID .genericName .brandName .manufacturer .mfgLicenceNo
  .batchNo .mfgDate .expiryDate .quantity .excipients .medType .contractVersion
  .daysToExpiry(today) .isExpired(today)
  .toWireDict()          // short keys: {v, id, gn, bn, mf, ml, bt, md, ed, qt, ex, tp}
  .toDict()              // snake_case, and exactly the mint body minus `location`
  .canonicalJSON()       // Buffer: the bytes that get signed
  .canonicalJSONString()
static MedicineData.fromWireDict(raw)      // from inside a QR
static MedicineData.fromCanonicalJSON(blob)
static MedicineData.fromDict(raw)          // from an API body
```

`toDict()` returns `contract_version, product_id, generic_name, brand_name,
manufacturer, mfg_licence_no, batch_no, mfg_date, expiry_date, quantity, excipients,
type` — which is why `{...medicine.toDict(), location}` is a complete, valid mint body.

### `verifyWire(wire, bundle, opts)`

`opts` is `{today?: Date}`. The second argument needs one member only,
`publicKeyFor(mfgLicenceNo, when)` — see trap §9.1. Returns:

```js
{ valid, verdict, severity, error, error_code, checks, warnings, data, medicine }
```

`medicine` is a `MedicineData` and is present even when the verdict is `COUNTERFEIT`,
which is what lets a forged scan still be filed against the product it impersonates.

### `TrustBundle`

```js
TrustBundle.fromJSON(blob, { rootPublicKey, requireSignature })
  .has(mfgLicenceNo) .entryFor(mfgLicenceNo) .publicKeyFor(mfgLicenceNo, when)
  .signableBytes() .rawJSON() .summary()
```

`summary()` → `{key_count, active_key_count, signed, issued_at}`. `rawJSON()` returns
the file's own text, so `/api/public-keys` can hand the phone every field the file
carried; `toDict()` would silently drop anything the class does not model.

---

## 3. `core/rules.js` — the shared vocabulary

```js
STATUS   = {MANUFACTURED:'manufactured', IN_TRANSIT:'in_transit',
            AT_PHARMACY:'at_pharmacy', DISPENSED:'dispensed', RECALLED:'recalled'}
TYPE     = {MEDICINE:'medicine', VACCINE:'vaccine'}       WIRE_TYPE = {M:…, V:…}
ROLE     = {MANUFACTURER, DISTRIBUTOR, SENSOR, REGULATOR, PHARMA, PHARMACY}
VERDICT  = {GENUINE:'GENUINE', OFFLINE_OK:'SIGNATURE_VALID_OFFLINE',
            EXPIRED:'EXPIRED', COLD_CHAIN:'COLD_CHAIN_BREACH',
            CLONE:'CLONE_SUSPECTED', RECALLED:'RECALLED',
            COUNTERFEIT:'COUNTERFEIT', UNVERIFIABLE:'UNVERIFIABLE'}
SEVERITY = {OK:'ok', WARN:'warn', CRITICAL:'critical'}
CHECK    = {PASS:'pass', FAIL:'fail', SKIPPED_OFFLINE:'skipped_offline',
            NOT_APPLICABLE:'not_applicable', NOT_EVALUATED:'not_evaluated',
            SKIPPED_NO_PAYLOAD:'skipped_no_payload'}
PHARMACY_STATUSES = ['at_pharmacy', 'dispensed']
API_KEY_RE = /^tm_(manufacturer|distributor|sensor|regulator|pharmacy|pharma)_[0-9a-f]{32}$/
```

Note the two enum keys whose name is not their value: `VERDICT.OFFLINE_OK` and
`VERDICT.COLD_CHAIN`. `ROLES` is the same six values as `ROLE` as an array, and
`ROLE_PURPOSE` maps each to the sentence `issue-api-key.js` prints. `TYPE_WIRE` maps
`'medicine' → 'M'`; `WIRE_TYPE` is the inverse.

Limits, all of them exported constants rather than inline numbers, because the
chaincode and the Python signer enforce the same figures:

```
VACCINE_TEMP_MIN_C 2.0     VACCINE_TEMP_MAX_C 8.0      // what a breach means
SENSOR_TEMP_MIN_C -55      SENSOR_TEMP_MAX_C 125       // what a DS18B20 can report
CLONE_SCAN_THRESHOLD 25    CLONE_DISTRICT_THRESHOLD 3  // when CLONE_SUSPECTED fires
MAX_EMBEDDED_READINGS 48   MAX_DISTINCT_DISTRICTS 32   // ledger record growth caps
MAX_CUSTODY_EVENTS 64      MAX_CUSTODY_EVENTS_RECALL 65
MAX_RECALL_PER_TX 500      MAX_RECALL_SCAN 100000      // one recall call's budget
MAX_RECORDED_AT_SKEW_MS 900000       (15 min into the future)
MAX_RECORDED_AT_AGE_MS 2592000000    (30 days into the past)
DEFAULT_PAGE_SIZE 50       MAX_PAGE_SIZE 500
LIMITS                     // per-field text lengths, keyed by field name
```

`MAX_CUSTODY_EVENTS_RECALL` is 65 rather than 64 on purpose: a recall must be able to
append its own event to a unit whose trail is already full, or the units that most need
recalling — the ones handled most — are the ones that cannot be.

Validators throw `TrueMedError(VALIDATION_ERROR)` and return the cleaned value:
`validateProductID`, `validateBatchNo`, `validateLocation`, `validateSensorID`,
`validateText(field, value, max)`, `validateTemperature`, `validateTransition(from, to)`,
`validateRecordedAt(recordedAt, referenceMs)`, `validateDateOrder`, `rejectControlChars`,
`findControlChar`, `asCodePointLabel`.
Helpers: `stamp(when)` → `YYYY-MM-DDTHH:MM:SSZ`, `dayOf`, `parseDate`, `parseInstant`,
`daysToExpiry`, `isExpired`, `knownStatus`, `worstVerdict(verdicts)`, `severityFor`,
`chainVerdict({status, expired, breached, cloneSuspected})`, `verdictToErrorCode`,
`roleOfApiKey(key)`, `isTerminalStatus`, `breachesColdChain`.

### 3.1 `core/errors.js`

```js
CODES  // 18 members, the §4.2 vocabulary:
  QR_MALFORMED QR_UNKNOWN_VERSION PAYLOAD_INVALID SIGNATURE_INVALID
  SIGNATURE_KEY_UNKNOWN EXPIRED NOT_ON_CHAIN RECALLED COLD_CHAIN_BREACH
  CLONE_SUSPECTED UPSTREAM_UNAVAILABLE RATE_LIMITED UNAUTHORIZED FORBIDDEN
  VALIDATION_ERROR NOT_FOUND CONFLICT INTERNAL_ERROR

new TrueMedError(code, message, details?)   // .code .status .details .expose
httpStatusFor(code)                          // unknown code → 500, never a throw
isTrueMedError(err)

// Each returns an error to throw; none of them throws by itself.
validationError(message, details?)      → 400
unauthorized(message?)                  → 401   default 'missing or invalid API key'
forbidden(message)                      → 403
notFound(message)                       → 404
notOnChain(productID)                   → 404   builds its own message
conflict(message)                       → 409
rateLimited(retryAfterSeconds)          → 429   puts the delay on `err.retryAfter`
upstreamUnavailable(what, cause?)       → 503   logs the cause, does not expose it
internalError(cause?)                   → 500   message is fixed and generic
```

The split between `notFound` and `notOnChain` is worth keeping: `NOT_ON_CHAIN` is a
verdict-adjacent answer about a medicine, and the mobile app treats it as evidence of a
counterfeit. `NOT_FOUND` is an ordinary missing route or row and means nothing about any
medicine.

---

## 4. Infrastructure drivers

Each driver family presents one method set, so `config.fabric.mock` swaps the whole
stack without a conditional anywhere above `createStore` / `createCache` / `createFabric`.

Four of the six class names do not match their filenames, so import paths are worth
stating plainly rather than guessing (trap §9.13):

```
db/memory-store.js      MemoryStore            db/index.js       createStore, both classes
db/postgres.js          PostgresStore
cache/memory.js         MemoryCache            cache/index.js    createCache, CACHE_STATE,
cache/redis.js          RedisCache                               all three classes
fabric/mock-ledger.js   MockLedger             fabric/index.js   createFabric, MSP,
fabric/gateway-client.js FabricGatewayClient                     mspForRole
```

`mspForRole` and `MSP` live in `fabric/index.js`, not in `core/rules.js` where the rest
of the vocabulary is. Every `index.js` re-exports its own classes, so importing from the
directory is the safer habit.

### Store — `MemoryStore` and `PostgresStore`

```js
insertApiKey({role, keyHash, label, scope})   findApiKey(keyHash)
touchApiKey(keyHash)                          revokeApiKey(keyHash)
insertSensor({sensorId, secretEnc, label})    getSensor(sensorId)
revokeSensor(sensorId)
insertReport(row)                             getReport(id)
reportsForProduct(productID, {limit})         recentReports({limit})
ping()                                        close()
```

`insertReport` takes `{id, product_id, pharmacy_name, district, state, lat, lon,
notes, photo, photo_bytes, reporter_contact_enc, client_ip}` and stores `status: 'new'`.
There is no `payload_verdict` column in either driver or in `schema.sql`: the verdict a
submitted payload produced is logged, deliberately, and not kept.

`createStore(config, logger, opts)` returns `MemoryStore` whenever `config.fabric.mock`
is true. There is no mock-ledger-with-Postgres combination.

### Cache — `MemoryCache`, `RedisCache`, `NullCache`

```js
get(productID)                              setVerify(productID, body, state)
del(productID)                              reserveNonce(sensorId, nonce, ttlS)
ping()                                      close()
CACHE_STATE = {TERMINAL:'terminal', ACTIVE:'active', NEGATIVE:'negative'}
```

`state` selects the TTL: `redis.ttl.terminalS` 3600, `activeS` 60, `negativeS` 30.
`reserveNonce` returns false when the nonce was already spent, and is the sensor replay
gate. No cache implementation holds a timer.

### Ledger — `MockLedger` and `FabricGatewayClient`

```js
// reads
medicineExists(productID)   getMedicine(productID)   verifyMedicine(productID, when)
allMedicines()              ping()                   close()
// writes, all taking ctx = {mspId, receipt}
createMedicine(input, ctx)        updateLocation(input, ctx)
addTemperatureReading(input, ctx) recordPatientScan(input, ctx)
recallBatch(input, ctx)
MSP = {MANUFACTURER:'ManufacturerMSP', DISTRIBUTOR:'DistributorMSP', REGULATOR:'RegulatorMSP'}
mspForRole('pharmacy') === 'DistributorMSP'
```

`ctx.receipt` is an out-parameter: pass `{}` and the driver writes `receipt.tx_id` into
it. Opt-in on purpose, so a read path never pays for a transaction id. `mspForRole`
mapping `pharmacy` onto `DistributorMSP` is why the pharmacy status restriction has to
be enforced in the service — the chaincode cannot tell the two apart (trap §9.9).

The on-chain record returned by `getMedicine`:

```
doc_type, contract_version, product_id, generic_name, brand_name, manufacturer,
mfg_licence_no, batch_no, mfg_date, expiry_date, quantity, excipients, type,
current_location, status, custody_trail[], temperature_history[], temp_reading_count,
temp_min_c, temp_max_c, cold_chain_breached, cold_chain_breached_at, scan_count,
first_scan_at, last_scan_at, distinct_scan_districts, recall_reason, recalled_at,
created_at, updated_at, created_by_msp
```

A `custody_trail` entry is `{status, location, timestamp, actor_msp}`.

---

## 5. Config

`loadConfig(env)` validates everything at once and freezes the result; `config` is the
frozen singleton. `assertRuntimePaths(cfg)` checks that the trust bundle and root key
files exist — and the three Fabric credential files too, unless `fabric.mock`.
`describe(cfg)` is the redacted startup line. `ConfigError.problems` is the full list.

```
env isProduction isTest isDevelopment
server.       port 8080 · host 0.0.0.0 · trustProxy · bodyLimit 2mb
              shutdownGraceMs 10000 · corsOrigins []
log.          level · pretty
db.           url · poolMax 10 · connectTimeoutMs · statementTimeoutMs · ssl
              connectRetries 5 · connectRetryDelayMs
redis.        enabled · url · connectTimeoutMs
              ttl.terminalS 3600 · ttl.activeS 60 · ttl.negativeS 30
              keyPrefix 'verify:v1:'
fabric.       mock · channel truemed-channel · chaincode truemed · mspId
              peerEndpoint · peerHostAlias · tlsCaPath · certPath · keyPath
              evaluateTimeoutMs 5000 · submitTimeoutMs 15000
trust.        bundlePath keys/trust-bundle.json · rootPublicKeyPath keys/root-public.pem
              requireSignature · reloadIntervalMs 300000
sensor.       requireHmac · nonceTtlS 86400 · maxClockSkewMs 900000
secrets.      encryptionKey · retentionDays 400
rateLimit.    publicPerMin 60 · authedPerMin 600 · reportPerHour 10 · sensorPerMin 120
secretNames   ['DATABASE_URL','REDIS_URL','SECRET_ENCRYPTION_KEY']
```

`FABRIC_MOCK=1`, `TRUST_REQUIRE_SIGNATURE=0` and `SENSOR_REQUIRE_HMAC=0` each refuse to
start when `NODE_ENV=production`. `DEV_ENCRYPTION_KEY` is the development default for
`SECRET_ENCRYPTION_KEY` and is rejected in production.

---

## 6. Services

Every service is a factory over injected dependencies, returns plain async functions,
and knows nothing about Express. `auth` is always `{role, scope?}` — the authenticated
key, never the request body.

### `makeVerifyService({cache, fabric, trust, logger, clock})` → `{byProductID, byPayload}`

```js
byProductID(rawProductID)                        → {body, cached}
byPayload({raw_payload, district})               → {body, cached}
```

Both resolve with a verdict body. `NOT_ON_CHAIN` is the one absence that throws
(404). `EXPIRED`, `RECALLED`, `COLD_CHAIN_BREACH`, `CLONE_SUSPECTED` and `COUNTERFEIT`
all resolve, because a verdict is an answer and not a protocol failure. The body:

```js
{
  verdict, severity,
  checks: {signature, on_chain, expiry, cold_chain, clone_telemetry},
  medicine: {…MedicineData.toDict(), status, current_location, days_to_expiry},
  cold_chain: {applicable, breached, min_c, max_c, reading_count},
  telemetry: {scan_count, distinct_districts, first_scan_at},
  custody_trail: [{status, location, timestamp, actor_msp}],
  error_code, error: {code, message}
}
```

`checks.signature` is `'skipped_no_payload'` on `byProductID` — a bare product id
carries no signature — and `'pass'` on a valid `byPayload`. Only `byPayload` records a
patient scan (§7.1), and only after the payload verifies; a rejected payload never
reaches the ledger.

The module also exports `verifyBody(verification, record, today)`, which is the function
that assembles the block above. It is exported so a test can assert the §4.4 shape
without a ledger, and it decides nothing: verdict, severity and checks are copied
verbatim from the verification it is handed.

### `makeSupplyChainService({cache, fabric, store, secrets, logger, clock})`

→ `{mint, recordLocation, recordTemperature, recall}`

```js
mint(input, auth)              input: MedicineData.toDict() fields + location
                               → {product_id, status, location, timestamp, tx_id}
recordLocation(input, auth)     input: {product_id, status, location}
                               → {…same…, tx_id, actor_msp}
recordTemperature(input, auth)  input: {product_id | batch_no, sensor_id, temperature,
                                        recorded_at, nonce, hmac, battery_pct?}
                               → {product_id, sensor_id, temperature, recorded_at,
                                  chain_ok, reading_count, tx_id}
                                 and for a batch reading, product_id is null and
                                 {batch_no, units_updated} are added instead
recall(input, auth)             input: {batch_no, reason}
                               → {batch_no, recalled, already_recalled, more_remaining,
                                  product_ids[], recalled_at, actor_msp}   // no tx_id
```

`actor_msp` comes from `auth.role` via `mspForRole`; a value supplied in the body is
ignored. Every write `cache.del`s the affected product ids before returning, and a
recall fans that out across the batch. Cache failures during invalidation are
swallowed — the ledger write is already durable and must not be undone by a Redis blip.

`recall` returns the chaincode's `RecallResult` unchanged and therefore carries no
`tx_id`, unlike the three custody writes. It also completes across several calls:
loop while `more_remaining` is true (§3.7).

### `makeReportsService({store, trust, secrets, logger, clock})` → `{submit}`

```js
submit(input, meta) → {report_id, received_at}
input: {product_id?, raw_payload?, pharmacy_name?, district?, state?, lat?, lon?,
        notes?, photo_base64?, reporter_contact?}
meta:  {ip?}
```

One of `product_id` or a readable `raw_payload` is required; the payload path recovers
the id from the scan, which is what makes one-tap reporting possible. `reporter_contact`
is sealed with the report id as AEAD context, coordinates are truncated to about 100 m,
`photo_base64` accepts a bare base64 string or a `data:` URL and rejects corrupt base64
rather than storing a truncated image. The response is two fields; the stored row —
ciphertext, photo bytes, client IP — is never returned.

### `makeDashboardsService({fabric, store, logger, clock})` → `{cdsco, pharma}`

```js
cdsco(query)        query: {days, limit}  → {window, totals, districts[], alerts[], reports[]}
pharma(auth, query) auth:  {scope}        → {window, totals, batches[], …}
```

The regulator's `totals` counts problems: `{reports, reports_open, units_recalled,
cold_chain_breaches, clone_suspected}`. Production counters such as `units_minted` are
on the pharma board instead. The pharma filter is `auth.scope` — the key's
`mfg_licence_no` — and never a query parameter (§4.4a); a blank scope is refused with
`FORBIDDEN` rather than shown an empty board, because an empty board reads as "you have
no stock" and hides a misissued key.

### `makeTrustService({config, bundle, logger, clock, load})`

→ `{publicKeys, liveView, summary, refresh, activeBundle}`

```js
await publicKeys()    // GET /api/public-keys body: the bundle's own JSON, verbatim
liveView()            // {publicKeyFor} — synchronous; hand THIS to verifyWire
summary()             // {key_count, active_key_count, signed, issued_at}
await refresh()       // re-read if mtime changed; never throws, keeps the old bundle
await activeBundle()  // the bundle, refreshed first if stale
```

The module also exports `loadTrustBundle(cfg)`, which reads `cfg.bundlePath` and
`cfg.rootPublicKeyPath` off disk and returns a verified `TrustBundle`. It is the default
value of the `load` dependency, so injecting `load` replaces all file I/O — which is how
the tests build a trust service from the fixtures with no `backend/keys/` directory
present. A `bundle` passed in directly is used as the initial value and `load` is only
called on refresh.

### `makeHealthService({store, cache, fabric, trust, config, version, logger, clock})`

→ `{live, ready}`

```js
live()        → {status:'ok', uptime_s, env?, version?}          // touches nothing
await ready() → {status, ready, httpStatus, checks, uptime_s}
```

The cache is optional: an outage gives `degraded` and 200. The database, the ledger and
a trust bundle with at least one active key are load-bearing: any of those gives
`unavailable` and 503. A replica that passes every connectivity probe but holds a bundle
with no usable keys answers `UNVERIFIABLE` to every scan, which is why the key count is
a readiness check and not just a log line.

---

## 7. Middleware and routes

```js
makeAuth({store, logger})        → {authenticate, requireRole(...roles)}   + sha256hex
makeRateLimiter({config, logger, clock}) → {public, authed, report, sensor, custom}
makeEnvelope(logger)             makeErrorHandler({logger})   notFoundHandler
asyncHandler(fn)
```

`authenticate` attaches `req.auth = {role, scope, keyHash, …}` and never the plaintext
key. A missing or unknown or revoked key is 401 with one indistinguishable message; a
valid key of the wrong role is 403 naming the role required. A `touchApiKey` failure is
swallowed: bookkeeping must not lock out a working credential.

`limiters.authed` and `limiters.sensor` key on `req.auth.keyHash` and fall back to the
client address when there is no identity yet, so **`auth.requireRole(...)` must be
mounted before the limiter** on all six authenticated routes (trap §9.4). Rejections
carry `err.retryAfter` in seconds. Budget headers are set on every response, not only
rejections.

Route factories, each returning an Express router:
`makeVerifyRoutes({verify, limiters})`, `makeSupplyChainRoutes({supplyChain, auth, limiters})`,
`makeReportRoutes({reports, limiters})`, `makeDashboardRoutes({dashboards, auth, limiters})`,
`makeTrustRoutes({trust, limiters})`, `makeHealthRoutes({health})`, and
`makeRoutes({services, auth, limiters})` which mounts them under `API_PREFIX`.

Success envelope `{ok:true, data, meta:{cached, took_ms}}`; failure
`{ok:false, error:{code, message, details?}}` (§4.1).

---

## 8. Utilities

```js
new SecretBox(keyMaterial)  .seal(plaintext, context) .open(sealed, context)
                            .openOrNull(sealed, context) .matches(sealed, candidate, context)
SecretBoxError
sensorContext(sensorID)     reportContext(reportRef)   generateSensorSecret()

temp2dp(celsius)            macInput({binding, sensorId, temperature, recordedAt, nonce})
computeSensorMac(secret, parts)                        verifySensorMac({…})
NONCE_RE = /^[0-9a-f]{8,64}$/   RECORDED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/

new Logger(bound, options)  .child(fields) .debug/.info/.warn/.error(msg, fields)
LEVELS = {debug:10, info:20, warn:30, error:40, silent:100}
sanitise(fields)            // applied to every line, not opt-in at the call site
REDACT_KEYS                 // 24 keys, replaced with '[redacted]'
SIZE_ONLY_KEYS              // 4 keys, replaced with '[<n> chars]'
```

The MAC covers `binding|sensor_id|temp2dp|recorded_at|nonce` and the nonce is burned
only after the MAC verifies — reserving first would let anyone holding the shared sensor
API key spend a real device's nonces with garbage MACs and lock the cold chain out.

`REDACT_KEYS` covers `x-api-key`, `authorization`, `hmac`, `signature`, `sensor_secret`,
`database_url`, `redis_url`, `reporter_contact` and sixteen more. `SIZE_ONLY_KEYS` is
`photo_base64`, `photo`, `raw_payload` and `body` — logged as a length, because a
`raw_payload` in a log file is a working QR code and a photo is evidence. Redaction lives
inside the logger rather than at the call sites so that a log line added later cannot
leak a key by forgetting to. `LOG_LEVEL=silent` is what the test suite runs with.

---

## 9. Interface traps

Each of these is a pair of interfaces that look interchangeable. Numbers 1, 2, 4 and 9
are not hypothetical: they reached finished code, and each one is now pinned by a test
that has been shown to fail without the fix.

**9.1 The trust service is not a trust bundle.** `verifyWire(wire, bundle, …)` calls
exactly one member, `publicKeyFor`. `makeTrustService` returns
`{publicKeys, liveView, summary, refresh, activeBundle}` and has no such member. Pass
`trust.liveView()`. Passing `trust` throws `TypeError: bundle.publicKeyFor is not a
function` — but only once a payload has decoded far enough to need a key, which means
every genuine QR code fails and every malformed one still passes. In `reports.js` the
surrounding `catch` converts it into "payload unreadable", so a report sent with only a
scan is refused for having no `product_id`.

**9.2 There are two fields named `contract_version`.** In a QR payload it is the int
`1` (§1.3). On a ledger record it is the chaincode build string — `'1.0.0'` from the Go
contract, `'truemed-1.0'` from the mock. Feeding a record straight into
`MedicineData.fromDict` makes every genuine unit answer 400 `PAYLOAD_INVALID`. Strip the
record's copy first.

**9.3 `pharma` and `pharmacy` are one letter apart and unrelated.** `pharma` is
read-only analytics scoped to one manufacturer's licence; `pharmacy` is a chemist who
moves stock. A `pharma` key must not satisfy a `pharmacy` gate, and `pharma` may not
write at all.

**9.4 Rate limiter ordering is load-bearing.** `limiters.authed` and `limiters.sensor`
fall back to the client address when `req.auth` is absent, so mounting a limiter before
`auth.requireRole(...)` silently converts a per-key budget into a per-address one, and
anyone sharing a pharmacy's NAT can spend that pharmacy's quota. The fallback is
deliberate; the ordering is what must be asserted.

**9.5 `verify.byPayload` takes `raw_payload`, not `payload`.**

**9.6 The verify body nests the signed fields under `medicine`.** There is no top-level
`product_id` or `status`; they are `body.medicine.product_id` and
`body.medicine.status`.

**9.7 A rate-limit rejection carries `err.retryAfter`,** not `err.details.retry_after_s`.

**9.8 The two dashboards count different things.** `units_minted` is on the pharma
board; the CDSCO board's `totals` has `{reports, reports_open, units_recalled,
cold_chain_breaches, clone_suspected}` and no production counters.

**9.9 A pharmacy submits to Fabric as `DistributorMSP`.** `mspForRole('pharmacy')`
returns `'DistributorMSP'`, so the chaincode cannot distinguish a chemist from a
distributor and would accept a rewind from `at_pharmacy` back to `in_transit` as
ordinary logistics. The two-status restriction (`PHARMACY_STATUSES`) is enforceable only
in the API.

**9.10 A recall response has no `tx_id`.** The three custody writes do. The id is
logged rather than returned, and the Dart `RecallResult` does not parse one.

**9.11 A missing enum member is `undefined`, and `assert.equal(x, VERDICT.TYPO)` passes
vacuously.** `VERDICT.COLD_CHAIN_BREACH` does not exist; the key is
`VERDICT.COLD_CHAIN`. Likewise `VERDICT.OFFLINE_OK` for `SIGNATURE_VALID_OFFLINE`.

**9.12 `ctx.receipt` is an out-parameter.** Pass `{}` to a ledger write and read
`receipt.tx_id` afterwards; omit it and no transaction id is produced.

**9.13 Four class names do not match their filenames, and `mspForRole` is not in
`rules.js`.** `PostgresStore` is in `db/postgres.js`, `FabricGatewayClient` in
`fabric/gateway-client.js`, `MemoryCache` in `cache/memory.js`, `RedisCache` in
`cache/redis.js`. `mspForRole` and `MSP` come from `fabric/index.js`, which is easy to
get wrong because every other shared enum is in `core/rules.js`. The failure is a clean
`ERR_MODULE_NOT_FOUND` or `is not a function` at import time rather than anything
subtle — it just costs a cycle. §4 lists the paths.

---

## 10. How this document is kept true

Nothing here should be taken on trust, and it would drift within a week if it depended
on anyone remembering to reread it. So the map is checked by the test suite:
`backend/tests/docs/interface-map.test.js`, twenty-one tests that treat this file as an
assertion about the code and fail when the two disagree.

**Completeness** — every exported symbol in `backend/src` (175 at the time of writing)
must be named here inside a code span. Prose does not count, because a symbol whose name
is an English word would otherwise pass by accident. This is the check most likely to
trip, and deliberately: an undocumented export makes a reader conclude it does not exist
and write a second version of it. When it fails, document the symbol rather than relaxing
the test.

**Attribution** — every symbol listed under a module in §2 must be exported by that
module. A symbol filed under the wrong file survives any amount of rereading and sends
the reader to an import that does not resolve.

**Transcription** — the enums copied out in §3, §3.1 and §4 are parsed back out of this
file and compared to the real objects key-for-key and value-for-value, along with `ROLES`,
`PHARMACY_STATUSES`, `API_KEY_RE` and all eighteen error codes. Parsed rather than
hardcoded in the test, so that the test checks the document and not just itself.

**Claims** — the response shapes and the traps in §9 are asserted against the live mock
stack: all thirty-one keys of the on-chain record, the exact key sets of five responses,
the nine config values quoted in §5, the method sets of all six drivers, and each trap
in §9 that can be expressed as an assertion.

Those four were shown to bite before being trusted. Three independent faults were
introduced into a throwaway copy of this file — an export removed from §3, `verifyWire`
misfiled under `core/canonical.js`, and `VERDICT.COLD_CHAIN` transcribed as
`VERDICT.COLD_CHAIN_BREACH`, which is precisely the mistake §9.11 warns about — and the
suite returned exactly three failures, each in the test written to catch it.

