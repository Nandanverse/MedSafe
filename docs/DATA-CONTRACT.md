# TrueMed — Canonical Data Contract (v1)

> **Truth in Every Medicine** · हर दवा में सच्चाई
>
> This document is the single source of truth for every field name, enum value, and
> payload shape in TrueMed. The QR generator, Go chaincode, Node.js API, Flutter app,
> and Grafana queries **must** all agree with this file. If you change a field here,
> grep for it across all five components before committing.
>
> Status: **FROZEN for v1.** Contract version is carried in the QR prefix (`TM1`) so a
> future v2 can change crypto or fields without bricking already-printed strips.

---

## 1. The QR payload

### 1.1 Wire format

A TrueMed QR encodes a single ASCII string in three dot-separated parts:

```
TM1.<base64url(canonical_payload_json)>.<base64url(signature_r_concat_s)>
```

| Part | Meaning |
|---|---|
| `TM1` | Format version tag. `TM` = TrueMed, `1` = contract v1. An app that sees `TM2` and does not understand it must fail closed with `UNKNOWN_FORMAT_VERSION`, never fail open. |
| Part 2 | Canonical JSON of the data elements (§1.3), base64url-encoded **without padding**. |
| Part 3 | ECDSA P-256 signature over the *exact bytes* of the canonical JSON, as raw `r‖s` (64 bytes, 32 each, big-endian, left-zero-padded), base64url without padding. |

Base64url (RFC 4648 §5, `-` and `_`, no `=` padding) is used because `+` and `/` are
not in the QR alphanumeric character set and would force byte mode for the whole
payload, inflating the code.

### 1.2 Why ECDSA P-256 and not RSA-2048

An RSA-2048 signature is 256 bytes → 344 base64 characters. A P-256 signature is
64 bytes → 86 characters. That 258-character saving drops the QR by roughly eight
version steps at error-correction level H, which is the difference between a code that
reads first-try on a ₹6,000 Android phone through a scratched foil blister and one that
needs three attempts and good light. Security is comparable — P-256 is ~128-bit
security, RSA-2048 is ~112-bit — so the smaller curve is strictly better here on both
axes. Signing stays offline-verifiable, which is the requirement RSA was chosen for.

### 1.3 Data elements

CDSCO's Drugs Rules barcode requirement (Rule 96 amendment) is the compliance baseline.
Nine elements were specified for TrueMed; a tenth, `ml` (manufacturing licence number),
is **added** because CDSCO's own list requires it and its absence would be the first
gap a regulator notices. It is mandatory in TrueMed v1.

Short keys are used on the wire because QR capacity is the scarce resource. Full names
are used everywhere else (chaincode, API, app, database).

| Wire key | Full field name | Type | Required | Example | Notes |
|---|---|---|---|---|---|
| `v` | `contract_version` | int | yes | `1` | Must equal `1` for `TM1`. |
| `id` | `product_id` | string | yes | `PARACETAMOL_PARACIP500_2026_000001` | See §1.4. Primary key everywhere. |
| `gn` | `generic_name` | string | yes | `Paracetamol 500mg` | Proper/generic name incl. strength. |
| `bn` | `brand_name` | string | yes | `Paracip 500` | |
| `mf` | `manufacturer` | string | yes | `Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018` | Name + address, comma-separated. |
| `ml` | `mfg_licence_no` | string | yes | `MH/25D/2019/187` | CDSCO manufacturing licence. |
| `bt` | `batch_no` | string | yes | `SP26A0417` | |
| `md` | `mfg_date` | string | yes | `2026-03-15` | ISO 8601 `YYYY-MM-DD`, strict. |
| `ed` | `expiry_date` | string | yes | `2028-02-29` | ISO 8601 `YYYY-MM-DD`, strict. Must be > `md`. |
| `qt` | `quantity` | string | yes | `10 tablets` | Free text, e.g. `10 tablets`, `1 vial (0.5 ml)`. |
| `ex` | `excipients` | array of string | yes | `["Maize Starch","Povidone K30","Talc"]` | **JSON array**, never a comma-joined string — a comma inside an excipient name would be unparseable. May be `[]`. |
| `tp` | `type` | string | yes | `M` | `M` = medicine, `V` = vaccine. Expanded to `medicine`/`vaccine` off-wire. Vaccines get cold-chain evaluation; medicines do not. |

### 1.4 `product_id` format

```
{GENERIC}_{BRAND}_{YEAR}_{SERIAL}
```

Each segment is uppercased and reduced to `[A-Z0-9]` (spaces, dots, hyphens and `/`
removed, not replaced). `YEAR` is the 4-digit manufacturing year. `SERIAL` is
zero-padded to 6 digits and is unique per `(brand, year)`.

```
Paracetamol 500mg + Paracip 500 + 2026 + 1
  →  PARACETAMOL500MG_PARACIP500_2026_000001
```

`product_id` is the on-chain world-state key, the API path parameter, and the
PostgreSQL foreign key. It must be treated as opaque and case-sensitive downstream.

### 1.5 Canonical JSON

The signature covers bytes, so generator and verifier must serialise **identically**.
Rules, applied by `truemed_qr.payload.canonical_json()`:

1. Keys sorted lexicographically (`bn, bt, ed, ex, gn, id, md, mf, ml, qt, tp, v`).
2. No whitespace: separators are `,` and `:`.
3. UTF-8, `ensure_ascii=False`.
4. Array order preserved as authored (excipient order is part of the signed data).
5. No trailing newline.

A verifier must sign/verify over the **received** part-2 bytes after base64url decoding
— never over a re-serialised parse of them. Re-serialising invites canonicalisation
mismatches, which is a classic signature-bypass bug class.

### 1.6 Size budget

| | bytes |
|---|---|
| `TM1.` prefix | 4 |
| Canonical JSON (typical, 4 excipients) | ~410 |
| base64url of that (×4/3) | ~547 |
| `.` separator | 1 |
| Signature base64url | 86 |
| **Total typical** | **~638** |
| Hard ceiling: QR v40 at ECC level H | **1273** |

Generation **fails loudly** above 1273 bytes and **warns** if the fitted QR version
exceeds 20, because density beyond that scans poorly on low-end cameras. The generator
reports the fitted version so you can tune excipient verbosity before a print run.

---

## 2. Verification semantics

### 2.1 The five checks

| # | Check | Needs network? | Failure verdict |
|---|---|---|---|
| 1 | QR parses, prefix is `TM1`, all required fields present and well-typed | no | `UNVERIFIABLE` / `COUNTERFEIT` |
| 2 | ECDSA signature valid under a trusted manufacturer public key | **no** | `COUNTERFEIT` |
| 3 | `expiry_date` is in the future | **no** | `EXPIRED` |
| 4 | `product_id` exists on the blockchain and is not `recalled` | yes | `COUNTERFEIT` / `RECALLED` |
| 5 | For `tp=V`, no temperature reading outside 2–8 °C in custody history | yes | `COLD_CHAIN_BREACH` |

Checks 1–3 are the **offline** verification path. Checks 4–5 require the API.

### 2.2 Honest limits of offline mode — and the clone defence

A valid signature proves *this QR was minted by the holder of the manufacturer's private
key*. It does **not** prove the physical strip is genuine, because a counterfeiter can
photograph one real strip and reprint that same valid QR onto ten thousand fakes. This
is the standard attack on every QR authentication scheme and it must be stated plainly
rather than papered over.

TrueMed's mitigation is **on-chain scan telemetry**, which is why check 4 matters and
why offline mode is explicitly degraded rather than equivalent:

- Chaincode keeps `scan_count`, `first_scan_at`, and `distinct_scan_districts` per `product_id`.
- A single sellable unit scanned 400 times across 14 districts is almost certainly cloned.
- The API returns these counters; the app surfaces `CLONE_SUSPECTED` when
  `scan_count > CLONE_SCAN_THRESHOLD` (default 25) or `distinct_scan_districts > 3`.

Therefore the app must never render offline success as an unqualified green tick. The
required offline wording is:

> **Signature verified.** This QR was issued by {manufacturer}. Connect to the internet
> to confirm it is not a duplicate and to check cold-chain status.

with severity `warn`, not `ok`.

### 2.3 Verdict and severity enums

`verdict` — exactly one of:

```
GENUINE            COUNTERFEIT        EXPIRED
COLD_CHAIN_BREACH  RECALLED           CLONE_SUSPECTED
SIGNATURE_VALID_OFFLINE               UNVERIFIABLE
```

`severity` — drives app and dashboard colour, exactly one of:

```
ok        → #4CAF50  green
warn      → #FFB300  amber
critical  → #E53935  red
```

| verdict | severity |
|---|---|
| `GENUINE` | `ok` |
| `SIGNATURE_VALID_OFFLINE` | `warn` |
| `EXPIRED` | `warn` |
| `COLD_CHAIN_BREACH` | `critical` |
| `CLONE_SUSPECTED` | `critical` |
| `RECALLED` | `critical` |
| `COUNTERFEIT` | `critical` |
| `UNVERIFIABLE` | `warn` |

Precedence when several apply, highest first:
`COUNTERFEIT` > `RECALLED` > `CLONE_SUSPECTED` > `COLD_CHAIN_BREACH` > `EXPIRED` >
`UNVERIFIABLE` > `SIGNATURE_VALID_OFFLINE` > `GENUINE`.
Rationale: a fake signature makes every other field meaningless, so it dominates.

All eight verdicts must appear in this list, including `UNVERIFIABLE`. An
implementation that omits it has no ordering to resolve `["UNVERIFIABLE"]` with
and falls through to whatever its default is — which in practice means a patient
holding genuine medicine sees a red counterfeit warning because their app's trust
bundle is a week out of date. `UNVERIFIABLE` outranks `SIGNATURE_VALID_OFFLINE`
because a code with any unverifiable part cannot be reported as offline-valid,
and sits below `EXPIRED` because a verified expiry date is the more actionable
fact. Both are `warn`, so the ordering changes the message, never the colour.

### 2.4 Machine-readable error codes

Returned in `error.code`. Stable strings — the app switches on these, not on prose.

| Code | Meaning |
|---|---|
| `QR_MALFORMED` | Not three dot-separated parts, or base64url decode failed |
| `QR_UNKNOWN_VERSION` | Prefix is not `TM1` |
| `PAYLOAD_INVALID` | JSON invalid, field missing, wrong type, or bad date format |
| `SIGNATURE_INVALID` | ECDSA verification failed |
| `SIGNATURE_KEY_UNKNOWN` | `ml` maps to no trusted public key |
| `EXPIRED` | Past `expiry_date` |
| `NOT_ON_CHAIN` | No such `product_id` in world state |
| `RECALLED` | On-chain status is `recalled` |
| `COLD_CHAIN_BREACH` | Vaccine saw a reading outside 2–8 °C |
| `CLONE_SUSPECTED` | Scan telemetry exceeds threshold |
| `UPSTREAM_UNAVAILABLE` | Fabric or DB unreachable |
| `RATE_LIMITED` | Too many requests |
| `UNAUTHORIZED` | Missing/invalid API key |
| `FORBIDDEN` | Key valid but lacks the required role |
| `VALIDATION_ERROR` | Request body failed schema validation |

---

## 3. On-chain model

Go struct tags are lowercase snake_case and are the JSON the API receives. Field names
here are authoritative for the chaincode.

```go
type Medicine struct {
    DocType string `json:"doc_type"`          // "medicine" — see §3.5

    ProductID     string   `json:"product_id"`
    GenericName   string   `json:"generic_name"`
    BrandName     string   `json:"brand_name"`
    Manufacturer  string   `json:"manufacturer"`
    MfgLicenceNo  string   `json:"mfg_licence_no"`
    BatchNo       string   `json:"batch_no"`
    MfgDate       string   `json:"mfg_date"`
    ExpiryDate    string   `json:"expiry_date"`
    Quantity      string   `json:"quantity"`
    Excipients    []string `json:"excipients"`
    Type          string   `json:"type"`            // medicine | vaccine

    CurrentLocation string         `json:"current_location"`
    Status          string         `json:"status"`
    CustodyTrail    []CustodyEvent `json:"custody_trail"`

    // Rolling display window only — 48 most recent entries. The complete series
    // lives in its own ledger keys; see §3.5.
    TemperatureHistory  []TemperatureReading `json:"temperature_history"`
    TempReadingCount    int                  `json:"temp_reading_count"`
    TempMinC            float64              `json:"temp_min_c"`
    TempMaxC            float64              `json:"temp_max_c"`
    ColdChainBreached   bool                 `json:"cold_chain_breached"`
    ColdChainBreachedAt string               `json:"cold_chain_breached_at"`

    ScanCount             int      `json:"scan_count"`
    FirstScanAt           string   `json:"first_scan_at"`
    LastScanAt            string   `json:"last_scan_at"`
    DistinctScanDistricts []string `json:"distinct_scan_districts"`

    RecallReason string `json:"recall_reason"`
    RecalledAt   string `json:"recalled_at"`

    CreatedAt       string `json:"created_at"`
    UpdatedAt       string `json:"updated_at"`
    CreatedByMSP    string `json:"created_by_msp"`
    ContractVersion string `json:"contract_version"`
}

type TemperatureReading struct {
    DocType     string  `json:"doc_type,omitempty"`    // "temperature"; omitted in the window
    ProductID   string  `json:"product_id,omitempty"`  //               omitted in the window
    Temperature float64 `json:"temperature"`
    Timestamp   string  `json:"timestamp"`   // ledger time — trustworthy
    RecordedAt  string  `json:"recorded_at"` // sensor's own claim — see §3.6
    Location    string  `json:"location"`
    SensorID    string  `json:"sensor_id"`
    Breach      bool    `json:"breach"`
}

type CustodyEvent struct {
    Status    string `json:"status"`
    Location  string `json:"location"`
    Timestamp string `json:"timestamp"`
    ActorMSP  string `json:"actor_msp"`
}
```

### 3.1 `status` enum and legal transitions

```
manufactured → in_transit → at_pharmacy → dispensed
        (any state) → recalled     [Regulator MSP only, terminal]
```

`in_transit` may repeat (factory→warehouse→distributor→pharmacy are all `in_transit`
hops distinguished by `location`). Backward transitions are rejected with
`VALIDATION_ERROR`. `dispensed` and `recalled` are terminal.

### 3.2 Timestamps are deterministic

Chaincode **must not** call `time.Now()`. Every endorsing peer executes the transaction
independently; wall-clock reads produce different values per peer, the read-write sets
diverge, and the transaction fails endorsement validation. All timestamps come from
`ctx.GetStub().GetTxTimestamp()`, which is identical across endorsers, formatted as
RFC 3339 UTC.

### 3.3 Cold-chain rule

Vaccines: valid range **2.0 °C to 8.0 °C inclusive**. Any reading outside it sets
`ColdChainBreached = true` permanently — a breach cannot be un-set, because a vaccine
that got warm does not become safe again when it cools. `medicine`-type products
accept temperature readings for logging but never set the breach flag.

### 3.4 MSP access control

| Operation | Permitted MSP |
|---|---|
| `CreateMedicine` | `ManufacturerMSP` |
| `UpdateLocation` | `ManufacturerMSP`, `DistributorMSP` |
| `AddTemperatureReading` | `ManufacturerMSP`, `DistributorMSP` |
| `RecordPatientScan` | any |
| `RecallBatch` | `RegulatorMSP` |
| `VerifyMedicine`, `MedicineExists`, `GetMedicine`, `GetTemperatureHistory`, `GetAllMedicines`, `GetMedicinesByBatch`, `GetMedicinesByStatus`, `GetBreachedVaccines` | any (read-only) |

Enforced in the contract, not only by channel membership. Every member of a channel
may submit any transaction to it, so without contract-level checks a distributor
could mint. Endorsement policy is the complementary control and cannot express
"only the manufacturer may call this".

### 3.5 World-state key layout

Three kinds of value share one state database, so every value carries a `doc_type`
discriminator. A CouchDB selector without one returns temperature readings where
medicines were expected.

| Key | Value | Written by |
|---|---|---|
| `<product_id>` | `Medicine` (`doc_type: "medicine"`) | `CreateMedicine` and every write |
| `batch~product` composite `(batch_no, product_id)` | single `0x00` byte | `CreateMedicine` |
| `temp~product` composite `(product_id, seq)` | `TemperatureReading` (`doc_type: "temperature"`) | `AddTemperatureReading` |

`seq` is `999999999999 - n`, zero-padded to 12 digits, so the newest reading sorts
first: Fabric iterates composite keys lexicographically and offers no reverse
iterator.

The batch index carries no payload. Index entries exist to be iterated, and
duplicating the record would double ledger size and create two copies that can
disagree. It is written in the same transaction as the record, so a recall can
never miss a unit that was successfully created.

`RecallBatch` must use this index rather than a CouchDB rich query: rich queries
are illegal in transactions that write, because their results cannot be re-derived
deterministically at validation.

### 3.6 Two timestamps on every reading

`timestamp` is ledger time. `recorded_at` is what the sensor claimed.

Both are needed because a device that lost connectivity for three days flushes its
buffer on reconnect. Stamping those readings with the moment of reconnection would
erase exactly the outage window in which an excursion is most likely.

`recorded_at` is validated against ledger time — never wall-clock time — with a
15-minute forward skew allowance (cheap ESP32 clocks drift between NTP syncs) and a
30-day backfill window.

### 3.7 Bounded growth

| Structure | Cap | Consequence of exceeding |
|---|---|---|
| `temperature_history` (embedded) | 48 | oldest entries dropped from the window; full series retained under its own keys |
| `custody_trail` | 64 | transaction rejected (`VALIDATION_ERROR`) |
| `custody_trail`, recall only | 65 | `RecallBatch` may use one slot above the cap; see below |
| `distinct_scan_districts` | 32 | further districts not recorded; verdict already `CLONE_SUSPECTED` |
| units recalled per `RecallBatch` call | 500 | `more_remaining: true`; call again |
| batch-index rows read per `RecallBatch` call | 100,000 | `more_remaining: true`; a batch this large cannot be fully recalled by batch number |
| rows per paginated query | 500 | `page_size` clamped |

The embedded window is a correctness requirement, not tidiness. A vial sampled every
five minutes produces ~105,000 readings a year; appending each to a slice inside the
record makes reads O(n) and n writes O(n²).

The two `RecallBatch` caps bound different costs and must not be conflated. The
500-unit cap is on units **written**, so the block stays a workable size. The
100,000-row cap is only a ceiling on the batch index **read**, and it is set far
higher on purpose: capping the read at 500 instead would make every call re-read
the same first 500 rows of the batch, so once those units were recalled each later
call would recall nothing while still reporting `more_remaining: true`, and the
units behind that prefix could never be reached at all. Capping writes and scanning
the batch is what makes "repeat while `more_remaining`" terminate.

Recall gets one custody slot above the 64-event cap for the same reason. Without
it the cap becomes a weapon: a distributor who loops `UpdateLocation` until a
unit's trail is full would make every later recall of that batch fail, with no
retry able to succeed. A stuck integration must not be able to veto a safety
recall. One slot is sufficient because recall is terminal — an already-recalled
unit is skipped, so the slot is claimable at most once per unit.

### 3.8 Chaincode events

One event per transaction — `SetEvent` overwrites rather than appends.

`MedicineCreated`, `CustodyUpdated`, `TemperatureRecorded`, `ColdChainBreach`,
`PatientScanned`, `CloneSuspected`, `BatchRecalled`.

Payloads carry identifiers and scalars only. Events are stored in blocks and
replicated to every peer permanently.

### 3.9 On-chain verdicts

The chaincode never returns `COUNTERFEIT`: it cannot see the QR signature. An absent
product ID yields `NOT_ON_CHAIN` (severity `warn`), which the API promotes to
`COUNTERFEIT` (severity `critical`) only once it has verified the signature. The
on-chain precedence is the §2 order minus the signature verdicts:

```
RECALLED > CLONE_SUSPECTED > COLD_CHAIN_BREACH > EXPIRED > GENUINE
```

---

## 4. REST API contract

Base: `https://<host>/api` · JSON in, JSON out · UTF-8.

### 4.1 Envelope

Success:
```json
{ "ok": true, "data": { }, "meta": { "cached": false, "took_ms": 42 } }
```
Failure:
```json
{ "ok": false, "error": { "code": "NOT_ON_CHAIN", "message": "human readable" } }
```
`ok` is always present, so a client can branch on one field. HTTP status still carries
meaning (200/201/400/401/403/404/429/503) but `error.code` is what the app switches on.

### 4.2 Authentication

Header `X-API-Key: tm_<role>_<32 hex chars>`.

Keys are generated server-side with a CSPRNG, shown **once**, and stored only as a
SHA-256 hash. Roles: `manufacturer`, `distributor`, `sensor`, `regulator`, `pharma`,
`pharmacy`.
`GET /api/verify/:productID` and `POST /api/report` are public and unauthenticated
because patients must never need an account to check a medicine.

**`pharma` and `pharmacy` are different roles and the names are dangerously close.**
`pharma` belongs to a manufacturer and grants read-only analytics over that
manufacturer's own batches — it cannot write anything. `pharmacy` belongs to a retail
chemist and grants exactly two custody transitions, `at_pharmacy` and `dispensed`, on
units in their possession. Issuing a `pharma` key to a chemist would expose a
manufacturer's whole distribution picture to a shop; issuing a `pharmacy` key to a
manufacturer would let them mark their own stock dispensed. Any tooling that lists
roles must show the descriptions above beside the names, not the names alone.

`pharmacy` was added on 2026-08-23, during Component 4, because the role list without
it made the `dispensed` status **unreachable**: §3.1 defines `dispensed` as terminal
and reachable from `at_pharmacy`, but only `manufacturer` and `distributor` could call
`POST /api/location`, and neither of them is present when a medicine is handed to a
patient. A status no actor can set is not a status, and the last hop of the supply
chain — the one the whole system exists to protect — had no way to be recorded.

### 4.3 Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/verify/:productID` | public | Full online verification |
| `POST` | `/api/verify/payload` | public | Verify a raw scanned `TM1...` string (signature + chain) |
| `POST` | `/api/medicine` | `manufacturer` | Mint on chain |
| `POST` | `/api/location` | `manufacturer`,`distributor`,`pharmacy` | Custody hop |
| `POST` | `/api/temperature` | `sensor` | IoT reading |
| `POST` | `/api/report` | public | Counterfeit report |
| `POST` | `/api/recall` | `regulator` | Recall a batch |
| `GET` | `/api/dashboard/cdsco` | `regulator` | Heat map + alerts |
| `GET` | `/api/dashboard/pharma` | `pharma` | Batch tracking |
| `GET` | `/api/public-keys` | public | Trusted keys for offline cache |
| `GET` | `/healthz`, `/readyz` | public | Probes |

A `pharmacy` key is additionally restricted *within* `POST /api/location` to the two
statuses a chemist can legitimately assert, `at_pharmacy` and `dispensed`. The role
check alone is not enough: without the status restriction a chemist's key could rewind
a unit to `in_transit` and route it somewhere else. Role gates the endpoint, the status
list gates the transition, and §3.1's ordering gates the direction — all three are
enforced server-side, and the app's copy in `rules.dart` exists only to give the user a
faster error message.

### 4.4 `GET /api/verify/:productID` → 200

```json
{
  "ok": true,
  "data": {
    "verdict": "GENUINE",
    "severity": "ok",
    "checks": {
      "signature": "skipped_no_payload",
      "on_chain": "pass",
      "expiry": "pass",
      "cold_chain": "pass",
      "clone_telemetry": "pass"
    },
    "medicine": {
      "product_id": "PARACETAMOL500MG_PARACIP500_2026_000001",
      "generic_name": "Paracetamol 500mg",
      "brand_name": "Paracip 500",
      "manufacturer": "Sanjeevani Pharma Ltd, Plot 42 MIDC, Pune 411018",
      "mfg_licence_no": "MH/25D/2019/187",
      "batch_no": "SP26A0417",
      "mfg_date": "2026-03-15",
      "expiry_date": "2028-02-29",
      "quantity": "10 tablets",
      "excipients": ["Maize Starch", "Povidone K30", "Talc"],
      "type": "medicine",
      "status": "at_pharmacy",
      "current_location": "PHARM_MUM_0142",
      "days_to_expiry": 558
    },
    "cold_chain": { "applicable": false, "breached": false, "min_c": null, "max_c": null, "reading_count": 0 },
    "telemetry": { "scan_count": 3, "distinct_districts": 1, "first_scan_at": "2026-08-19T09:12:44Z" },
    "custody_trail": [
      { "status": "manufactured", "location": "FACTORY_PUNE_01", "timestamp": "2026-03-15T06:10:00Z", "actor_msp": "ManufacturerMSP" }
    ]
  },
  "meta": { "cached": true, "took_ms": 8 }
}
```

`checks.signature` is `"skipped_no_payload"` on this endpoint because a bare
`product_id` carries no signature. Clients wanting the signature checked server-side
must use `POST /api/verify/payload` with the full scanned string.

### 4.4a Dashboards

Both dashboards are read-only aggregates. Neither returns a verdict, so neither is
on the verification path — a dashboard that is stale, truncated or unavailable
degrades a regulator's view and can never change what a patient is told.

Both accept `?days=` (1–365, default 30) to set the aggregation window, and
`?limit=` (1–`MAX_PAGE_SIZE`, default `DEFAULT_PAGE_SIZE`) to bound the row arrays.
When more rows exist than `limit`, the response sets `truncated: true` on the
affected array's parent rather than returning a cursor. This is a deliberate
limitation: these are triage screens, ordered worst-first, and a regulator who needs
the long tail needs an export, not a second page. Adding real pagination later is a
compatible change; a cursor protocol nobody implements is not.

`GET /api/dashboard/cdsco` → 200
```json
{
  "ok": true,
  "data": {
    "window": { "from": "2026-07-24T00:00:00Z", "to": "2026-08-23T00:00:00Z", "days": 30 },
    "totals": {
      "reports": 412, "reports_open": 87, "units_recalled": 1500,
      "cold_chain_breaches": 23, "clone_suspected": 6
    },
    "districts": [
      { "district": "Patna", "state": "Bihar", "reports": 41,
        "distinct_batches": 7, "severity": "critical" }
    ],
    "alerts": [
      { "kind": "clone_suspected", "severity": "critical",
        "product_id": "PARACETAMOL500MG_PARACIP500_2026_000001",
        "batch_no": "SP26A0417", "manufacturer": "Sanjeevani Pharma Ltd",
        "detail": "38 scans across 5 districts", "at": "2026-08-22T18:04:11Z" }
    ],
    "truncated": false
  },
  "meta": { "cached": true, "took_ms": 61 }
}
```

`districts` is the heat map, ordered by `reports` descending; `severity` is the worst
severity among that district's reports and follows §2.3, so one palette drives the map,
the alert list and the patient's verdict screen. `alerts[].kind` is one of
`counterfeit_report`, `clone_suspected`, `cold_chain_breach`, `recall_incomplete`.
Clients must ignore an unrecognised `kind` and still render the row, because this list
is expected to grow and a regulator dropping an alert they have never seen before is
worse than showing one with a generic label.

`recall_incomplete` deserves naming here: `POST /api/recall` recalls at most
`MAX_RECALL_PER_TX` units per transaction and returns `more_remaining`, so a batch of
5,000 needs ten calls. If a client stops early — the app was closed, the network
dropped — part of the batch stays live on chain with no other trace. That alert is the
only thing that surfaces it.

`GET /api/dashboard/pharma` → 200
```json
{
  "ok": true,
  "data": {
    "manufacturer": "Sanjeevani Pharma Ltd",
    "mfg_licence_no": "MH/25D/2019/187",
    "window": { "from": "2026-07-24T00:00:00Z", "to": "2026-08-23T00:00:00Z", "days": 30 },
    "totals": {
      "units_minted": 240000, "units_dispensed": 191204,
      "units_recalled": 1500, "batches": 38
    },
    "batches": [
      { "batch_no": "SP26A0417", "generic_name": "Paracetamol 500mg",
        "brand_name": "Paracip 500", "type": "medicine",
        "mfg_date": "2026-03-15", "expiry_date": "2028-02-29", "days_to_expiry": 558,
        "unit_count": 5000,
        "status_counts": { "manufactured": 120, "in_transit": 400,
                           "at_pharmacy": 980, "dispensed": 3500, "recalled": 0 },
        "cold_chain": { "applicable": false, "breached": false,
                        "min_c": null, "max_c": null, "reading_count": 0 },
        "reports": 2, "worst_severity": "warn" }
    ],
    "expiring_soon": [
      { "batch_no": "SP25K0088", "expiry_date": "2026-09-19",
        "days_to_expiry": 27, "units_remaining": 812 }
    ],
    "truncated": false
  }
}
```

The key scoped by the API key decides `mfg_licence_no`; a `pharma` key never sees
another manufacturer's batches. `status_counts` keys are exactly the five §3.1
statuses, and every key is present even at zero, so a client can lay out a fixed bar
chart without checking for absent keys. `expiring_soon` is `days_to_expiry <= 90` and
`units_remaining > 0`, ordered soonest first; `units_remaining` counts units not yet
`dispensed` or `recalled`, which is the number that decides whether to pull stock.

### 4.5 Request bodies

`POST /api/verify/payload` — the whole scanned string, unmodified:
```json
{ "raw_payload": "TM1.eyJ2IjoxLCJpZCI6...:.MEUCIQD..." }
```
The field is named `raw_payload` to match `POST /api/report`, so a client that scans
something suspicious and then reports it sends the identical bytes under the identical
key in both calls. The server verifies the signature over the bytes **as received**
(§1.5) and must not normalise, trim beyond the outer whitespace, re-encode, or
re-serialise the payload before checking it.

A client that has already verified the signature offline still gains from this call:
the server adds the on-chain, cold-chain and clone-telemetry checks that a phone with
no network cannot perform. It does not replace the local check — see §2.2.

`POST /api/medicine` — mirrors §1.3 with full field names:
```json
{
  "product_id": "...", "generic_name": "...", "brand_name": "...",
  "manufacturer": "...", "mfg_licence_no": "...", "batch_no": "...",
  "mfg_date": "2026-03-15", "expiry_date": "2028-02-29",
  "quantity": "10 tablets", "excipients": ["Maize Starch"],
  "type": "medicine", "location": "FACTORY_PUNE_01"
}
```

`POST /api/location`:
```json
{ "product_id": "...", "location": "WH_MUM_001", "status": "in_transit" }
```

`POST /api/temperature`:
```json
{
  "product_id": "...", "sensor_id": "TM-SENSOR-001",
  "temperature": 4.5, "recorded_at": "2026-08-21T10:00:00Z",
  "battery_pct": 87, "nonce": "a1b2c3d4", "hmac": "<hex>"
}
```
`product_id` may instead be `batch_no` for a cold box holding a whole batch. `hmac` is
HMAC-SHA256 over `product_id|sensor_id|temperature|recorded_at|nonce` with the sensor's
shared secret, so a stolen API key alone cannot forge readings. `nonce` is replayed-
checked for 24 h in Redis.

`POST /api/report`:
```json
{
  "product_id": "...", "raw_payload": "TM1...", "pharmacy_name": "Sharma Medical",
  "district": "Patna", "state": "Bihar", "lat": 25.5941, "lon": 85.1376,
  "photo_base64": "<jpeg>", "notes": "Printing looked blurry", "reporter_contact": null
}
```
`reporter_contact` is optional and nullable — anonymous reporting must be possible, and
under the DPDP Act we should not collect personal data we do not need.

`POST /api/recall`:
```json
{ "batch_no": "SP26A0417", "reason": "NSQ: assay 78% of label claim" }
```
`reason` is required and non-blank: it is shown to the pharmacist and to the patient,
and a recall with no stated cause is not actionable by anyone. The response carries
the chaincode's `RecallResult` through unchanged:
```json
{
  "ok": true,
  "data": {
    "batch_no": "SP26A0417",
    "recalled": 500,
    "already_recalled": 0,
    "more_remaining": true,
    "product_ids": ["PARACETAMOL500MG_PARACIP500_2026_000001", "..."],
    "recalled_at": "2026-06-01T10:00:00Z",
    "actor_msp": "RegulatorMSP"
  },
  "meta": { "cached": false, "took_ms": 812 }
}
```
`recalled` is a **count** and `product_ids` is the **list** — of exactly the units this
call moved to `recalled`, so a regulator can log precisely what changed. `already_recalled`
counts units this call examined and found already recalled, which is how a repeated call
reports that it had nothing left to do rather than failing. Units past the point where the
500-unit write cap stopped the scan are in neither number, because they were never looked
at. While `more_remaining` is true the client repeats the call; §3.7 explains why that
loop terminates.

### 4.5a Write responses

`POST /api/verify/payload` returns the §4.4 verification body. `POST /api/recall` returns the
body above. The three remaining writes return the object they wrote, so a client can confirm
what landed without a follow-up read:

```json
POST /api/medicine  → 201
{ "ok": true, "data": {
    "product_id": "PARACETAMOL500MG_PARACIP500_2026_000001",
    "status": "manufactured",
    "location": "CIPLA_GOA_PLANT_02",
    "timestamp": "2026-06-01T10:00:00Z",
    "tx_id": "8f2a...c1"
  }, "meta": { "cached": false, "took_ms": 640 } }
```
```json
POST /api/location  → 200
{ "ok": true, "data": {
    "product_id": "PARACETAMOL500MG_PARACIP500_2026_000001",
    "status": "at_pharmacy",
    "location": "PHARM_MUM_0142",
    "timestamp": "2026-06-04T09:12:00Z",
    "actor_msp": "DistributorMSP",
    "tx_id": "3b71...9e"
  }, "meta": { "cached": false, "took_ms": 590 } }
```
```json
POST /api/temperature  → 201
{ "ok": true, "data": {
    "product_id": "COVAXIN_BBV152_2026_000042",
    "sensor_id": "SENSOR_MUM_001",
    "temperature": 4.5,
    "recorded_at": "2026-06-04T09:10:00Z",
    "chain_ok": true,
    "reading_count": 288,
    "tx_id": "d40c...77"
  }, "meta": { "cached": false, "took_ms": 410 } }
```

Three notes on these:

`timestamp` is the chaincode's deterministic transaction time (§3.2), **not** the API server's
clock. Returning the server's clock would be the more obvious implementation and would put a
value in the client's custody trail that does not match what a later read of the same event
returns — a difference no one would notice until an investigator compared a pharmacy's
screenshot against the ledger and found them disagreeing by a few hundred milliseconds.

`tx_id` is the Fabric transaction ID. It is the only field here that lets a dispute be settled:
given it, anyone with ledger access can fetch the exact transaction, its endorsing peers and
its read/write set. Clients should record it alongside a custody action even though nothing in
the UI displays it.

`chain_ok` on a temperature write reports whether **this reading** is inside the batch's range,
not whether the batch is still good. A single `true` says nothing about the 287 readings before
it, so a sensor must not treat it as an all-clear; the cold-chain verdict comes from
`cold_chain.breached` in §4.4, which is computed over the whole history.

`POST /api/location` echoes `actor_msp` so a client can tell which organisation the API
attributed the write to. This matters for the `pharmacy` role in particular: a chemist whose
key was mis-issued against the wrong MSP will see writes succeed and land under someone else's
organisation, which is otherwise invisible from the client side.

### 4.6 Caching

Redis, key `verify:v1:<product_id>`.

| Product state | TTL |
|---|---|
| `dispensed` or `recalled` (terminal) | 3600 s |
| active | 60 s |
| not found on chain | 30 s (negative cache, blunts enumeration scans) |

Any write to a `product_id` (`/location`, `/temperature`, `/recall`) **must** delete that
key before returning, or a pharmacy will keep seeing stale custody data.

### 4.7 Sensor HMAC — the exact bytes

§4.5 says the `hmac` covers `product_id|sensor_id|temperature|recorded_at|nonce`. That
sentence is not sufficient to implement, and an under-specified MAC is worse than none:
firmware and server each pick a plausible float format, every reading is rejected with
`UNAUTHORIZED`, and the failure looks like a wrong secret rather than a formatting
disagreement. `4.5`, `4.50` and `4.500000` are three different MACs. So the byte string is
pinned here.

```
mac_input = binding "|" sensor_id "|" temp2dp "|" recorded_at "|" nonce
hmac      = lowercase_hex( HMAC-SHA256( sensor_secret, utf8(mac_input) ) )
```

| Slot | Value | Rule |
|---|---|---|
| `binding` | `product_id` if the body carries one, otherwise `batch_no` | Exactly the string sent in the body. A cold box holding a whole batch sends `batch_no`; the MAC covers whichever key is present, so the two cases can never collide into the same input. |
| `sensor_id` | as sent | Uppercase, `TM-SENSOR-{NNN}` per §5. |
| `temp2dp` | temperature, **exactly 2 decimal places** | Rounded half-away-from-zero. Always a leading digit (`0.00`, not `.00`), `-` only for negatives, never `+`, never exponent notation. Negative zero normalises to `0.00`. |
| `recorded_at` | as sent | Exactly `YYYY-MM-DDTHH:MM:SSZ` — UTC, second precision, literal `Z`. The server's parser accepts offsets and fractional seconds from other clients, but a TrueMed sensor emits only this form and the MAC covers the exact characters sent. |
| `nonce` | as sent | 8–64 characters of lowercase `[0-9a-f]`. Firmware emits 32 (128 bits from the hardware RNG). |

Two decimals is the right width because it is finer than the sensor and coarser than the
float. A DS18B20 at 12-bit resolution steps in 0.0625 °C, so 2 dp is below its noise
floor and loses no real information; and any value with at most 2 decimals survives the
`double` round-trip exactly, so the server can re-derive `temp2dp` from the parsed JSON
number with a plain 2-dp format and always reproduce what the device signed. The device
must therefore round to 2 dp **before** both the MAC and the JSON body, so the number in
the body and the number in the MAC are the same value.

`battery_pct` is deliberately outside the MAC. It is operational telemetry, not evidence
about a medicine, and widening the MAC to cover it would break every already-flashed
device the first time the field changed. It must not be used in any safety decision.

The shared secret is per device, generated by the API (`sensors.secret_enc`), and is not
the API key. The key authenticates the *channel*; the MAC authenticates the *reading*. A
stolen key alone therefore cannot forge temperature history, which is the point — a
warm vaccine that reports 4 °C is the one failure this system exists to catch.

---

## 5. Naming conventions

| Concept | Convention | Example |
|---|---|---|
| Location IDs | `{TYPE}_{CITY}_{NNN}` | `FACTORY_PUNE_01`, `WH_MUM_001`, `PHARM_MUM_0142`, `TRUCK_MH12AB1234` |
| Sensor IDs | `TM-SENSOR-{NNN}` | `TM-SENSOR-001` |
| Batch numbers | manufacturer-defined | `SP26A0417` |
| API keys | `tm_{role}_{32 hex}` | `tm_sensor_9f2a…` |
| SQL | snake_case, plural tables | `counterfeit_reports` |
| JSON off-wire | snake_case | `mfg_licence_no` |
| Dart | lowerCamelCase, `fromJson` maps snake_case | `mfgLicenceNo` |

---

## 6. Demo data policy

Real generic/molecule names (Paracetamol 500mg, Amoxicillin 500mg, Metformin 500mg,
BCG, Measles-Rubella) paired with **fictional** brands and manufacturers
(`Paracip 500` / `Sanjeevani Pharma Ltd`, `Amoxinova 500` / `Bharat Biologics Pvt Ltd`).

No real trademark appears anywhere in seed data, screenshots, slides, or the demo video.
Attaching invented counterfeit-detection records to a real company's brand in a
presentation to CDSCO and pharma representatives would be indefensible, and fictional
brands cost the demo nothing.

---

## 7. Change control

Adding an **optional** off-wire field is a minor change: bump nothing, document it.
Changing anything inside the signed QR payload, or the crypto, requires a new prefix
(`TM2`) and dual-verification support in the app for the lifetime of already-printed
stock — realistically three years, since that is a typical shelf life.

### 7.1 Amendments

| Date | Section | Change |
|---|---|---|
| 2026-08-22 | §2.3 | Added `UNVERIFIABLE` to the verdict precedence list, which had omitted it. Positioned between `EXPIRED` and `SIGNATURE_VALID_OFFLINE`, matching `_PRECEDENCE` in `verifier.py`. Severity unchanged (`warn`), so no client colour changes. |
| 2026-08-22 | §4.3 | `POST /api/verify/payload` accepts an optional `district` in the request body and is the only endpoint that submits `RecordPatientScan`. `GET /api/verify/:productID` stays a pure read. Rationale: a full signed `TM1` string is evidence that a physical strip was scanned, whereas a bare product ID in a URL is not, and counting the latter would let anyone inflate another unit's scan telemetry into a false `CLONE_SUSPECTED` verdict. |
| 2026-08-23 | §4.7 (new) | Pinned the exact byte string the sensor HMAC covers. `temperature` is formatted to exactly 2 decimal places, half-away-from-zero, negative zero normalised; slot 1 is `product_id` or, for a whole-batch cold box, `batch_no`; `recorded_at` is exactly `YYYY-MM-DDTHH:MM:SSZ`; `nonce` is 8–64 lowercase hex characters; output is lowercase hex. Rationale: "HMAC over `a|b|c`" does not specify a float format, and a mismatch presents as `UNAUTHORIZED` on every reading — indistinguishable from a wrong secret. Found while writing Component 5, before either side existed, so no deployed device is affected. `battery_pct` is explicitly outside the MAC. |
| 2026-08-23 | §4.4, §5 | The app's offline path needs a `mfg_licence_no` → public key lookup that works with no network, so `GET /api/public-keys` must serve the trust bundle's **original bytes**, root-signature included, and the Dart client verifies that root signature against a key pinned in the APK before trusting any entry. Documented here because it constrains the API: the server holds no root private key and therefore must not re-serialise the bundle for any reason, including pretty-printing it. |

