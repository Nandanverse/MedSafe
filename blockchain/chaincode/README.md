# TrueMed Chaincode

The smart contract that holds TrueMed's ledger state: one record per sellable unit
of medicine or vaccine, its chain of custody, its cold-chain history, its scan
telemetry, and its recall status.

This is Component 2a. It runs on Hyperledger Fabric 2.5 and is written in Go
against `fabric-contract-api-go`.

## What this component is responsible for

The QR generator (Component 1) proves a code was signed by a real manufacturer.
That is a cryptographic claim, and it is checkable offline, on a phone, with no
network. What it cannot tell you is anything that happened *after* printing: that
the batch was recalled last Tuesday, that the vial spent six hours at 19 °C in a
failed fridge, that this same code has already been scanned 340 times in eleven
districts. Those are facts about the world, and they need a shared, tamper-evident
record that no single participant can quietly edit. That is what this chaincode is.

The division of labour is worth stating plainly, because it is the part reviewers
ask about first:

| Check | Where it happens | Works offline |
|---|---|---|
| QR structure and CDSCO field set | app + API (Component 1 code) | yes |
| ECDSA P-256 signature | app + API (Component 1 code) | yes |
| Registered by its manufacturer | this chaincode | no |
| Expiry | both (app for the printed date, chaincode for the record) | app: yes |
| Cold-chain breach | this chaincode | no |
| Recall | this chaincode | no |
| Clone / duplicate-scan heuristic | this chaincode | no |

The chaincode never sees the QR payload or its signature, so it never returns
`COUNTERFEIT`. When a product ID is absent it returns `NOT_ON_CHAIN`, and the API
promotes that to `COUNTERFEIT` only once it knows the signature was valid — a
signed code for a unit that was never minted means a signing key has leaked, which
is a much stronger and more serious claim than "I couldn't find it".

## Layout

```
blockchain/chaincode/
├── main.go                     chaincode entry point
├── contract.go                 the eleven transaction functions
├── medicine.go                 record types, deterministic time, derived views
├── keys.go                     world-state keys, composite indexes, iterators
├── access.go                   MSP authorisation
├── go.mod
├── internal/rules/
│   ├── rules.go                all business rules, zero Fabric imports
│   └── rules_test.go           stdlib-only unit tests
└── META-INF/statedb/couchdb/indexes/
    ├── indexStatus.json
    └── indexBreach.json
```

`internal/rules` exists because of a practical problem: testing chaincode properly
needs a running peer, and nobody runs a peer while iterating on an expiry
comparison. So every rule that could plausibly be wrong — the custody state
machine, the inclusive 2–8 °C boundary, the expiry-day-is-still-valid rule, the
verdict precedence, the clone thresholds — lives in a package that imports nothing
but the standard library, and is covered by tests that run in under a second on a
laptop with no Docker installed. What remains in the Fabric-facing files is
plumbing thin enough to review by eye.

## Prerequisites

Go 1.21 or newer, and Docker for the network in `../network`. Both are free.

Verify Go first, because the version matters:

```bash
go version     # expect go1.21 or newer
```

## Build and test

Run this from `blockchain/chaincode`:

```bash
go mod tidy                      # resolves fabric-chaincode-go, writes go.sum
go vet ./...                     # catches the mistakes a compiler won't
gofmt -l .                       # must print nothing
go test ./internal/rules/... -v  # 30-odd rule tests, no peer required
go build ./...                   # must produce no output
```

`go mod tidy` is not optional on a fresh clone: `go.sum` is not committed, and
without it the build fails with a missing-go.sum-entry error.

The test suite is the fastest way to convince yourself the business logic is right,
and it is worth reading rather than just running. `TestExpiryDayItselfIsValid`,
`TestColdChainBoundariesAreInclusive`, `TestRepeatOnlyPermittedForInTransit` and
`TestSeverityNeverDefaultsToOK` each pin down a decision where the obvious
implementation is subtly wrong.

## Transaction reference

Eleven functions. Permissions are enforced in the contract, not merely by channel
membership — see the long comment in `access.go` for why that distinction matters.

| Function | Kind | Who may call it |
|---|---|---|
| `CreateMedicine(medicineJSON)` | write | `ManufacturerMSP` |
| `UpdateLocation(locationJSON)` | write | `ManufacturerMSP`, `DistributorMSP` |
| `AddTemperatureReading(readingJSON)` | write | `ManufacturerMSP`, `DistributorMSP` |
| `RecordPatientScan(scanJSON)` | write | any channel member |
| `RecallBatch(recallJSON)` | write | `RegulatorMSP` |
| `VerifyMedicine(productID)` | read | any |
| `GetMedicine(productID)` | read | any |
| `MedicineExists(productID)` | read | any |
| `GetTemperatureHistory(productID, limit)` | read | any |
| `GetMedicinesByBatch(batchNo)` | read | any |
| `GetMedicinesByStatus(status, pageSize, bookmark)` | read (CouchDB) | any |
| `GetAllMedicines(pageSize, bookmark)` | read (CouchDB) | any |
| `GetBreachedVaccines(pageSize, bookmark)` | read (CouchDB) | any |

`UpdateLocation`, `AddTemperatureReading`, `RecordPatientScan` and `RecallBatch`
each take one JSON object with the same field names the REST API uses
(`product_id`, `location`, `status`, `sensor_id`, `recorded_at`, `batch_no`,
`reason`). Business errors are returned as `CODE: message` so the Node.js
gateway can map them to HTTP 403/400/404/409 instead of a generic 503.

`CreateMedicine` takes a single JSON object rather than thirteen positional
strings. Fabric passes every argument as a string, so a positional signature makes
transposing `mfg_date` and `expiry_date` a silent error that produces a
plausible-looking record with the wrong expiry printed on real stock. The accepted
fields are exactly those of `createRequest` in `medicine.go`, and unknown fields
are rejected — send `expiry` instead of `expiry_date` and you get an immediate
error rather than an empty expiry date discovered months later.

`UpdateLocation` requires the caller to state the new status explicitly. An earlier
design inferred it from the location string, which fails the day a warehouse is
renamed, and cannot distinguish "arrived at pharmacy" from "dispensed at pharmacy"
at all.

## Events

Every write emits exactly one event. One, not several: `SetEvent` overwrites rather
than appends, so a second call silently discards the first.

`MedicineCreated`, `CustodyUpdated`, `TemperatureRecorded`, `ColdChainBreach`,
`PatientScanned`, `CloneSuspected`, `BatchRecalled`.

The backend subscribes to these to invalidate its Redis cache and to push
cold-chain alerts, which is what makes a fridge failure visible on the CDSCO
dashboard in seconds rather than at the next poll. Payloads carry identifiers and
scalars only — an event is stored in the block and replicated to every peer
forever, so putting a whole record in one doubles the ledger cost of every write
for data the listener can fetch on demand.

## Packaging and deployment

The network scripts in `../network` do this for you. The manual sequence, for when
something goes wrong and you need to see each step:

```bash
# 1. Vendor dependencies. The peer builds chaincode inside a container that has no
#    network access, so the modules must be on disk.
go mod tidy
go mod vendor

# 2. Package. --lang golang --path must point at the module root.
peer lifecycle chaincode package truemed.tar.gz \
  --path . --lang golang --label truemed_1.0

# 3. Install on a peer of every organisation, approve for each, then commit.
#    ../network/scripts/deployCC.sh does all of this.
```

CouchDB is required, not optional: `GetMedicinesByStatus` and
`GetBreachedVaccines` use rich queries, which LevelDB cannot serve. The peers must
run with `CORE_LEDGER_STATE_STATEDATABASE=CouchDB`. The two files under `META-INF`
are deployed automatically with the package and create the CouchDB indexes those
queries need; without them the queries still return correct answers, but by
scanning every document in the database, and they degrade from milliseconds to
minutes as the channel fills.

There are only two indexes on purpose. Each one adds work to every single write, so
an index that no query uses is a permanent tax paid for nothing.

## Design decisions worth knowing before you change anything

**No `time.Now()`, ever.** Every timestamp comes from `ledgerTime()`, which reads
the transaction timestamp out of the proposal. Each endorsing peer executes the
transaction independently, so a wall-clock read gives every peer a slightly
different value, their write sets differ, and the transaction is rejected at
validation as a read-write set conflict. Worse than failing: with a single
endorsing peer it *works*, and then breaks the day a second organisation joins —
which on this project would be the week of the demo.

**Failure is data, not a Go error.** `VerifyMedicine` returns a
`VerificationSnapshot` and reserves errors for infrastructure faults. An error
return aborts the transaction and the contract API throws away any accompanying
value, so returning `(medicine, error)` for a recalled vial gives the patient
"transaction failed" and nothing else — no product name, no batch, no reason. The
moment the system most needs to communicate clearly is the moment it would go
silent.

**The temperature series is not stored in the record.** A vaccine vial sampled every
five minutes produces about 105,000 readings a year. Appending each one to a slice
inside the unit's record makes every write read and rewrite the entire history:
reading n readings is O(n) and writing n of them is O(n²), and the state database,
the gossip payload and the block size all grow without bound. So the full series
goes to one ledger key per reading, and the record keeps a 48-entry rolling window
for display plus min/max/count aggregates and a sticky breach flag. Drawing a
sparkline stays a single read.

**Temperature keys count down.** Fabric iterates composite keys in lexicographic
order and provides no reverse iterator, but every caller wants the newest readings.
Storing sequence `n` as `(999999999999 - n)`, zero-padded, puts the most recent
reading first, so "the last twenty" stops after twenty rows instead of walking a
hundred thousand.

**Recall uses a composite-key index, not a rich query.** Rich queries are not
permitted in transactions that write, because their results depend on the state
database at execution time and cannot be re-derived deterministically at
validation. A range query over `batch~product` records a proper phantom-protected
read set — and it keeps working with CouchDB switched off, which matters because a
recall is the one operation that runs when something has already gone wrong.

**A cold-chain breach is permanent.** Once `cold_chain_breached` is set it is never
cleared. A vaccine that reached 15 °C does not become safe again when the fridge
recovers; potency loss is cumulative and irreversible. Any code that resets that
flag is a bug, however tempting it looks when a dashboard is full of red.

**Expired units can be registered.** Refusing them would make it impossible to
onboard existing inventory, and a real deployment begins with warehouses full of
stock manufactured before the system went live.

## Known limits

`RecordPatientScan` is a read-modify-write on one key, so two people scanning the
same strip in the same second will collide and one transaction will be rejected
with an MVCC conflict. The API layer coalesces scans per product before submitting.
This is a deliberate trade: the counter is a heuristic for detecting mass cloning,
losing one increment in four hundred changes no verdict, and the lock-free
alternative is one ledger key per scan and unbounded state growth.

`RecallBatch` recalls at most 500 units per transaction, because rewriting tens of
thousands in one go produces a write set the orderer refuses. It returns
`more_remaining: true` when units are left, and the deploy scripts' recall helper
loops until the flag clears.

That cap is on units **written**, not on index rows **read**, and the distinction is
the difference between a loop that terminates and one that cannot. Capping the scan
at 500 looks equivalent — units already recalled are skipped, so surely each pass
gets further — but the scan always restarts at the head of the batch index, so the
second call re-reads the same 500 rows it just recalled, recalls nothing, and still
reports `more_remaining: true`. Every unit past row 500 becomes permanently
unreachable: a batch that can never be fully recalled, which in this system means
dangerous medicine that keeps verifying as genuine on every patient's phone. The
contract therefore scans the batch (bounded by `maxRecallScan`, purely to keep the
read set finite) and stops after `maxRecallPerTx` writes.

Recall also gets one `custody_trail` slot above the normal 64-event cap. Without it
the cap is a weapon: a distributor who loops `UpdateLocation` until a unit's trail is
full would make every later recall of that batch fail with no retry able to succeed.
One slot is enough because recall is terminal, so it can be claimed at most once per
unit. Both properties are covered by `backend/tests/fabric/mock-ledger-recall.test.js`
against the mock, which mirrors this contract.

The clone heuristic (more than 25 scans, or more than 3 districts) is a heuristic.
A genuine strip passed around a large family in a border district could in principle
trip it. The thresholds are defined once in `internal/rules/rules.go` and asserted
against the Python reference in `TestThresholdsMatchPythonReference`, so tuning them
is a one-line change in two files that the test suite will catch if you forget one.

District is optional on a scan. A patient may decline location permission, and the
DPDP Act's data-minimisation principle means the scan must still be recorded
without it — which does mean clone detection is weaker for privacy-conscious users.

## Related documents

`docs/DATA-CONTRACT.md` §3 is the authoritative schema and is the arbiter whenever
this code, the Python reference implementation, and the mobile app disagree. Change
it first, then change the code.
