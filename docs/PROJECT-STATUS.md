# Project status

**As of 2026-08-26.** Written by walking the tree file by file, running every test suite
that can run in this environment, and comparing what exists against
`docs/DATA-CONTRACT.md`, which is the authority for all seven components.

Section 3 was rewritten on 2026-08-26: the backend HTTP layer described there as missing
has since been built, so the old text is gone rather than annotated. Sections 1, 2, 4, 5,
6 and 7 are unchanged and still describe the tree as it stands.

## How to read the words "done" in this document

Three very different things get called "finished" in student projects, and conflating
them is how a demo fails in front of an examiner. This report keeps them apart:

**Executed** means a command was actually run and passed, and the command is named so
you can re-run it yourself. **Written and cross-checked** means the source is complete
and has been read against the contract and against its callers, but no compiler or
runtime has ever seen it — because this environment has no Go toolchain, no Docker, no
Flutter SDK and no ESP32 cross-compiler. **Missing** means the file does not exist.

Nothing in this project has been *executed* except the Python QR generator and the
Node backend's unit tests. That is not a criticism of the rest; it is the honest state,
and the first run of each un-run component belongs on your machine, where the
toolchains live.

## Summary

| # | Component | Lines | State | What blocks it |
|---|---|---|---|---|
| 1 | `qr-generator/` (Python) | 6,799 | **Executed** — 30 self-tests pass | Nothing. Complete. |
| 2 | `blockchain/` (Go + Fabric) | 5,191 | Written, cross-checked | Never compiled. Needs Go 1.21 + Docker on your machine. |
| 3 | `backend/` (Node + Express) | 20,816 | **Complete** — 570 tests pass; Express layer un-run | Nothing structural. `npm install` has never run here, so the route layer has no executed test. |
| 4 | `mobile/` (Flutter) | 9,219 | Libraries written, app not assembled | No `main.dart`, no screens, no `android/` build files. Cannot be built or launched. |
| 5 | `iot/` (ESP32) | 2,029 | Logic layer only | No `main.cpp`, no device wrappers, no `test/host/` — so even the host test target cannot build. |
| 6 | `dashboards/` (Grafana) | 0 | **Not started** | Nothing exists at all. |
| 7 | `integration-tests/` | 440 | Written by you, currently failing | `ImportError` — five exception names are not re-exported from `truemed_qr`. One-line fix, see below. |

Total: about 45,000 lines across 155 files. The line counts in the table were taken on
slightly different bases at different times and are not meant to be added up; the
backend figure counts every file under `backend/`, tests and fixtures included.

What matters more than the volume is where the remaining gap sits, and it has moved.
Until 2026-08-24 the backend was the blocker and five components were queued behind it.
That queue is now clear: the API exists, so the Flutter app has something to talk to, the
ESP32 has somewhere to POST, and Grafana has a datasource to point at. What is left is
assembly work in `mobile/` and `iot/`, and `dashboards/`, which is still empty.

---

## 1. `qr-generator/` — complete

Nineteen files, 6,799 lines, with its own pytest suite in `qr-generator/tests/`
(six test modules) and a dependency-free self-test in the CLI.

Executed here today:

```
$ cd qr-generator && python3 main.py selftest
passed 30   failed 0
All checks passed. Signing, tamper detection and verdict precedence work.
```

That covers ECDSA P-256 signing, the `TM1` wire codec, base64url round-tripping,
canonical JSON, tamper detection on every field, expiry arithmetic and verdict
precedence. The public surface exports 36 names. This component needs no further work
to function.

Two loose ends, both cosmetic rather than functional. There is no
`qr-generator/README.md`, so the per-component instructions the root README promises do
not exist for it yet. And `truemed_qr/__init__.py` re-exports only the base
`TrueMedError`, not the nine specific subclasses that live in `truemed_qr/errors.py`
(`QRMalformedError`, `UnknownFormatVersionError`, `SignatureInvalidError`,
`KeyUnknownError`, `ExpiredError`, `PayloadError`, `CapacityError`,
`DependencyMissingError`, `KeyStoreError`). That second one is not cosmetic to *you* —
it is exactly what breaks your integration test, see section 7.

## 2. `blockchain/` — written, never compiled

The Go chaincode is complete: `contract.go`, `medicine.go`, `keys.go`, `access.go`,
`ccerror.go`, `main.go`, `internal/rules/rules.go` plus `rules_test.go`, a `go.mod`, and
two CouchDB index definitions under `META-INF/statedb/couchdb/indexes/`. The 3-org
Fabric network is also complete: `configtx.yaml`, `crypto-config.yaml`,
`docker-compose.yaml`, and nine shell scripts including the in-container
channel-creation, chaincode-deploy and smoke-test steps. Both directories have their own
README, the only two per-component READMEs in the repository.

An earlier audit of this chaincode found and fixed four defects, one of which was a
recall loop that could never terminate. Those fixes are in the source. But
`rules_test.go` has never been run, because there is no Go toolchain in this
environment, and the network has never been brought up, because there is no Docker. Do
not describe this component as working until `go test ./...` and
`blockchain/network/scripts/network.sh up` have both succeeded on your machine. It is
written and statically cross-checked, which is a real thing, but it is not the same
thing.

One housekeeping item: `blockchain/chaincode/contract/` is an empty directory left over
from an earlier package layout and should be deleted, because an empty `contract/`
sitting next to `contract.go` will make a reviewer look for a package that is not
there. `blockchain/network/config/` is also empty but should stay — it is where
`configtxgen` writes its output at runtime, so give it a `.gitkeep`.

## 3. `backend/` — complete, and 570 tests of it are executed

This was the blocker in the 2026-08-24 report, which described an empty `src/services/`,
an empty `src/routes/`, no `app.js`, no `server.js` and no `scripts/`. All of that has
since been written. Seventy-six files, 20,816 lines counting tests and fixtures.

What is **executed**. Running the suite here today:

```
$ cd backend && node --test "tests/**/*.test.js"
# tests 570
# suites 115
# pass 570
# fail 0
```

Five hundred and seventy passing tests with no dependencies installed at all —
`node_modules/` is still absent and the suite still runs. That is deliberate rather than
lucky: `pg`, `redis` and the Fabric SDK are imported lazily, inside the function that
needs them, so every module except the Express-facing ones loads under plain Node. What
the suite covers is the verification core (`src/core/`: nine modules mirroring the Python
implementation), configuration loading and validation, the structured logger, the
request/response envelope middleware, the in-memory database and cache fallbacks, the
mock ledger including its recall path, `src/utils/secret-box.js`, the §4.7 sensor HMAC,
all six services, and all three scripts in `backend/scripts/`.

What was built to close the gap. `src/services/` holds the six services — `verify`,
`supply-chain`, `reports`, `dashboards`, `trust` and `health` — and they hold the logic,
which is why they are testable without Express. `src/routes/` holds seven modules plus an
`index.js` that mounts them under `/api` and the two probes at the root; each route is a
thin adapter that validates, calls one service method and hands the result to the
envelope. `src/app.js` exports `createServices` and `createApp`, a dependency-injection
factory whose whole purpose is that a test can build the entire application over the
in-memory store and the mock ledger without touching a socket. `src/server.js` is the
only file in the component that reads `process.env`, binds a port or calls
`process.exit`; it orders startup so that anything certain to be fatal — invalid
configuration, an unreadable or unsigned trust bundle — is discovered *before* the port
is bound, because a replica that accepts connections and then cannot prove which keys it
trusts would answer UNVERIFIABLE to every patient who scanned a medicine while looking
perfectly alive to a rolling deploy.

All ten endpoints in §4.3 now exist, plus the probes: `GET /api/verify/:productID`,
`POST /api/verify/payload`, `POST /api/medicine`, `POST /api/location`,
`POST /api/temperature`, `POST /api/report`, `POST /api/recall`,
`GET /api/dashboard/cdsco`, `GET /api/dashboard/pharma`, `GET /api/public-keys`, and
`/healthz` and `/readyz` mounted outside the `/api` prefix where a load balancer expects
them.

The three contract requirements that had not been started are done. The `pharmacy` role
is enforced in `services/supply-chain.js`, which refuses any status other than
`at_pharmacy` or `dispensed` from a pharmacy key — that check has to live here, because
on the Fabric network a pharmacy submits under `DistributorMSP`, so the chaincode cannot
tell the two apart and would happily let a chemist's key rewind a unit to `in_transit`
and reroute it. The §4.4a dashboard aggregates are in `services/dashboards.js`, scoped so
that a pharma key sees only batches under its own licence. The §4.5a write-response
shapes are uniform across both ledger drivers and carry a `tx_id` receipt.

`backend/scripts/` holds three files. `issue-api-key.js` issues and revokes API keys and
provisions sensor secrets: the key comes from a CSPRNG, is formatted `tm_<role>_<32 hex>`,
and only its hash is stored, so the plaintext is printed to stdout exactly once and is
unrecoverable afterwards. No flag anywhere in it accepts a secret — a test asserts that
`--key`, `--secret`, `--password`, `--api-key` and `--sensor-secret` are all rejected as
unknown options, because `argv` is readable by any other local user through `ps`. Its
happy paths are all asserted by pushing the issued key through the real authentication
middleware, since the store keeps only a hash and a disagreement between issuer and
authenticator would produce a credential indistinguishable from a revoked one.
`seed-demo.js` builds a demo world: ten units spanning all five verdicts, including a
vaccine whose cold chain is broken by real out-of-range readings, one API key per role, a
provisioned sensor, and a ready-to-run `curl` for `POST /api/temperature` with a valid
HMAC already computed — which saves a firmware author from computing one by hand, and is
proven rather than assumed, because a test parses the key and body back out of the
printed command and replays them. `make-dev-keys.js` materialises `backend/keys/` from
the shared test fixtures, which is needed because `assertRuntimePaths` will not let the
server start without a trust bundle and a root public key even in mock mode, and the
repository ships neither (`keys/` is gitignored). It writes the *same* root the mobile app
pins, and a test reaches across into `mobile/assets/trust_bundle.json` to prove it: a
freshly generated root would verify perfectly on the server and make every scan from the
phone fail, a failure that is total, silent on the server side and looks nothing like its
cause.

`package.json` declares `dev-keys`, `seed` and `issue-key` for these, and `src/server.js`
reads `SEED_DEMO=1` to run the seeder in-process before binding the port. That last part
is not a convenience: with `FABRIC_MOCK=1` the ledger, database and cache are objects in
one heap and `MockLedger` has no file behind it, so everything a separate `npm run seed`
wrote would vanish when it exited, keys included.

What is **not executed**, and this is the honest limit of the claim above. The npm
registry is unreachable from this environment — `npm ping` returns 403 — so `npm install`
has never run, and nothing that imports Express has ever been loaded, let alone served a
request. `node src/server.js` here fails with
`Cannot find package 'express' imported from .../src/app.js`. Every route module passes
`node --check` and has been read against its service and against §4.3, and every service
is exercised through its own interface, but nothing has exercised the Express
wiring itself: no status code, no envelope as it appears on the wire, no auth middleware
inside a real request, no 404, no body-size limit. Treat `src/routes/`, `src/app.js` and
`src/server.js` as *written and cross-checked*; the first `npm install && npm start`
belongs on your machine.

The first run, in order:

```
$ cd backend
$ npm install
$ npm run dev-keys                      # writes keys/trust-bundle.json + root-public.pem
$ FABRIC_MOCK=1 SEED_DEMO=1 npm start   # prints the demo API keys and a curl to copy
```

This working tree already has both files in `backend/keys/`, so `dev-keys` is only needed
after a fresh clone. The next thing worth writing for this component is an HTTP-level
test — Node's built-in `fetch` against a server listening on port 0 needs no new
dependency, so it can go in `tests/http/` without breaking the zero-devDependency rule
the rest of the suite keeps.

Housekeeping: `backend/db/migrations/` is still empty and vestigial — `src/db/migrate.js`
reads `src/db/schema.sql` directly and never looks in `db/`. Delete it, or a future
reader will assume there is a migration runner that there is not.

## 4. `mobile/` — libraries complete, application not assembled

Twenty-five files, 9,219 lines. By volume this looks close to done; by runnability it is
at zero, because there is no entrypoint. You cannot `flutter run` this directory today.

Finished. `pubspec.yaml` (Flutter >=3.22, Dart >=3.4, with `mobile_scanner`,
`pointycastle`, `flutter_secure_storage`, `http`, `image_picker`,
`shared_preferences`); `analysis_options.yaml`, which matters more than usual here
because there is no `dart analyze` in this environment, so `strict-casts`,
`strict-raw-types` and `strict-inference` are the substitute for a type checker;
`lib/config.dart`; the ten-file `lib/core/` port of the verification logic
(`base64url`, `canonical`, `codec`, `ecdsa`, `errors`, `payload`, `pinned_root_key`,
`rules`, `trust_bundle`, `verifier`); `lib/api/` (`client`, `envelope`, `models`);
`lib/store/` (`secure_store`, `trust_store`, `credentials`, `scan_history`);
`lib/l10n/strings.dart`, a hand-written localisation layer with English complete and
Hindi wired as a drop-in; `lib/ui/theme.dart`; and `lib/ui/widgets.dart`, where three
widgets exist specifically to make safety rules impossible to break by accident —
`SeverityBanner` cannot be constructed without a text label, so a verdict can never be
communicated by colour alone, which matters because red-green colour vision deficiency
affects roughly one man in twelve.

`assets/trust_bundle.json` is present and has been verified three ways: it round-trips
identically to the `trust_bundle_signed` object in `backend/tests/fixtures/fixtures.json`,
it contains zero control bytes and zero non-ASCII bytes, and its **root signature
verifies** when loaded through the backend's own `TrustBundle.fromJSON` with
`requireSignature: true`. Its root fingerprint `bff333b3eef9f2df` matches
`_developmentRootFingerprint` in `lib/core/pinned_root_key.dart`, and the SPKI baked
into that Dart source decodes to 91 bytes byte-identical to the DER SPKI of the
fixture's root public key. So the bundled asset and the pinned key agree, which is the
one thing in the offline path that cannot be checked at runtime.

Missing:

`lib/service/verify_service.dart` — the orchestration layer implementing §7.1
client-side. Parse the payload, verify offline against the trust store, call the API,
merge the server verdict, apply the network-failure downgrade, write to `ScanHistory`,
return a `VerificationOutcome`. Everything it needs already exists; nothing calls it
yet. This is the next file to write and it is roughly 250 lines.

All nine screens. Patient: scan, verdict, medicine details, temperature history, report
counterfeit, scan history. Pharmacy: sign-in and accept-stock. Regulator: recall and
overview dashboard.

`lib/ui/app.dart` and `lib/main.dart`. These go last, deliberately, so that no import
points at a file that does not exist yet.

`mobile/test/` — the whole directory. The intent is a suite driven by all 26 cases in
`backend/tests/fixtures/fixtures.json` plus `canonical-cases.json`, so the Dart core is
proven to agree with the Python and Node implementations byte for byte rather than
merely looking like it does.

The entire `mobile/android/` build tree. `mobile/android/app/src/main/` exists as an
empty directory and contains no `AndroidManifest.xml`; there are no Gradle files at any
level. Without these, `flutter build apk` cannot run. The manifest needs exactly two
permissions, `CAMERA` and `INTERNET`, and nothing else — an anti-counterfeit app that
asks for contacts or storage undermines its own credibility. `minSdkVersion 21`. Release
signing must read from a gitignored `key.properties`; `.gitignore` already covers
`mobile/android/key.properties`, `*.jks` and `*.keystore`, so the ignore rules are ready
and waiting.

`mobile/README.md`.

Housekeeping: five empty directories survive from an earlier layout and should be
deleted, because they contradict the current one and will send a reader looking in the
wrong place: `mobile/lib/models`, `mobile/lib/screens`, `mobile/lib/services`,
`mobile/lib/theme` and `mobile/lib/widgets`. The real code lives in `lib/core`,
`lib/api`, `lib/store`, `lib/ui` and (soon) `lib/service`.

## 5. `iot/` — logic layer only

Ten files, 2,029 lines. `iot/src/truemed/` holds the five logic modules as `.cpp`/`.h`
pairs: `crypto` (HMAC-SHA256 per §4.7), `format` (the reading payload), `policy` (the
2 to 8 °C breach rule and alert hysteresis), `queue` (the offline store-and-forward
ring) and `reading`. `platformio.ini` and `partitions_truemed.csv` are present. An
earlier pass found and fixed a rounding defect in the two-decimal temperature
conversion, verified by diffing against an independent oracle implementation.

Missing: the `src/device/` hardware wrappers (board, sensor, net, filesystem queue,
serial console), `src/main.cpp`, `include/config.h`,
`include/secrets.h.example`, `test/host/test_main.cpp` with its `Makefile`,
`iot/README.md`, and `iot/docs/WIRING.md` — `iot/docs/` exists but is empty.

There is a trap here worth knowing about before you try to build. `platformio.ini`
already declares `build_src_filter = +<truemed/> +<../test/host/>` and adds `-Itest/host`
to the host environment's include path. Because `test/host/` does not exist,
`pio run -e host` fails on configuration, not on code. The logic layer is host-testable
by design and cannot currently be host-tested, purely for want of that directory.

Scope decisions already settled and reflected in the source: Blynk is skipped entirely,
so the device talks only to the TrueMed API and raises breaches on a local buzzer and
LED; and provisioning is by a gitignored `include/secrets.h` plus a serial console, with
`.gitignore` already listing `iot/include/secrets.h`.

## 6. `dashboards/` — not started

`dashboards/provisioning/alerting/`, `dashboards/provisioning/dashboards/` and
`dashboards/provisioning/datasources/` all exist and all three are empty. There is not a
single file in this component. The root README promises Grafana 10.3 with dashboard JSON
plus datasource and alert provisioning for three audiences (CDSCO, pharma, health
department), and none of it exists.

This is the cheapest component to finish and the one most likely to impress in a viva,
because it is the only visual artefact — and it is no longer blocked: the §4.4a dashboard
endpoints it needs now exist, and `SEED_DEMO=1 npm start` gives it a populated world to
draw.

## 7. `integration-tests/` — your contribution, and the one-line fix it needs

`integration-tests/scripts/full-workflow-test.py`, 440 lines, walks QR generation
through offline verification to blockchain query and result display. The structure is
sound: a result accumulator, per-test logging with pass and fail counters, and a
staged workflow.

It does not run. `integration-tests/results/output.log` records an older failure on
`SIGNATURE_INVALID`, which you have since removed from the import list — but the same
class of problem remains. The current import block asks `truemed_qr` for 21 names and
five of them are not there:

```
MISSING from truemed_qr: SignatureInvalidError, KeyUnknownError,
                         ExpiredError, QRMalformedError, UnknownFormatVersionError
```

Those five classes do exist, in `qr-generator/truemed_qr/errors.py`. They are simply not
re-exported from the package's `__init__.py`, whose `__all__` lists 36 names and
includes only the base `TrueMedError`. Two ways to fix it, and the first is better:

Add the nine subclasses to `truemed_qr/__init__.py` and to its `__all__`, so the package
exposes the exception hierarchy that callers need in order to write precise `except`
clauses. Anyone importing the library hits this same wall, so fixing it at the source
fixes it once.

Or change the test to `from truemed_qr.errors import SignatureInvalidError, ...`, which
works immediately but leaves the library awkward for the next caller.

Two other things about this file. It hardcodes
`sys.path.insert(0, r'C:\Users\nanda\OneDrive\Desktop\My project\TrueMed\qr-generator')`,
which is fine on your machine and breaks for anyone else and in CI; deriving the path
from `__file__` costs one line and removes that. And `integration-tests/fixtures/` is
empty, so the test currently generates its own key material at runtime rather than
pinning against the shared fixtures the other components are tested with — which means
it can pass while silently disagreeing with them.

---

## Repository-level gaps

The root `README.md` describes several files that do not exist, which matters because a
reviewer will follow the README first and every dead reference costs credibility.

`docker-compose.yml` is listed in the repository-layout table and is the first command
in Quick Start. It does not exist. Neither does a root `.env.example`, which the same
Quick Start block tells you to copy; only `backend/.env.example` exists.
`docs/SETUP.md`, cited for Oracle Cloud deployment, does not exist. `docs/PROJECT-STATUS.md`
did not exist until this file. The README says "Full instructions per component live in
each directory's README.md", but only `blockchain/chaincode/` and `blockchain/network/`
have one. The root `scripts/` directory is empty.

The README's technology table says Flutter 3.19, in two places, while `mobile/pubspec.yaml`
requires `>=3.22.0`. Fix the README, not the pubspec — `mobile_scanner ^5.2.3` needs the
newer SDK.

`docs/` now contains four files. `DATA-CONTRACT.md`, 877 lines, is the authority for all
seven components and is in good shape; §4.7 pins the sensor HMAC byte string, which was
the last ambiguity. `BACKEND-INTERFACES.md`, 615 lines, is the exact export map of every
module under `backend/src/`, and `backend/tests/docs/interface-map.test.js` fails if a
new export is added without documenting it, so it cannot quietly rot. `AGENT-PROMPT.md`
is the paste-ready brief for the remaining work, and this file is the fourth.

Two odds and ends. There is a stray empty directory at the repository root literally
named `C:devtruemed` — that is a Windows path handed to a Unix `mkdir`, almost certainly
while following the README's advice about moving the project out of OneDrive. Delete it.

And `.git` now exists here, with one commit (`c798031`), inside OneDrive — which is the
exact thing the README warns against, because OneDrive syncing a live `.git` directory is
a known way to corrupt a repository. It has not corrupted anything yet and the working
tree is clean apart from `integration-tests/results/output.log`. The safe move is to
`git clone` or copy this folder to a local path outside OneDrive, for example
`C:\dev\truemed`, work there, and push to GitHub — treating GitHub rather than OneDrive
as the sync layer. Not urgent today; genuinely worth doing before the repository gets
large or a second developer joins.

## What has actually been executed

| Command | Result | When |
|---|---|---|
| `cd qr-generator && python3 main.py selftest` | 30 passed, 0 failed | 2026-08-24 |
| `cd backend && node --test "tests/**/*.test.js"` | 570 passed, 115 suites, 0 failed | 2026-08-26 |
| `cd backend && npm install` | npm registry unreachable here (403) | never |
| `cd backend && npm start` | blocked: Express is not installed | never |
| `qr-generator/tools/run_tests.py` (pytest, 6 modules) | not run in this environment | — |
| `go test ./...` in `blockchain/chaincode` | no Go toolchain available | never |
| `blockchain/network/scripts/network.sh up` | no Docker available | never |
| `flutter analyze` / `flutter test` in `mobile` | no Flutter SDK available | never |
| `pio run -e host` in `iot` | blocked: `test/host/` does not exist | never |
| `integration-tests/scripts/full-workflow-test.py` | fails at import, see section 7 | 2026-08-23 |

## Suggested order of work

The backend HTTP layer, which used to head this list, is done. What follows it in the
dependency order is the Flutter service (`lib/service/verify_service.dart`), then the nine
screens, then `app.dart` and `main.dart` last so that no import ever points at a file that
does not exist yet — the app is the demo, so it earns the next block of time. Then the
Android build files, because an APK you cannot build is not a deliverable. Then the ESP32
device layer and host tests. Then Grafana, now unblocked. Then `docker-compose.yml` and
the READMEs, last, because they should describe what is actually there rather than what
was planned.

One thing is worth inserting early, out of dependency order: run `npm install` in
`backend/` and start the server once. It is the only way to find out whether the Express
layer works at all, everything downstream will be debugging against it, and it takes a
minute. `FABRIC_MOCK=1 SEED_DEMO=1 npm start` needs no database, no Redis and no Fabric
network.

Two more things take under a minute each and remove a real obstacle: export the exception
classes from `truemed_qr/__init__.py`, which unblocks your integration test, and delete
the eight stale empty directories (`mobile/lib/{models,screens,services,theme,widgets}`,
`blockchain/chaincode/contract`, `backend/db/migrations`, and the stray `C:devtruemed`).

A paste-ready brief for handing the remaining work to an AI agent is in
`docs/AGENT-PROMPT.md`.
