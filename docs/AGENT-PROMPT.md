# Agent handoff prompt

Copy everything below the horizontal rule into a fresh AI coding agent session that has
read/write access to this repository. It is written to be self-contained: it does not
assume the agent has seen any earlier conversation.

Current state of the repository is described in `docs/PROJECT-STATUS.md`. Read that first
if you are a human; the prompt below tells the agent to read it too.

---

You are completing a final-year BS Cybersecurity capstone project called **TrueMed** — a
blockchain-backed anti-counterfeit verification system for medicines and vaccines in
India. A patient scans the QR code on a strip or vial and learns within a second whether
it is genuine, expired, recalled, cloned, or has been through a cold-chain failure.

The repository root contains `README.md`, `docs/DATA-CONTRACT.md`,
`docs/PROJECT-STATUS.md`, and seven component directories: `qr-generator/` (Python),
`blockchain/` (Go chaincode + Hyperledger Fabric 2.5 network), `backend/` (Node 20 +
Express), `mobile/` (Flutter), `iot/` (ESP32 + PlatformIO), `dashboards/` (Grafana), and
`integration-tests/` (Python).

## Before you write anything

Read `docs/DATA-CONTRACT.md` in full. It is 877 lines and it is the authority: every
field name, enum value, error code, endpoint, payload shape and canonicalisation rule is
specified there, and all seven components must agree with it. If your code and the
contract disagree, the contract wins. If the contract is genuinely ambiguous, amend it
under its own §7.1 change-control rules and say so — do not silently pick a
behaviour.

Then read `docs/PROJECT-STATUS.md`, which lists exactly what exists, what has been
executed, and what is missing.

Then read the existing code in the component you are about to extend, and match it.
Every module in this project carries substantial explanatory comments describing *why* a
decision was made, not just what the code does. Continue that. A reviewer will read this
project as much as run it.

## Non-negotiable rules

These are not style preferences. Each one is here because violating it has already caused
a real problem in this project, or because it is a security requirement of the domain.

**Never write control characters literally into source files or heredocs.** Writing a
raw newline, tab or escape byte inside a string literal has already silently corrupted
`backend/src/core/rules.js` and a JSON fixture in this project, and has silently defeated
an edit to `logger.js`. Build them from character codes instead —
`String.fromCharCode(10)` in JavaScript and Dart, `chr(10)` in Python, `'\n'` written as
a two-character escape sequence in the source text. After writing any file, grep it for
stray bytes below `0x20` and confirm the count is zero.

**Secrets never enter the repository.** They come from environment variables, from a
gitignored `mobile/android/key.properties`, or from a gitignored `iot/include/secrets.h`
for which you ship only a `secrets.h.example` containing placeholder values. `.gitignore`
already covers all three. Never commit a private key, an API key, a database password or
a keystore.

**Passwords never come from `argv`.** Anything on a command line is readable by any local
user via `ps`. Accept a password only from `--key-password-file`, from an environment
variable, or interactively from a TTY. This applies to signing scripts, key-issuing
scripts and the Gradle signing configuration.

**Private keys are written with restrictive permissions.** In Python that means
`os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)`, not a plain `open()`. In
Node, pass `{ mode: 0o600 }`.

**Never claim that an un-run component works.** You will not have a Go toolchain,
Docker, a Flutter SDK or an ESP32 cross-compiler. For anything you cannot execute, say it
is "written and statically cross-checked" and state plainly that the first real run
happens on the developer's machine. Do not write "tested", "verified" or "working" about
code no compiler has seen. This honesty is a graded property of the project.

**All C++ sources stay ASCII-only.** Write `degC`, never the degree sign. The ESP32
toolchain and serial console cannot be relied on to handle multi-byte characters, and a
mangled byte in a firmware string is very hard to trace. This rule applies to `iot/`
only. Dart and Markdown are UTF-8 and may use `°C` freely.

**No TODO comments, no placeholders, no stub functions that throw "not implemented".**
Every file you create must be complete and correct on delivery. If you cannot finish a
file, do not create it.

**Client-side verdicts are a floor, never a ceiling.** The mobile app may only ever make
a verdict *more* severe when it learns something new, never less. And keep amber and red
distinct: `UNVERIFIABLE` means the check could not be completed and is not evidence of a
counterfeit. Telling a patient a real medicine is fake and telling them a fake medicine
is real are both failures.

## Environment facts

Node 20 and Python 3.11 are available. `backend/node_modules/` is absent and
`npm install` may not be possible; the existing 400-test backend suite deliberately runs
without dependencies, using only Node built-ins and the pure modules under `src/core/`.
Keep new tests in that spirit wherever you reasonably can, so the suite keeps running
with no install step.

Not available: Go, Docker, Flutter, `dart analyze`, PlatformIO, `pio`. Anything targeting
those toolchains must be written carefully and cross-checked by reading, since you cannot
compile it.

Fixtures shared across components live in `backend/tests/fixtures/fixtures.json` (26
verification cases plus a signed trust bundle and a root key pair) and
`backend/tests/fixtures/canonical-cases.json`. Use them rather than inventing new test
vectors — the point of shared fixtures is that the Python, Node and Dart implementations
can be proven to agree byte for byte.

`mobile/assets/trust_bundle.json` is the development trust bundle. Its root fingerprint
is `bff333b3eef9f2df` and it matches the SPKI pinned in
`mobile/lib/core/pinned_root_key.dart`. Do not regenerate either one without
regenerating both.

## The work, in order

The order matters. Later phases import from earlier ones, and writing them out of order
produces files with dangling imports that cannot be checked. Complete each phase and
verify it before starting the next.

### Phase 0 — housekeeping, under five minutes

Delete eight stale empty directories that contradict the current layout:
`mobile/lib/models`, `mobile/lib/screens`, `mobile/lib/services`, `mobile/lib/theme`,
`mobile/lib/widgets`, `blockchain/chaincode/contract`, `backend/db/migrations`, and a
stray root directory literally named `C:devtruemed`. Keep
`blockchain/network/config/` — it is a runtime output directory — and add a `.gitkeep`
to it.

In `qr-generator/truemed_qr/__init__.py`, re-export the nine exception subclasses that
already exist in `truemed_qr/errors.py` (`PayloadError`, `QRMalformedError`,
`UnknownFormatVersionError`, `SignatureInvalidError`, `KeyUnknownError`, `ExpiredError`,
`CapacityError`, `DependencyMissingError`, `KeyStoreError`) and add them to `__all__`.
Only the base `TrueMedError` is currently exported, which makes it impossible for a
caller to write a precise `except` clause. Verify with
`cd qr-generator && python3 main.py selftest` — it must still report 30 passed, 0 failed.

In `integration-tests/scripts/full-workflow-test.py`, replace the hardcoded
`sys.path.insert(0, r'C:\Users\...')` with a path derived from `__file__`, so the test
runs for a second developer and in CI. Then run it and make it pass.

In `README.md`, correct the two occurrences of "Flutter 3.19" to 3.22 — `mobile/pubspec.yaml`
requires `>=3.22.0` because `mobile_scanner ^5.2.3` needs it.

### Phase 1 — the backend HTTP layer, the critical path

`backend/src/routes/` and `backend/src/services/` are empty. There is no `src/app.js`
and no `src/server.js`, yet `package.json` sets `"main": "src/server.js"` and
`"start": "node src/server.js"`, so `npm start` currently fails with `MODULE_NOT_FOUND`.
Five other components are waiting on this.

Everything the HTTP layer needs already exists and is tested: the verification core in
`src/core/` (nine modules), config loading in `src/config/`, the structured logger, the
envelope/auth/rate-limit/async-handler/error-handler middleware in `src/middleware/`,
Postgres and in-memory database adapters plus `schema.sql` and `migrate.js` in `src/db/`,
Redis and in-memory caches in `src/cache/`, and both a real Fabric gateway client and a
mock ledger in `src/fabric/`. Wire these together; do not reimplement them, and do not
change their signatures without reading their tests first.

Implement all eleven endpoints exactly as specified in data contract §4.3, with the
response shapes from §4.4, §4.4a and §4.5a, the request bodies from §4.5, the envelope
from §4.1, the authentication model from §4.2, the machine-readable error codes from
§2.4, and the caching behaviour from §4.6:

`GET /api/verify/:productID` (public), `POST /api/verify/payload` (public),
`POST /api/medicine` (manufacturer), `POST /api/location` (manufacturer, distributor,
pharmacy), `POST /api/temperature` (sensor), `POST /api/report` (public),
`POST /api/recall` (regulator), `GET /api/dashboard/cdsco` (regulator),
`GET /api/dashboard/pharma` (pharma), `GET /api/public-keys` (public), and
`GET /healthz` plus `GET /readyz` (public).

Three specific requirements that are easy to miss. First, the `pharmacy` role must be
restricted *within* `POST /api/location` to the two statuses a chemist may legitimately
assert, `at_pharmacy` and `dispensed` — the role check alone is insufficient, because
without the status restriction a chemist's key could rewind a unit to `in_transit` and
reroute it. Role gates the endpoint, the status list gates the transition, and §3.1's
ordering gates the direction; all three are enforced server-side. Second,
`checks.signature` on `GET /api/verify/:productID` is `"skipped_no_payload"`, because a
bare `product_id` carries no signature; only `POST /api/verify/payload` can check it.
Third, the sensor HMAC on `POST /api/temperature` must be computed over exactly the byte
string pinned in §4.7 — no reordering, no whitespace differences.

Write `src/app.js` as an exported factory that takes its dependencies as arguments, so
tests can construct an app over the in-memory database, in-memory cache and mock ledger
with no external services running. Write `src/server.js` as a thin entrypoint that reads
config, builds the app, listens, and handles `SIGTERM` gracefully.

Create `backend/scripts/seed-demo.js` and `backend/scripts/issue-api-key.js`, which
`package.json` already references as `npm run seed` and `npm run issue-key`. The
key-issuing script must never accept a secret via `argv`, and must store only the hash of
the key it issues, printing the plaintext once to stdout.

Add route and service tests under `backend/tests/`. Acceptance for this phase:
`node --test "tests/**/*.test.js"` passes with the existing 400 tests still green plus
your new ones, and `npm start` starts a listening server against the in-memory stack.

### Phase 2 — the Flutter verification service

Write `mobile/lib/service/verify_service.dart`, implementing data contract §7.1 on the
client. It parses the scanned payload, verifies the signature offline against the trust
store, calls the API, merges the server verdict, applies the network-failure downgrade,
records the scan to `ScanHistory`, and returns a `VerificationOutcome`.

Everything it needs already exists in `lib/core/` and `lib/api/`: `verifyWireSafe`,
`mergeServerVerdict`, `withNetworkFailure`, `worstVerdict`, `offlineCaveat`,
`OnlineVerification.fromData`, `MedicineData`, `VerificationResult`. Read those before
writing, and use them as they are.

Two rules bind here. The merge may only make a verdict more severe, never less. And an
API failure produces `UNVERIFIABLE` with the offline caveat attached — never `GENUINE`
and never `COUNTERFEIT`.

Scan history is health data under India's DPDP Act. It is encrypted at rest via
`SecureStore`, capped at 100 entries, and the user can erase it.

### Phase 3 — the Flutter screens, then the entrypoint

Nine screens, all three roles. Patient: scan (using `mobile_scanner`), verdict, medicine
details, temperature history, report counterfeit (with photo via `image_picker`,
location, and pharmacy name), and scan history. Pharmacy: sign-in and accept-stock.
Regulator: recall and an overview dashboard.

Build every screen from the widgets already in `lib/ui/widgets.dart` and the strings
already in `lib/l10n/strings.dart`. Do not introduce new colour constants — use
`lib/ui/theme.dart`. Do not write user-facing English inline; add it to `Strings` and
`StringsEn`, because `Strings` is an abstract class specifically so the compiler
enumerates anything missing. English only for now; Hindi is a deliberate later drop-in
and the delegate is already wired for it.

Use `SeverityBanner` for every verdict, which structurally cannot be constructed without
a text label — colour-only encoding of a verdict is a safety defect, because red-green
colour vision deficiency affects roughly one man in twelve. Use `BusyButton` for report
and recall, which are not idempotent; it disables itself while its action is in flight,
because a double tap on a slow connection is the ordinary way a user files two reports.

Write `lib/ui/app.dart` and `lib/main.dart` **last**, so no import ever points at a file
that does not yet exist.

### Phase 4 — Flutter tests and the Android build

Create `mobile/test/` driving all 26 cases in `backend/tests/fixtures/fixtures.json` and
every case in `canonical-cases.json`, so the Dart core is proven to agree with the Python
and Node implementations rather than merely appearing to.

Create the whole `mobile/android/` build tree: `settings.gradle`, root `build.gradle`,
`app/build.gradle`, `gradle.properties`, the Gradle wrapper, and
`app/src/main/AndroidManifest.xml`. The manifest declares exactly two permissions,
`CAMERA` and `INTERNET`, and nothing else — an anti-counterfeit app that requests
contacts or storage undermines the trust it is asking for. `minSdkVersion 21`. Release
signing reads a gitignored `key.properties`; never a password from `argv`. `.gitignore`
already covers `mobile/android/key.properties`, `*.jks` and `*.keystore`.

Then `mobile/README.md`: prerequisites, `flutter pub get`, running against a local
backend, the `--dart-define=TRUEMED_ROOT_SPKI_B64` flag that replaces the development
root key for a real deployment, `flutter test`, and `flutter build apk --release`
including keystore generation.

### Phase 5 — the ESP32 device layer

`iot/src/truemed/` already holds the five logic modules (`crypto`, `format`, `policy`,
`queue`, `reading`) as host-testable `.cpp`/`.h` pairs. Add the hardware layer around
them: `src/device/` wrappers for board, DS18B20 sensor, network, filesystem-backed queue
and serial console; `src/main.cpp`; `include/config.h`; and
`include/secrets.h.example` with placeholder values only.

Then `test/host/test_main.cpp` with a `Makefile`. Note that `platformio.ini` already
declares `build_src_filter = +<truemed/> +<../test/host/>` and adds `-Itest/host`, so
`pio run -e host` currently fails on configuration purely because that directory does
not exist. Creating it unblocks host testing of the logic layer.

Scope is already settled: no Blynk. The device talks only to the TrueMed API and raises
cold-chain breaches on a local buzzer and LED. Provisioning is a gitignored
`include/secrets.h` plus a serial console.

Finally `iot/README.md` and `iot/docs/WIRING.md` — `iot/docs/` exists and is empty. The
wiring document needs a pin table, the DS18B20 pull-up resistor value, and power notes.

Remember: ASCII only in every C++ file. Write `degC`.

### Phase 6 — Grafana dashboards

`dashboards/provisioning/{alerting,dashboards,datasources}/` all exist and all three are
empty. Build three dashboards against the backend's §4.4a endpoints and the Postgres
schema in `backend/src/db/schema.sql`: a CDSCO view (counterfeit-report heat map by
district, recall alerts, compliance summary), a pharma view (batch tracking, temperature
history, expiry horizon), and a health-department view (vaccine stock, cold-chain
compliance, immunisation coverage).

Provision datasources and alert rules as files, not through the UI, so the whole thing is
reproducible from the repository. No credentials in any committed file — reference
environment variables.

### Phase 7 — orchestration and documentation, last

Write the root `docker-compose.yml` that the README's Quick Start already invokes,
covering Postgres 15, Redis 7, the backend, and Grafana 10.3, with healthchecks and a
`.env`-driven configuration. Write the root `.env.example` that Quick Start tells the user
to copy. Note that the Fabric network has its own compose file at
`blockchain/network/docker-compose.yaml` and should stay separate.

Write `docs/SETUP.md` covering deployment to Oracle Cloud Always Free, which the README
cites. Write the missing per-component READMEs: `qr-generator/README.md`,
`backend/README.md`, `dashboards/README.md`, `integration-tests/README.md`.

Then update `docs/PROJECT-STATUS.md` so it describes the repository as it then is,
keeping its distinction between "executed", "written and cross-checked" and "missing"
intact and honest.

## Definition of done

`cd qr-generator && python3 main.py selftest` reports 30 passed, 0 failed.
`cd backend && node --test "tests/**/*.test.js"` passes, including new route and service
tests. `npm start` in `backend/` serves all eleven endpoints against the in-memory stack.
`integration-tests/scripts/full-workflow-test.py` runs to completion and passes. No file
in the repository contains a TODO, a placeholder or a stub that throws. No file contains
a stray byte below `0x20`. No secret is committed. Every claim in `docs/PROJECT-STATUS.md`
about what has been executed is one you actually ran and can reproduce.

## What not to do

Do not change `docs/DATA-CONTRACT.md` except through its own §7.1 amendment process, and
if you do amend it, update every component that depends on the changed field in the same
pass.

Do not regenerate `mobile/assets/trust_bundle.json` or
`mobile/lib/core/pinned_root_key.dart` independently of each other; they are
cryptographically linked by fingerprint `bff333b3eef9f2df`.

Do not modify the shared fixtures in `backend/tests/fixtures/` to make a test pass. The
fixtures are the specification; a disagreement means your implementation is wrong, or the
contract is, and either way the fixture is the last thing to change.

Do not run `git init` or any git command in a directory inside OneDrive. If you need
version control, say so and let the developer move the project to a local path first.

Do not delete or rewrite existing working code to suit a new file. Read it, and fit your
code to it.
