# MedSafe

**Truth in Every Medicine** · हर दवा में सच्चाई

Blockchain-backed anti-counterfeit verification for medicines and vaccines in India.
A patient scans the QR on a strip or vial and learns, in under a second, whether it is
genuine, expired, recalled, cloned, or has been through a cold-chain failure.

Final-year capstone project · BS Cybersecurity

---

## Why

Counterfeit and substandard medicines circulate widely in India, and the cold chain that
keeps vaccines between 2 °C and 8 °C fails routinely in rural facilities. Neither problem
has a feedback loop: a patient cannot check a strip before swallowing it, and a regulator
with a few hundred inspectors cannot watch five lakh pharmacies. MedSafe closes both
loops with cryptographic proof at the point of sale and an immutable custody record
behind it.

See `docs/PROJECT-STATUS.md` for sourced figures — the widely-quoted statistics on this
topic vary a lot between sources, and the report cites only what can be defended.

---

## How it works

```
 Manufacturer                Distribution                 Patient
 ────────────                ────────────                 ───────
 Mint QR                     Scan at each hop             Scan strip
 ECDSA P-256 sign     ──▶    Custody → chain       ──▶    5 checks:
 Print on strip              IoT temp → chain             signature, on-chain,
 Write to chain              (vaccines, every 5 min)      expiry, cold chain,
      │                            │                      clone telemetry
      └────────────────────────────┴──────────────┬─────────────┘
                                                  ▼
                            Hyperledger Fabric (3 orgs)
                     Manufacturer · Distributor · Regulator
                                                  │
                                                  ▼
                          Grafana: CDSCO · Pharma · Health Dept
```

The signature is verifiable **without a network**, which is the point: rural pharmacies
have patchy connectivity, and a verification system that needs 4G to work does not work.
Offline mode is honestly labelled as partial — see §2.2 of the data contract for why a
valid signature alone cannot rule out a photocopied QR, and what stops that attack.

---

## Repository layout

| Path | What it is |
|---|---|
| `docs/DATA-CONTRACT.md` | **Read this first.** Every field name, enum, and payload shape. The other six components must agree with it. |
| `qr-generator/` | Python. Mints CDSCO-format QR codes, ECDSA P-256 signing, offline verifier. |
| `blockchain/chaincode/` | Go smart contract for Hyperledger Fabric 2.5. |
| `blockchain/network/` | 3-org Fabric network: configtx, crypto-config, compose, deploy scripts. |
| `backend/` | Node.js 20 + Express REST API. Fabric Gateway + PostgreSQL + Redis. |
| `mobile/` | Flutter 3.19 patient app. Scanner, verdict screens, offline verify, reporting. |
| `iot/` | ESP32 + DS18B20 firmware. PlatformIO. |
| `dashboards/` | Grafana 10.3 dashboard JSON + datasource and alert provisioning. |
| `docker-compose.yml` | Whole stack, one command. |
| `docs/PROJECT-STATUS.md` | What is built, what is verified, what is not, and known issues. |

---

## Quick start

```bash
cp .env.example .env          # then edit the secrets
docker compose up -d
docker compose ps             # all services should be healthy
curl localhost:3000/healthz
```

Then generate and verify a QR without any of the above running:

```bash
cd qr-generator
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py selftest                 # 30 checks, no keys or network needed
python main.py keygen --out keys/       # run once; signing keys must persist
python main.py demo --count 5 --out out/
python main.py verify --wire "$(python -c \
  "import json;print(json.load(open('out/manifest.json'))['items'][0]['wire'])")"
```

`verify --image out/*.png` reads the code back out of the PNG, which needs the optional
OpenCV dependency — see `qr-generator/requirements.txt`. The `--wire` form above works
with the default install because `demo` writes every wire string to `out/manifest.json`,
which is also what seeds the blockchain and API test data.

Full instructions per component live in each directory's `README.md`.
Deployment to Oracle Cloud Always Free is in `docs/SETUP.md`.

---

## Technology

| Layer | Choice | Version |
|---|---|---|
| QR + crypto | Python, `qrcode`, `cryptography` | 3.11 |
| Blockchain | Hyperledger Fabric | 2.5 |
| Chaincode | Go | 1.21 |
| API | Node.js + Express | 20.x |
| Database | PostgreSQL | 15 |
| Cache | Redis | 7 |
| Mobile | Flutter | 3.19 |
| IoT | ESP32 + DS18B20, PlatformIO | — |
| Dashboards | Grafana | 10.3 |
| Orchestration | Docker Compose | 24.x |

Everything is open source and runs on free tiers. Total spend: about ₹1,000 for one
temperature sensor.

Two deliberate deviations from the original specification, both documented with
reasoning in `docs/DATA-CONTRACT.md`:

- **ECDSA P-256 instead of RSA-2048** for QR signatures — a 64-byte signature instead of
  256 keeps the printed code sparse enough to scan reliably on a low-end phone camera,
  at comparable security.
- **`@hyperledger/fabric-gateway` instead of `fabric-network`** — the Gateway API is the
  supported client for Fabric 2.4+; the older SDK is legacy.

---

## Working on this with a second developer

Split by component; the contract in `docs/DATA-CONTRACT.md` is the interface, so two
people can work without blocking each other. A reasonable division is QR + chaincode on
one side, backend + Flutter on the other, with dashboards and firmware last.

> **One caution.** This directory currently sits inside OneDrive. Do not run `git init`
> here — OneDrive syncing a live `.git` directory is a known way to corrupt a repository,
> and it gets worse with two people syncing the same folder. Copy the project to a local
> path outside OneDrive, for example `C:\dev\MedSafe`, initialise git there, and push to
> GitHub. Use GitHub as the sync layer between the two of you, not OneDrive.

---

## Licence and status

Unreleased academic work. Patent disclosure pending through the college IP cell — do not
publish the repository publicly until that is filed, because public disclosure can
compromise novelty in a subsequent patent application.
