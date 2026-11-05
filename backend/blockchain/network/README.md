# TrueMed Fabric network

A three-organisation Hyperledger Fabric 2.5 network that runs on one machine and
hosts the TrueMed chaincode.

Everything here runs in containers. The only thing you install on the host is
Docker — no Go toolchain, no Fabric binaries, no `jq`, no `curl | bash` of the
Fabric bootstrap script.

## Quickstart

```bash
cd blockchain/network

cp .env.example .env
# Set COUCHDB_PASSWORD. Generate one:
openssl rand -base64 24

./scripts/network.sh up       # crypto, containers, channel      ~2 min
./scripts/network.sh deploy   # vendor, package, install, commit  ~5 min first run
./scripts/network.sh test     # end-to-end smoke test            ~2 min
```

If all three succeed you have a working ledger and the smoke test has just
demonstrated every verdict the mobile app can show.

To stop:

```bash
./scripts/network.sh down     # containers + volumes gone, identities kept
```

## Who is on the network

Three organisations, because a single-org blockchain is a database with extra
steps. The whole argument for putting medicine provenance on a ledger is that no
single party can rewrite history, and that argument only holds when the parties
are distinct.

| Organisation | MSP ID | Represents | Peer | CouchDB | Metrics |
|---|---|---|---|---|---|
| Manufacturer | `ManufacturerMSP` | Pharma company | `localhost:7051` | `127.0.0.1:5984` | 9444 |
| Distributor | `DistributorMSP` | Warehouse, transporter, pharmacy | `localhost:9051` | `127.0.0.1:6984` | 9445 |
| Regulator | `RegulatorMSP` | CDSCO / state drug controller | `localhost:11051` | `127.0.0.1:7984` | 9446 |

Plus one orderer, `orderer.truemed.in`, on `localhost:7050` with its admin API on
7053 and metrics on 9443.

Endorsement policy is `MAJORITY` of organisations, so two of the three must
independently agree on the result of every transaction before it commits. The
manufacturer cannot mint a unit that the distributor and regulator did not both
compute the same way.

CouchDB is bound to `127.0.0.1`, not `0.0.0.0`. On a cloud VM the difference is
whether Fauxton is on the public internet with a password you generated in a
hurry. Reach it through an SSH tunnel:

```bash
ssh -L 5984:127.0.0.1:5984 user@your-vm
# then open http://127.0.0.1:5984/_utils
```

## Files

```
network/
├── .env.example                   template; copy to .env and set the password
├── .env                           git-ignored, holds the CouchDB password
├── crypto-config.yaml             identities to generate
├── configtx.yaml                  channel policies, capabilities, anchor peers
├── docker-compose.yaml            orderer, 3 peers, 3 CouchDB, CLI
├── organizations/                 generated MSPs and TLS certs (git-ignored)
├── channel-artifacts/             generated genesis block, cc package (git-ignored)
└── scripts/
    ├── network.sh                 the only script you run directly
    ├── generate.sh                cryptogen + configtxgen
    ├── lib.sh                     host-side helpers, .env parsing
    └── _incontainer/              run inside truemed-cli, not on the host
        ├── env.sh                 org switching, peer args, retry
        ├── create-channel.sh      osnadmin channel join + peer channel join
        ├── deploy-cc.sh           package, install, approve, commit
        └── smoke-test.sh          end-to-end scenario, 54 assertions
```

The `_incontainer/` split is not cosmetic. Those scripts reference paths like
`/opt/truemed/organizations` that only exist inside the CLI container. Running one
on the host produces a confusing "file not found" instead of an obvious "you are
in the wrong place", so they are kept somewhere you would not run them by
accident.

## Commands

| Command | What it does |
|---|---|
| `network.sh up` | Generates crypto if `organizations/` is absent, starts containers, waits for them, creates the channel and joins all three peers |
| `network.sh deploy` | Runs `go mod tidy && go mod vendor` and the rule tests in a `golang:1.21` container, then packages, installs, approves and commits |
| `network.sh test` | Runs the smoke test; exits non-zero on any failed assertion |
| `network.sh down` | `compose down --volumes`, plus removes the `dev-peer0*` chaincode containers and images that Compose does not manage |
| `network.sh restart` | down, up, deploy |
| `network.sh status` | `docker ps` filtered to this stack |
| `network.sh logs [container]` | Follow all logs, or one container's |

`up` and `deploy` are both idempotent. Re-running after a partial failure reports
what already exists rather than erroring.

## Changing the chaincode

Fabric's chaincode lifecycle has a counter that catches everyone once. The
**sequence** is a per-channel counter for the chaincode definition, and it is not
the version string. Editing Go code and redeploying with the same sequence fails
with a message about the definition already existing.

So after editing anything under `blockchain/chaincode/`:

```bash
# in .env
CHAINCODE_VERSION=1.1
CHAINCODE_SEQUENCE=2

./scripts/network.sh deploy
```

The old chaincode container keeps running until the new definition commits, so
there is no downtime in the middle.

## Throughput, honestly

This network runs one orderer and one peer per organisation on a single host, so
whatever it does is a property of that host, not of Fabric.

What the configuration is tuned for: `BatchTimeout: 2s` and
`MaxMessageCount: 500` in `configtx.yaml` mean a block closes either when 500
transactions have arrived or after two seconds, whichever comes first. Under light
load that gives roughly two-second latency; under heavy load it batches
aggressively.

What you should say about capacity: measure it. Run the smoke test, then write a
loop that submits `CreateMedicine` and count. Published Fabric benchmarks reach
thousands of transactions per second, but they use multi-host clusters, several
peers per org, and tuned CouchDB — none of which describes a free-tier VM. Quoting
someone else's benchmark as your own number is the kind of claim a CDSCO reviewer
or a patent examiner will ask you to substantiate, and not being able to is worse
than a modest measured figure.

The honest framing: TrueMed's throughput requirement is set by manufacturing
volume, and the write path is designed so that the expensive operation
(temperature ingestion) is one key write per reading with no read of the full
series. That is the property worth defending, not a headline TPS number.

## Design decisions

**cryptogen, not Fabric CA.** `generate.sh` uses `cryptogen`, which mints every
identity in one shot from `crypto-config.yaml`. It is the right tool for a
reproducible demo and the wrong tool for production: there is no enrolment, no
revocation, no CRL, and every private key sits in a directory on one machine. A
real deployment gives each organisation its own Fabric CA, enrols identities on
demand, and can revoke a compromised one. Saying that out loud in a viva is
better than being asked.

**One orderer.** A single Raft consenter is a single point of failure. It is also
the only shape that fits in ₹0 of infrastructure. Production needs three or five
consenters across failure domains; the `configtx.yaml` `EtcdRaft` section is
already the multi-consenter format, so adding them is configuration rather than
redesign.

**All admin credentials in one CLI container.** `truemed-cli` mounts all three
organisations' keys so one script can act as each of them in turn. On a real
network that container would be three separate clients in three separate
administrative domains, and the fact that our smoke test can impersonate the
regulator is an artefact of the demo, not a property of Fabric.

**`EnableNodeOUs: true`.** Without it, OU-based policy principals like
`ManufacturerMSP.peer` and `ManufacturerMSP.client` match nothing, and the
`Endorsement` policies in `configtx.yaml` silently never satisfy.

**Anchor peers in `configtx.yaml`.** The usual tutorial route is to commit the
channel first and then perform a channel-config update with `configtxlator` and
`jq` to add anchor peers — five steps, a JSON round-trip, and a dependency on
`jq` being installed. Declaring `AnchorPeers` in the org definitions puts them in
the genesis block instead. Cross-org gossip works from block 0.

**Secrets from `.env`, validated.** `docker-compose.yaml` uses
`${COUCHDB_PASSWORD:?...}`, so Compose refuses to start without one instead of
falling back to a default. `lib.sh` additionally rejects `password`, `admin`,
`couchdb`, `changeme`, `truemed` and `test`, because a required variable with an
obvious value is only marginally better than a hardcoded one.

**`.env` is parsed, not sourced.** `lib.sh` reads it line by line rather than
`source`-ing it. `source` executes the file, so a stray backtick in a password
becomes a shell command — in a file whose entire purpose is to hold passwords.

## Troubleshooting

**`./scripts/network.sh: Permission denied`.** The execute bit did not survive the
clone — common on Windows, on a zip round-trip, and on a OneDrive-synced working
copy. Either restore it or call the interpreter:

```bash
chmod +x scripts/*.sh scripts/_incontainer/*.sh
# or just
bash scripts/network.sh up
```

The scripts that run inside the container are already invoked as `bash <path>`, so
they are immune to this.

**`COUCHDB_PASSWORD` errors on `up`.** You have not copied `.env.example` to
`.env`, or the password is empty or one of the rejected weak values.

**`peer channel join` fails, or the peer sits at height 0.** The peer joined but
cannot reach the orderer. Check `docker logs orderer.truemed.in --tail 40`. The
usual cause is a stale volume from a previous run with different crypto — run
`./scripts/network.sh down` (which removes volumes) and `up` again.

**Chaincode install hangs for minutes.** Expected on first run: the peer compiles
Go inside a build container and prints nothing while it does. Two to four minutes
per peer on a free-tier VM. `CORE_CHAINCODE_INSTALLTIMEOUT` is set to 600s for
this reason.

**Install fails with a module download error.** `vendor/` is missing. Use
`./scripts/network.sh deploy` rather than calling `deploy-cc.sh` directly — the
peer's build sandbox has no network access, so dependencies must be vendored on
disk first.

**Invoke fails with "could not find any peers".** Cross-org gossip has not formed.
Check that `CORE_PEER_GOSSIP_EXTERNALENDPOINT` is set on all three peers in
`docker-compose.yaml`; without it a peer advertises an address its neighbours
cannot resolve.

**Invoke times out waiting for the chaincode container.** The chaincode container
landed on a different Docker network from the peers. `CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE`
must equal the Compose network name, which is pinned to `truemed_net` in
`docker-compose.yaml` precisely so it cannot drift with the directory name.

**Rich queries fail; everything else works.** The peers are running LevelDB
instead of CouchDB. `GetMedicinesByStatus` and `GetBreachedVaccines` need
`CORE_LEDGER_STATE_STATEDATABASE=CouchDB` and reachable CouchDB containers. The
error message names the state database, so this one is at least self-diagnosing.

**Endorsement policy failure after a code change on some peers only.** Different
peers are running different chaincode. `./scripts/network.sh down` removes the
`dev-peer0*` containers and images; a stale one will otherwise attach to the new
network and serve the old logic.

**Everything is baffling.** Start clean:

```bash
./scripts/network.sh down
rm -rf organizations channel-artifacts
./scripts/network.sh up && ./scripts/network.sh deploy && ./scripts/network.sh test
```

## Ports in one place

| Port | Service |
|---|---|
| 7050 | orderer, client gRPC |
| 7053 | orderer, admin API (`osnadmin`) |
| 7051 | peer0.manufacturer |
| 9051 | peer0.distributor |
| 11051 | peer0.regulator |
| 9443–9446 | Prometheus metrics: orderer, then the three peers |
| 5984 / 6984 / 7984 | CouchDB, localhost only |

The metrics endpoints are what Component 6 scrapes for the Grafana dashboards, so
they are enabled here rather than bolted on later.
