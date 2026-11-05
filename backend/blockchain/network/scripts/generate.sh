#!/usr/bin/env bash
#
# TrueMed — generate crypto material and the channel genesis block.
#
# Runs cryptogen and configtxgen inside the fabric-tools container, so the Fabric
# binaries never have to be installed on the host. The only prerequisite is Docker.
#
# Idempotent in the sense that it refuses to overwrite: if organizations/ already
# exists it stops. Regenerating crypto material under a running network is a
# uniquely miserable failure — every peer keeps its old identity in its volume,
# every certificate on disk is new, and each rejection looks like a different
# problem. Use network.sh down first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib.sh"

load_env

FORCE="${1:-}"

if [[ -d "${NET_DIR}/organizations" && "${FORCE}" != "--force" ]]; then
  err "organizations/ already exists."
  cat >&2 <<'EOF'

Crypto material is already present. Generating it again would give every node a
new identity while the running peers keep their old one in their data volume, and
nothing on the channel would trust anything else.

To start over completely:

    ./scripts/network.sh down      # removes containers AND volumes
    ./scripts/generate.sh

To regenerate deliberately anyway (you will also need to wipe the volumes):

    ./scripts/generate.sh --force

EOF
  exit 1
fi

if [[ "${FORCE}" == "--force" ]]; then
  warn "Removing existing crypto material and channel artifacts."
  rm -rf "${NET_DIR}/organizations" "${NET_DIR}/channel-artifacts"
fi

mkdir -p "${NET_DIR}/channel-artifacts"

# --user keeps the generated files owned by the invoking user. Without it every
# file lands owned by root, and `network.sh down` cannot delete them without sudo.
DOCKER_USER_FLAG=()
if command -v id >/dev/null 2>&1; then
  DOCKER_USER_FLAG=(--user "$(id -u):$(id -g)")
fi

step "Generating MSP and TLS material with cryptogen"
docker run --rm "${DOCKER_USER_FLAG[@]}" \
  -v "${NET_DIR}:/work" -w /work \
  "hyperledger/fabric-tools:${FABRIC_VERSION}" \
  cryptogen generate --config=./crypto-config.yaml --output=organizations

# cryptogen writes an admincerts folder in older layouts and none in newer ones.
# The check below is about a different and much more common failure: a silent
# partial generation leaves directories in place but no signing key, and the peer
# then starts and fails to endorse anything.
for org in manufacturer distributor regulator; do
  key_dir="${NET_DIR}/organizations/peerOrganizations/${org}.truemed.in/peers/peer0.${org}.truemed.in/msp/keystore"
  if [[ ! -d "${key_dir}" ]] || [[ -z "$(ls -A "${key_dir}" 2>/dev/null)" ]]; then
    err "cryptogen did not produce a signing key for peer0.${org}.truemed.in"
    err "Check the output above; crypto-config.yaml may be malformed."
    exit 1
  fi
done
ok "Crypto material generated for 1 orderer org and 3 peer orgs"

step "Building the channel genesis block for '${CHANNEL_NAME}'"
docker run --rm "${DOCKER_USER_FLAG[@]}" \
  -v "${NET_DIR}:/work" -w /work \
  -e FABRIC_CFG_PATH=/work \
  "hyperledger/fabric-tools:${FABRIC_VERSION}" \
  configtxgen \
  -profile TrueMedChannel \
  -channelID "${CHANNEL_NAME}" \
  -outputBlock "./channel-artifacts/${CHANNEL_NAME}.block"

if [[ ! -s "${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.block" ]]; then
  err "configtxgen produced no genesis block."
  exit 1
fi
ok "Genesis block written to channel-artifacts/${CHANNEL_NAME}.block"

cat <<EOF

Next:  ./scripts/network.sh up

EOF
