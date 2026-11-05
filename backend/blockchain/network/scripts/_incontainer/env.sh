#!/usr/bin/env bash
#
# Shared environment for the in-container scripts. Sourced, never executed.
#
# Runs inside truemed-cli, where the Fabric binaries live and every
# organisation's admin credentials are mounted. On a real deployment each
# organisation would run its own client with only its own keys; a single container
# holding all three exists because this is a demo, and pretending otherwise would
# be the wrong lesson to take from it.

set -euo pipefail

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
  C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''
fi

step() { printf '\n%s==>%s %s%s%s\n' "${C_BLUE}" "${C_RESET}" "${C_BOLD}" "$*" "${C_RESET}"; }
ok()   { printf '%s  ok%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn() { printf '%s warn%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
err()  { printf '%serror%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }

ORG_DIR=/opt/truemed/organizations
ARTIFACTS=/opt/truemed/channel-artifacts
CC_DIR=/opt/truemed/chaincode

: "${CHANNEL_NAME:=truemed}"
: "${CHAINCODE_NAME:=truemed}"
: "${CHAINCODE_VERSION:=1.0}"
: "${CHAINCODE_SEQUENCE:=1}"
CC_LABEL="${CHAINCODE_NAME}_${CHAINCODE_VERSION}"
CC_PACKAGE="${ARTIFACTS}/${CC_LABEL}.tar.gz"

# core.yaml lives here in the fabric-tools image. Without FABRIC_CFG_PATH the peer
# CLI exits complaining about a missing config file rather than about the path.
export FABRIC_CFG_PATH=/etc/hyperledger/fabric
export CORE_PEER_TLS_ENABLED=true

ORDERER_HOST=orderer.truemed.in
ORDERER_PORT=7050
ORDERER_ADMIN_PORT=7053
ORDERER_CA="${ORG_DIR}/ordererOrganizations/truemed.in/orderers/orderer.truemed.in/msp/tlscacerts/tlsca.truemed.in-cert.pem"
ORDERER_TLS_CERT="${ORG_DIR}/ordererOrganizations/truemed.in/orderers/orderer.truemed.in/tls/server.crt"
ORDERER_TLS_KEY="${ORG_DIR}/ordererOrganizations/truemed.in/orderers/orderer.truemed.in/tls/server.key"

ORGS=(manufacturer distributor regulator)
declare -A MSP_ID=(
  [manufacturer]=ManufacturerMSP
  [distributor]=DistributorMSP
  [regulator]=RegulatorMSP
)
declare -A PEER_PORT=(
  [manufacturer]=7051
  [distributor]=9051
  [regulator]=11051
)

peer_address() { printf 'peer0.%s.truemed.in:%s' "$1" "${PEER_PORT[$1]}"; }
peer_tls_ca()  { printf '%s/peerOrganizations/%s.truemed.in/peers/peer0.%s.truemed.in/tls/ca.crt' "${ORG_DIR}" "$1" "$1"; }

# set_org switches the peer CLI to act as one organisation's admin.
#
# Note which identity this is: the org's *Admin user*, not its peer. Chaincode
# authorisation reads the MSP of whoever signed the proposal, so acting as the
# distributor's admin is what makes requireMSP see DistributorMSP — regardless of
# which peers end up endorsing.
set_org() {
  local org="$1"
  if [[ -z "${MSP_ID[$org]:-}" ]]; then
    err "unknown organisation: ${org}"
    exit 1
  fi
  export CORE_PEER_LOCALMSPID="${MSP_ID[$org]}"
  export CORE_PEER_MSPCONFIGPATH="${ORG_DIR}/peerOrganizations/${org}.truemed.in/users/Admin@${org}.truemed.in/msp"
  export CORE_PEER_TLS_ROOTCERT_FILE="$(peer_tls_ca "${org}")"
  export CORE_PEER_ADDRESS="$(peer_address "${org}")"

  if [[ ! -d "${CORE_PEER_MSPCONFIGPATH}" ]]; then
    err "admin MSP for ${org} not found at ${CORE_PEER_MSPCONFIGPATH}"
    err "Run ./scripts/generate.sh on the host."
    exit 1
  fi
}

# all_peer_args builds the --peerAddresses / --tlsRootCertFiles pairs for every
# organisation.
#
# The channel's endorsement policy is MAJORITY, so two organisations would be
# enough. All three are targeted deliberately: three independent executions of the
# same transaction must produce byte-identical write sets, and any determinism bug
# in the chaincode — a wall-clock read, a map iteration, a rich query in a write
# path — shows up here as a commit failure rather than in production.
all_peer_args() {
  local args=() org
  for org in "${ORGS[@]}"; do
    args+=(--peerAddresses "$(peer_address "${org}")" --tlsRootCertFiles "$(peer_tls_ca "${org}")")
  done
  printf '%s\n' "${args[@]}"
}

# retry runs a command up to n times with a pause, printing nothing until it
# either succeeds or gives up. Fabric nodes accept TCP connections slightly before
# they are ready to serve, so the first attempt at almost anything can fail with a
# message that has nothing to do with the real cause.
retry() {
  local attempts="$1"; shift
  local delay="$1"; shift
  local n=1 output rc
  while true; do
    set +e
    output="$("$@" 2>&1)"
    rc=$?
    set -e
    if [[ ${rc} -eq 0 ]]; then
      [[ -n "${output}" ]] && printf '%s\n' "${output}" | sed 's/^/    /'
      return 0
    fi
    if (( n >= attempts )); then
      err "command failed after ${n} attempt(s): $*"
      printf '%s\n' "${output}" | sed 's/^/    /' >&2
      return "${rc}"
    fi
    n=$(( n + 1 ))
    sleep "${delay}"
  done
}

# json_arg escapes a JSON document so it can be embedded as a single string
# element inside the -c argument of peer chaincode invoke.
#
# Fabric takes chaincode arguments as an array of strings, and CreateMedicine's
# argument is itself a JSON object, so the quotes have to survive one level of
# nesting. Doing this with sed and backslashes by hand is where every hand-written
# Fabric demo script goes wrong.
json_arg() {
  local raw="$1"
  printf '%s' "${raw//\"/\\\"}"
}
