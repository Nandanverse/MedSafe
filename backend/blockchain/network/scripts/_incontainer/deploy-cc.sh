#!/usr/bin/env bash
#
# Package, install, approve and commit the TrueMed chaincode. Runs inside
# truemed-cli.
#
# Fabric 2.x chaincode lifecycle in four steps:
#
#   package   → a tar.gz plus a package ID (label + hash of the contents)
#   install   → on each peer, individually
#   approve   → by each organisation, individually, for a given sequence number
#   commit    → once, when enough organisations have approved
#
# The sequence number is the part that trips people up. It is not the version
# string; it is a monotonically increasing counter for the channel's chaincode
# definition. Changing the code means a new sequence, even if the version stays
# the same, and committing sequence 1 twice fails with a message about the
# definition already existing.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

if [[ ! -d "${CC_DIR}/vendor" ]]; then
  err "${CC_DIR}/vendor is missing."
  cat >&2 <<'EOF'

The peer builds Go chaincode inside a container that has no network access, so
the modules must be vendored on disk first. Run this on the host:

    ./scripts/network.sh deploy

which vendors the dependencies before calling this script.

EOF
  exit 1
fi

# ── 1. Package ───────────────────────────────────────────────────────────────

step "Packaging ${CC_LABEL}"

peer lifecycle chaincode package "${CC_PACKAGE}" \
  --path "${CC_DIR}" \
  --lang golang \
  --label "${CC_LABEL}"

PACKAGE_ID="$(peer lifecycle chaincode calculatepackageid "${CC_PACKAGE}")"
if [[ -z "${PACKAGE_ID}" ]]; then
  err "could not compute the package ID"
  exit 1
fi
ok "package ID ${PACKAGE_ID}"

# ── 2. Install ───────────────────────────────────────────────────────────────
#
# This is the slow step on first run: the peer compiles the Go chaincode inside a
# build container. On a free-tier VM expect two to four minutes per peer. There is
# no progress output — the command simply sits there.

step "Installing on each peer (first run compiles Go; this takes a few minutes)"

for org in "${ORGS[@]}"; do
  set_org "${org}"

  if peer lifecycle chaincode queryinstalled 2>/dev/null | grep -q "${PACKAGE_ID}"; then
    ok "peer0.${org}: already installed"
    continue
  fi

  printf '     installing on peer0.%s ... ' "${org}"
  if peer lifecycle chaincode install "${CC_PACKAGE}" >/tmp/install.log 2>&1; then
    printf '%sdone%s\n' "${C_GREEN}" "${C_RESET}"
  else
    # An install that races another one reports "already successfully installed".
    if grep -q "already successfully installed" /tmp/install.log; then
      printf '%salready present%s\n' "${C_GREEN}" "${C_RESET}"
    else
      printf '%sfailed%s\n' "${C_RED}" "${C_RESET}"
      sed 's/^/    /' /tmp/install.log >&2
      exit 1
    fi
  fi
done

# ── 3. Approve ───────────────────────────────────────────────────────────────
#
# Each organisation approves for itself. The endorsement policy is left
# unspecified, so the chaincode inherits the channel default — MAJORITY of
# organisations — set in configtx.yaml.

step "Approving for each organisation (sequence ${CHAINCODE_SEQUENCE})"

for org in "${ORGS[@]}"; do
  set_org "${org}"

  # checkcommitreadiness reports each org's approval for this exact definition.
  # Re-approving is harmless but slow, so it is skipped when already true.
  approved="$(peer lifecycle chaincode checkcommitreadiness \
    --channelID "${CHANNEL_NAME}" \
    --name "${CHAINCODE_NAME}" \
    --version "${CHAINCODE_VERSION}" \
    --sequence "${CHAINCODE_SEQUENCE}" \
    --output json 2>/dev/null | sed -n "s/.*\"${MSP_ID[$org]}\": *\\(true\\|false\\).*/\\1/p")"

  if [[ "${approved}" == "true" ]]; then
    ok "${MSP_ID[$org]}: already approved"
    continue
  fi

  retry 5 5 peer lifecycle chaincode approveformyorg \
    -o "${ORDERER_HOST}:${ORDERER_PORT}" \
    --ordererTLSHostnameOverride "${ORDERER_HOST}" \
    --tls --cafile "${ORDERER_CA}" \
    --channelID "${CHANNEL_NAME}" \
    --name "${CHAINCODE_NAME}" \
    --version "${CHAINCODE_VERSION}" \
    --package-id "${PACKAGE_ID}" \
    --sequence "${CHAINCODE_SEQUENCE}" >/dev/null
  ok "${MSP_ID[$org]}: approved"
done

step "Commit readiness"
peer lifecycle chaincode checkcommitreadiness \
  --channelID "${CHANNEL_NAME}" \
  --name "${CHAINCODE_NAME}" \
  --version "${CHAINCODE_VERSION}" \
  --sequence "${CHAINCODE_SEQUENCE}" \
  --output json | sed 's/^/    /'

# ── 4. Commit ────────────────────────────────────────────────────────────────

step "Committing the definition to the channel"

set_org manufacturer

if peer lifecycle chaincode querycommitted \
     --channelID "${CHANNEL_NAME}" --name "${CHAINCODE_NAME}" 2>/dev/null \
     | grep -q "Sequence: ${CHAINCODE_SEQUENCE},"; then
  ok "sequence ${CHAINCODE_SEQUENCE} is already committed"
else
  mapfile -t PEER_ARGS < <(all_peer_args)
  retry 5 5 peer lifecycle chaincode commit \
    -o "${ORDERER_HOST}:${ORDERER_PORT}" \
    --ordererTLSHostnameOverride "${ORDERER_HOST}" \
    --tls --cafile "${ORDERER_CA}" \
    --channelID "${CHANNEL_NAME}" \
    --name "${CHAINCODE_NAME}" \
    --version "${CHAINCODE_VERSION}" \
    --sequence "${CHAINCODE_SEQUENCE}" \
    "${PEER_ARGS[@]}" >/dev/null
  ok "committed"
fi

step "Committed definition"
peer lifecycle chaincode querycommitted \
  --channelID "${CHANNEL_NAME}" \
  --name "${CHAINCODE_NAME}" | sed 's/^/    /'

printf '\n%sChaincode %s v%s (sequence %s) is live on %s.%s\n\n' \
  "${C_GREEN}" "${CHAINCODE_NAME}" "${CHAINCODE_VERSION}" "${CHAINCODE_SEQUENCE}" "${CHANNEL_NAME}" "${C_RESET}"
