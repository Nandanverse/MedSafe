#!/usr/bin/env bash
#
# Create the channel and join all three peers. Runs inside truemed-cli.
#
# Two distinct steps that are easy to conflate:
#
#   1. osnadmin channel join  — tells the ORDERER to start a channel from the
#      genesis block. This is the Fabric 2.3+ channel participation API; there is
#      no system channel any more, and no "peer channel create".
#   2. peer channel join      — tells each PEER to fetch and replay that channel.
#
# Both are idempotent here: re-running reports the existing state rather than
# failing, so the script is safe to run again after a partial failure.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

GENESIS_BLOCK="${ARTIFACTS}/${CHANNEL_NAME}.block"

if [[ ! -s "${GENESIS_BLOCK}" ]]; then
  err "genesis block not found at ${GENESIS_BLOCK}"
  err "Run ./scripts/generate.sh on the host."
  exit 1
fi

# ── 1. Orderer ───────────────────────────────────────────────────────────────

step "Asking the orderer to join channel '${CHANNEL_NAME}'"

existing="$(osnadmin channel list \
  -o "${ORDERER_HOST}:${ORDERER_ADMIN_PORT}" \
  --ca-file "${ORDERER_CA}" \
  --client-cert "${ORDERER_TLS_CERT}" \
  --client-key "${ORDERER_TLS_KEY}" 2>/dev/null || true)"

if grep -q "\"${CHANNEL_NAME}\"" <<< "${existing}"; then
  ok "orderer is already on '${CHANNEL_NAME}'"
else
  retry 10 3 osnadmin channel join \
    --channelID "${CHANNEL_NAME}" \
    --config-block "${GENESIS_BLOCK}" \
    -o "${ORDERER_HOST}:${ORDERER_ADMIN_PORT}" \
    --ca-file "${ORDERER_CA}" \
    --client-cert "${ORDERER_TLS_CERT}" \
    --client-key "${ORDERER_TLS_KEY}"
  ok "orderer joined '${CHANNEL_NAME}'"
fi

# ── 2. Peers ─────────────────────────────────────────────────────────────────

step "Joining peers"

for org in "${ORGS[@]}"; do
  set_org "${org}"

  if peer channel getinfo -c "${CHANNEL_NAME}" >/dev/null 2>&1; then
    ok "peer0.${org} is already on the channel"
    continue
  fi

  # The peer needs a few seconds after the orderer starts serving the channel
  # before it can fetch block 0.
  if retry 15 4 peer channel join -b "${GENESIS_BLOCK}" >/dev/null; then
    ok "peer0.${org} joined"
  else
    err "peer0.${org} could not join the channel."
    err "Check: docker logs peer0.${org}.truemed.in --tail 50"
    exit 1
  fi
done

# ── 3. Verify ────────────────────────────────────────────────────────────────
#
# Not decoration. A peer can report a successful join and then sit at height 0
# because it cannot reach the orderer for subsequent blocks, and the next thing to
# fail would be chaincode approval with an unrelated-looking error.

step "Channel state"

for org in "${ORGS[@]}"; do
  set_org "${org}"
  info="$(peer channel getinfo -c "${CHANNEL_NAME}" 2>&1 || true)"
  height="$(sed -n 's/.*"height":\([0-9]*\).*/\1/p' <<< "${info}")"
  if [[ -z "${height}" ]]; then
    err "peer0.${org}: could not read channel height"
    printf '%s\n' "${info}" | sed 's/^/    /' >&2
    exit 1
  fi
  if (( height < 1 )); then
    err "peer0.${org}: channel height is ${height}; the peer has no blocks"
    exit 1
  fi
  ok "peer0.${org}: height ${height}"
done

step "Anchor peers"
# Anchor peers were declared in configtx.yaml, so they are already in the genesis
# block. Nothing to update — which is the point of doing it that way.
ok "set from the genesis block (no channel update needed)"

printf '\n%sChannel %s is ready.%s\n\n' "${C_GREEN}" "${CHANNEL_NAME}" "${C_RESET}"
