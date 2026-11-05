#!/usr/bin/env bash
#
# End-to-end smoke test. Runs inside truemed-cli.
#
# This is not a unit test — the business rules already have those, and they run in
# a second without Docker. This exercises the parts that only break when real
# peers, real identities and real endorsement are involved: MSP authorisation,
# determinism across three independent executions, event emission, composite-key
# iteration, and the CouchDB rich queries.
#
# It is also the demo script. Every verdict a patient can see is produced here from
# a real transaction, in order, with the ledger doing the deciding.
#
# Exits non-zero if any assertion fails, so it can gate a deployment.

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# env.sh sets -e for the deployment scripts, where any failure is fatal. Here it
# must be off: half of these checks assert that a transaction is REJECTED, and
# with -e the first successful rejection would kill the test run.
set +e
set -uo pipefail

PASS=0
FAIL=0

check() {
  local label="$1" haystack="$2" needle="$3"
  if grep -qF -- "${needle}" <<< "${haystack}"; then
    ok "${label}"
    PASS=$(( PASS + 1 ))
  else
    err "${label}"
    printf '       expected to find: %s\n' "${needle}" >&2
    printf '       actual output:\n' >&2
    printf '%s\n' "${haystack}" | head -20 | sed 's/^/         /' >&2
    FAIL=$(( FAIL + 1 ))
  fi
}

check_absent() {
  local label="$1" haystack="$2" needle="$3"
  if grep -qF -- "${needle}" <<< "${haystack}"; then
    err "${label}"
    printf '       did not expect to find: %s\n' "${needle}" >&2
    FAIL=$(( FAIL + 1 ))
  else
    ok "${label}"
    PASS=$(( PASS + 1 ))
  fi
}

# Exact equality, for cases where a substring match would pass by accident —
# grep -F "4" happily matches "4.5", which would let a broken sort order through.
check_eq() {
  local label="$1" actual="$2" expected="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    ok "${label}"
    PASS=$(( PASS + 1 ))
  else
    err "${label}"
    printf '       expected exactly: %s\n       got:              %s\n' "${expected}" "${actual}" >&2
    FAIL=$(( FAIL + 1 ))
  fi
}

# cc_invoke <org> <function> [args...]
cc_invoke() {
  local org="$1"; shift
  local fn="$1"; shift
  set_org "${org}"

  local args_json="[" first=1 a
  for a in "$@"; do
    (( first )) || args_json+=","
    args_json+="\"$(json_arg "${a}")\""
    first=0
  done
  args_json+="]"

  mapfile -t PEER_ARGS < <(all_peer_args)
  peer chaincode invoke \
    -o "${ORDERER_HOST}:${ORDERER_PORT}" \
    --ordererTLSHostnameOverride "${ORDERER_HOST}" \
    --tls --cafile "${ORDERER_CA}" \
    -C "${CHANNEL_NAME}" -n "${CHAINCODE_NAME}" \
    "${PEER_ARGS[@]}" \
    --waitForEvent \
    -c "{\"function\":\"${fn}\",\"Args\":${args_json}}" 2>&1
}

# cc_query <org> <function> [args...]
cc_query() {
  local org="$1"; shift
  local fn="$1"; shift
  set_org "${org}"

  local args_json="[" first=1 a
  for a in "$@"; do
    (( first )) || args_json+=","
    args_json+="\"$(json_arg "${a}")\""
    first=0
  done
  args_json+="]"

  peer chaincode query \
    -C "${CHANNEL_NAME}" -n "${CHAINCODE_NAME}" \
    -c "{\"function\":\"${fn}\",\"Args\":${args_json}}" 2>&1
}

# ── Fixtures ─────────────────────────────────────────────────────────────────
#
# Dates are computed relative to today so the test keeps working next year. A
# fixture with a hardcoded 2027 expiry passes until it silently starts testing the
# expiry path instead of the happy path.

MFG_DATE="$(date -u -d '-6 months' +%F)"
EXP_FUTURE="$(date -u -d '+18 months' +%F)"
MFG_OLD="$(date -u -d '-30 months' +%F)"
EXP_PAST="$(date -u -d '-10 days' +%F)"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EARLIER="$(date -u -d '-2 hours' +%Y-%m-%dT%H:%M:%SZ)"

VACCINE_ID="MEASLESRUBELLA_SURAKSHAMR_2026_000101"
VACCINE_BATCH="MR26A0117"
MEDICINE_ID="PARACETAMOL500MG_PARALIEF500_2026_000001"
MEDICINE_BATCH="PL26C0417"
EXPIRED_ID="AMOXICILLIN500MG_AMOXIGEN_2026_000777"
EXPIRED_BATCH="AG24B0009"
GHOST_ID="FENTANYL100MCG_GHOSTBRAND_2026_999999"

vaccine_json() {
  cat <<EOF
{"product_id":"${VACCINE_ID}","generic_name":"Measles-Rubella Vaccine","brand_name":"SurakshaMR","manufacturer":"Sanjeevani Biologicals, Pune","mfg_licence_no":"MH/BIO/2019/0442","batch_no":"${VACCINE_BATCH}","mfg_date":"${MFG_DATE}","expiry_date":"${EXP_FUTURE}","quantity":"5 doses (2.5 ml)","excipients":["Sorbitol","Hydrolysed gelatin"],"type":"vaccine","location":"FACTORY_PUNE_01"}
EOF
}

medicine_json() {
  cat <<EOF
{"product_id":"${MEDICINE_ID}","generic_name":"Paracetamol 500 mg","brand_name":"Paralief 500","manufacturer":"Vaidya Pharmaceuticals, Ahmedabad","mfg_licence_no":"GJ/DRUG/2016/1187","batch_no":"${MEDICINE_BATCH}","mfg_date":"${MFG_DATE}","expiry_date":"${EXP_FUTURE}","quantity":"10 tablets","excipients":["Maize starch","Povidone K30","Magnesium stearate"],"type":"medicine","location":"FACTORY_AHM_02"}
EOF
}

expired_json() {
  cat <<EOF
{"product_id":"${EXPIRED_ID}","generic_name":"Amoxicillin 500 mg","brand_name":"Amoxigen","manufacturer":"Vaidya Pharmaceuticals, Ahmedabad","mfg_licence_no":"GJ/DRUG/2016/1187","batch_no":"${EXPIRED_BATCH}","mfg_date":"${MFG_OLD}","expiry_date":"${EXP_PAST}","quantity":"10 capsules","excipients":["Magnesium stearate"],"type":"medicine","location":"FACTORY_AHM_02"}
EOF
}

printf '\n%s TrueMed smoke test %s\n' "${C_BOLD}" "${C_RESET}"
printf '  channel   %s\n  chaincode %s v%s\n  ledger    3 orgs, MAJORITY endorsement\n' \
  "${CHANNEL_NAME}" "${CHAINCODE_NAME}" "${CHAINCODE_VERSION}"

# ── 1. Minting ───────────────────────────────────────────────────────────────

step "1. Manufacturer registers stock"

out="$(cc_invoke manufacturer CreateMedicine "$(vaccine_json)")"
check "vaccine minted" "${out}" "status:200"

out="$(cc_invoke manufacturer CreateMedicine "$(medicine_json)")"
check "tablet strip minted" "${out}" "status:200"

out="$(cc_invoke manufacturer CreateMedicine "$(expired_json)")"
check "already-expired stock accepted (onboarding existing inventory)" "${out}" "status:200"

out="$(cc_invoke manufacturer CreateMedicine "$(vaccine_json)")"
check "duplicate product ID refused" "${out}" "is already registered"

out="$(cc_invoke manufacturer CreateMedicine '{"product_id":"BAD_ID","generic_name":"x"}')"
check "malformed payload refused" "${out}" "product_id"

# ── 2. Access control ────────────────────────────────────────────────────────
#
# The single most important property of the ledger: only the manufacturer can
# create the claim "this unit is genuine", and only the regulator can recall.

step "2. MSP authorisation"

out="$(cc_invoke distributor CreateMedicine "$(medicine_json)")"
check "distributor cannot mint" "${out}" "DistributorMSP is not authorised to call CreateMedicine"

out="$(cc_invoke manufacturer RecallBatch "{\"batch_no\":\"${VACCINE_BATCH}\",\"reason\":\"unauthorised attempt\"}")"
check "manufacturer cannot recall" "${out}" "ManufacturerMSP is not authorised to call RecallBatch"

out="$(cc_invoke regulator UpdateLocation "{\"product_id\":\"${MEDICINE_ID}\",\"location\":\"WH_MUM_001\",\"status\":\"in_transit\"}")"
check "regulator cannot move stock" "${out}" "RegulatorMSP is not authorised to call UpdateLocation"

# ── 3. Verification of clean stock ───────────────────────────────────────────

step "3. Clean stock verifies as genuine"

out="$(cc_query regulator VerifyMedicine "${MEDICINE_ID}")"
check "verdict GENUINE" "${out}" '"verdict":"GENUINE"'
check "severity ok" "${out}" '"severity":"ok"'
check "brand name returned" "${out}" 'Paralief 500'
check "cold chain not applicable to a tablet" "${out}" '"applicable":false'

out="$(cc_query regulator VerifyMedicine "${EXPIRED_ID}")"
check "expired stock verdict EXPIRED" "${out}" '"verdict":"EXPIRED"'
check "expired stock severity warn" "${out}" '"severity":"warn"'

out="$(cc_query regulator VerifyMedicine "${GHOST_ID}")"
check "unregistered ID is NOT_ON_CHAIN" "${out}" '"verdict":"NOT_ON_CHAIN"'
check_absent "unregistered ID is not called COUNTERFEIT on chain" "${out}" 'COUNTERFEIT'

out="$(cc_query regulator MedicineExists "${GHOST_ID}")"
check "MedicineExists false for a ghost" "${out}" "false"

# ── 4. Custody ───────────────────────────────────────────────────────────────

step "4. Custody moves forward only"

out="$(cc_invoke distributor UpdateLocation "{\"product_id\":\"${VACCINE_ID}\",\"location\":\"WH_PUNE_COLD_01\",\"status\":\"in_transit\"}")"
check "factory to warehouse" "${out}" "status:200"

out="$(cc_invoke distributor UpdateLocation "{\"product_id\":\"${VACCINE_ID}\",\"location\":\"WH_MUM_COLD_03\",\"status\":\"in_transit\"}")"
check "warehouse to warehouse (in_transit may repeat)" "${out}" "status:200"

out="$(cc_invoke distributor UpdateLocation "{\"product_id\":\"${VACCINE_ID}\",\"location\":\"PHC_THANE_0042\",\"status\":\"at_pharmacy\"}")"
check "arrival at the health centre" "${out}" "status:200"

out="$(cc_invoke distributor UpdateLocation "{\"product_id\":\"${VACCINE_ID}\",\"location\":\"WH_MUM_COLD_03\",\"status\":\"in_transit\"}")"
check "backward hop refused" "${out}" "refusing to move this unit backwards"

out="$(cc_invoke distributor UpdateLocation "{\"product_id\":\"${VACCINE_ID}\",\"location\":\"PHC_THANE_0042\",\"status\":\"recalled\"}")"
check "recall via UpdateLocation refused" "${out}" "use RecallBatch"

# ── 5. Cold chain ────────────────────────────────────────────────────────────

step "5. Cold chain"

out="$(cc_invoke distributor AddTemperatureReading "{\"product_id\":\"${VACCINE_ID}\",\"temperature\":4.5,\"location\":\"WH_MUM_COLD_03\",\"sensor_id\":\"ESP32-TM-0001\",\"recorded_at\":\"${EARLIER}\"}")"
check "compliant reading accepted" "${out}" "status:200"

out="$(cc_query regulator VerifyMedicine "${VACCINE_ID}")"
check "still genuine at 4.5C" "${out}" '"verdict":"GENUINE"'

out="$(cc_invoke distributor AddTemperatureReading "{\"product_id\":\"${VACCINE_ID}\",\"temperature\":8.0,\"location\":\"WH_MUM_COLD_03\",\"sensor_id\":\"ESP32-TM-0001\",\"recorded_at\":\"${NOW}\"}")"
check "8.0C is inside the range (inclusive bound)" "${out}" "status:200"

out="$(cc_query regulator VerifyMedicine "${VACCINE_ID}")"
check "8.0C did not trip a breach" "${out}" '"verdict":"GENUINE"'

out="$(cc_invoke distributor AddTemperatureReading "{\"product_id\":\"${VACCINE_ID}\",\"temperature\":15.2,\"location\":\"PHC_THANE_0042\",\"sensor_id\":\"ESP32-TM-0001\",\"recorded_at\":\"${NOW}\"}")"
check "excursion recorded" "${out}" "status:200"

out="$(cc_query regulator VerifyMedicine "${VACCINE_ID}")"
check "verdict COLD_CHAIN_BREACH" "${out}" '"verdict":"COLD_CHAIN_BREACH"'
check "severity critical" "${out}" '"severity":"critical"'
check "breach flag set" "${out}" '"breached":true'
check "max temperature aggregated" "${out}" '"max_c":15.2'

out="$(cc_invoke distributor AddTemperatureReading "{\"product_id\":\"${VACCINE_ID}\",\"temperature\":4.0,\"location\":\"PHC_THANE_0042\",\"sensor_id\":\"ESP32-TM-0001\",\"recorded_at\":\"${NOW}\"}")"
check "recovery reading accepted" "${out}" "status:200"

out="$(cc_query regulator VerifyMedicine "${VACCINE_ID}")"
check "breach is permanent after recovery" "${out}" '"verdict":"COLD_CHAIN_BREACH"'

out="$(cc_invoke distributor AddTemperatureReading "{\"product_id\":\"${VACCINE_ID}\",\"temperature\":-127,\"location\":\"PHC_THANE_0042\",\"sensor_id\":\"ESP32-TM-0001\",\"recorded_at\":\"${NOW}\"}")"
check "disconnected sensor rejected, not logged as a breach" "${out}" "sensor or wiring fault"

out="$(cc_invoke distributor AddTemperatureReading "{\"product_id\":\"${VACCINE_ID}\",\"temperature\":4.0,\"location\":\"PHC_THANE_0042\",\"sensor_id\":\"ESP32-TM-0001\",\"recorded_at\":\"2019-01-01T00:00:00Z\"}")"
check "ancient backfill rejected" "${out}" "refusing to backfill"

out="$(cc_invoke distributor AddTemperatureReading "{\"product_id\":\"${MEDICINE_ID}\",\"temperature\":31.0,\"location\":\"WH_MUM_001\",\"sensor_id\":\"ESP32-TM-0002\",\"recorded_at\":\"${NOW}\"}")"
check "tablet at 31C logged without a breach" "${out}" "status:200"

out="$(cc_query regulator VerifyMedicine "${MEDICINE_ID}")"
check "tablet still genuine at 31C" "${out}" '"verdict":"GENUINE"'

step "5b. Temperature history is newest-first"
out="$(cc_query regulator GetTemperatureHistory "${VACCINE_ID}" "3")"
check "history returned" "${out}" '"temperature"'
# The most recent reading is 4.0 at the health centre; if the descending key
# encoding is wrong, the first element would be the 4.5 from the warehouse.
# Go marshals 4.0 as "4", not "4.0".
first_temp="$(sed -n 's/^\[{[^}]*"temperature":\([-0-9.]*\).*/\1/p' <<< "${out}")"
check_eq "newest reading returned first" "${first_temp}" "4"

# ── 6. Clone detection ───────────────────────────────────────────────────────

step "6. Patient scans and clone detection"

out="$(cc_invoke regulator RecordPatientScan "{\"product_id\":\"${MEDICINE_ID}\",\"district\":\"Thane\"}")"
check "scan recorded" "${out}" "status:200"

for district in Pune Nagpur Nashik Kolhapur; do
  out="$(cc_invoke regulator RecordPatientScan "{\"product_id\":\"${MEDICINE_ID}\",\"district\":\"${district}\"}")"
done
check "fifth district recorded" "${out}" "status:200"

out="$(cc_query regulator VerifyMedicine "${MEDICINE_ID}")"
check "five districts trips CLONE_SUSPECTED" "${out}" '"verdict":"CLONE_SUSPECTED"'
check "clone severity critical" "${out}" '"severity":"critical"'
check "district count reported" "${out}" '"distinct_districts":5'

out="$(cc_invoke regulator RecordPatientScan "{\"product_id\":\"${MEDICINE_ID}\",\"district\":\"\"}")"
check "scan without a district accepted (DPDP data minimisation)" "${out}" "status:200"

# ── 7. Recall ────────────────────────────────────────────────────────────────

step "7. Regulator recall"

out="$(cc_invoke regulator RecallBatch "{\"batch_no\":\"${VACCINE_BATCH}\",\"reason\":\"Potency assay failure at CDL Kasauli\"}")"
check "batch recalled" "${out}" "status:200"

out="$(cc_query regulator VerifyMedicine "${VACCINE_ID}")"
check "recall outranks cold-chain breach" "${out}" '"verdict":"RECALLED"'
check "recall reason surfaced to the patient" "${out}" 'Potency assay failure at CDL Kasauli'

out="$(cc_invoke distributor UpdateLocation "{\"product_id\":\"${VACCINE_ID}\",\"location\":\"PHC_THANE_0042\",\"status\":\"dispensed\"}")"
check "recalled stock cannot be dispensed" "${out}" "final state"

out="$(cc_invoke regulator RecallBatch "{\"batch_no\":\"NOSUCHBATCH\",\"reason\":\"typo in the batch number\"}")"
check "recall of an unknown batch refused" "${out}" "no units are registered under batch"

# ── 8. Rich queries ──────────────────────────────────────────────────────────
#
# These need CouchDB. If the peers were started with LevelDB they fail here, with
# an error naming the state database rather than something cryptic.

step "8. CouchDB rich queries"

out="$(cc_query regulator GetMedicinesByStatus "recalled" "10" "")"
check "recalled units listed" "${out}" "${VACCINE_ID}"

out="$(cc_query regulator GetBreachedVaccines "10" "")"
check "breached vaccines listed" "${out}" "${VACCINE_ID}"

out="$(cc_query regulator GetMedicinesByStatus "sold" "10" "")"
check "invalid status refused" "${out}" "is not one of"

out="$(cc_query regulator GetMedicinesByBatch "${MEDICINE_BATCH}")"
check "batch index resolves (no rich query involved)" "${out}" "${MEDICINE_ID}"

# ── Result ───────────────────────────────────────────────────────────────────

printf '\n%s─────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
if (( FAIL == 0 )); then
  printf '%s  %d checks passed, 0 failed%s\n\n' "${C_GREEN}" "${PASS}" "${C_RESET}"
  exit 0
else
  printf '%s  %d passed, %d FAILED%s\n\n' "${C_RED}" "${PASS}" "${FAIL}" "${C_RESET}"
  printf 'Useful next steps:\n'
  printf '  docker logs peer0.manufacturer.truemed.in --tail 60\n'
  printf '  docker logs orderer.truemed.in --tail 40\n'
  printf '  ./scripts/network.sh down && ./scripts/network.sh up && ./scripts/network.sh deploy\n\n'
  exit 1
fi
