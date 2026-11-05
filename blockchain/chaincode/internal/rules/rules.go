// Package rules holds TrueMed's on-chain business rules as pure functions.
//
// Nothing in this package imports Hyperledger Fabric. That is deliberate: the
// state machine, the cold-chain rule, the expiry arithmetic and the clone
// heuristic are the parts most likely to be wrong, and keeping them free of the
// chaincode stub means they can be unit-tested with nothing but `go test` — no
// peer, no Docker, no network. The Fabric-facing code in the parent package
// stays thin enough to review by eye.
//
// These rules are the Go mirror of docs/DATA-CONTRACT.md §3 and of the Python
// reference implementation in qr-generator/truemed_qr/verifier.py. Where the
// three could drift, this file and the Python module must be changed together;
// the contract document is the arbiter.
package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ── Enumerations ─────────────────────────────────────────────────────────────

// Custody statuses. See DATA-CONTRACT.md §3.1.
const (
	StatusManufactured = "manufactured"
	StatusInTransit    = "in_transit"
	StatusAtPharmacy   = "at_pharmacy"
	StatusDispensed    = "dispensed"
	StatusRecalled     = "recalled"
)

// Product types.
const (
	TypeMedicine = "medicine"
	TypeVaccine  = "vaccine"
)

// Verdicts returned by an on-chain verification. This is a subset of the app's
// verdict set: the chaincode cannot see the QR signature, so it never returns
// COUNTERFEIT for a bad signature — only the app or the API can, and it does so
// by folding this snapshot into its own result. See verifier.py.
const (
	VerdictGenuine   = "GENUINE"
	VerdictExpired   = "EXPIRED"
	VerdictColdChain = "COLD_CHAIN_BREACH"
	VerdictClone     = "CLONE_SUSPECTED"
	VerdictRecalled  = "RECALLED"
	VerdictNotFound  = "NOT_ON_CHAIN"
)

// Severities. Only GENUINE is "ok"; everything else asks a human to stop.
const (
	SeverityOK       = "ok"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
)

// VaccineTempMinC and VaccineTempMaxC bound the WHO cold chain for routine
// vaccines. The range is inclusive: exactly 2.0 °C and exactly 8.0 °C are both
// compliant. See DATA-CONTRACT.md §3.3.
const (
	VaccineTempMinC = 2.0
	VaccineTempMaxC = 8.0
)

// SensorTempMinC and SensorTempMaxC are the DS18B20's rated measurement range.
// A reading outside it is a hardware or wiring fault, not a cold-chain event —
// a disconnected one-wire bus commonly reads -127 °C or +85 °C. Recording those
// as breaches would bury real excursions under sensor noise, so they are
// rejected at the door instead.
const (
	SensorTempMinC = -55.0
	SensorTempMaxC = 125.0
)

// CloneScanThreshold and CloneDistrictThreshold mirror verifier.py exactly. A
// single sellable strip is legitimately scanned a handful of times — patient,
// pharmacist, a curious relative — not dozens, and it cannot be in four
// districts at once.
const (
	CloneScanThreshold     = 25
	CloneDistrictThreshold = 3
)

// MaxEmbeddedReadings caps the temperature window carried inline on the medicine
// record.
//
// This cap is a correctness requirement, not tidiness. A vaccine vial sampled
// every five minutes produces ~105,000 readings a year. Appending each one to a
// slice inside the record means every write reads and rewrites the whole
// history, so the ledger cost of reading n is O(n) and of a batch of n writes is
// O(n²) — the state database, the gossip payload and the block size all grow
// without bound, and throughput collapses long before the target load. The full
// series lives in one ledger key per reading; the record keeps only the most
// recent window for display plus min/max/count aggregates.
const MaxEmbeddedReadings = 48

// ── Field limits ─────────────────────────────────────────────────────────────
//
// Mirrors qr-generator/truemed_qr/payload.py. Two independent reasons to keep
// them: an over-long field means someone is fuzzing or a form is broken, and
// unbounded strings on a replicated ledger are a denial-of-service vector that
// cannot be undone once committed.

const (
	MaxProductID    = 80
	MaxGenericName  = 64
	MaxBrandName    = 48
	MaxManufacturer = 120
	MaxLicenceNo    = 32
	MaxBatchNo      = 24
	MaxQuantity     = 32
	MaxExcipient    = 40
	MaxExcipients   = 12
	MaxLocation     = 32
	MaxSensorID     = 32
	MaxDistrict     = 48
	MaxReason       = 200
)

// MaxDistinctDistricts bounds the district list kept for clone detection. Once
// the count is past CloneDistrictThreshold the verdict is already CLONE_SUSPECTED
// and further districts change nothing, so there is no reason to let the list
// grow to the ~800 districts of India.
const MaxDistinctDistricts = 32

// productIDPattern is the four-segment form GENERIC_BRAND_YEAR_SERIAL, matching
// make_product_id() in payload.py. Anchored at both ends so a value with a
// trailing newline or an appended field is rejected rather than partially
// matched.
var productIDPattern = regexp.MustCompile(`^[A-Z0-9]{1,40}_[A-Z0-9]{1,24}_(?:19|20)[0-9]{2}_[0-9]{6}$`)

// batchNoPattern allows the alphanumeric-with-separators forms Indian
// manufacturers actually print, e.g. "SP26C0417", "AB-1234/26".
var batchNoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./-]{0,23}$`)

// ── Field validation ─────────────────────────────────────────────────────────

// ValidateText checks a required free-text field.
//
// Control characters are rejected everywhere. No real brand name, excipient or
// facility code contains a newline or a NUL, and allowing them is how log
// injection and display spoofing begin — a value ending in "\n[OK] GENUINE"
// rendered into a log or a terminal is a forged line of output.
func ValidateText(field, value string, max int) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if len(trimmed) > max {
		return fmt.Errorf("%s is %d bytes, exceeding the %d-byte limit", field, len(trimmed), max)
	}
	for _, r := range trimmed {
		// Unicode category Cc plus DEL. Printable non-ASCII (Devanagari) passes,
		// which Phase 2 needs.
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character (U+%04X), which is not allowed in a ledger record", field, r)
		}
	}
	return nil
}

// ValidateProductID enforces the canonical product ID form.
func ValidateProductID(productID string) error {
	if productID == "" {
		return fmt.Errorf("product_id must not be empty")
	}
	if len(productID) > MaxProductID {
		return fmt.Errorf("product_id is %d bytes, exceeding the %d-byte limit", len(productID), MaxProductID)
	}
	if !productIDPattern.MatchString(productID) {
		return fmt.Errorf(
			"product_id %q does not match the required GENERIC_BRAND_YEAR_SERIAL form "+
				"(example: PARACETAMOL500MG_PARACIP500_2026_000001)", productID)
	}
	return nil
}

// ValidateBatchNo enforces the printable batch-number form.
func ValidateBatchNo(batchNo string) error {
	if err := ValidateText("batch_no", batchNo, MaxBatchNo); err != nil {
		return err
	}
	if !batchNoPattern.MatchString(strings.TrimSpace(batchNo)) {
		return fmt.Errorf(
			"batch_no %q may contain only letters, digits, dot, slash and hyphen, and "+
				"must start with a letter or digit", batchNo)
	}
	return nil
}

// ValidateType checks the product type.
func ValidateType(medType string) error {
	if medType != TypeMedicine && medType != TypeVaccine {
		return fmt.Errorf("type must be %q or %q, got %q", TypeMedicine, TypeVaccine, medType)
	}
	return nil
}

// ParseDate parses a strict YYYY-MM-DD date at UTC midnight.
//
// Strict on purpose: time.Parse with this layout rejects "2026-3-15" and
// "2026-02-30", and a date that is off by a month on a vaccine record is an
// expiry check that silently passes when it should fail.
func ParseDate(field, value string) (time.Time, error) {
	if len(value) != 10 {
		return time.Time{}, fmt.Errorf("%s must be exactly YYYY-MM-DD, got %q", field, value)
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s is not a valid YYYY-MM-DD date: %q", field, value)
	}
	return parsed.UTC(), nil
}

// ValidateDateOrder requires expiry strictly after manufacture. Equal dates are
// rejected: a product that expires the day it is made is a data-entry error, and
// treating it as valid would put an already-dead unit into circulation.
func ValidateDateOrder(mfgDate, expiryDate string) error {
	mfg, err := ParseDate("mfg_date", mfgDate)
	if err != nil {
		return err
	}
	exp, err := ParseDate("expiry_date", expiryDate)
	if err != nil {
		return err
	}
	if !exp.After(mfg) {
		return fmt.Errorf("expiry_date %s must be after mfg_date %s", expiryDate, mfgDate)
	}
	return nil
}

// ValidateExcipients checks the excipient list.
func ValidateExcipients(excipients []string) error {
	if len(excipients) > MaxExcipients {
		return fmt.Errorf("%d excipients is over the limit of %d", len(excipients), MaxExcipients)
	}
	for i, e := range excipients {
		if err := ValidateText(fmt.Sprintf("excipients[%d]", i), e, MaxExcipient); err != nil {
			return err
		}
	}
	return nil
}

// ── Custody state machine ────────────────────────────────────────────────────

// statusRank orders the forward custody path. Recalled sits above everything
// because it is reachable from any state and terminates the chain.
var statusRank = map[string]int{
	StatusManufactured: 0,
	StatusInTransit:    1,
	StatusAtPharmacy:   2,
	StatusDispensed:    3,
	StatusRecalled:     4,
}

// KnownStatus reports whether a status is part of the enum.
func KnownStatus(status string) bool {
	_, ok := statusRank[status]
	return ok
}

// IsTerminal reports whether a status admits no further transitions.
func IsTerminal(status string) bool {
	return status == StatusDispensed || status == StatusRecalled
}

// ValidateTransition checks a custody hop.
//
// Backward movement is refused because it is the signature of a counterfeit
// injection: stock that has been dispensed to a patient cannot re-enter a
// warehouse, and a system that accepts the rewrite loses the very audit trail it
// exists to provide. `in_transit` may repeat — factory to warehouse to
// distributor are separate hops with the same status, distinguished by location.
//
// Transitions to `recalled` are permitted from any non-terminal state; the
// caller is responsible for enforcing that only the regulator may request one.
func ValidateTransition(from, to string) error {
	fromRank, ok := statusRank[from]
	if !ok {
		return fmt.Errorf("stored status %q is not a known status; the record is corrupt", from)
	}
	toRank, ok := statusRank[to]
	if !ok {
		return fmt.Errorf(
			"status %q is not one of manufactured, in_transit, at_pharmacy, dispensed, recalled", to)
	}
	if IsTerminal(from) {
		return fmt.Errorf(
			"this unit is already %s, which is a final state — it cannot be moved to %s", from, to)
	}
	if to == StatusRecalled {
		return nil
	}
	if to == StatusManufactured {
		return fmt.Errorf("a unit cannot return to %s once it has left the factory", StatusManufactured)
	}
	if toRank < fromRank {
		return fmt.Errorf(
			"refusing to move this unit backwards from %s to %s; custody only moves forward, "+
				"and a backward hop is how counterfeit stock is laundered into a legitimate trail",
			from, to)
	}
	if toRank == fromRank && to != StatusInTransit {
		return fmt.Errorf(
			"this unit is already %s; only %s may repeat (one hop per leg of the journey)",
			from, StatusInTransit)
	}
	return nil
}

// ── Cold chain ───────────────────────────────────────────────────────────────

// ValidateTemperature rejects readings a DS18B20 cannot physically produce.
func ValidateTemperature(temperature float64) error {
	// NaN fails every comparison, so it must be caught by self-inequality rather
	// than by a range check. A JSON "NaN" reaching the ledger would make min/max
	// aggregates permanently useless.
	if temperature != temperature {
		return fmt.Errorf("temperature is NaN, which is not a measurement")
	}
	if temperature < SensorTempMinC || temperature > SensorTempMaxC {
		return fmt.Errorf(
			"temperature %.2f°C is outside the DS18B20's rated range of %.0f°C to %.0f°C, "+
				"so this is a sensor or wiring fault rather than a cold-chain event "+
				"(a disconnected one-wire bus typically reads -127°C or +85°C)",
			temperature, SensorTempMinC, SensorTempMaxC)
	}
	return nil
}

// BreachesColdChain reports whether a reading violates the cold chain for a
// product of the given type. Non-vaccines never breach: temperature is logged
// for them, because a warehouse fire is worth recording, but paracetamol does
// not lose potency at 20 °C.
func BreachesColdChain(medType string, temperature float64) bool {
	if medType != TypeVaccine {
		return false
	}
	return temperature < VaccineTempMinC || temperature > VaccineTempMaxC
}

// MaxRecordedAtSkew and MaxRecordedAtAge bound the sensor's own claimed
// timestamp against ledger time.
//
// A sensor that has been offline flushes its buffer on reconnect, so readings
// legitimately arrive hours or days late — hence a generous backward window. A
// reading claiming to be from the future is either a wrong clock or an attempt
// to plant an alibi ahead of an excursion, so only a little skew is tolerated.
const (
	MaxRecordedAtSkew = 15 * time.Minute
	MaxRecordedAtAge  = 30 * 24 * time.Hour
)

// ValidateRecordedAt checks a sensor-supplied RFC 3339 timestamp against the
// deterministic ledger time for the transaction.
//
// Comparing against ledger time rather than wall-clock time is what keeps this
// deterministic: every endorsing peer sees the same txTime, so every peer
// reaches the same verdict. A time.Now() comparison here would reintroduce
// exactly the non-determinism this design avoids.
func ValidateRecordedAt(recordedAt string, txTime time.Time) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, recordedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"recorded_at %q is not an RFC 3339 timestamp (expected 2026-08-21T10:00:00Z)", recordedAt)
	}
	parsed = parsed.UTC()
	if parsed.After(txTime.Add(MaxRecordedAtSkew)) {
		return time.Time{}, fmt.Errorf(
			"recorded_at %s is more than %s ahead of ledger time %s; check the sensor clock",
			recordedAt, MaxRecordedAtSkew, txTime.Format(time.RFC3339))
	}
	if parsed.Before(txTime.Add(-MaxRecordedAtAge)) {
		return time.Time{}, fmt.Errorf(
			"recorded_at %s is more than %s older than ledger time %s; refusing to backfill "+
				"history this old", recordedAt, MaxRecordedAtAge, txTime.Format(time.RFC3339))
	}
	return parsed, nil
}

// ── Expiry ───────────────────────────────────────────────────────────────────

// IsExpired reports whether a product is past its expiry date as at asOf.
//
// The expiry day itself is still valid. A pharmacist reading "EXP 02/2028"
// dispenses on 29 February 2028 without hesitation, and a system that calls that
// unit expired would be wrong in a way that destroys trust in every other
// verdict it gives.
func IsExpired(expiryDate string, asOf time.Time) (bool, error) {
	exp, err := ParseDate("expiry_date", expiryDate)
	if err != nil {
		return false, err
	}
	return exp.Before(dayOf(asOf)), nil
}

// DaysToExpiry returns whole days remaining; negative once expired, 0 on the
// expiry day itself.
func DaysToExpiry(expiryDate string, asOf time.Time) (int, error) {
	exp, err := ParseDate("expiry_date", expiryDate)
	if err != nil {
		return 0, err
	}
	return int(exp.Sub(dayOf(asOf)).Hours() / 24), nil
}

// dayOf truncates to UTC midnight so comparisons are date-to-date. Without this
// a unit expiring today would flip to expired at 00:00:01 rather than at
// midnight tomorrow.
func dayOf(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

// ── Clone heuristic and verdict ──────────────────────────────────────────────

// CloneSuspected applies the duplicate-scan heuristic.
func CloneSuspected(scanCount, distinctDistricts int) bool {
	return scanCount > CloneScanThreshold || distinctDistricts > CloneDistrictThreshold
}

// Verdict folds the on-chain facts into a single verdict, most severe first.
//
// The precedence is a subset of the order in verifier.py, minus the signature
// verdicts the ledger cannot evaluate. Keeping the order in one place per
// language is the only way three implementations stay in agreement about what a
// patient is shown.
func Verdict(status string, expired, breached, cloneSuspected bool) string {
	switch {
	case status == StatusRecalled:
		return VerdictRecalled
	case cloneSuspected:
		return VerdictClone
	case breached:
		return VerdictColdChain
	case expired:
		return VerdictExpired
	default:
		return VerdictGenuine
	}
}

// Severity maps a verdict to the urgency a UI should convey.
func Severity(verdict string) string {
	switch verdict {
	case VerdictGenuine:
		return SeverityOK
	case VerdictExpired, VerdictNotFound:
		return SeverityWarn
	case VerdictColdChain, VerdictClone, VerdictRecalled:
		return SeverityCritical
	default:
		return SeverityWarn
	}
}
