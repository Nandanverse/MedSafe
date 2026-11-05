package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/truemed/chaincode/internal/rules"
)

// ContractVersion is reported in the chaincode metadata and stamped onto every
// record written. When the schema changes, this changes, and a reader can tell
// which version wrote a given record without guessing from its shape.
const ContractVersion = "1.0.0"

// Document type discriminators.
//
// Every value in world state carries one. CouchDB holds medicine records and
// temperature readings in the same database, so a rich query without a doc_type
// filter would happily return a temperature reading where a medicine was
// expected and then fail to unmarshal it in a confusing place.
const (
	docTypeMedicine    = "medicine"
	docTypeTemperature = "temperature"
)

// Medicine is the world-state record for one sellable unit — a strip, a bottle
// or a vial. Field names and JSON tags are fixed by docs/DATA-CONTRACT.md §3;
// the REST API passes this through to clients unchanged.
type Medicine struct {
	DocType string `json:"doc_type"`

	// Immutable identity, copied from the signed QR payload. Nothing below
	// changes these after CreateMedicine.
	ProductID    string   `json:"product_id"`
	GenericName  string   `json:"generic_name"`
	BrandName    string   `json:"brand_name"`
	Manufacturer string   `json:"manufacturer"`
	MfgLicenceNo string   `json:"mfg_licence_no"`
	BatchNo      string   `json:"batch_no"`
	MfgDate      string   `json:"mfg_date"`
	ExpiryDate   string   `json:"expiry_date"`
	Quantity     string   `json:"quantity"`
	Excipients   []string `json:"excipients"`
	Type         string   `json:"type"`

	// Custody.
	CurrentLocation string         `json:"current_location"`
	Status          string         `json:"status"`
	CustodyTrail    []CustodyEvent `json:"custody_trail"`

	// Cold chain. TemperatureHistory is a bounded rolling window for display —
	// the complete series lives in one ledger key per reading, addressed by
	// composite key, and is read with GetTemperatureHistory. See
	// rules.MaxEmbeddedReadings for why the window is capped.
	TemperatureHistory  []TemperatureReading `json:"temperature_history"`
	TempReadingCount    int                  `json:"temp_reading_count"`
	TempMinC            float64              `json:"temp_min_c"`
	TempMaxC            float64              `json:"temp_max_c"`
	ColdChainBreached   bool                 `json:"cold_chain_breached"`
	ColdChainBreachedAt string               `json:"cold_chain_breached_at"`

	// Clone telemetry. A single physical unit cannot be scanned in many
	// districts, so these two counters are the only defence against a QR
	// photographed off a genuine strip and reprinted onto fakes.
	ScanCount             int      `json:"scan_count"`
	FirstScanAt           string   `json:"first_scan_at"`
	LastScanAt            string   `json:"last_scan_at"`
	DistinctScanDistricts []string `json:"distinct_scan_districts"`

	// Recall.
	RecallReason string `json:"recall_reason"`
	RecalledAt   string `json:"recalled_at"`

	// Provenance.
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	CreatedByMSP    string `json:"created_by_msp"`
	ContractVersion string `json:"contract_version"`
}

// TemperatureReading is one measurement.
//
// Two timestamps, deliberately. Timestamp is ledger time — deterministic, taken
// from the transaction, and trustworthy. RecordedAt is what the sensor claimed,
// which matters because a device that lost WiFi for three days flushes its
// buffer on reconnect and every one of those readings would otherwise be stamped
// with the moment of reconnection, erasing the outage window in which an
// excursion is most likely.
type TemperatureReading struct {
	DocType     string  `json:"doc_type,omitempty"`
	ProductID   string  `json:"product_id,omitempty"`
	Temperature float64 `json:"temperature"`
	Timestamp   string  `json:"timestamp"`
	RecordedAt  string  `json:"recorded_at"`
	Location    string  `json:"location"`
	SensorID    string  `json:"sensor_id"`
	Breach      bool    `json:"breach"`
}

// CustodyEvent is one hop in the chain of custody.
type CustodyEvent struct {
	Status    string `json:"status"`
	Location  string `json:"location"`
	Timestamp string `json:"timestamp"`
	ActorMSP  string `json:"actor_msp"`
}

// ColdChainSummary is the aggregate view the API and dashboards use, so they do
// not have to fetch a hundred thousand readings to draw one status badge.
type ColdChainSummary struct {
	Applicable   bool    `json:"applicable"`
	Breached     bool    `json:"breached"`
	BreachedAt   string  `json:"breached_at"`
	MinC         float64 `json:"min_c"`
	MaxC         float64 `json:"max_c"`
	ReadingCount int     `json:"reading_count"`
}

// Telemetry is the clone-detection view.
type Telemetry struct {
	ScanCount         int      `json:"scan_count"`
	DistinctDistricts int      `json:"distinct_districts"`
	Districts         []string `json:"districts"`
	FirstScanAt       string   `json:"first_scan_at"`
	LastScanAt        string   `json:"last_scan_at"`
}

// VerificationSnapshot is what VerifyMedicine returns.
//
// It reports failures as data, never as a Go error. That distinction is the
// whole design: an error return from chaincode aborts the transaction, the
// contract API discards any accompanying value, and the client receives a bare
// string. A patient scanning a recalled vial would then see "transaction failed"
// with no product name, no batch, and no reason — the moment the system most
// needs to communicate clearly is the moment it would go silent. Errors here are
// reserved for infrastructure faults: a ledger read that failed, a record that
// will not unmarshal.
type VerificationSnapshot struct {
	ProductID    string           `json:"product_id"`
	Found        bool             `json:"found"`
	Verdict      string           `json:"verdict"`
	Severity     string           `json:"severity"`
	Reasons      []string         `json:"reasons"`
	Expired      bool             `json:"expired"`
	DaysToExpiry int              `json:"days_to_expiry"`
	Medicine     *Medicine        `json:"medicine"`
	ColdChain    ColdChainSummary `json:"cold_chain"`
	Telemetry    Telemetry        `json:"telemetry"`
	VerifiedAt   string           `json:"verified_at"`
}

// MedicinePage is a paginated query result. Fabric's pagination is bookmark
// based, not offset based, because an offset over a replicated key-value store
// would need a full scan to skip rows.
type MedicinePage struct {
	Medicines []*Medicine `json:"medicines"`
	Count     int         `json:"count"`
	Bookmark  string      `json:"bookmark"`
}

// createRequest is the JSON accepted by CreateMedicine.
//
// One JSON argument rather than thirteen positional strings. Fabric passes every
// argument as a string, so a positional signature makes transposing
// generic_name and brand_name — or mfg_date and expiry_date — a silent error
// that produces a plausible-looking record with the wrong expiry on it. Named
// fields make that class of mistake impossible, and the REST layer already holds
// this exact object.
type createRequest struct {
	ProductID    string   `json:"product_id"`
	GenericName  string   `json:"generic_name"`
	BrandName    string   `json:"brand_name"`
	Manufacturer string   `json:"manufacturer"`
	MfgLicenceNo string   `json:"mfg_licence_no"`
	BatchNo      string   `json:"batch_no"`
	MfgDate      string   `json:"mfg_date"`
	ExpiryDate   string   `json:"expiry_date"`
	Quantity     string   `json:"quantity"`
	Excipients   []string `json:"excipients"`
	Type         string   `json:"type"`
	Location     string   `json:"location"`
}

// validate applies every field rule, collecting nothing — the first failure
// stops the transaction, because a partially valid medicine record must never
// reach the ledger.
func (r *createRequest) validate() error {
	if err := rules.ValidateProductID(r.ProductID); err != nil {
		return err
	}
	if err := rules.ValidateText("generic_name", r.GenericName, rules.MaxGenericName); err != nil {
		return err
	}
	if err := rules.ValidateText("brand_name", r.BrandName, rules.MaxBrandName); err != nil {
		return err
	}
	if err := rules.ValidateText("manufacturer", r.Manufacturer, rules.MaxManufacturer); err != nil {
		return err
	}
	if err := rules.ValidateText("mfg_licence_no", r.MfgLicenceNo, rules.MaxLicenceNo); err != nil {
		return err
	}
	if err := rules.ValidateBatchNo(r.BatchNo); err != nil {
		return err
	}
	if err := rules.ValidateText("quantity", r.Quantity, rules.MaxQuantity); err != nil {
		return err
	}
	if err := rules.ValidateText("location", r.Location, rules.MaxLocation); err != nil {
		return err
	}
	if err := rules.ValidateType(r.Type); err != nil {
		return err
	}
	if err := rules.ValidateDateOrder(r.MfgDate, r.ExpiryDate); err != nil {
		return err
	}
	return rules.ValidateExcipients(r.Excipients)
}

// parseCreateRequest decodes the JSON argument strictly.
//
// DisallowUnknownFields matters more than it looks. Without it, a caller that
// sends "expiry" instead of "expiry_date" gets a record with an empty expiry
// date and no complaint, and the mistake surfaces months later as a unit that
// cannot be verified. Rejecting the typo at the door turns a silent data defect
// into an immediate, fixable error.
func parseCreateRequest(payload string) (*createRequest, error) {
	var req createRequest
	if err := decodeJSON("CreateMedicine", payload, &req); err != nil {
		return nil, err
	}
	if err := req.validate(); err != nil {
		return nil, wrap(CodeValidation, err)
	}
	return &req, nil
}

// locationRequest is the JSON accepted by UpdateLocation. Named fields rather
// than three positional strings, matching POST /api/location and the gateway
// client, so transposing location and status is a schema error instead of a
// silent wrong hop.
type locationRequest struct {
	ProductID string `json:"product_id"`
	Location  string `json:"location"`
	Status    string `json:"status"`
}

// temperatureRequest is the JSON accepted by AddTemperatureReading, matching
// POST /api/temperature. Location is optional: an IoT reading that omits it is
// stamped with the unit's current custody location.
type temperatureRequest struct {
	ProductID   string  `json:"product_id"`
	Temperature float64 `json:"temperature"`
	Location    string  `json:"location"`
	SensorID    string  `json:"sensor_id"`
	RecordedAt  string  `json:"recorded_at"`
}

// scanRequest is the JSON accepted by RecordPatientScan.
type scanRequest struct {
	ProductID string `json:"product_id"`
	District  string `json:"district"`
}

// recallRequest is the JSON accepted by RecallBatch, matching POST /api/recall.
type recallRequest struct {
	BatchNo string `json:"batch_no"`
	Reason  string `json:"reason"`
}

func decodeJSON(label, payload string, dest interface{}) error {
	if strings.TrimSpace(payload) == "" {
		return coded(CodeValidation, "%s needs a JSON object, got an empty argument", label)
	}
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return coded(CodeValidation, "%s JSON is not valid: %v", label, err)
	}
	if decoder.More() {
		return coded(CodeValidation, "%s JSON contains trailing data after the object", label)
	}
	return nil
}

// ── Deterministic time ───────────────────────────────────────────────────────

// ledgerTime returns the transaction's timestamp, in UTC.
//
// This function exists so that time.Now() never appears in this chaincode. Every
// endorsing peer executes the transaction independently; a wall-clock read gives
// each peer a different value, so their write sets differ, and the transaction is
// rejected at validation as a read-write set conflict — or, worse, succeeds while
// the network has a single endorser and then breaks the day a second organisation
// joins. The transaction timestamp is set once by the submitting client and
// carried in the proposal, so every peer sees the same value.
//
// Seconds and nanos are read individually rather than via AsTime() so the code
// compiles against both the old github.com/golang/protobuf timestamp type and
// the current google.golang.org/protobuf one.
func ledgerTime(ctx contractapi.TransactionContextInterface) (time.Time, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return time.Time{}, fmt.Errorf("could not read the transaction timestamp: %v", err)
	}
	if ts == nil {
		return time.Time{}, fmt.Errorf("transaction timestamp is missing from the proposal")
	}
	return time.Unix(ts.GetSeconds(), int64(ts.GetNanos())).UTC(), nil
}

// stamp formats a ledger time for storage. RFC 3339 in UTC, matching the
// timestamps the QR payload and the REST API use, so no consumer has to guess a
// timezone.
func stamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// ── Derived views ────────────────────────────────────────────────────────────

// coldChainSummary builds the aggregate cold-chain view.
func (m *Medicine) coldChainSummary() ColdChainSummary {
	return ColdChainSummary{
		Applicable:   m.Type == rules.TypeVaccine,
		Breached:     m.ColdChainBreached,
		BreachedAt:   m.ColdChainBreachedAt,
		MinC:         m.TempMinC,
		MaxC:         m.TempMaxC,
		ReadingCount: m.TempReadingCount,
	}
}

// telemetry builds the clone-detection view.
func (m *Medicine) telemetry() Telemetry {
	districts := m.DistinctScanDistricts
	if districts == nil {
		// A JSON null here would make every client handle two shapes for "no
		// scans yet". An empty array is one shape.
		districts = []string{}
	}
	return Telemetry{
		ScanCount:         m.ScanCount,
		DistinctDistricts: len(districts),
		Districts:         districts,
		FirstScanAt:       m.FirstScanAt,
		LastScanAt:        m.LastScanAt,
	}
}

// appendCustody records a hop and keeps the trail bounded.
//
// The cap is generous — a real unit sees under ten hops — but unbounded growth
// driven by an authenticated distributor calling UpdateLocation in a loop is a
// denial-of-service against the whole channel, and ledger writes cannot be
// undone.
const maxCustodyEvents = 64

// maxCustodyEventsRecall is the ceiling RecallBatch is allowed to reach: one slot
// above the normal cap.
//
// Without this headroom the cap becomes a weapon. A distributor who has filled a
// unit's trail with 64 location hops would make every future RecallBatch call on
// that batch fail — the loop aborts the whole transaction, so nothing is
// persisted and no retry can ever succeed. A stuck integration must not be able
// to veto a safety recall.
//
// One extra slot is enough because recall is terminal: a unit already recalled is
// skipped on the next page, so RecallBatch can claim this slot at most once per
// unit and growth stays bounded.
const maxCustodyEventsRecall = maxCustodyEvents + 1

// appendCustodyUpTo is the shared implementation. The limit is a parameter rather
// than a package constant precisely so the recall path can be given its own.
func (m *Medicine) appendCustodyUpTo(event CustodyEvent, limit int) error {
	if len(m.CustodyTrail) >= limit {
		// VALIDATION_ERROR: the caller is doing something wrong and retrying will
		// never help, so this must reach the client as a 400 rather than a 503.
		return coded(CodeValidation,
			"%s already has %d custody events, which is the maximum; a legitimate "+
				"unit sees fewer than ten, so this looks like a stuck integration",
			m.ProductID, limit)
	}
	m.CustodyTrail = append(m.CustodyTrail, event)
	return nil
}

func (m *Medicine) appendCustody(event CustodyEvent) error {
	return m.appendCustodyUpTo(event, maxCustodyEvents)
}

// appendRecallCustody records the recall hop, drawing on the reserved slot.
func (m *Medicine) appendRecallCustody(event CustodyEvent) error {
	return m.appendCustodyUpTo(event, maxCustodyEventsRecall)
}

// appendReading updates the aggregates and the rolling display window.
func (m *Medicine) appendReading(reading TemperatureReading) {
	if m.TempReadingCount == 0 {
		m.TempMinC = reading.Temperature
		m.TempMaxC = reading.Temperature
	} else {
		if reading.Temperature < m.TempMinC {
			m.TempMinC = reading.Temperature
		}
		if reading.Temperature > m.TempMaxC {
			m.TempMaxC = reading.Temperature
		}
	}
	m.TempReadingCount++

	// The embedded copy carries no doc_type or product_id: those exist only on
	// the standalone ledger records, and repeating them inside every element of
	// the window would inflate the record for no benefit.
	windowEntry := reading
	windowEntry.DocType = ""
	windowEntry.ProductID = ""

	m.TemperatureHistory = append(m.TemperatureHistory, windowEntry)
	if len(m.TemperatureHistory) > rules.MaxEmbeddedReadings {
		// Re-slice from the tail, then copy into a fresh slice. Simply re-slicing
		// would keep the whole backing array alive and, more importantly, would
		// serialise correctly today but leave a slice that grows in place on the
		// next append.
		trimmed := make([]TemperatureReading, rules.MaxEmbeddedReadings)
		copy(trimmed, m.TemperatureHistory[len(m.TemperatureHistory)-rules.MaxEmbeddedReadings:])
		m.TemperatureHistory = trimmed
	}
}

// recordDistrict adds a district to the clone-detection set, returning whether
// it was new.
func (m *Medicine) recordDistrict(district string) bool {
	if district == "" {
		return false
	}
	for _, existing := range m.DistinctScanDistricts {
		if strings.EqualFold(existing, district) {
			return false
		}
	}
	if len(m.DistinctScanDistricts) >= rules.MaxDistinctDistricts {
		// Already far past the clone threshold; the verdict cannot get worse and
		// the list has served its purpose.
		return false
	}
	m.DistinctScanDistricts = append(m.DistinctScanDistricts, district)
	return true
}
