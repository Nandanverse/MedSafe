// TrueMed — Hyperledger Fabric chaincode.
//
// Manages the lifecycle of medicine and vaccine units on the ledger: minting at
// the factory, custody hops through the supply chain, IoT cold-chain readings,
// patient scans, regulator recalls, and verification queries.
//
// Two rules govern everything in this file.
//
//  1. No wall-clock reads. time.Now() must never appear in chaincode; all
//     timestamps come from ledgerTime(), which reads the transaction timestamp.
//     See the comment on that function for why.
//  2. Business outcomes are data, not errors. An expired or recalled unit is a
//     successful query with an unwelcome answer. Go errors are reserved for
//     infrastructure faults and rejected writes.
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"github.com/truemed/chaincode/internal/rules"
)

// MedicineContract is the TrueMed smart contract.
type MedicineContract struct {
	contractapi.Contract
}

// Chaincode event names. The REST API subscribes to these to invalidate its
// Redis cache and to push alerts to the CDSCO dashboard, which is what makes a
// cold-chain excursion visible in seconds rather than at the next poll.
const (
	EventMedicineCreated = "MedicineCreated"
	EventCustodyUpdated  = "CustodyUpdated"
	EventTemperature     = "TemperatureRecorded"
	EventColdChainBreach = "ColdChainBreach"
	EventPatientScan     = "PatientScanned"
	EventCloneSuspected  = "CloneSuspected"
	EventBatchRecalled   = "BatchRecalled"
)

// maxRecallPerTx bounds one recall transaction.
//
// A batch can hold tens of thousands of units, and rewriting all of them in a
// single transaction produces a write set the orderer will refuse and a block
// that would stall the channel. The call reports whether units remain; because
// already-recalled units are skipped, calling again always makes progress.
const maxRecallPerTx = 500

// maxRecallScan bounds the index rows one recall reads.
//
// This is deliberately far larger than maxRecallPerTx, because the two limits
// protect against different things: the write cap keeps the block a workable
// size, while this cap only stops a single transaction from reading an
// unbounded index. Index rows are tiny and a read is cheap next to a write, so
// the scan can afford to cover a whole realistic batch — which is what makes
// repeated calls converge. See RecallBatch for why capping the scan instead
// would break that.
const maxRecallScan = 100000

// defaultPageSize and maxPageSize bound query results. An unbounded query
// against a channel holding millions of units is a denial-of-service that any
// channel member could trigger by accident.
const (
	defaultPageSize = 50
	maxPageSize     = 500
)

// RecallResult reports the outcome of a recall.
//
// Recalled counts the units this call moved to recalled and ProductIDs names
// exactly those, so a caller can log precisely what changed. AlreadyRecalled
// counts units this call examined and found already recalled — units beyond the
// point where the write cap stopped the scan are not included, since they were
// never looked at.
type RecallResult struct {
	BatchNo         string   `json:"batch_no"`
	Recalled        int      `json:"recalled"`
	AlreadyRecalled int      `json:"already_recalled"`
	MoreRemaining   bool     `json:"more_remaining"`
	ProductIDs      []string `json:"product_ids"`
	RecalledAt      string   `json:"recalled_at"`
	ActorMSP        string   `json:"actor_msp"`
}

// ── Writes ───────────────────────────────────────────────────────────────────

// CreateMedicine registers a new unit on the ledger.
//
// Takes one JSON object; see createRequest for the field names and for why a
// single JSON argument is safer than thirteen positional strings.
//
// Restricted to the manufacturer organisation. This is the single most important
// access-control rule in TrueMed: if anyone else can mint, then "it exists on the
// blockchain" stops meaning "its manufacturer registered it", and the ledger no
// longer distinguishes genuine stock from a counterfeiter's inventory.
//
// An already-expired unit is accepted. Refusing one would make it impossible to
// onboard existing inventory, which is exactly how a real deployment starts —
// warehouses are full of stock manufactured before the system went live.
func (c *MedicineContract) CreateMedicine(ctx contractapi.TransactionContextInterface, medicineJSON string) error {
	mspID, err := requireMSP(ctx, "CreateMedicine", MSPManufacturer)
	if err != nil {
		return err
	}

	request, err := parseCreateRequest(medicineJSON)
	if err != nil {
		return err
	}

	// Existence is checked against world state rather than trusting the caller,
	// and a duplicate is refused outright. Overwriting would let a compromised
	// manufacturer identity rewrite the history of a unit already in circulation.
	if _, found, err := readMedicine(ctx, request.ProductID); err != nil {
		return err
	} else if found {
		return coded(CodeConflict,
			"a unit with product ID %s is already registered; product IDs are unique per "+
				"sellable unit and must never be reused", request.ProductID)
	}

	now, err := ledgerTime(ctx)
	if err != nil {
		return err
	}
	timestamp := stamp(now)

	excipients := request.Excipients
	if excipients == nil {
		excipients = []string{}
	}

	medicine := &Medicine{
		DocType:      docTypeMedicine,
		ProductID:    request.ProductID,
		GenericName:  strings.TrimSpace(request.GenericName),
		BrandName:    strings.TrimSpace(request.BrandName),
		Manufacturer: strings.TrimSpace(request.Manufacturer),
		MfgLicenceNo: strings.TrimSpace(request.MfgLicenceNo),
		BatchNo:      strings.TrimSpace(request.BatchNo),
		MfgDate:      request.MfgDate,
		ExpiryDate:   request.ExpiryDate,
		Quantity:     strings.TrimSpace(request.Quantity),
		Excipients:   excipients,
		Type:         request.Type,

		CurrentLocation: strings.TrimSpace(request.Location),
		Status:          rules.StatusManufactured,
		CustodyTrail: []CustodyEvent{{
			Status:    rules.StatusManufactured,
			Location:  strings.TrimSpace(request.Location),
			Timestamp: timestamp,
			ActorMSP:  mspID,
		}},

		TemperatureHistory:    []TemperatureReading{},
		DistinctScanDistricts: []string{},

		CreatedAt:       timestamp,
		UpdatedAt:       timestamp,
		CreatedByMSP:    mspID,
		ContractVersion: ContractVersion,
	}

	if err := writeMedicine(ctx, medicine); err != nil {
		return err
	}
	// The batch index is written in the same transaction as the record, so a
	// recall can never miss a unit that was successfully created.
	if err := putBatchIndex(ctx, medicine.BatchNo, medicine.ProductID); err != nil {
		return err
	}

	return emit(ctx, EventMedicineCreated, map[string]interface{}{
		"product_id": medicine.ProductID,
		"batch_no":   medicine.BatchNo,
		"type":       medicine.Type,
		"licence_no": medicine.MfgLicenceNo,
		"created_at": timestamp,
	})
}

// UpdateLocation records a custody hop.
//
// The caller supplies the new status explicitly rather than having it inferred
// from the location string, because location is a facility code — FACTORY_PUNE_01,
// WH_MUM_001, PHARM_MUM_0142 — and inferring meaning from a substring of a code
// is exactly the kind of guess that breaks the day a facility is renamed.
func (c *MedicineContract) UpdateLocation(
	ctx contractapi.TransactionContextInterface,
	requestJSON string,
) error {
	mspID, err := requireMSP(ctx, "UpdateLocation", MSPManufacturer, MSPDistributor)
	if err != nil {
		return err
	}
	var request locationRequest
	if err := decodeJSON("UpdateLocation", requestJSON, &request); err != nil {
		return err
	}
	if err := rules.ValidateProductID(request.ProductID); err != nil {
		return wrap(CodeValidation, err)
	}
	if err := rules.ValidateText("location", request.Location, rules.MaxLocation); err != nil {
		return wrap(CodeValidation, err)
	}
	// A recall is not a custody hop and must go through RecallBatch, which is
	// restricted to the regulator. Without this guard a distributor could mark
	// stock recalled — or, more likely, an integration bug could.
	if request.Status == rules.StatusRecalled {
		return coded(CodeValidation,
			"a recall cannot be recorded through UpdateLocation; use RecallBatch, which is "+
				"restricted to %s", MSPRegulator)
	}

	medicine, err := mustReadMedicine(ctx, request.ProductID)
	if err != nil {
		return err
	}
	if err := rules.ValidateTransition(medicine.Status, request.Status); err != nil {
		return wrap(CodeValidation, err)
	}

	now, err := ledgerTime(ctx)
	if err != nil {
		return err
	}
	timestamp := stamp(now)
	trimmedLocation := strings.TrimSpace(request.Location)

	previousStatus := medicine.Status
	medicine.Status = request.Status
	medicine.CurrentLocation = trimmedLocation
	medicine.UpdatedAt = timestamp
	if err := medicine.appendCustody(CustodyEvent{
		Status:    request.Status,
		Location:  trimmedLocation,
		Timestamp: timestamp,
		ActorMSP:  mspID,
	}); err != nil {
		return wrap(CodeValidation, err)
	}

	if err := writeMedicine(ctx, medicine); err != nil {
		return err
	}

	return emit(ctx, EventCustodyUpdated, map[string]interface{}{
		"product_id":      medicine.ProductID,
		"batch_no":        medicine.BatchNo,
		"previous_status": previousStatus,
		"status":          request.Status,
		"location":        trimmedLocation,
		"actor_msp":       mspID,
		"timestamp":       timestamp,
	})
}

// AddTemperatureReading records one IoT measurement.
//
// The reading is stored twice, on purpose: once as its own ledger key so the full
// series is auditable, and once in a bounded rolling window on the unit's record
// so a dashboard can draw a sparkline with a single read. Aggregates (count, min,
// max, breach flag) live on the record too.
//
// A breach is sticky. Once set, ColdChainBreached is never cleared, because a
// vaccine that reached 15 °C does not become safe again when the fridge recovers —
// potency loss is cumulative and irreversible. Any code path that "resets" this
// flag is a bug, however tempting it looks when a dashboard is full of red.
func (c *MedicineContract) AddTemperatureReading(
	ctx contractapi.TransactionContextInterface,
	requestJSON string,
) error {
	mspID, err := requireMSP(ctx, "AddTemperatureReading", MSPManufacturer, MSPDistributor)
	if err != nil {
		return err
	}
	var request temperatureRequest
	if err := decodeJSON("AddTemperatureReading", requestJSON, &request); err != nil {
		return err
	}
	if err := rules.ValidateProductID(request.ProductID); err != nil {
		return wrap(CodeValidation, err)
	}
	if err := rules.ValidateText("sensor_id", request.SensorID, rules.MaxSensorID); err != nil {
		return wrap(CodeValidation, err)
	}
	if err := rules.ValidateTemperature(request.Temperature); err != nil {
		return wrap(CodeValidation, err)
	}

	now, err := ledgerTime(ctx)
	if err != nil {
		return err
	}
	sensorTime, err := rules.ValidateRecordedAt(request.RecordedAt, now)
	if err != nil {
		return wrap(CodeValidation, err)
	}

	medicine, err := mustReadMedicine(ctx, request.ProductID)
	if err != nil {
		return err
	}
	if medicine.TempReadingCount >= maxTempReadings {
		return coded(CodeValidation, "unit %s has reached the maximum recordable readings", request.ProductID)
	}

	location := strings.TrimSpace(request.Location)
	if location == "" {
		location = medicine.CurrentLocation
	} else if err := rules.ValidateText("location", location, rules.MaxLocation); err != nil {
		return wrap(CodeValidation, err)
	}

	timestamp := stamp(now)
	breach := rules.BreachesColdChain(medicine.Type, request.Temperature)

	reading := TemperatureReading{
		DocType:     docTypeTemperature,
		ProductID:   request.ProductID,
		Temperature: request.Temperature,
		Timestamp:   timestamp,
		RecordedAt:  stamp(sensorTime),
		Location:    location,
		SensorID:    strings.TrimSpace(request.SensorID),
		Breach:      breach,
	}

	// The sequence number is the pre-increment count, so keys are dense and
	// gap-free, and it is derived from ledger state rather than from a clock —
	// which keeps it identical on every endorsing peer.
	sequence := medicine.TempReadingCount
	if err := putTemperatureReading(ctx, reading, sequence); err != nil {
		return err
	}

	medicine.appendReading(reading)
	firstBreach := breach && !medicine.ColdChainBreached
	if firstBreach {
		medicine.ColdChainBreached = true
		medicine.ColdChainBreachedAt = timestamp
	}
	medicine.UpdatedAt = timestamp

	if err := writeMedicine(ctx, medicine); err != nil {
		return err
	}

	// Exactly one event per transaction: SetEvent overwrites rather than appends,
	// so emitting two would silently discard the first.
	if breach {
		return emit(ctx, EventColdChainBreach, map[string]interface{}{
			"product_id":   request.ProductID,
			"batch_no":     medicine.BatchNo,
			"temperature":  request.Temperature,
			"location":     reading.Location,
			"sensor_id":    reading.SensorID,
			"recorded_at":  reading.RecordedAt,
			"timestamp":    timestamp,
			"first_breach": firstBreach,
			"actor_msp":    mspID,
		})
	}
	return emit(ctx, EventTemperature, map[string]interface{}{
		"product_id":  request.ProductID,
		"temperature": request.Temperature,
		"location":    reading.Location,
		"sensor_id":   reading.SensorID,
		"recorded_at": reading.RecordedAt,
		"timestamp":   timestamp,
	})
}

// RecordPatientScan increments the clone-detection counters.
//
// Open to any channel member, because the party submitting it is the public
// verification API rather than a supply-chain participant.
//
// This is a read-modify-write on a single key, so concurrent scans of the same
// unit will collide at validation and one will be rejected with an MVCC conflict.
// That is acceptable and is handled at the API layer, which coalesces scans per
// product before submitting; the counter is a heuristic for detecting mass
// cloning, and losing one increment out of four hundred changes no verdict.
// Building it as a lock-free counter would mean one ledger key per scan, which
// trades a rare retry for unbounded state growth.
func (c *MedicineContract) RecordPatientScan(
	ctx contractapi.TransactionContextInterface,
	requestJSON string,
) error {
	mspID, err := callerMSP(ctx)
	if err != nil {
		return err
	}
	var request scanRequest
	if err := decodeJSON("RecordPatientScan", requestJSON, &request); err != nil {
		return err
	}
	if err := rules.ValidateProductID(request.ProductID); err != nil {
		return wrap(CodeValidation, err)
	}
	// District is optional: a patient may deny location permission, and the DPDP
	// Act principle of collecting no more than necessary means the scan must still
	// be recorded without it.
	trimmedDistrict := strings.TrimSpace(request.District)
	if trimmedDistrict != "" {
		if err := rules.ValidateText("district", trimmedDistrict, rules.MaxDistrict); err != nil {
			return wrap(CodeValidation, err)
		}
	}

	medicine, err := mustReadMedicine(ctx, request.ProductID)
	if err != nil {
		return err
	}

	now, err := ledgerTime(ctx)
	if err != nil {
		return err
	}
	timestamp := stamp(now)

	medicine.ScanCount++
	if medicine.FirstScanAt == "" {
		medicine.FirstScanAt = timestamp
	}
	medicine.LastScanAt = timestamp
	medicine.recordDistrict(trimmedDistrict)
	medicine.UpdatedAt = timestamp

	if err := writeMedicine(ctx, medicine); err != nil {
		return err
	}

	districtCount := len(medicine.DistinctScanDistricts)
	if rules.CloneSuspected(medicine.ScanCount, districtCount) {
		return emit(ctx, EventCloneSuspected, map[string]interface{}{
			"product_id":         request.ProductID,
			"batch_no":           medicine.BatchNo,
			"scan_count":         medicine.ScanCount,
			"distinct_districts": districtCount,
			"districts":          medicine.DistinctScanDistricts,
			"timestamp":          timestamp,
		})
	}
	return emit(ctx, EventPatientScan, map[string]interface{}{
		"product_id": request.ProductID,
		"district":   trimmedDistrict,
		"scan_count": medicine.ScanCount,
		"timestamp":  timestamp,
		"actor_msp":  mspID,
	})
}

// RecallBatch marks every unit of a batch as recalled.
//
// Regulator only. Recall is the most destructive operation in the system — it
// tells pharmacies to pull stock from shelves — so the authority to invoke it is
// narrower than any other.
//
// Recall is per batch rather than per unit because that is how a real recall is
// issued: a contamination finding or a failed potency assay condemns a
// manufacturing lot, and no regulator enumerates ten thousand product IDs.
func (c *MedicineContract) RecallBatch(
	ctx contractapi.TransactionContextInterface,
	requestJSON string,
) (*RecallResult, error) {
	mspID, err := requireMSP(ctx, "RecallBatch", MSPRegulator)
	if err != nil {
		return nil, err
	}
	var request recallRequest
	if err := decodeJSON("RecallBatch", requestJSON, &request); err != nil {
		return nil, err
	}
	if err := rules.ValidateBatchNo(request.BatchNo); err != nil {
		return nil, wrap(CodeValidation, err)
	}
	if err := rules.ValidateText("reason", request.Reason, rules.MaxReason); err != nil {
		return nil, wrap(CodeValidation, err)
	}

	now, err := ledgerTime(ctx)
	if err != nil {
		return nil, err
	}
	timestamp := stamp(now)
	trimmedBatch := strings.TrimSpace(request.BatchNo)
	trimmedReason := strings.TrimSpace(request.Reason)

	// The cap is on units *recalled*, not on index rows read, and getting that
	// distinction the wrong way round costs the caller all forward progress.
	// Capping the scan means every call re-reads the same first 500 rows of the
	// batch index; once those units are recalled, each further call recalls
	// nothing, still reports more_remaining: true, and the units past row 500 can
	// never be reached at all. Scanning the batch and stopping after 500 *writes*
	// means each call recalls the next 500 not-yet-recalled units, so "call again
	// until more_remaining is false" (§3.7) actually terminates.
	productIDs, scanTruncated, err := productIDsInBatch(ctx, trimmedBatch, maxRecallScan)
	if err != nil {
		return nil, err
	}
	if len(productIDs) == 0 {
		return nil, coded(CodeNotOnChain,
			"no units are registered under batch %s on this channel; check the batch number "+
				"against the manufacturer's records", trimmedBatch)
	}

	result := &RecallResult{
		BatchNo:    trimmedBatch,
		ProductIDs: make([]string, 0, len(productIDs)),
		RecalledAt: timestamp,
		ActorMSP:   mspID,
	}

	capReached := false
	for _, productID := range productIDs {
		if result.Recalled >= maxRecallPerTx {
			// Stop before reading another record, let alone writing one: the write
			// set is already as large as a block should carry.
			capReached = true
			break
		}
		medicine, err := mustReadMedicine(ctx, productID)
		if err != nil {
			// An index entry without a record means the ledger is inconsistent.
			// Failing the whole transaction is correct: a partial recall that
			// reports success is worse than one that reports a problem.
			return nil, fmt.Errorf("batch %s index refers to %s: %v", trimmedBatch, productID, err)
		}
		if medicine.Status == rules.StatusRecalled {
			result.AlreadyRecalled++
			continue
		}

		medicine.Status = rules.StatusRecalled
		medicine.RecallReason = trimmedReason
		medicine.RecalledAt = timestamp
		medicine.UpdatedAt = timestamp
		if err := medicine.appendRecallCustody(CustodyEvent{
			Status:    rules.StatusRecalled,
			Location:  medicine.CurrentLocation,
			Timestamp: timestamp,
			ActorMSP:  mspID,
		}); err != nil {
			// wrap, not a fresh fmt.Errorf: the error already carries its
			// VALIDATION_ERROR prefix and the product ID, and re-wrapping in an
			// unprefixed message would bury the code where the gateway cannot parse
			// it, turning a 400 into a misleading 503.
			return nil, wrap(CodeValidation, err)
		}
		if err := writeMedicine(ctx, medicine); err != nil {
			return nil, err
		}
		result.Recalled++
		result.ProductIDs = append(result.ProductIDs, productID)
	}
	result.MoreRemaining = capReached || scanTruncated

	// The one case repeated calls cannot resolve: a batch bigger than the scan
	// ceiling whose entire scanned prefix is already recalled. more_remaining
	// would stay true while no call could ever reach the units beyond the ceiling,
	// so say so plainly instead of inviting an infinite retry loop.
	if scanTruncated && !capReached && result.Recalled == 0 {
		return nil, coded(CodeValidation,
			"batch %s holds more than %d units and every unit examined is already recalled; "+
				"a batch this large cannot be fully recalled by batch number — recall the "+
				"remaining units individually, and split batches at manufacture",
			trimmedBatch, maxRecallScan)
	}

	if err := emit(ctx, EventBatchRecalled, map[string]interface{}{
		"batch_no":       trimmedBatch,
		"reason":         trimmedReason,
		"recalled":       result.Recalled,
		"more_remaining": result.MoreRemaining,
		"actor_msp":      mspID,
		"timestamp":      timestamp,
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// ── Reads ────────────────────────────────────────────────────────────────────

// MedicineExists reports whether a product ID is registered.
//
// Cheap enough to call before a write, and the negative answer is itself the
// counterfeit signal: a QR bearing a valid signature for a product ID that was
// never minted means a signing key has leaked.
func (c *MedicineContract) MedicineExists(ctx contractapi.TransactionContextInterface, productID string) (bool, error) {
	if err := rules.ValidateProductID(productID); err != nil {
		// A malformed ID cannot exist. Returning false rather than an error means
		// a scanner pointed at an unrelated QR gets a clean answer instead of a
		// stack of validation text.
		return false, nil
	}
	raw, err := ctx.GetStub().GetState(productID)
	if err != nil {
		return false, fmt.Errorf("ledger read failed for %s: %v", productID, err)
	}
	return raw != nil, nil
}

// GetMedicine returns the full record.
func (c *MedicineContract) GetMedicine(ctx contractapi.TransactionContextInterface, productID string) (*Medicine, error) {
	if err := rules.ValidateProductID(productID); err != nil {
		return nil, wrap(CodeValidation, err)
	}
	medicine, found, err := readMedicine(ctx, productID)
	if err != nil {
		return nil, err
	}
	if !found {
		// Empty body, not an error: the gateway treats absence as null so a
		// verify route can promote NOT_ON_CHAIN itself after the signature check.
		return nil, nil
	}
	return medicine, nil
}

// VerifyMedicine evaluates every check the ledger can answer and returns a
// verdict as data.
//
// It never returns an error for a bad outcome — see VerificationSnapshot for the
// reasoning. A missing record yields Found=false with verdict NOT_ON_CHAIN, which
// the API turns into COUNTERFEIT once it knows the QR signature was valid; the
// ledger alone cannot distinguish "counterfeit" from "not registered yet",
// and asserting the stronger claim here would put words in the regulator's mouth.
//
// The signature check is absent by necessity: the chaincode never sees the QR
// payload or its ECDSA signature. Checks 1 and 2 of the contract happen in the
// app and the API; checks 3, 4 and 5 happen here.
func (c *MedicineContract) VerifyMedicine(
	ctx contractapi.TransactionContextInterface,
	productID string,
) (*VerificationSnapshot, error) {
	now, err := ledgerTime(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := &VerificationSnapshot{
		ProductID:  productID,
		VerifiedAt: stamp(now),
		Reasons:    []string{},
	}

	if err := rules.ValidateProductID(productID); err != nil {
		snapshot.Found = false
		snapshot.Verdict = rules.VerdictNotFound
		snapshot.Severity = rules.Severity(rules.VerdictNotFound)
		snapshot.Reasons = append(snapshot.Reasons, err.Error())
		return snapshot, nil
	}

	medicine, found, err := readMedicine(ctx, productID)
	if err != nil {
		return nil, err
	}
	if !found {
		snapshot.Found = false
		snapshot.Verdict = rules.VerdictNotFound
		snapshot.Severity = rules.Severity(rules.VerdictNotFound)
		snapshot.Reasons = append(snapshot.Reasons,
			"this product ID is not registered on the TrueMed ledger")
		return snapshot, nil
	}

	expired, err := rules.IsExpired(medicine.ExpiryDate, now)
	if err != nil {
		// A stored record with an unparseable expiry date is corrupt, not merely
		// expired, and must not be reported as a clean unit.
		return nil, fmt.Errorf("record for %s has an invalid expiry_date: %v", productID, err)
	}
	daysLeft, err := rules.DaysToExpiry(medicine.ExpiryDate, now)
	if err != nil {
		return nil, fmt.Errorf("record for %s has an invalid expiry_date: %v", productID, err)
	}

	districtCount := len(medicine.DistinctScanDistricts)
	cloneSuspected := rules.CloneSuspected(medicine.ScanCount, districtCount)
	verdict := rules.Verdict(medicine.Status, expired, medicine.ColdChainBreached, cloneSuspected)

	if medicine.Status == rules.StatusRecalled {
		reason := medicine.RecallReason
		if reason == "" {
			reason = "no reason recorded"
		}
		snapshot.Reasons = append(snapshot.Reasons,
			fmt.Sprintf("batch %s was recalled by the regulator on %s: %s",
				medicine.BatchNo, medicine.RecalledAt, reason))
	}
	if cloneSuspected {
		snapshot.Reasons = append(snapshot.Reasons, fmt.Sprintf(
			"this code has been scanned %d times across %d districts; one physical pack "+
				"cannot be in that many places, so the QR has probably been copied",
			medicine.ScanCount, districtCount))
	}
	if medicine.ColdChainBreached {
		snapshot.Reasons = append(snapshot.Reasons, fmt.Sprintf(
			"cold chain breach recorded at %s; readings ranged %.1f°C to %.1f°C against a "+
				"required %.0f–%.0f°C, so this vaccine may have lost potency",
			medicine.ColdChainBreachedAt, medicine.TempMinC, medicine.TempMaxC,
			rules.VaccineTempMinC, rules.VaccineTempMaxC))
	}
	if expired {
		snapshot.Reasons = append(snapshot.Reasons, fmt.Sprintf(
			"expired %d day(s) ago on %s", -daysLeft, medicine.ExpiryDate))
	}
	if medicine.Type == rules.TypeVaccine && medicine.TempReadingCount == 0 {
		snapshot.Reasons = append(snapshot.Reasons,
			"no temperature readings have been recorded for this vaccine, so cold-chain "+
				"integrity is unconfirmed")
	}

	snapshot.Found = true
	snapshot.Verdict = verdict
	snapshot.Severity = rules.Severity(verdict)
	snapshot.Expired = expired
	snapshot.DaysToExpiry = daysLeft
	snapshot.Medicine = medicine
	snapshot.ColdChain = medicine.coldChainSummary()
	snapshot.Telemetry = medicine.telemetry()
	return snapshot, nil
}

// GetTemperatureHistory returns the full recorded series for a unit, newest
// first.
//
// Newest first because that is what every caller wants — a dashboard shows the
// last few hours, an investigator looks at what happened most recently — and
// because the ledger keys are ordered to make it cheap. See tempSeqSpace.
func (c *MedicineContract) GetTemperatureHistory(
	ctx contractapi.TransactionContextInterface,
	productID string,
	limit int,
) ([]TemperatureReading, error) {
	if err := rules.ValidateProductID(productID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultPageSize
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	return readTemperatureSeries(ctx, productID, limit)
}

// GetMedicinesByBatch lists the units of a batch.
func (c *MedicineContract) GetMedicinesByBatch(
	ctx contractapi.TransactionContextInterface,
	batchNo string,
) ([]*Medicine, error) {
	if err := rules.ValidateBatchNo(batchNo); err != nil {
		return nil, err
	}
	productIDs, _, err := productIDsInBatch(ctx, strings.TrimSpace(batchNo), maxPageSize)
	if err != nil {
		return nil, err
	}
	medicines := make([]*Medicine, 0, len(productIDs))
	for _, productID := range productIDs {
		medicine, found, err := readMedicine(ctx, productID)
		if err != nil {
			return nil, err
		}
		if found {
			medicines = append(medicines, medicine)
		}
	}
	return medicines, nil
}

// GetMedicinesByStatus lists units in a given custody state, with pagination.
//
// Implemented with a CouchDB rich query, which is why the peers must run with
// CORE_LEDGER_STATE_STATEDATABASE=CouchDB and why META-INF ships index
// definitions. Without those indexes CouchDB answers correctly but with a full
// scan of every document, and the query degrades from milliseconds to minutes as
// the channel grows.
//
// Read-only by construction. Rich queries are not permitted in transactions that
// write, because their result depends on the state database at execution time and
// therefore cannot be re-derived deterministically at validation.
func (c *MedicineContract) GetMedicinesByStatus(
	ctx contractapi.TransactionContextInterface,
	status string,
	pageSize int,
	bookmark string,
) (*MedicinePage, error) {
	if !rules.KnownStatus(status) {
		return nil, coded(CodeValidation,
			"status %q is not one of manufactured, in_transit, at_pharmacy, dispensed, recalled",
			status)
	}
	// status is one of five compile-time constants at this point, so interpolating
	// it into the selector cannot inject anything.
	query := fmt.Sprintf(
		`{"selector":{"doc_type":"%s","status":"%s"},`+
			`"use_index":["_design/indexStatusDoc","indexStatus"]}`,
		docTypeMedicine, status)
	return paginatedQuery(ctx, query, pageSize, bookmark)
}

// GetBreachedVaccines lists vaccines with a recorded cold-chain breach, for the
// CDSCO and health-department dashboards.
func (c *MedicineContract) GetBreachedVaccines(
	ctx contractapi.TransactionContextInterface,
	pageSize int,
	bookmark string,
) (*MedicinePage, error) {
	query := fmt.Sprintf(
		`{"selector":{"doc_type":"%s","type":"%s","cold_chain_breached":true},`+
			`"use_index":["_design/indexBreachDoc","indexBreach"]}`,
		docTypeMedicine, rules.TypeVaccine)
	return paginatedQuery(ctx, query, pageSize, bookmark)
}

// GetAllMedicines lists every unit on the channel, with pagination.
//
// The dashboards need totals — units per status, breach rates, counterfeit
// reports per district — and computing those from a status-filtered query means
// one round trip per status, with the counts drifting between calls because each
// query sees a different state. One paged scan gives a consistent picture.
//
// Paginated with no exception. An unpaged "return everything" would build a
// response proportional to the whole ledger inside the peer's memory, and the
// first thing that grows in this system is the medicine count — a single Indian
// manufacturer ships millions of strips a month. The caller repeats with the
// returned bookmark until it comes back empty.
//
// Reuses indexStatus rather than shipping a third index. Its fields are
// ["doc_type", "status"] and a Mango query may use a compound index when its
// selector covers a leading subset of those fields, so a doc_type-only selector
// is served by it. Every additional index is re-written on every document write,
// so an index that buys nothing is a permanent tax on the write path.
func (c *MedicineContract) GetAllMedicines(
	ctx contractapi.TransactionContextInterface,
	pageSize int,
	bookmark string,
) (*MedicinePage, error) {
	query := fmt.Sprintf(
		`{"selector":{"doc_type":"%s"},`+
			`"use_index":["_design/indexStatusDoc","indexStatus"]}`,
		docTypeMedicine)
	return paginatedQuery(ctx, query, pageSize, bookmark)
}

// paginatedQuery runs a CouchDB selector with bookmark pagination.
func paginatedQuery(
	ctx contractapi.TransactionContextInterface,
	query string,
	pageSize int,
	bookmark string,
) (*MedicinePage, error) {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	iter, metadata, err := ctx.GetStub().GetQueryResultWithPagination(query, int32(pageSize), bookmark)
	if err != nil {
		return nil, fmt.Errorf(
			"rich query failed: %v. This function needs peers configured with CouchDB as the "+
				"state database; with the default LevelDB it cannot work", err)
	}
	defer closeQuietly(iter)

	medicines, err := collectMedicines(iter)
	if err != nil {
		return nil, err
	}

	page := &MedicinePage{Medicines: medicines, Count: len(medicines)}
	if metadata != nil {
		page.Bookmark = metadata.GetBookmark()
	}
	return page, nil
}

// ── Events ───────────────────────────────────────────────────────────────────

// emit publishes a chaincode event.
//
// Payloads carry identifiers and scalars only. An event is stored in the block
// and replicated to every peer forever, so putting a whole record in one doubles
// the ledger cost of every write for data the listener can fetch when it needs it.
func emit(ctx contractapi.TransactionContextInterface, name string, payload map[string]interface{}) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not serialise the %s event: %v", name, err)
	}
	if err := ctx.GetStub().SetEvent(name, encoded); err != nil {
		return fmt.Errorf("could not emit the %s event: %v", name, err)
	}
	return nil
}
