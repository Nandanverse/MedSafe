package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Composite-key namespaces. Fabric prefixes these with U+0000 and joins the
// attributes with the same separator, which is why no attribute may contain one —
// product IDs and batch numbers are validated to a restricted alphabet before
// they ever reach here.
const (
	// batchIndex maps a batch number to its member units, so a recall can find
	// every affected unit without a rich query. A recall must work on a plain
	// LevelDB peer with CouchDB switched off: it is the one operation that runs
	// when something has already gone wrong.
	batchIndex = "batch~product"

	// tempIndex holds the complete temperature series, one ledger key per
	// reading, addressed by product then sequence.
	tempIndex = "temp~product"
)

// tempSeqSpace is the sequence space for temperature keys.
//
// Sequence numbers are stored *descending* — key n is written as
// (tempSeqSpace - n), zero-padded. Fabric iterates composite keys in
// lexicographic order and offers no reverse iterator, and what every caller
// actually wants is the most recent readings. Counting down means the newest
// reading sorts first and a query for the last twenty can stop after twenty rows
// instead of walking a hundred thousand.
const (
	tempSeqSpace = 999999999999
	tempSeqWidth = 12
)

// maxTempReadings is the ceiling implied by the sequence space. Reaching it
// requires a reading every five minutes for nine million years, so the guard
// exists only so the encoding can never silently wrap and overwrite history.
const maxTempReadings = tempSeqSpace - 1

// ── Medicine records ─────────────────────────────────────────────────────────

// readMedicine fetches a unit from world state.
//
// The three-valued return separates "absent" from "broken". Absent is an ordinary
// business outcome — most likely a counterfeit, possibly a stale cache — while a
// record that will not unmarshal is a bug or a corrupted ledger, and collapsing
// the two would hide the second behind the first.
func readMedicine(ctx contractapi.TransactionContextInterface, productID string) (*Medicine, bool, error) {
	raw, err := ctx.GetStub().GetState(productID)
	if err != nil {
		return nil, false, fmt.Errorf("ledger read failed for %s: %v", productID, err)
	}
	if raw == nil {
		return nil, false, nil
	}
	var medicine Medicine
	if err := json.Unmarshal(raw, &medicine); err != nil {
		return nil, false, fmt.Errorf(
			"the stored record for %s is not valid JSON (%v); the ledger may have been "+
				"written by an incompatible chaincode version", productID, err)
	}
	return &medicine, true, nil
}

// mustReadMedicine fetches a unit, treating absence as an error. Used by the
// write paths, where there is nothing sensible to do without the record.
func mustReadMedicine(ctx contractapi.TransactionContextInterface, productID string) (*Medicine, error) {
	medicine, found, err := readMedicine(ctx, productID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, coded(CodeNotOnChain,
			"no unit with product ID %s exists on this channel; it was never registered by "+
				"a manufacturer, which for a code that carries a valid signature means a "+
				"leaked signing key", productID)
	}
	return medicine, nil
}

// writeMedicine serialises and stores a unit.
func writeMedicine(ctx contractapi.TransactionContextInterface, medicine *Medicine) error {
	encoded, err := json.Marshal(medicine)
	if err != nil {
		return fmt.Errorf("could not serialise the record for %s: %v", medicine.ProductID, err)
	}
	if err := ctx.GetStub().PutState(medicine.ProductID, encoded); err != nil {
		return fmt.Errorf("ledger write failed for %s: %v", medicine.ProductID, err)
	}
	return nil
}

// ── Batch index ──────────────────────────────────────────────────────────────

// putBatchIndex records batch membership. The value is a single NUL byte rather
// than the record itself: index entries exist to be iterated, and duplicating
// the payload would double the ledger size and create two copies that can
// disagree.
func putBatchIndex(ctx contractapi.TransactionContextInterface, batchNo, productID string) error {
	key, err := ctx.GetStub().CreateCompositeKey(batchIndex, []string{batchNo, productID})
	if err != nil {
		return fmt.Errorf("could not build the batch index key for %s/%s: %v", batchNo, productID, err)
	}
	if err := ctx.GetStub().PutState(key, []byte{0x00}); err != nil {
		return fmt.Errorf("could not write the batch index entry for %s: %v", productID, err)
	}
	return nil
}

// productIDsInBatch lists the units belonging to a batch.
//
// A range query over a composite key, not a CouchDB rich query. Rich queries are
// forbidden in transactions that write, because their results are not
// reproducible at validation time; a range query records a proper read set and
// is phantom-protected. Since RecallBatch writes, this is the only correct
// mechanism — and it works with CouchDB switched off entirely.
func productIDsInBatch(ctx contractapi.TransactionContextInterface, batchNo string, limit int) ([]string, bool, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(batchIndex, []string{batchNo})
	if err != nil {
		return nil, false, fmt.Errorf("could not scan batch %s: %v", batchNo, err)
	}
	defer closeQuietly(iter)

	var productIDs []string
	truncated := false
	for iter.HasNext() {
		if limit > 0 && len(productIDs) >= limit {
			// A ceiling on the read set, nothing more. It is not the recall batch
			// size — RecallBatch caps its own writes and relies on this scan covering
			// the batch, because a scan that stops early would hand back the same
			// prefix on every call and never reach the units behind it. `truncated`
			// tells the caller the scan was cut short so it can say so rather than
			// silently reporting a partial batch as the whole batch.
			truncated = true
			break
		}
		entry, err := iter.Next()
		if err != nil {
			return nil, false, fmt.Errorf("error while scanning batch %s: %v", batchNo, err)
		}
		_, attributes, err := ctx.GetStub().SplitCompositeKey(entry.GetKey())
		if err != nil {
			return nil, false, fmt.Errorf("malformed batch index key %q: %v", entry.GetKey(), err)
		}
		if len(attributes) != 2 {
			return nil, false, fmt.Errorf(
				"batch index key %q has %d attributes, expected 2", entry.GetKey(), len(attributes))
		}
		productIDs = append(productIDs, attributes[1])
	}
	return productIDs, truncated, nil
}

// ── Temperature series ───────────────────────────────────────────────────────

// tempSequenceKey encodes a descending sequence number.
func tempSequenceKey(sequence int) (string, error) {
	if sequence < 0 || sequence > maxTempReadings {
		return "", fmt.Errorf("temperature sequence %d is outside the encodable range", sequence)
	}
	return fmt.Sprintf("%0*d", tempSeqWidth, tempSeqSpace-sequence), nil
}

// putTemperatureReading stores one reading under its own ledger key.
func putTemperatureReading(
	ctx contractapi.TransactionContextInterface,
	reading TemperatureReading,
	sequence int,
) error {
	sequenceKey, err := tempSequenceKey(sequence)
	if err != nil {
		return err
	}
	key, err := ctx.GetStub().CreateCompositeKey(tempIndex, []string{reading.ProductID, sequenceKey})
	if err != nil {
		return fmt.Errorf("could not build the temperature key for %s: %v", reading.ProductID, err)
	}
	encoded, err := json.Marshal(reading)
	if err != nil {
		return fmt.Errorf("could not serialise the temperature reading: %v", err)
	}
	if err := ctx.GetStub().PutState(key, encoded); err != nil {
		return fmt.Errorf("could not store the temperature reading for %s: %v", reading.ProductID, err)
	}
	return nil
}

// readTemperatureSeries returns up to limit readings, newest first.
func readTemperatureSeries(
	ctx contractapi.TransactionContextInterface,
	productID string,
	limit int,
) ([]TemperatureReading, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(tempIndex, []string{productID})
	if err != nil {
		return nil, fmt.Errorf("could not read the temperature history for %s: %v", productID, err)
	}
	defer closeQuietly(iter)

	// Never nil: an empty JSON array is one shape for clients to handle, whereas
	// null plus array is two.
	readings := make([]TemperatureReading, 0, 16)
	for iter.HasNext() {
		if limit > 0 && len(readings) >= limit {
			break
		}
		entry, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("error while reading temperature history for %s: %v", productID, err)
		}
		var reading TemperatureReading
		if err := json.Unmarshal(entry.GetValue(), &reading); err != nil {
			return nil, fmt.Errorf("stored temperature reading %q is not valid JSON: %v", entry.GetKey(), err)
		}
		readings = append(readings, reading)
	}
	return readings, nil
}

// ── Iterator plumbing ────────────────────────────────────────────────────────

// closeQuietly releases an iterator.
//
// The error is deliberately discarded, and this wrapper exists so that fact is
// stated once rather than repeated at every call site. Close only reports a
// failure to release a peer-side resource; by the time it runs the useful work is
// done, and returning it from a deferred call would either be silently dropped
// anyway or overwrite a real error with a trivial one.
func closeQuietly(iter shim.StateQueryIteratorInterface) {
	if iter != nil {
		_ = iter.Close()
	}
}

// collectMedicines drains an iterator into medicine records.
func collectMedicines(iter shim.StateQueryIteratorInterface) ([]*Medicine, error) {
	medicines := make([]*Medicine, 0, 16)
	for iter.HasNext() {
		entry, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("error while reading query results: %v", err)
		}
		var medicine Medicine
		if err := json.Unmarshal(entry.GetValue(), &medicine); err != nil {
			return nil, fmt.Errorf("stored record %q is not valid JSON: %v", entry.GetKey(), err)
		}
		// Defensive: a rich query whose selector was edited badly could return a
		// temperature reading, which unmarshals into Medicine without error and
		// then appears as a unit with an empty product ID.
		if medicine.DocType != docTypeMedicine {
			continue
		}
		medicines = append(medicines, &medicine)
	}
	return medicines, nil
}
