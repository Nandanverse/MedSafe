package main

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Membership Service Provider identifiers for the three organisations on the
// TrueMed channel. These are public identity labels, not secrets, so they belong
// in source where they can be reviewed — unlike keys and passwords, which come
// from the environment.
//
// They must match the MSP names in blockchain/network/configtx.yaml exactly. A
// mismatch does not fail loudly at deployment: it fails the first time a
// manufacturer tries to mint, with a permission error that looks like a
// certificate problem.
const (
	MSPManufacturer = "ManufacturerMSP"
	MSPDistributor  = "DistributorMSP"
	MSPRegulator    = "RegulatorMSP"
)

// Why authorisation lives in the chaincode at all.
//
// Fabric already decides who may connect to the channel, and a reasonable first
// reaction is that channel membership is sufficient. It is not. Every member of
// the channel can submit any transaction to it, so without the checks below a
// distributor — or anyone who obtains a distributor's certificate — could mint
// new units, and a pharmacy could recall a competitor's batch. The entire value
// of the ledger is the claim "this unit was registered by its manufacturer and
// nobody else could have said so", and that claim is only true if the contract
// enforces it.
//
// Endorsement policies are the complementary control: they decide how many
// organisations must agree on a result. They cannot express "only the
// manufacturer may call this function", which is why both are needed.

// callerMSP returns the MSP identifier of the submitting identity.
func callerMSP(ctx contractapi.TransactionContextInterface) (string, error) {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("could not determine the caller's organisation: %v", err)
	}
	if mspID == "" {
		// FORBIDDEN rather than an unprefixed internal fault. An identity that
		// presents no MSP cannot match any of the three organisations, so this is a
		// permission outcome, not a transient one: the caller needs a 403 telling
		// them their enrolment is wrong, not a 503 inviting them to retry forever.
		// The line above is different — GetMSPID failing is the stub misbehaving.
		return "", coded(CodeForbidden, "the submitting identity carries no MSP identifier")
	}
	return mspID, nil
}

// requireMSP authorises an operation against a list of permitted organisations,
// returning the caller's MSP so it can be recorded on the ledger.
//
// Every write in this contract stamps the acting MSP onto the record. That is
// what makes the audit trail meaningful after the fact: knowing that a unit moved
// to a pharmacy is much less useful than knowing which organisation said so.
func requireMSP(ctx contractapi.TransactionContextInterface, operation string, allowed ...string) (string, error) {
	mspID, err := callerMSP(ctx)
	if err != nil {
		return "", err
	}
	for _, permitted := range allowed {
		if mspID == permitted {
			return mspID, nil
		}
	}
	return "", coded(CodeForbidden,
		"permission denied: %s is not authorised to call %s (permitted: %s)",
		mspID, operation, strings.Join(allowed, ", "))
}
