package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// main starts the chaincode process.
//
// The peer launches this binary in its own container and talks to it over gRPC;
// it is never run by hand. Any error here is fatal by design — a chaincode that
// starts in a half-configured state would endorse transactions it cannot
// evaluate, so failing to start is the safe outcome.
//
// MedicineContract deliberately leaves contractapi.Contract.Name unset. The
// framework then registers it under its type name and makes it the default
// contract, so both invocation forms work:
//
//	peer chaincode invoke ... -c '{"function":"CreateMedicine","Args":["{...}"]}'
//	peer chaincode invoke ... -c '{"function":"MedicineContract:CreateMedicine","Args":["{...}"]}'
//
// The short form is what the Node.js SDK in the backend uses.
func main() {
	chaincode, err := contractapi.NewChaincode(new(MedicineContract))
	if err != nil {
		log.Panicf("TrueMed chaincode could not be created: %v", err)
	}
	if err := chaincode.Start(); err != nil {
		log.Panicf("TrueMed chaincode could not be started: %v", err)
	}
}
