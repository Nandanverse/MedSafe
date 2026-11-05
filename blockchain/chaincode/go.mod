module github.com/truemed/chaincode

go 1.21

// Only the direct dependency is pinned here. github.com/hyperledger/fabric-chaincode-go
// (used for shim.StateQueryIteratorInterface in keys.go) is resolved by `go mod tidy`
// at the version the contract API already requires, which is safer than pinning a
// pseudo-version by hand: a mismatched pair of these two modules fails to compile
// with an error about an interface that "does not implement" another interface, and
// that error points nowhere near the real cause.
//
// Run `go mod tidy` before the first build. See README.md.
require github.com/hyperledger/fabric-contract-api-go v1.2.1
