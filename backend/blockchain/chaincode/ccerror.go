package main

import (
	"fmt"
	"strings"
)

// Machine-readable prefixes the Node.js gateway parses out of a chaincode
// error. Fabric surfaces a contract error as an opaque endorse failure, so the
// only way the API can distinguish "a distributor tried to mint" (403) from
// "the peer is down" (503) is if the message itself carries the code. These
// strings are the same identifiers as docs/DATA-CONTRACT.md §2.4.
const (
	CodeForbidden  = "FORBIDDEN"
	CodeValidation = "VALIDATION_ERROR"
	CodeNotOnChain = "NOT_ON_CHAIN"
	CodeConflict   = "CONFLICT"
)

func coded(code, format string, args ...interface{}) error {
	return fmt.Errorf("%s: %s", code, fmt.Sprintf(format, args...))
}

func wrap(code string, err error) error {
	if err == nil {
		return nil
	}
	if alreadyCoded(err.Error()) {
		return err
	}
	return fmt.Errorf("%s: %s", code, err.Error())
}

func alreadyCoded(msg string) bool {
	i := strings.IndexByte(msg, ':')
	if i < 3 {
		return false
	}
	switch msg[:i] {
	case CodeForbidden, CodeValidation, CodeNotOnChain, CodeConflict:
		return true
	default:
		return false
	}
}
