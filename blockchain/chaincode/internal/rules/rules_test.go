package rules

import (
	"math"
	"strings"
	"testing"
	"time"
)

// Fixed reference date so no test result depends on the day it is run.
var refTime = time.Date(2026, 6, 1, 12, 30, 0, 0, time.UTC)

// ── Field validation ─────────────────────────────────────────────────────────

func TestValidateProductID(t *testing.T) {
	valid := []string{
		"PARACETAMOL500MG_PARACIP500_2026_000001",
		"A_B_1999_999999",
		"COVISHIELD_COVISHIELD_2026_000042",
	}
	for _, id := range valid {
		if err := ValidateProductID(id); err != nil {
			t.Errorf("ValidateProductID(%q) = %v, want nil", id, err)
		}
	}

	invalid := map[string]string{
		"empty":            "",
		"lowercase":        "paracetamol_paracip_2026_000001",
		"short serial":     "PARA_BRAND_2026_1",
		"long serial":      "PARA_BRAND_2026_0000001",
		"missing segment":  "PARA_BRAND_000001",
		"extra segment":    "PARA_BRAND_2026_000001_X",
		"bad year":         "PARA_BRAND_1899_000001",
		"hyphen":           "PARA-BRAND_2026_000001",
		"trailing newline": "PARA_BRAND_2026_000001\n",
		"leading space":    " PARA_BRAND_2026_000001",
	}
	for name, id := range invalid {
		if err := ValidateProductID(id); err == nil {
			t.Errorf("ValidateProductID rejected nothing for %s (%q)", name, id)
		}
	}
}

func TestValidateProductIDRejectsOverlong(t *testing.T) {
	long := strings.Repeat("A", 40) + "_" + strings.Repeat("B", 40) + "_2026_000001"
	err := ValidateProductID(long)
	if err == nil {
		t.Fatal("expected an over-length product_id to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeding") {
		t.Errorf("error should name the limit, got: %v", err)
	}
}

func TestValidateTextRejectsControlCharacters(t *testing.T) {
	// Newline, NUL, tab, DEL and a carriage return: every one of these is a log
	// or display injection vector, and none appears in a real drug name.
	for _, bad := range []string{"Para\ncip", "Para\x00cip", "Para\tcip", "Para\x7fcip", "Para\rcip"} {
		if err := ValidateText("brand_name", bad, 48); err == nil {
			t.Errorf("ValidateText accepted %q", bad)
		}
	}
}

func TestValidateTextAcceptsDevanagari(t *testing.T) {
	// Phase 2 puts Hindi in these fields. A byte-oriented control-character check
	// must not reject multi-byte printable text.
	if err := ValidateText("manufacturer", "संजीवनी फार्मा, पुणे", MaxManufacturer); err != nil {
		t.Errorf("Devanagari manufacturer rejected: %v", err)
	}
}

func TestValidateTextLimitsAreBytesNotRunes(t *testing.T) {
	// 60 Devanagari characters are 180 bytes. The limit must bite, because what
	// the ledger stores is bytes.
	if err := ValidateText("manufacturer", strings.Repeat("स", 60), MaxManufacturer); err == nil {
		t.Error("expected 180 bytes of Devanagari to exceed the 120-byte manufacturer limit")
	}
}

func TestValidateTextRejectsWhitespaceOnly(t *testing.T) {
	if err := ValidateText("brand_name", "   \t  ", 48); err == nil {
		t.Error("whitespace-only value should be treated as empty")
	}
}

func TestValidateBatchNo(t *testing.T) {
	for _, ok := range []string{"SP26C0417", "AB-1234/26", "B.1", "0001"} {
		if err := ValidateBatchNo(ok); err != nil {
			t.Errorf("ValidateBatchNo(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "-LEADINGDASH", "has space", "semi;colon", strings.Repeat("X", 25)} {
		if err := ValidateBatchNo(bad); err == nil {
			t.Errorf("ValidateBatchNo accepted %q", bad)
		}
	}
}

func TestValidateType(t *testing.T) {
	if err := ValidateType(TypeMedicine); err != nil {
		t.Errorf("medicine rejected: %v", err)
	}
	if err := ValidateType(TypeVaccine); err != nil {
		t.Errorf("vaccine rejected: %v", err)
	}
	for _, bad := range []string{"", "syrup", "Vaccine", "MEDICINE"} {
		if err := ValidateType(bad); err == nil {
			t.Errorf("ValidateType accepted %q", bad)
		}
	}
}

func TestValidateExcipients(t *testing.T) {
	if err := ValidateExcipients(nil); err != nil {
		t.Errorf("an empty excipient list is legitimate, got %v", err)
	}
	if err := ValidateExcipients([]string{"Maize Starch", "Povidone K30"}); err != nil {
		t.Errorf("valid excipients rejected: %v", err)
	}
	tooMany := make([]string, MaxExcipients+1)
	for i := range tooMany {
		tooMany[i] = "Talc"
	}
	if err := ValidateExcipients(tooMany); err == nil {
		t.Error("expected the excipient count limit to be enforced")
	}
	if err := ValidateExcipients([]string{"Starch", ""}); err == nil {
		t.Error("an empty excipient entry should be rejected")
	}
}

// ── Dates ────────────────────────────────────────────────────────────────────

func TestParseDate(t *testing.T) {
	got, err := ParseDate("d", "2028-02-29")
	if err != nil {
		t.Fatalf("leap day rejected: %v", err)
	}
	if got.Year() != 2028 || got.Month() != time.February || got.Day() != 29 {
		t.Errorf("parsed %v, want 2028-02-29", got)
	}
	if got.Location() != time.UTC {
		t.Errorf("parsed date should be UTC, got %v", got.Location())
	}
}

func TestParseDateRejectsLooseForms(t *testing.T) {
	// "2026-3-15" and "20260315" are the two forms a hand-written form produces,
	// and both must be refused rather than silently reinterpreted.
	for _, bad := range []string{"2026-3-15", "20260315", "15-03-2026", "2026-02-30", "2026-13-01", "", "2026-02-29"} {
		if _, err := ParseDate("d", bad); err == nil {
			t.Errorf("ParseDate accepted %q", bad)
		}
	}
}

func TestValidateDateOrder(t *testing.T) {
	if err := ValidateDateOrder("2026-01-15", "2028-01-14"); err != nil {
		t.Errorf("valid date pair rejected: %v", err)
	}
	if err := ValidateDateOrder("2026-06-01", "2026-05-01"); err == nil {
		t.Error("expiry before manufacture should be rejected")
	}
	if err := ValidateDateOrder("2026-06-01", "2026-06-01"); err == nil {
		t.Error("expiry equal to manufacture should be rejected")
	}
}

func TestExpiryDayItselfIsValid(t *testing.T) {
	// The single most consequential boundary in the system: a pharmacist reading
	// "EXP 06/2026" dispenses on the last day of validity.
	expired, err := IsExpired("2026-06-01", refTime)
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		t.Error("a unit expiring today must not be reported as expired")
	}
	days, err := DaysToExpiry("2026-06-01", refTime)
	if err != nil {
		t.Fatal(err)
	}
	if days != 0 {
		t.Errorf("DaysToExpiry on the expiry day = %d, want 0", days)
	}
}

func TestDayAfterExpiryIsExpired(t *testing.T) {
	expired, err := IsExpired("2026-05-31", refTime)
	if err != nil {
		t.Fatal(err)
	}
	if !expired {
		t.Error("a unit whose expiry was yesterday must be reported as expired")
	}
	days, err := DaysToExpiry("2026-05-31", refTime)
	if err != nil {
		t.Fatal(err)
	}
	if days != -1 {
		t.Errorf("DaysToExpiry the day after expiry = %d, want -1", days)
	}
}

func TestExpiryIgnoresTimeOfDay(t *testing.T) {
	// Late in the evening of the expiry date the unit is still valid. If the
	// comparison used the raw timestamp instead of the truncated date, a unit
	// would expire at 00:00:01 on its own expiry day.
	lateEvening := time.Date(2026, 6, 1, 23, 59, 59, 0, time.UTC)
	expired, err := IsExpired("2026-06-01", lateEvening)
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		t.Error("time of day must not affect expiry")
	}
}

func TestDaysToExpiryCountsForward(t *testing.T) {
	days, err := DaysToExpiry("2026-07-01", refTime)
	if err != nil {
		t.Fatal(err)
	}
	if days != 30 {
		t.Errorf("DaysToExpiry = %d, want 30", days)
	}
}

// ── Custody state machine ────────────────────────────────────────────────────

func TestForwardTransitionsAllowed(t *testing.T) {
	pairs := [][2]string{
		{StatusManufactured, StatusInTransit},
		{StatusManufactured, StatusAtPharmacy},
		{StatusInTransit, StatusInTransit},
		{StatusInTransit, StatusAtPharmacy},
		{StatusInTransit, StatusDispensed},
		{StatusAtPharmacy, StatusDispensed},
	}
	for _, p := range pairs {
		if err := ValidateTransition(p[0], p[1]); err != nil {
			t.Errorf("ValidateTransition(%s, %s) = %v, want nil", p[0], p[1], err)
		}
	}
}

func TestBackwardTransitionsRejected(t *testing.T) {
	pairs := [][2]string{
		{StatusInTransit, StatusManufactured},
		{StatusAtPharmacy, StatusInTransit},
		{StatusAtPharmacy, StatusManufactured},
	}
	for _, p := range pairs {
		err := ValidateTransition(p[0], p[1])
		if err == nil {
			t.Errorf("ValidateTransition(%s, %s) allowed a backward hop", p[0], p[1])
		}
	}
}

func TestTerminalStatesAreFinal(t *testing.T) {
	for _, from := range []string{StatusDispensed, StatusRecalled} {
		for _, to := range []string{StatusInTransit, StatusAtPharmacy, StatusDispensed, StatusRecalled} {
			if err := ValidateTransition(from, to); err == nil {
				t.Errorf("ValidateTransition(%s, %s) should be refused: %s is terminal", from, to, from)
			}
		}
	}
}

func TestRecallReachableFromAnyLiveState(t *testing.T) {
	for _, from := range []string{StatusManufactured, StatusInTransit, StatusAtPharmacy} {
		if err := ValidateTransition(from, StatusRecalled); err != nil {
			t.Errorf("a regulator must be able to recall from %s: %v", from, err)
		}
	}
}

func TestRepeatOnlyPermittedForInTransit(t *testing.T) {
	if err := ValidateTransition(StatusInTransit, StatusInTransit); err != nil {
		t.Errorf("consecutive in_transit hops are legitimate: %v", err)
	}
	if err := ValidateTransition(StatusAtPharmacy, StatusAtPharmacy); err == nil {
		t.Error("a duplicate at_pharmacy submission should be refused")
	}
}

func TestUnknownStatusRejected(t *testing.T) {
	if err := ValidateTransition(StatusInTransit, "sold"); err == nil {
		t.Error("an unknown target status should be refused")
	}
	if err := ValidateTransition("corrupt", StatusInTransit); err == nil {
		t.Error("an unknown stored status should be refused")
	}
	if KnownStatus("sold") {
		t.Error("KnownStatus should not accept an invented status")
	}
}

// ── Cold chain ───────────────────────────────────────────────────────────────

func TestColdChainBoundariesAreInclusive(t *testing.T) {
	// Exactly 2.0 and exactly 8.0 are compliant. Off-by-one here means either
	// discarding good vaccine or passing spoiled vaccine, and both cost lives.
	for _, ok := range []float64{2.0, 4.5, 8.0, 7.999} {
		if BreachesColdChain(TypeVaccine, ok) {
			t.Errorf("%.3f°C should be inside the 2–8°C cold chain", ok)
		}
	}
	for _, bad := range []float64{1.999, -10, 8.001, 25} {
		if !BreachesColdChain(TypeVaccine, bad) {
			t.Errorf("%.3f°C should breach the 2–8°C cold chain", bad)
		}
	}
}

func TestMedicinesNeverBreachColdChain(t *testing.T) {
	// Temperature is still logged for tablets, but 30 °C does not spoil them and
	// flagging it would drown real vaccine excursions in noise.
	for _, temp := range []float64{-20, 0, 25, 45} {
		if BreachesColdChain(TypeMedicine, temp) {
			t.Errorf("a tablet at %.1f°C must not be flagged as a cold-chain breach", temp)
		}
	}
}

func TestValidateTemperatureRejectsSensorFaults(t *testing.T) {
	// The two values a disconnected DS18B20 actually reports.
	for _, fault := range []float64{-127, 85.5 + 100, 1000, -273} {
		if err := ValidateTemperature(fault); err == nil {
			t.Errorf("ValidateTemperature accepted the implausible reading %.1f", fault)
		}
	}
	for _, ok := range []float64{-55, -10, 0, 4.5, 37, 125} {
		if err := ValidateTemperature(ok); err != nil {
			t.Errorf("ValidateTemperature(%.1f) = %v, want nil", ok, err)
		}
	}
}

func TestValidateTemperatureRejectsNaN(t *testing.T) {
	// NaN fails every range comparison, so without an explicit check it would
	// sail through and poison the min/max aggregates permanently.
	if err := ValidateTemperature(math.NaN()); err == nil {
		t.Error("NaN must be rejected")
	}
	if err := ValidateTemperature(math.Inf(1)); err == nil {
		t.Error("+Inf must be rejected")
	}
	if err := ValidateTemperature(math.Inf(-1)); err == nil {
		t.Error("-Inf must be rejected")
	}
}

func TestValidateRecordedAt(t *testing.T) {
	got, err := ValidateRecordedAt("2026-06-01T10:00:00Z", refTime)
	if err != nil {
		t.Fatalf("a reading from earlier today was rejected: %v", err)
	}
	if !got.Equal(time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("parsed %v, want 2026-06-01T10:00:00Z", got)
	}
}

func TestValidateRecordedAtAcceptsBufferedBacklog(t *testing.T) {
	// A sensor that lost WiFi for three days flushes its SPIFFS buffer on
	// reconnect. Refusing those readings would erase exactly the outage window in
	// which an excursion is most likely.
	threeDaysAgo := refTime.Add(-72 * time.Hour).Format(time.RFC3339)
	if _, err := ValidateRecordedAt(threeDaysAgo, refTime); err != nil {
		t.Errorf("a three-day-old buffered reading should be accepted: %v", err)
	}
}

func TestValidateRecordedAtRejectsFutureAndAncient(t *testing.T) {
	future := refTime.Add(2 * time.Hour).Format(time.RFC3339)
	if _, err := ValidateRecordedAt(future, refTime); err == nil {
		t.Error("a reading two hours in the future should be rejected")
	}
	ancient := refTime.Add(-60 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := ValidateRecordedAt(ancient, refTime); err == nil {
		t.Error("a sixty-day-old reading should be rejected")
	}
	// Small skew is tolerated: cheap ESP32 clocks drift between NTP syncs.
	slightlyAhead := refTime.Add(5 * time.Minute).Format(time.RFC3339)
	if _, err := ValidateRecordedAt(slightlyAhead, refTime); err != nil {
		t.Errorf("five minutes of clock skew should be tolerated: %v", err)
	}
}

func TestValidateRecordedAtRejectsNonRFC3339(t *testing.T) {
	for _, bad := range []string{"", "2026-06-01", "01/06/2026 10:00", "1748772000"} {
		if _, err := ValidateRecordedAt(bad, refTime); err == nil {
			t.Errorf("ValidateRecordedAt accepted %q", bad)
		}
	}
}

// ── Clone heuristic and verdict precedence ───────────────────────────────────

func TestCloneSuspected(t *testing.T) {
	cases := []struct {
		scans     int
		districts int
		want      bool
	}{
		{0, 0, false},
		{3, 1, false},
		{CloneScanThreshold, CloneDistrictThreshold, false}, // at the threshold, not over
		{CloneScanThreshold + 1, 1, true},
		{2, CloneDistrictThreshold + 1, true},
		{400, 14, true},
	}
	for _, c := range cases {
		if got := CloneSuspected(c.scans, c.districts); got != c.want {
			t.Errorf("CloneSuspected(%d, %d) = %v, want %v", c.scans, c.districts, got, c.want)
		}
	}
}

func TestVerdictPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		status    string
		expired   bool
		breached  bool
		clone     bool
		want      string
	}{
		{"clean", StatusAtPharmacy, false, false, false, VerdictGenuine},
		{"expired only", StatusAtPharmacy, true, false, false, VerdictExpired},
		{"breach only", StatusAtPharmacy, false, true, false, VerdictColdChain},
		{"clone only", StatusAtPharmacy, false, false, true, VerdictClone},
		{"recalled only", StatusRecalled, false, false, false, VerdictRecalled},
		{"breach beats expiry", StatusAtPharmacy, true, true, false, VerdictColdChain},
		{"clone beats breach", StatusAtPharmacy, false, true, true, VerdictClone},
		{"recall beats clone", StatusRecalled, true, true, true, VerdictRecalled},
	}
	for _, c := range cases {
		got := Verdict(c.status, c.expired, c.breached, c.clone)
		if got != c.want {
			t.Errorf("%s: Verdict = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSeverityMapping(t *testing.T) {
	// Only GENUINE may be green. Everything else must make a pharmacist pause.
	if Severity(VerdictGenuine) != SeverityOK {
		t.Error("GENUINE must be ok")
	}
	for _, v := range []string{VerdictRecalled, VerdictClone, VerdictColdChain} {
		if Severity(v) != SeverityCritical {
			t.Errorf("%s must be critical", v)
		}
	}
	for _, v := range []string{VerdictExpired, VerdictNotFound} {
		if Severity(v) != SeverityWarn {
			t.Errorf("%s must be warn", v)
		}
	}
	if Severity("SOMETHING_NEW") != SeverityWarn {
		t.Error("an unrecognised verdict must default to warn, never to ok")
	}
}

func TestSeverityNeverDefaultsToOK(t *testing.T) {
	// Regression guard for the fail-open case: if a future verdict is added and
	// the Severity switch is not updated, it must not render as a green tick.
	for _, v := range []string{"", "UNKNOWN", "genuine", "Genuine"} {
		if Severity(v) == SeverityOK {
			t.Errorf("Severity(%q) returned ok; unknown verdicts must fail safe", v)
		}
	}
}

// ── Invariants shared with the Python reference implementation ───────────────

func TestThresholdsMatchPythonReference(t *testing.T) {
	// These four numbers appear in qr-generator/truemed_qr/verifier.py and
	// payload.py. If either side changes, the app and the ledger will disagree
	// about the same physical unit, so the constants are asserted explicitly
	// rather than merely used.
	if CloneScanThreshold != 25 {
		t.Errorf("CloneScanThreshold = %d, want 25 to match verifier.py", CloneScanThreshold)
	}
	if CloneDistrictThreshold != 3 {
		t.Errorf("CloneDistrictThreshold = %d, want 3 to match verifier.py", CloneDistrictThreshold)
	}
	if VaccineTempMinC != 2.0 || VaccineTempMaxC != 8.0 {
		t.Errorf("cold chain = %.1f–%.1f, want 2.0–8.0 to match payload.py",
			VaccineTempMinC, VaccineTempMaxC)
	}
}
