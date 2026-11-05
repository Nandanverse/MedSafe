// TrueMed - what the device decides between samples.
//
// Every decision a cold box makes about power, alarms and uploads lives here as a
// pure function over an explicit state struct, so the whole schedule can be
// simulated on a host in microseconds instead of observed in a fridge over three
// days.
//
// The one rule that overrides everything else in this file: a reading is evidence
// and is *never* suppressed. Debounce, hysteresis and backoff govern the buzzer,
// the radio and the sleep timer - never whether a measurement is recorded. A
// warm vaccine that reports 4 degC is the single failure this project exists to
// catch, so any logic that could drop an inconvenient sample is a bug by
// construction.

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace truemed {

// The vaccine safe window, matching VACCINE_TEMP_MIN_C / VACCINE_TEMP_MAX_C in
// rules.js (2.0 .. 8.0 degC inclusive). The server makes the authoritative
// cold-chain determination; this copy exists so the box can scream locally when
// the network is down, which is most of the time in the deployments that matter.
constexpr int64_t kVaccineMinHundredths = 200;
constexpr int64_t kVaccineMaxHundredths = 800;

// One sample every 5 minutes, as DATA-CONTRACT.md and the project brief specify.
constexpr uint32_t kSampleIntervalSeconds = 300;

// Consecutive out-of-window samples needed to raise the local alarm, and
// consecutive in-window samples needed to clear it. Asymmetric on purpose:
// opening the cold box door spikes the probe for a minute or two, and an alarm
// that shrieks every time a nurse takes out a vial is an alarm that gets
// unplugged - which is a far worse outcome than a 10-minute delay. Clearing is
// slower than raising because the cost of a missed excursion beats the cost of a
// late all-clear.
constexpr uint8_t kSamplesToRaiseAlarm = 2;   // 10 minutes out of window
constexpr uint8_t kSamplesToClearAlarm = 3;   // 15 minutes back in window

// Upload cadence when nothing is wrong. Batching is what makes the battery last:
// the WiFi radio dominates the energy budget, so six samples per connection turns
// 288 radio wake-ups a day into 48.
constexpr uint16_t kSamplesPerUpload = 6;     // every 30 minutes

// Force a connection attempt once the backlog reaches this depth, regardless of
// cadence, so a long outage drains rather than only ever growing.
constexpr size_t kForceUploadQueueDepth = 60;  // 5 hours of samples

// Records to send per wake-up. Bounded so one wake-up cannot exhaust the battery
// or the server's rate limit while draining a week-old backlog.
constexpr size_t kMaxUploadsPerWake = 12;

// The server rejects recorded_at older than MAX_RECORDED_AT_AGE_MS (30 days), so
// retrying anything older burns radio energy on a guaranteed 400. Dropped one day
// early to leave room for clock skew and for the time a batch spends in transit.
constexpr int64_t kMaxBacklogAgeSeconds = 29 * 24 * 60 * 60;

// Exponential backoff on the *radio*, never on sampling. Expressed in samples so
// it composes with the fixed 5-minute wake-up: 1, 2, 4, 8, 12, 12, ... samples
// skipped, i.e. up to an hour between attempts.
constexpr uint8_t kMaxBackoffSamples = 12;

// Battery curve endpoints for a single LiPo cell behind a 2:1 divider.
constexpr int kBatteryEmptyMillivolts = 3300;
constexpr int kBatteryFullMillivolts = 4200;

enum class AlarmState : uint8_t { kNormal = 0, kBreach = 1 };

// Everything the scheduler must remember across a deep sleep. Small and
// trivially copyable so it fits in RTC_DATA_ATTR memory, which survives deep
// sleep but not a power cut - see board.h for what happens then.
struct PolicyState {
  AlarmState alarm = AlarmState::kNormal;
  uint8_t consecutiveOutOfWindow = 0;
  uint8_t consecutiveInWindow = 0;
  uint16_t samplesSinceUpload = 0;
  uint16_t samplesSinceAttempt = 0;
  uint8_t consecutiveUploadFailures = 0;
  // Diagnostics for the console's `status` command. Counters, never used in a
  // decision.
  uint32_t sensorFaults = 0;
  uint32_t droppedTooOld = 0;
  uint32_t uploadsSucceeded = 0;
};

struct SampleOutcome {
  bool sensorFault = false;   // bus read failed, or a value outside -55..125
  bool storeReading = false;  // false only on a sensor fault: there is no reading
  bool breachEntered = false; // rising edge - light the LED, sound the buzzer
  bool breachCleared = false; // falling edge - silence it
  bool alarmActive = false;   // current latch state, for the LED each wake-up
  bool uploadNow = false;     // attempt a connection this wake-up
};

// Fold one sample into the state machine.
//
// `sensorOk` false means the DS18B20 did not answer; `tempHundredths` is then
// ignored. `queueDepth` is the number of records currently waiting, including the
// one this call is about to store.
SampleOutcome observeSample(PolicyState* state, bool sensorOk, int64_t tempHundredths,
                            size_t queueDepth);

// Record the result of an upload attempt. Success resets the backoff; failure
// grows it. Kept separate from observeSample because the attempt happens after
// it, and a state machine that guessed the outcome in advance would be lying.
void noteUploadResult(PolicyState* state, bool success);

// True when a reading is outside the vaccine window. No hysteresis - this is the
// raw predicate, used for the per-reading flag; the latch is in observeSample.
bool isVaccineBreach(int64_t tempHundredths);

// True when the value cannot be a real measurement (outside the DS18B20's rated
// range), which means a wiring fault rather than a cold-chain event.
bool isSensorFaultValue(int64_t tempHundredths);

// How long to sleep so that wake-ups land on the sampling cadence, given how long
// this wake-up has already been awake. Never returns 0 - a zero-length deep sleep
// is a reboot loop - and never returns more than the interval.
uint32_t sleepSecondsAfter(uint32_t awakeMilliseconds);

// True if a queued record is older than the server's backfill window and must be
// discarded rather than retried forever. `recordedAt` and `nowEpoch` are both UTC
// epoch seconds; a boot-relative record is never too old because it has not been
// dated yet.
bool isBacklogTooOld(int64_t recordedAt, int64_t nowEpoch);

// Approximate state of charge, 0..100. Deliberately crude: battery_pct is outside
// the MAC, is operational telemetry only, and DATA-CONTRACT.md 4.7 forbids using
// it in any safety decision. Returns Reading::kBatteryUnknown (-1) for a reading
// that cannot be a battery at all, so the field is omitted rather than guessed.
int batteryPctFromMillivolts(int millivolts);

}  // namespace truemed
