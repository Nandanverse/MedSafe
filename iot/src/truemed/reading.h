// TrueMed - the reading: what a sensor measured, what it signs, what it stores.
//
// A Reading is the single unit of evidence this device produces. Three
// representations have to agree exactly and this file is the only place that
// converts between them:
//
//   1. the MAC input     - DATA-CONTRACT.md 4.7, the bytes the HMAC covers
//   2. the JSON body     - POST /api/temperature, 4.5
//   3. the queue record  - one line of LittleFS, for readings taken offline
//
// Two decisions worth stating, because both had a tempting alternative:
//
// Temperature is stored as an integer count of hundredths, not a double. The
// double from the DS18B20 driver is quantised once, at capture, and every later
// use formats that integer. The MAC covers a 2-decimal string, so if the queue
// stored a float there would be a second rounding step between capture and send
// and any disagreement between the two would surface as UNAUTHORIZED on a reading
// the device itself produced - undebuggable in the field.
//
// The queue stores unsigned records and the MAC is computed at send time, rather
// than storing a finished, signed body. That is deliberate: a device in a rural
// PHC routinely boots during a power cut with no WiFi and therefore no NTP, so it
// has no idea what time it is. Storing structured records lets those readings
// keep a boot-relative timestamp and be rebased onto real time once the clock is
// finally set (see rebaseToAbsolute), which turns "the outage we have no data
// for" into "the outage we have data for". Signing at capture instead would mean
// discarding exactly the readings that matter most. The device's own flash is
// inside the trust boundary anyway - an attacker who can rewrite it can also read
// the secret out of NVS, so signing earlier buys nothing.

#pragma once

#include <stdint.h>

#include <string>

namespace truemed {

// The DS18B20's rated range, matching SENSOR_TEMP_MIN_C/MAX_C in rules.js. A
// value outside this is a wiring fault or a dead bus, not a cold-chain event, and
// the server rejects it with VALIDATION_ERROR.
constexpr int64_t kSensorMinHundredths = -5500;
constexpr int64_t kSensorMaxHundredths = 12500;

// LIMITS in rules.js. Exceeding these is a client bug; the server would 400.
constexpr size_t kMaxProductIdLen = 80;
constexpr size_t kMaxBatchNoLen = 24;
constexpr size_t kMaxSensorIdLen = 32;

// Whether this cold box is bound to one unit or to a whole batch. DATA-CONTRACT
// 4.7: the MAC covers whichever key the body carries, so the two cases cannot
// collide into the same input.
enum class BindingKind : uint8_t { kProductId = 0, kBatchNo = 1 };

enum class ReadingProblem : uint8_t {
  kNone = 0,
  kBindingMissing,
  kBindingTooLong,
  kBindingCharset,
  kSensorIdInvalid,
  kTemperatureOutOfRange,
  kTimeNotAbsolute,
  kTimeUnrepresentable,
  kNonceInvalid,
  kBatteryOutOfRange,
};

// A short human-readable reason, for the serial log. Never null.
const char* describe(ReadingProblem problem);

struct Reading {
  BindingKind bindingKind = BindingKind::kProductId;
  std::string binding;   // product_id, or batch_no when bindingKind says so
  std::string sensorId;  // TM-SENSOR-{NNN}

  // Hundredths of a degree Celsius. Quantised once from the driver's double by
  // quantiseHundredths(); never re-derived from a float after that.
  int64_t tempHundredths = 0;

  // When false, `recordedAt` is seconds since boot and the reading is not yet
  // sendable - it is waiting for the clock. When true, `recordedAt` is a UTC
  // epoch in seconds.
  bool timeIsAbsolute = false;
  int64_t recordedAt = 0;

  // 0..100, or kBatteryUnknown to omit the field entirely rather than send a
  // guess. battery_pct is outside the MAC and must not influence any safety
  // decision (DATA-CONTRACT 4.7).
  static constexpr int kBatteryUnknown = -1;
  int batteryPct = kBatteryUnknown;

  std::string nonce;  // 32 lowercase hex chars from the hardware RNG

  // The 2-decimal string that both the MAC and the JSON number use.
  std::string temp2dp() const;

  // "YYYY-MM-DDTHH:MM:SSZ", or "" if the time is still boot-relative.
  std::string recordedAtIso() const;

  bool isVaccineBreach(int64_t minHundredths, int64_t maxHundredths) const {
    return tempHundredths < minHundredths || tempHundredths > maxHundredths;
  }
};

// Structural validation: everything the server would reject with a 400, checked
// before spending radio energy. Vaccine-range policy is *not* here - a reading of
// 25 degC is perfectly valid data reporting a serious problem, and policy.cpp
// decides what to do about it.
ReadingProblem validate(const Reading& reading);

// DATA-CONTRACT.md 4.7:
//   binding "|" sensor_id "|" temp2dp "|" recorded_at "|" nonce
// Returns "" if the reading is not sendable, so a caller cannot accidentally sign
// a boot-relative timestamp.
std::string macInput(const Reading& reading);

// Lowercase hex HMAC-SHA256 of macInput() under the per-device shared secret.
// Returns "" for an unsendable reading.
std::string signReading(const Reading& reading, const std::string& sensorSecret);

// The exact POST /api/temperature body. `hmacHex` comes from signReading().
// Returns "" if the reading is unsendable or the MAC is not 64 hex characters.
std::string jsonBody(const Reading& reading, const std::string& hmacHex);

// One line of the offline queue, without the trailing newline. Includes a CRC-32
// so that a record truncated by a power cut mid-append is detected and dropped
// individually instead of poisoning the file.
std::string serialiseRecord(const Reading& reading);

// Parses a line written by serialiseRecord. Returns false - leaving `out`
// untouched - on a bad CRC, a wrong field count, or any field the validator would
// reject. A false return always means "drop this record", never "retry".
bool parseRecord(const std::string& line, Reading* out);

// Rebase a boot-relative reading onto real time, given the epoch that corresponds
// to boot (that is, ntpEpoch - uptimeSecondsAtSync). No-op for a reading that is
// already absolute. Returns false if the result would be negative or the reading
// was not boot-relative to begin with.
bool rebaseToAbsolute(Reading* reading, int64_t bootEpochSeconds);

// True if `text` is a plausible product_id: the same shape payload.js accepts,
// deliberately no stricter, because a binding this firmware refuses is a cold box
// that cannot be provisioned for genuine stock.
bool isValidProductId(const std::string& text);

// batch_no is manufacturer-defined and the server only bounds its length, so this
// is permissive by design. It does reject '|' and control characters, because the
// queue record is pipe-delimited - the console explains that at provisioning time
// rather than letting it corrupt a record later.
bool isValidBatchNo(const std::string& text);

bool isValidSensorId(const std::string& text);

}  // namespace truemed
