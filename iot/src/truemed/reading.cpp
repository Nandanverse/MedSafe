#include "truemed/reading.h"

#include <vector>

#include "truemed/crypto.h"
#include "truemed/format.h"

namespace truemed {
namespace {

const char kRecordTag[] = "TMR1";
constexpr char kFieldSep = '|';
constexpr size_t kRecordFieldCount = 9;
constexpr size_t kHmacHexLen = 64;

constexpr uint8_t kFlagBatchBinding = 0x01;
constexpr uint8_t kFlagAbsoluteTime = 0x02;

bool isUpperAlnum(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

bool isDigit(char c) { return c >= '0' && c <= '9'; }

bool isControlChar(unsigned char c) {
  // C0 and DEL/C1, matching findControlChar in rules.js. Nothing that could
  // corrupt a serial log or an HTTP header may reach the wire.
  return c < 0x20 || (c >= 0x7f && c <= 0x9f);
}

std::vector<std::string> splitFields(const std::string& line, char sep) {
  std::vector<std::string> parts;
  std::string current;
  for (size_t i = 0; i < line.size(); ++i) {
    if (line[i] == sep) {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(line[i]);
    }
  }
  parts.push_back(current);
  return parts;
}

bool isLowerHexOfLength(const std::string& text, size_t len) {
  if (text.size() != len) return false;
  for (size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

void appendJsonStringField(std::string* out, const char* key, const std::string& value) {
  out->push_back('"');
  *out += key;
  *out += "\":\"";
  *out += escapeJsonString(value);
  out->push_back('"');
}

}  // namespace

const char* describe(ReadingProblem problem) {
  switch (problem) {
    case ReadingProblem::kNone:
      return "ok";
    case ReadingProblem::kBindingMissing:
      return "no product_id or batch_no provisioned";
    case ReadingProblem::kBindingTooLong:
      return "binding exceeds the server's length limit";
    case ReadingProblem::kBindingCharset:
      return "binding has characters this firmware cannot store";
    case ReadingProblem::kSensorIdInvalid:
      return "sensor_id is not TM-SENSOR-{NNN}";
    case ReadingProblem::kTemperatureOutOfRange:
      return "temperature outside the DS18B20 rated range (sensor fault)";
    case ReadingProblem::kTimeNotAbsolute:
      return "clock not set yet, reading is still boot-relative";
    case ReadingProblem::kTimeUnrepresentable:
      return "timestamp cannot be written as YYYY-MM-DDTHH:MM:SSZ";
    case ReadingProblem::kNonceInvalid:
      return "nonce is not 8-64 lowercase hex characters";
    case ReadingProblem::kBatteryOutOfRange:
      return "battery_pct outside 0..100";
  }
  return "unknown problem";
}

bool isValidProductId(const std::string& text) {
  // ^[A-Z0-9]+_[A-Z0-9]+_\d{4}_\d{6}$ - the same shape as PRODUCT_ID_RE in
  // rules.js and _PRODUCT_ID_RE in payload.py, with the same unbounded first two
  // segments and the same permissive 4-digit year. Overall length is bounded
  // separately by LIMITS.product_id, exactly as the other two do it.
  if (text.empty() || text.size() > kMaxProductIdLen) return false;

  // Walk backwards: the tail is fixed-width, which makes the check unambiguous
  // without a regex engine. Tail is "_YYYY_NNNNNN" = 12 characters.
  if (text.size() < 1 + 1 + 1 + 12) return false;  // a_b_YYYY_NNNNNN at minimum
  const size_t tailStart = text.size() - 12;
  if (text[tailStart] != '_' || text[tailStart + 5] != '_') return false;
  for (size_t i = tailStart + 1; i < tailStart + 5; ++i) {
    if (!isDigit(text[i])) return false;
  }
  for (size_t i = tailStart + 6; i < text.size(); ++i) {
    if (!isDigit(text[i])) return false;
  }

  // The head must be exactly [A-Z0-9]+_[A-Z0-9]+ with one separator.
  size_t underscore = std::string::npos;
  for (size_t i = 0; i < tailStart; ++i) {
    const char c = text[i];
    if (c == '_') {
      if (underscore != std::string::npos) return false;  // a second separator
      underscore = i;
    } else if (!isUpperAlnum(c)) {
      return false;
    }
  }
  if (underscore == std::string::npos) return false;
  if (underscore == 0 || underscore == tailStart - 1) return false;  // empty segment
  return true;
}

bool isValidBatchNo(const std::string& text) {
  if (text.empty() || text.size() > kMaxBatchNoLen) return false;
  for (size_t i = 0; i < text.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(text[i]);
    if (isControlChar(c)) return false;
    // The queue record is pipe-delimited, so a batch number containing '|' cannot
    // round-trip through flash. The console refuses it at provisioning time with
    // that explanation, which is far better than a record that fails its CRC days
    // later inside a cold box.
    if (c == static_cast<unsigned char>(kFieldSep)) return false;
  }
  return true;
}

bool isValidSensorId(const std::string& text) {
  // ^TM-SENSOR-[A-Z0-9]{2,12}$
  const char kPrefix[] = "TM-SENSOR-";
  const size_t prefixLen = sizeof(kPrefix) - 1;
  if (text.size() > kMaxSensorIdLen) return false;
  if (text.size() < prefixLen + 2 || text.size() > prefixLen + 12) return false;
  for (size_t i = 0; i < prefixLen; ++i) {
    if (text[i] != kPrefix[i]) return false;
  }
  for (size_t i = prefixLen; i < text.size(); ++i) {
    if (!isUpperAlnum(text[i])) return false;
  }
  return true;
}

std::string Reading::temp2dp() const { return formatHundredths(tempHundredths); }

std::string Reading::recordedAtIso() const {
  if (!timeIsAbsolute) return std::string();
  return formatRfc3339(recordedAt);
}

ReadingProblem validate(const Reading& reading) {
  if (reading.binding.empty()) return ReadingProblem::kBindingMissing;
  if (reading.bindingKind == BindingKind::kProductId) {
    if (reading.binding.size() > kMaxProductIdLen) return ReadingProblem::kBindingTooLong;
    if (!isValidProductId(reading.binding)) return ReadingProblem::kBindingCharset;
  } else {
    if (reading.binding.size() > kMaxBatchNoLen) return ReadingProblem::kBindingTooLong;
    if (!isValidBatchNo(reading.binding)) return ReadingProblem::kBindingCharset;
  }

  if (!isValidSensorId(reading.sensorId)) return ReadingProblem::kSensorIdInvalid;

  if (reading.tempHundredths < kSensorMinHundredths ||
      reading.tempHundredths > kSensorMaxHundredths) {
    return ReadingProblem::kTemperatureOutOfRange;
  }

  if (!reading.timeIsAbsolute) return ReadingProblem::kTimeNotAbsolute;
  if (reading.recordedAtIso().empty()) return ReadingProblem::kTimeUnrepresentable;

  if (!isContractNonce(reading.nonce)) return ReadingProblem::kNonceInvalid;

  if (reading.batteryPct != Reading::kBatteryUnknown &&
      (reading.batteryPct < 0 || reading.batteryPct > 100)) {
    return ReadingProblem::kBatteryOutOfRange;
  }

  return ReadingProblem::kNone;
}

std::string macInput(const Reading& reading) {
  if (validate(reading) != ReadingProblem::kNone) return std::string();

  std::string out;
  out.reserve(reading.binding.size() + reading.sensorId.size() + reading.nonce.size() + 32);
  out += reading.binding;
  out.push_back('|');
  out += reading.sensorId;
  out.push_back('|');
  out += reading.temp2dp();
  out.push_back('|');
  out += reading.recordedAtIso();
  out.push_back('|');
  out += reading.nonce;
  return out;
}

std::string signReading(const Reading& reading, const std::string& sensorSecret) {
  const std::string input = macInput(reading);
  if (input.empty()) return std::string();
  // An empty secret would still produce a valid-looking 64-hex MAC that the
  // server rejects, so refuse rather than emit one and let the failure look like a
  // key mismatch.
  if (sensorSecret.empty()) return std::string();
  return hmacSha256Hex(sensorSecret, input);
}

std::string jsonBody(const Reading& reading, const std::string& hmacHex) {
  if (validate(reading) != ReadingProblem::kNone) return std::string();
  if (!isLowerHexOfLength(hmacHex, kHmacHexLen)) return std::string();

  std::string out;
  out.reserve(320);
  out.push_back('{');

  appendJsonStringField(&out, reading.bindingKind == BindingKind::kBatchNo ? "batch_no" : "product_id",
                        reading.binding);
  out.push_back(',');
  appendJsonStringField(&out, "sensor_id", reading.sensorId);

  // The temperature is emitted as the same characters the MAC covers, so the
  // number in the body and the number that was signed cannot differ. "4.50" is a
  // valid JSON number, and any 2-decimal value survives the double round-trip
  // exactly, so the server re-derives "4.50" from the parsed 4.5 (DATA-CONTRACT
  // 4.7).
  out += ",\"temperature\":";
  out += reading.temp2dp();

  out += ",\"recorded_at\":\"";
  out += reading.recordedAtIso();
  out.push_back('"');

  if (reading.batteryPct != Reading::kBatteryUnknown) {
    out += ",\"battery_pct\":";
    out += formatInt(reading.batteryPct);
  }

  out.push_back(',');
  appendJsonStringField(&out, "nonce", reading.nonce);
  out.push_back(',');
  appendJsonStringField(&out, "hmac", hmacHex);

  out.push_back('}');
  return out;
}

std::string serialiseRecord(const Reading& reading) {
  uint8_t flags = 0;
  if (reading.bindingKind == BindingKind::kBatchNo) flags |= kFlagBatchBinding;
  if (reading.timeIsAbsolute) flags |= kFlagAbsoluteTime;

  std::string body;
  body.reserve(160);
  body += kRecordTag;
  body.push_back(kFieldSep);
  body += formatInt(flags);
  body.push_back(kFieldSep);
  body += reading.binding;
  body.push_back(kFieldSep);
  body += reading.sensorId;
  body.push_back(kFieldSep);
  body += formatInt(reading.tempHundredths);
  body.push_back(kFieldSep);
  body += formatInt(reading.recordedAt);
  body.push_back(kFieldSep);
  body += formatInt(reading.batteryPct);
  body.push_back(kFieldSep);
  body += reading.nonce;

  const uint32_t sum = crc32(body);
  const uint8_t bytes[4] = {static_cast<uint8_t>(sum >> 24), static_cast<uint8_t>(sum >> 16),
                            static_cast<uint8_t>(sum >> 8), static_cast<uint8_t>(sum)};

  std::string line = body;
  line.push_back(kFieldSep);
  line += toLowerHex(bytes, sizeof(bytes));
  return line;
}

bool parseRecord(const std::string& line, Reading* out) {
  if (out == nullptr) return false;

  const size_t lastSep = line.rfind(kFieldSep);
  if (lastSep == std::string::npos) return false;

  const std::string body = line.substr(0, lastSep);
  const std::string checksum = line.substr(lastSep + 1);
  if (!isLowerHexOfLength(checksum, 8)) return false;

  const uint32_t expected = crc32(body);
  const uint8_t bytes[4] = {static_cast<uint8_t>(expected >> 24),
                            static_cast<uint8_t>(expected >> 16),
                            static_cast<uint8_t>(expected >> 8),
                            static_cast<uint8_t>(expected)};
  // A plain comparison: this is corruption detection over the device's own flash,
  // not authentication, so there is no timing channel worth closing here.
  if (checksum != toLowerHex(bytes, sizeof(bytes))) return false;

  const std::vector<std::string> parts = splitFields(line, kFieldSep);
  if (parts.size() != kRecordFieldCount) return false;
  if (parts[0] != kRecordTag) return false;

  int64_t flags = 0;
  int64_t tempHundredths = 0;
  int64_t recordedAt = 0;
  int64_t battery = 0;
  if (!parseInt64(parts[1], &flags)) return false;
  if (!parseInt64(parts[4], &tempHundredths)) return false;
  if (!parseInt64(parts[5], &recordedAt)) return false;
  if (!parseInt64(parts[6], &battery)) return false;
  if (flags < 0 || flags > 3) return false;
  if (battery < Reading::kBatteryUnknown || battery > 100) return false;

  Reading parsed;
  parsed.bindingKind = (flags & kFlagBatchBinding) != 0 ? BindingKind::kBatchNo
                                                        : BindingKind::kProductId;
  parsed.binding = parts[2];
  parsed.sensorId = parts[3];
  parsed.tempHundredths = tempHundredths;
  parsed.timeIsAbsolute = (flags & kFlagAbsoluteTime) != 0;
  parsed.recordedAt = recordedAt;
  parsed.batteryPct = static_cast<int>(battery);
  parsed.nonce = parts[7];

  // Everything except the timestamp must already be sendable. A boot-relative
  // record is legitimately not sendable yet, so that one problem is tolerated
  // here and resolved later by rebaseToAbsolute.
  const ReadingProblem problem = validate(parsed);
  if (problem != ReadingProblem::kNone) {
    const bool onlyWaitingForClock =
        !parsed.timeIsAbsolute && problem == ReadingProblem::kTimeNotAbsolute;
    if (!onlyWaitingForClock) return false;
    if (parsed.recordedAt < 0) return false;
  }

  *out = parsed;
  return true;
}

bool rebaseToAbsolute(Reading* reading, int64_t bootEpochSeconds) {
  if (reading == nullptr) return false;
  if (reading->timeIsAbsolute) return true;
  const int64_t absolute = bootEpochSeconds + reading->recordedAt;
  if (absolute < 0) return false;
  reading->recordedAt = absolute;
  reading->timeIsAbsolute = true;
  // A rebased timestamp still has to be representable; if it is not, the caller
  // must drop the record rather than send an empty recorded_at.
  return !reading->recordedAtIso().empty();
}

}  // namespace truemed
