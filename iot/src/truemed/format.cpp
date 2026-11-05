#include "truemed/format.h"

#include <math.h>

namespace truemed {
namespace {

const char kHexDigits[] = "0123456789abcdef";

void appendTwoDigits(std::string* out, int value) {
  out->push_back(static_cast<char>('0' + ((value / 10) % 10)));
  out->push_back(static_cast<char>('0' + (value % 10)));
}

void appendFourDigits(std::string* out, int value) {
  out->push_back(static_cast<char>('0' + ((value / 1000) % 10)));
  out->push_back(static_cast<char>('0' + ((value / 100) % 10)));
  out->push_back(static_cast<char>('0' + ((value / 10) % 10)));
  out->push_back(static_cast<char>('0' + (value % 10)));
}

// Absolute value of a non-negative integer's decimal digits, appended MSB first.
void appendUnsignedDigits(std::string* out, uint64_t value) {
  if (value == 0) {
    out->push_back('0');
    return;
  }
  char digits[24];
  int n = 0;
  while (value > 0 && n < static_cast<int>(sizeof(digits))) {
    digits[n++] = static_cast<char>('0' + static_cast<int>(value % 10));
    value /= 10;
  }
  while (n > 0) out->push_back(digits[--n]);
}

// Howard Hinnant's civil_from_days: exact integer calendar arithmetic on a
// proleptic Gregorian calendar, with the year shifted so that the leap-year rule
// falls at the end of the era. No libc, no locale, no time zone database.
void civilFromDays(int64_t z, int* year, unsigned* month, unsigned* day) {
  z += 719468;
  const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);                 // [0, 146096]
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;   // [0, 399]
  const int64_t y = static_cast<int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                 // [0, 365]
  const unsigned mp = (5 * doy + 2) / 153;                                      // [0, 11]
  const unsigned d = doy - (153 * mp + 2) / 5 + 1;                              // [1, 31]
  const unsigned m = mp < 10 ? mp + 3 : mp - 9;                                 // [1, 12]
  *year = static_cast<int>(y + (m <= 2 ? 1 : 0));
  *month = m;
  *day = d;
}

int64_t daysFromCivil(int year, unsigned month, unsigned day) {
  const int64_t y = static_cast<int64_t>(year) - (month <= 2 ? 1 : 0);
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy =
      (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

bool allDigits(const std::string& s, size_t from, size_t count) {
  if (from + count > s.size()) return false;
  for (size_t i = from; i < from + count; ++i) {
    if (s[i] < '0' || s[i] > '9') return false;
  }
  return true;
}

int digitsToInt(const std::string& s, size_t from, size_t count) {
  int value = 0;
  for (size_t i = from; i < from + count; ++i) {
    value = value * 10 + (s[i] - '0');
  }
  return value;
}

unsigned daysInMonth(int year, unsigned month) {
  static const unsigned kLengths[12] = {31, 28, 31, 30, 31, 30,
                                        31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12) return 0;
  if (month == 2) {
    const bool leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    return leap ? 29u : 28u;
  }
  return kLengths[month - 1];
}

}  // namespace

int64_t quantiseHundredths(double celsius) {
  // NaN and infinity have no representation the server would accept, and signing
  // the string "nan" would be worse than sending nothing.
  if (isnan(celsius) || isinf(celsius)) return 0;

  const bool negative = celsius < 0.0;
  const double magnitude = negative ? -celsius : celsius;

  // Far outside any physical temperature. policy.cpp rejects anything beyond the
  // DS18B20's -55..125 long before this, so the clamp exists only so that no
  // input can reach the integer arithmetic below with a value that would overflow
  // it - converting an out-of-range double to int64 is undefined behaviour.
  const double kClamp = 1.0e15;
  if (magnitude > kClamp) {
    return negative ? -100000000000000000LL : 100000000000000000LL;
  }

  // Round half away from zero *exactly*, which the obvious
  //     (int64_t)(magnitude * 100.0 + 0.5)
  // does not do: that rounds twice, once in the multiply and once in the
  // truncation. For 2.675 - whose nearest double is 2.674999999999999822... -
  // the multiply lands on exactly 267.5 and the result becomes 2.68, while
  // DATA-CONTRACT.md 4.7 (and Python's Decimal, and V8's toFixed) all say 2.67.
  // In the current firmware the discrepancy is unreachable, because the body
  // carries the already-rounded value and the server re-derives that same string.
  // But then the contract and the firmware would be two definitions of rounding
  // that merely happen to agree, and this is the one MAC in the system: a second
  // definition is exactly the ambiguity 4.7 was written to remove.
  //
  // So decompose the double exactly instead. Every finite double is
  // mantissa * 2^exponent with an integral 53-bit mantissa, and from there the
  // rounding is integer arithmetic with no error at all.
  int exponent = 0;
  const double fraction = frexp(magnitude, &exponent);  // 0.5 <= fraction < 1, or 0
  const int kMantissaBits = 53;
  // fraction has at most 53 significant bits, so this scaling is exact and the
  // result is an integer.
  const int64_t mantissa = static_cast<int64_t>(ldexp(fraction, kMantissaBits));
  exponent -= kMantissaBits;
  // magnitude == mantissa * 2^exponent, exactly.

  int64_t hundredths = 0;
  if (exponent >= 0) {
    // Unreachable for any magnitude <= kClamp (a 53-bit mantissa forces
    // exponent <= -3 there), but handled rather than assumed.
    hundredths = mantissa * 100;
    for (int i = 0; i < exponent && hundredths != 0; ++i) hundredths *= 2;
  } else {
    const int shift = -exponent;
    // mantissa < 2^53, so n < 2^60; the rounding addend is at most 2^62; the sum
    // therefore stays inside int64.
    const int64_t n = mantissa * 100;
    if (shift >= 64) {
      // magnitude <= 2^53 * 2^-64 = 2^-11, so magnitude * 100 < 0.05: rounds to 0.
      hundredths = 0;
    } else {
      const int64_t half = static_cast<int64_t>(1) << (shift - 1);
      hundredths = (n + half) >> shift;
    }
  }

  return negative ? -hundredths : hundredths;
}

std::string formatHundredths(int64_t hundredths) {
  // Take the magnitude in unsigned space so that INT64_MIN does not overflow on
  // negation - the classic hand-rolled-formatter bug.
  const bool negative = hundredths < 0;
  const uint64_t magnitude = negative
                                 ? (~static_cast<uint64_t>(hundredths) + 1u)
                                 : static_cast<uint64_t>(hundredths);

  std::string out;
  // Zero is zero: "-0.00" is not a value DATA-CONTRACT.md 4.7 permits, so the
  // sign is dropped when everything rounded away.
  if (negative && magnitude != 0) out.push_back('-');

  appendUnsignedDigits(&out, magnitude / 100u);
  out.push_back('.');
  appendTwoDigits(&out, static_cast<int>(magnitude % 100u));
  return out;
}

std::string formatTemp2dp(double celsius) {
  return formatHundredths(quantiseHundredths(celsius));
}

std::string formatRfc3339(int64_t epochSeconds) {
  // A negative epoch means the clock was never set. Returning "" makes the
  // caller's validation fail rather than producing a signed reading dated 1969,
  // which the server would reject as outside the 30-day backfill window anyway -
  // but only after the device had spent radio energy sending it.
  if (epochSeconds < 0) return std::string();

  const int64_t days = epochSeconds / 86400;
  int64_t secondOfDay = epochSeconds % 86400;

  int year = 0;
  unsigned month = 0;
  unsigned day = 0;
  civilFromDays(days, &year, &month, &day);

  // Four fixed digits cannot represent a year outside 0..9999, and a device that
  // somehow reports year 10000 must not emit a 21-character timestamp that the
  // server would reject for the wrong reason.
  if (year < 0 || year > 9999) return std::string();

  const int hour = static_cast<int>(secondOfDay / 3600);
  secondOfDay %= 3600;
  const int minute = static_cast<int>(secondOfDay / 60);
  const int second = static_cast<int>(secondOfDay % 60);

  std::string out;
  out.reserve(20);
  appendFourDigits(&out, year);
  out.push_back('-');
  appendTwoDigits(&out, static_cast<int>(month));
  out.push_back('-');
  appendTwoDigits(&out, static_cast<int>(day));
  out.push_back('T');
  appendTwoDigits(&out, hour);
  out.push_back(':');
  appendTwoDigits(&out, minute);
  out.push_back(':');
  appendTwoDigits(&out, second);
  out.push_back('Z');
  return out;
}

bool parseRfc3339Utc(const std::string& text, int64_t* epochSeconds) {
  if (epochSeconds == nullptr) return false;
  if (text.size() != 20) return false;
  if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' ||
      text[16] != ':' || text[19] != 'Z') {
    return false;
  }
  if (!allDigits(text, 0, 4) || !allDigits(text, 5, 2) || !allDigits(text, 8, 2) ||
      !allDigits(text, 11, 2) || !allDigits(text, 14, 2) || !allDigits(text, 17, 2)) {
    return false;
  }

  const int year = digitsToInt(text, 0, 4);
  const unsigned month = static_cast<unsigned>(digitsToInt(text, 5, 2));
  const unsigned day = static_cast<unsigned>(digitsToInt(text, 8, 2));
  const int hour = digitsToInt(text, 11, 2);
  const int minute = digitsToInt(text, 14, 2);
  const int second = digitsToInt(text, 17, 2);

  // Reject 2026-02-31 rather than rolling it into March, exactly as rules.js
  // parseDate does. A calendar that silently rolls over is a calendar in which an
  // out-of-window timestamp can be smuggled in.
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > daysInMonth(year, month)) return false;
  // No leap seconds: 60 is not accepted, matching every other parser here.
  if (hour > 23 || minute > 59 || second > 59) return false;

  *epochSeconds = daysFromCivil(year, month, day) * 86400 +
                  static_cast<int64_t>(hour) * 3600 +
                  static_cast<int64_t>(minute) * 60 + second;
  return true;
}

std::string formatInt(int64_t value) {
  const bool negative = value < 0;
  const uint64_t magnitude =
      negative ? (~static_cast<uint64_t>(value) + 1u) : static_cast<uint64_t>(value);
  std::string out;
  if (negative) out.push_back('-');
  appendUnsignedDigits(&out, magnitude);
  return out;
}

bool parseInt64(const std::string& text, int64_t* value) {
  if (value == nullptr || text.empty()) return false;

  size_t i = 0;
  bool negative = false;
  if (text[0] == '-') {
    negative = true;
    i = 1;
  }
  if (i >= text.size()) return false;  // a lone "-"

  // Accumulate the magnitude in unsigned space, with the limit depending on sign
  // so that "-9223372036854775808" parses and "9223372036854775808" does not.
  const uint64_t limit = negative ? 9223372036854775808ull : 9223372036854775807ull;
  uint64_t magnitude = 0;
  for (; i < text.size(); ++i) {
    const char c = text[i];
    if (c < '0' || c > '9') return false;
    const uint64_t digit = static_cast<uint64_t>(c - '0');
    if (magnitude > (limit - digit) / 10u) return false;
    magnitude = magnitude * 10u + digit;
  }

  *value = negative ? static_cast<int64_t>(~magnitude + 1u) : static_cast<int64_t>(magnitude);
  return true;
}

std::string escapeJsonString(const std::string& raw) {
  std::string out;
  out.reserve(raw.size() + 8);
  for (size_t i = 0; i < raw.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(raw[i]);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case 0x08:
        out += "\\b";
        break;
      case 0x09:
        out += "\\t";
        break;
      case 0x0a:
        out += "\\n";
        break;
      case 0x0c:
        out += "\\f";
        break;
      case 0x0d:
        out += "\\r";
        break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out.push_back(kHexDigits[(c >> 4) & 0x0fu]);
          out.push_back(kHexDigits[c & 0x0fu]);
        } else {
          // Bytes >= 0x80 pass through untouched: the input is already UTF-8 and
          // re-encoding it as \u escapes would need a decoder here for no gain.
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

std::string toLowerHex(const uint8_t* bytes, size_t len) {
  std::string out;
  if (bytes == nullptr) return out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kHexDigits[(bytes[i] >> 4) & 0x0fu]);
    out.push_back(kHexDigits[bytes[i] & 0x0fu]);
  }
  return out;
}

bool isContractNonce(const std::string& text) {
  if (text.size() < 8 || text.size() > 64) return false;
  for (size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    const bool isDigit = c >= '0' && c <= '9';
    const bool isLowerHexAlpha = c >= 'a' && c <= 'f';
    if (!isDigit && !isLowerHexAlpha) return false;
  }
  return true;
}

uint32_t crc32(const uint8_t* data, size_t len) {
  // Table-free bitwise form. 8 iterations per byte is irrelevant next to a WiFi
  // wake-up, and it avoids putting a 1 KB table in RAM on a 320 KB part.
  uint32_t crc = 0xffffffffu;
  for (size_t i = 0; i < len; ++i) {
    crc ^= static_cast<uint32_t>(data[i]);
    for (int bit = 0; bit < 8; ++bit) {
      const uint32_t mask = static_cast<uint32_t>(-static_cast<int32_t>(crc & 1u));
      crc = (crc >> 1) ^ (0xedb88320u & mask);
    }
  }
  return ~crc;
}

uint32_t crc32(const std::string& text) {
  return crc32(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

}  // namespace truemed
