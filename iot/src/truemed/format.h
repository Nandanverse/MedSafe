// TrueMed - deterministic formatting for everything that crosses the wire.
//
// Every function here is pure and every one of them exists because a plausible
// one-line alternative is subtly wrong:
//
//   formatHundredths - not snprintf("%.2f"), because that is locale-dependent
//                     (LC_NUMERIC=de_DE yields "4,50") and because glibc rounds
//                     exact halves to even while DATA-CONTRACT.md 4.7 specifies
//                     half-away-from-zero. The HMAC covers these characters, so
//                     "4,50" or a banker's-rounded "4.06" is a rejected reading.
//   formatRfc3339   - not gmtime_r + strftime, because strftime is also
//                     locale-sensitive and gmtime_r is absent on some bare-metal
//                     libcs. The civil-from-days arithmetic is 15 lines, exact
//                     for all values we care about, and testable without a clock.
//   escapeJsonString- because the body is assembled by hand (see platformio.ini
//                     for why there is no JSON library on the device).
//
// The temperature path is deliberately split into quantise-then-format. A reading
// is converted from double to an integer count of hundredths exactly once, at
// capture, and every later use - the MAC input, the JSON number, the queue record
// on flash - formats that same integer. Nothing downstream ever re-rounds a
// float, so there is no way for the number stored on flash to drift from the
// number that was signed.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

namespace truemed {

// Round a Celsius reading to an integer count of hundredths, half away from
// zero, on the double's *exact* binary value - so this agrees with Python's
// Decimal(x).quantize(ROUND_HALF_UP) and with JavaScript's toFixed(2) for every
// finite input, not merely for the ones the sensor happens to produce. Non-finite
// input returns 0; callers reject NaN before this point (see policy.cpp) and this
// is only the backstop.
int64_t quantiseHundredths(double celsius);

// Hundredths to exactly two decimal places: no exponent, always a leading digit,
// "-" only for negatives, and 0 formatting as "0.00" rather than "-0.00".
// DATA-CONTRACT.md 4.7.
std::string formatHundredths(int64_t hundredths);

// Convenience composition of the two above, for tests and for the console.
std::string formatTemp2dp(double celsius);

// Epoch seconds (UTC) to exactly "YYYY-MM-DDTHH:MM:SSZ".
// Returns an empty string for a negative epoch, which cannot be a real reading
// and must never be sent - an empty recorded_at fails the server's regex loudly
// rather than silently signing 1969.
std::string formatRfc3339(int64_t epochSeconds);

// Inverse, for the serial console and for the NTP sanity check. Returns false if
// the text is not exactly the format above, including rejecting 2026-02-31 rather
// than rolling it into March.
bool parseRfc3339Utc(const std::string& text, int64_t* epochSeconds);

// Minimal integer to decimal. Present so that no path on the device pulls in
// snprintf for something this simple.
std::string formatInt(int64_t value);

// Strict decimal integer parse: an optional leading '-', then digits, nothing
// else. No leading '+', no whitespace, no empty string, and overflow is rejected
// rather than wrapped. Used for queue records and console arguments, where a
// silently truncated number would be a corrupted reading.
bool parseInt64(const std::string& text, int64_t* value);

// JSON string body escaping per RFC 8259: quote, backslash, and the C0 range.
// Short forms for \b \t \n \f \r, \u00xx with lowercase hex for the rest, which
// is what both Python's json and JavaScript's JSON.stringify emit - the same
// convention canonical.js documents.
std::string escapeJsonString(const std::string& raw);

// Lowercase hex of `len` bytes. A nonce is 16 bytes -> 32 characters, inside the
// 8..64 the contract permits.
std::string toLowerHex(const uint8_t* bytes, size_t len);

// True if `text` is 8..64 characters of lowercase [0-9a-f]. The device generates
// its own nonces, so this is really a guard for values read back from the queue
// after a flash corruption.
bool isContractNonce(const std::string& text);

// CRC-32 (IEEE 802.3, reflected, the same value zlib.crc32 and gzip produce).
// This detects a queue record truncated by a power cut mid-append. It is
// emphatically not authentication - the HMAC does that - and nothing security
// relevant may depend on it.
uint32_t crc32(const uint8_t* data, size_t len);
uint32_t crc32(const std::string& text);

}  // namespace truemed
