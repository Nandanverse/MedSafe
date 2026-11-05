// TrueMed - SHA-256 and HMAC-SHA256, portable.
//
// Why this is here rather than a call into mbedTLS, which the ESP32 already
// links: the HMAC in DATA-CONTRACT.md 4.7 is the only thing standing between a
// stolen API key and forged temperature history, and the host test build has no
// mbedTLS. Calling the platform library on the device and something else in the
// tests would mean the tested code is not the shipped code - which is the exact
// class of gap this project has been bitten by before (see the mock-ledger
// divergence in the Component 2 audit).
//
// So: one implementation, compiled into both builds, checked on the host against
// the RFC 4231 vectors and independently against Python's hmac module. ~140 lines
// of well-specified arithmetic is a fair price for that.
//
// Not constant-time by construction, and it does not need to be: this side only
// ever *produces* a MAC over data it already owns. The comparison that must not
// leak timing happens on the server. constantTimeEquals is provided anyway for
// the console's secret-check command.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

namespace truemed {

constexpr size_t kSha256DigestLen = 32;
constexpr size_t kSha256BlockLen = 64;

class Sha256 {
 public:
  Sha256() { reset(); }

  void reset();
  void update(const uint8_t* data, size_t len);
  void update(const std::string& text);

  // Writes the digest and resets, so the object is reusable.
  void finish(uint8_t out[kSha256DigestLen]);

 private:
  void compress(const uint8_t block[kSha256BlockLen]);

  uint32_t state_[8];
  uint8_t buffer_[kSha256BlockLen];
  size_t buffered_;
  uint64_t totalBytes_;
};

void sha256(const uint8_t* data, size_t len, uint8_t out[kSha256DigestLen]);

// RFC 2104. Keys longer than the 64-byte block are hashed first; shorter keys
// are zero-padded. Both cases are exercised by the host tests because a
// 64-byte-boundary bug here is invisible until someone rotates to a long secret.
void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg,
                size_t msgLen, uint8_t out[kSha256DigestLen]);

std::string hmacSha256Hex(const std::string& key, const std::string& message);

// Lowercase hex, as DATA-CONTRACT.md 4.7 requires.
std::string toHex(const uint8_t* data, size_t len);

// Decodes lowercase or uppercase hex. Returns false on odd length or a stray
// character, leaving `out` untouched.
bool fromHex(const std::string& hex, std::string* out);

// Length-independent only when both strings are the same length, which is the
// case for two hex digests. Used by the console, not on the hot path.
bool constantTimeEquals(const std::string& a, const std::string& b);

// Overwrite key material before it leaves scope. Written through a volatile
// pointer so the compiler may not elide it as a dead store - a plain memset on
// a buffer that is never read again is exactly what optimisers remove.
void secureZero(void* data, size_t len);

}  // namespace truemed
