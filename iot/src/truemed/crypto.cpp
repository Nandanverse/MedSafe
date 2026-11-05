#include "truemed/crypto.h"

#include <string.h>

namespace truemed {
namespace {

inline uint32_t rotr(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

inline uint32_t bigEndian32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline void putBigEndian32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

// FIPS 180-4: first 32 bits of the fractional parts of the cube roots of the
// first 64 primes.
const uint32_t kK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

const char kHexDigits[] = "0123456789abcdef";

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

void Sha256::reset() {
  // Fractional parts of the square roots of the first eight primes.
  state_[0] = 0x6a09e667u;
  state_[1] = 0xbb67ae85u;
  state_[2] = 0x3c6ef372u;
  state_[3] = 0xa54ff53au;
  state_[4] = 0x510e527fu;
  state_[5] = 0x9b05688cu;
  state_[6] = 0x1f83d9abu;
  state_[7] = 0x5be0cd19u;
  buffered_ = 0;
  totalBytes_ = 0;
  memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const uint8_t block[kSha256BlockLen]) {
  uint32_t w[64];
  for (size_t i = 0; i < 16; ++i) {
    w[i] = bigEndian32(block + i * 4);
  }
  for (size_t i = 16; i < 64; ++i) {
    const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
  uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

  for (size_t i = 0; i < 64; ++i) {
    const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const uint32_t ch = (e & f) ^ (~e & g);
    const uint32_t temp1 = h + S1 + ch + kK[i] + w[i];
    const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const uint8_t* data, size_t len) {
  if (data == nullptr || len == 0) return;
  totalBytes_ += len;

  // Top up a partial block first.
  if (buffered_ > 0) {
    const size_t want = kSha256BlockLen - buffered_;
    const size_t take = (len < want) ? len : want;
    memcpy(buffer_ + buffered_, data, take);
    buffered_ += take;
    data += take;
    len -= take;
    if (buffered_ == kSha256BlockLen) {
      compress(buffer_);
      buffered_ = 0;
    }
  }

  while (len >= kSha256BlockLen) {
    compress(data);
    data += kSha256BlockLen;
    len -= kSha256BlockLen;
  }

  if (len > 0) {
    memcpy(buffer_, data, len);
    buffered_ = len;
  }
}

void Sha256::update(const std::string& text) {
  update(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

void Sha256::finish(uint8_t out[kSha256DigestLen]) {
  const uint64_t bitLength = totalBytes_ * 8u;

  // Append 0x80, then zeros, until 8 bytes remain in the final block.
  buffer_[buffered_++] = 0x80u;
  if (buffered_ > kSha256BlockLen - 8) {
    memset(buffer_ + buffered_, 0, kSha256BlockLen - buffered_);
    compress(buffer_);
    buffered_ = 0;
  }
  memset(buffer_ + buffered_, 0, (kSha256BlockLen - 8) - buffered_);

  // 64-bit big-endian bit count.
  putBigEndian32(buffer_ + kSha256BlockLen - 8,
                 static_cast<uint32_t>(bitLength >> 32));
  putBigEndian32(buffer_ + kSha256BlockLen - 4,
                 static_cast<uint32_t>(bitLength & 0xffffffffu));
  compress(buffer_);

  for (size_t i = 0; i < 8; ++i) {
    putBigEndian32(out + i * 4, state_[i]);
  }
  reset();
}

void sha256(const uint8_t* data, size_t len, uint8_t out[kSha256DigestLen]) {
  Sha256 h;
  h.update(data, len);
  h.finish(out);
}

void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg,
                size_t msgLen, uint8_t out[kSha256DigestLen]) {
  uint8_t normalisedKey[kSha256BlockLen];
  memset(normalisedKey, 0, sizeof(normalisedKey));

  if (keyLen > kSha256BlockLen) {
    // RFC 2104: over-long keys are replaced by their own digest.
    uint8_t digest[kSha256DigestLen];
    sha256(key, keyLen, digest);
    memcpy(normalisedKey, digest, kSha256DigestLen);
    secureZero(digest, sizeof(digest));
  } else if (keyLen > 0) {
    memcpy(normalisedKey, key, keyLen);
  }

  uint8_t inner[kSha256BlockLen];
  uint8_t outer[kSha256BlockLen];
  for (size_t i = 0; i < kSha256BlockLen; ++i) {
    inner[i] = static_cast<uint8_t>(normalisedKey[i] ^ 0x36u);
    outer[i] = static_cast<uint8_t>(normalisedKey[i] ^ 0x5cu);
  }

  uint8_t innerDigest[kSha256DigestLen];
  Sha256 h;
  h.update(inner, sizeof(inner));
  h.update(msg, msgLen);
  h.finish(innerDigest);

  h.update(outer, sizeof(outer));
  h.update(innerDigest, sizeof(innerDigest));
  h.finish(out);

  secureZero(normalisedKey, sizeof(normalisedKey));
  secureZero(inner, sizeof(inner));
  secureZero(outer, sizeof(outer));
  secureZero(innerDigest, sizeof(innerDigest));
}

std::string hmacSha256Hex(const std::string& key, const std::string& message) {
  uint8_t mac[kSha256DigestLen];
  hmacSha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
             reinterpret_cast<const uint8_t*>(message.data()), message.size(), mac);
  const std::string hex = toHex(mac, sizeof(mac));
  secureZero(mac, sizeof(mac));
  return hex;
}

std::string toHex(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kHexDigits[(data[i] >> 4) & 0x0fu]);
    out.push_back(kHexDigits[data[i] & 0x0fu]);
  }
  return out;
}

bool fromHex(const std::string& hex, std::string* out) {
  if (out == nullptr || (hex.size() % 2) != 0) return false;
  std::string decoded;
  decoded.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = hexValue(hex[i]);
    const int lo = hexValue(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    decoded.push_back(static_cast<char>((hi << 4) | lo));
  }
  *out = decoded;
  return true;
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
  // Length is compared up front and leaks, which is fine: the length of a hex
  // digest is public. The bytes are then folded without an early exit.
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff = static_cast<unsigned char>(
        diff | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i])));
  }
  return diff == 0;
}

void secureZero(void* data, size_t len) {
  volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
  while (len-- > 0) {
    *p++ = 0;
  }
}

}  // namespace truemed
