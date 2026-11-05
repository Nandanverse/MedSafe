// TrueMed - the offline queue: a power-cut-safe ring buffer of readings.
//
// This is the component that decides whether a rural PHC's cold box has data for
// the week its uplink was down. Three designs were on the table:
//
//   append-only log, rewritten on drain  - simplest, but rewriting ~200 KB after
//     every upload is ~10 MB of flash writes a day purely to delete lines.
//   append-only log with a head offset   - much less wear, but variable-length
//     records mean the head can land mid-record after a truncated write, and
//     recovering from that needs a resync scan anyway.
//   fixed-size slots, ring buffer        - chosen. Push and drop are both O(1)
//     with no rewriting ever, each slot is written once per full lap so wear is
//     spread evenly by construction, and a slot half-written when the power died
//     simply fails its CRC and is skipped. A partially written slot cannot
//     corrupt its neighbours because the slot boundaries are arithmetic, not
//     delimiters.
//
// The cost is padding: a typical record is ~110 bytes in a 224-byte slot. That
// buys about 7500 readings in 1.7 MB, or 26 days at one reading per 5 minutes -
// which is almost exactly the server's 30-day backfill window, so the storage runs
// out at roughly the same moment the data would stop being acceptable anyway.
// Spending flash to fit more would buy records the server rejects.
//
// Storage is injected so the host tests exercise this logic with an in-memory
// implementation and the device gets LittleFS, with no #ifdef anywhere in here.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "truemed/reading.h"

namespace truemed {

// One slot must hold the longest possible record. Worst case is an 80-character
// product_id, a 32-character sensor_id and a 64-character nonce:
//   tag 4 + flags 1 + binding 80 + sensor 32 + temp 7 + time 11 + battery 4
//   + nonce 64 + crc 8 + 8 separators + newline = 219 bytes.
// 224 leaves a little room and keeps the arithmetic tidy.
constexpr size_t kRecordSlotBytes = 224;

// 7500 slots = 1.68 MB, inside the 2 MB filesystem partition with room for
// LittleFS metadata and the queue's own checkpoint file.
constexpr size_t kDefaultQueueCapacity = 7500;

// The abstract flash the queue writes to. Slot indices are 0..capacity()-1 and
// every slot is exactly kRecordSlotBytes long.
class QueueStorage {
 public:
  virtual ~QueueStorage() {}

  // Reads the raw bytes of one slot. Returns false only on an I/O error; a slot
  // that has never been written must read back as filler, not fail.
  virtual bool readSlot(size_t index, std::string* out) = 0;

  // Writes exactly kRecordSlotBytes at that slot and flushes, so that a power cut
  // immediately afterwards cannot lose the record.
  virtual bool writeSlot(size_t index, const std::string& bytes) = 0;

  // The tiny checkpoint file holding head, depth and counters.
  virtual bool readMeta(std::string* out) = 0;
  virtual bool writeMeta(const std::string& bytes) = 0;

  virtual size_t capacity() const = 0;
};

// One slot's worth of drain result. `valid` false means the slot did not parse -
// a truncated write, or filler from a slot that was never used - and the caller
// must treat it as already dealt with rather than retrying it forever.
struct QueuedItem {
  bool valid = false;
  Reading reading;
};

struct QueueStats {
  size_t depth = 0;            // records currently waiting
  size_t capacity = 0;
  uint32_t overwritten = 0;    // oldest records lost because the ring filled
  uint32_t droppedTooOld = 0;  // records past the server's backfill window
  uint32_t corrupt = 0;        // slots that failed to parse while draining
};

class ReadingQueue {
 public:
  explicit ReadingQueue(QueueStorage* storage) : storage_(storage) {}

  // Loads the checkpoint. If it is missing or fails its CRC - a power cut during
  // the checkpoint write - the queue recovers by assuming the whole ring may hold
  // records and letting the drain path skip the slots that do not parse. That
  // recovery can re-send readings that were already delivered and can rotate
  // their order, and both are harmless: every reading carries its own
  // recorded_at, so order does not matter, and the server's 24-hour nonce replay
  // check turns a duplicate into a no-op. Losing a real excursion because the
  // checkpoint was unreadable would not be harmless, which is why the trade goes
  // this way.
  bool begin();

  // Appends a reading. When the ring is full the oldest record is overwritten:
  // recent readings are worth more than 26-day-old ones the server is about to
  // start rejecting, and refusing new readings would mean going blind exactly
  // when the outage is longest.
  bool push(const Reading& reading);

  // Reads up to `maxSlots` slots from the head without consuming them.
  std::vector<QueuedItem> peek(size_t maxSlots);

  // Marks the first `slots` slots from the head as dealt with. Call this with the
  // number of *leading* slots fully handled - so if the third upload of a batch
  // failed, commit 2, not the whole batch.
  bool commit(size_t slots);

  // Drops dated records older than `maxAgeSeconds` from the front. The threshold
  // is a parameter rather than a constant read from policy.h, so that the queue
  // stays a storage structure with no opinion about vaccines and the test can
  // check the boundary without waiting 29 days. Boot-relative records are never
  // dropped: they have not been dated yet.
  size_t pruneTooOld(int64_t nowEpoch, int64_t maxAgeSeconds);

  // Stamps boot-relative records with real time once the clock is known, rewriting
  // them in place. Returns how many were rebased. This is what turns readings
  // taken during a power cut - before any NTP sync was possible - into evidence
  // the server will accept.
  size_t rebase(int64_t bootEpochSeconds);

  size_t depth() const { return depth_; }
  bool empty() const { return depth_ == 0; }
  QueueStats stats() const;

 private:
  bool saveMeta();
  size_t slotAt(size_t offsetFromHead) const;

  QueueStorage* storage_ = nullptr;
  size_t head_ = 0;
  size_t depth_ = 0;
  uint32_t overwritten_ = 0;
  uint32_t droppedTooOld_ = 0;
  uint32_t corrupt_ = 0;
  bool started_ = false;
};

// Pads a record line into exactly kRecordSlotBytes: the line, a newline, then
// spaces. Exposed for the tests and for the console's raw slot dump.
std::string padToSlot(const std::string& line);

// Extracts the record line from raw slot bytes: everything before the first
// newline, with trailing spaces removed. Returns "" for filler.
std::string lineFromSlot(const std::string& slotBytes);

}  // namespace truemed
