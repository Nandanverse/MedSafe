#include "truemed/queue.h"

#include "truemed/format.h"

namespace truemed {
namespace {

const char kMetaTag[] = "TMQ1";
constexpr char kFieldSep = '|';
constexpr size_t kMetaFieldCount = 6;

bool isLowerHex8(const std::string& text) {
  if (text.size() != 8) return false;
  for (size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

std::string crcHex(const std::string& body) {
  const uint32_t sum = crc32(body);
  const uint8_t bytes[4] = {static_cast<uint8_t>(sum >> 24), static_cast<uint8_t>(sum >> 16),
                            static_cast<uint8_t>(sum >> 8), static_cast<uint8_t>(sum)};
  return toLowerHex(bytes, sizeof(bytes));
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

}  // namespace

std::string padToSlot(const std::string& line) {
  std::string slot = line;
  // A line that somehow exceeds the slot is truncated, which will fail its CRC on
  // read and be skipped. Silently writing a short slot and corrupting the next one
  // would be far worse; the record length is bounded by construction anyway (see
  // the arithmetic in queue.h).
  if (slot.size() >= kRecordSlotBytes) {
    slot.resize(kRecordSlotBytes - 1);
  }
  slot.push_back('\n');
  slot.resize(kRecordSlotBytes, ' ');
  return slot;
}

std::string lineFromSlot(const std::string& slotBytes) {
  size_t end = slotBytes.find('\n');
  if (end == std::string::npos) end = slotBytes.size();
  std::string line = slotBytes.substr(0, end);
  while (!line.empty() && (line[line.size() - 1] == ' ' || line[line.size() - 1] == '\r')) {
    line.resize(line.size() - 1);
  }
  return line;
}

size_t ReadingQueue::slotAt(size_t offsetFromHead) const {
  const size_t capacity = storage_ != nullptr ? storage_->capacity() : 1;
  if (capacity == 0) return 0;
  return (head_ + offsetFromHead) % capacity;
}

bool ReadingQueue::begin() {
  if (storage_ == nullptr) return false;
  const size_t capacity = storage_->capacity();
  if (capacity == 0) return false;

  started_ = true;
  head_ = 0;
  depth_ = 0;
  overwritten_ = 0;
  droppedTooOld_ = 0;
  corrupt_ = 0;

  std::string meta;
  if (!storage_->readMeta(&meta)) {
    // No checkpoint at all: either a first boot or a wiped filesystem. Assume the
    // ring may hold records and let the drain path sort it out - on a genuine
    // first boot every slot is filler, so this costs one pass of skipped slots.
    depth_ = capacity;
    return saveMeta();
  }

  const std::string trimmed = lineFromSlot(meta);
  const size_t lastSep = trimmed.rfind(kFieldSep);
  bool metaOk = lastSep != std::string::npos;
  if (metaOk) {
    const std::string body = trimmed.substr(0, lastSep);
    const std::string checksum = trimmed.substr(lastSep + 1);
    metaOk = isLowerHex8(checksum) && checksum == crcHex(body);
  }

  std::vector<std::string> parts;
  if (metaOk) {
    parts = splitFields(trimmed, kFieldSep);
    metaOk = parts.size() == kMetaFieldCount && parts[0] == kMetaTag;
  }

  int64_t head = 0;
  int64_t depth = 0;
  int64_t overwritten = 0;
  int64_t droppedTooOld = 0;
  if (metaOk) {
    metaOk = parseInt64(parts[1], &head) && parseInt64(parts[2], &depth) &&
             parseInt64(parts[3], &overwritten) && parseInt64(parts[4], &droppedTooOld);
  }
  if (metaOk) {
    metaOk = head >= 0 && static_cast<size_t>(head) < capacity && depth >= 0 &&
             static_cast<size_t>(depth) <= capacity && overwritten >= 0 && droppedTooOld >= 0;
  }

  if (!metaOk) {
    // Corrupt checkpoint - most likely a power cut mid-write. Recover pessimistically
    // by treating the whole ring as potentially full; see the note in queue.h for
    // why re-sending is the acceptable side of this trade.
    depth_ = capacity;
    return saveMeta();
  }

  head_ = static_cast<size_t>(head);
  depth_ = static_cast<size_t>(depth);
  overwritten_ = static_cast<uint32_t>(overwritten);
  droppedTooOld_ = static_cast<uint32_t>(droppedTooOld);
  return true;
}

bool ReadingQueue::saveMeta() {
  if (storage_ == nullptr) return false;
  std::string body;
  body += kMetaTag;
  body.push_back(kFieldSep);
  body += formatInt(static_cast<int64_t>(head_));
  body.push_back(kFieldSep);
  body += formatInt(static_cast<int64_t>(depth_));
  body.push_back(kFieldSep);
  body += formatInt(static_cast<int64_t>(overwritten_));
  body.push_back(kFieldSep);
  body += formatInt(static_cast<int64_t>(droppedTooOld_));

  std::string line = body;
  line.push_back(kFieldSep);
  line += crcHex(body);
  line.push_back('\n');
  return storage_->writeMeta(line);
}

bool ReadingQueue::push(const Reading& reading) {
  if (storage_ == nullptr || !started_) return false;
  const size_t capacity = storage_->capacity();

  const std::string line = serialiseRecord(reading);
  if (line.empty()) return false;

  const size_t tail = slotAt(depth_);
  if (!storage_->writeSlot(tail, padToSlot(line))) return false;

  if (depth_ < capacity) {
    ++depth_;
  } else {
    // Full: the write above landed on the oldest record, so the head moves up to
    // keep pointing at the oldest surviving one.
    head_ = (head_ + 1) % capacity;
    if (overwritten_ < UINT32_MAX) ++overwritten_;
  }
  return saveMeta();
}

std::vector<QueuedItem> ReadingQueue::peek(size_t maxSlots) {
  std::vector<QueuedItem> items;
  if (storage_ == nullptr || !started_) return items;

  const size_t limit = maxSlots < depth_ ? maxSlots : depth_;
  items.reserve(limit);
  for (size_t i = 0; i < limit; ++i) {
    QueuedItem item;
    std::string slotBytes;
    if (!storage_->readSlot(slotAt(i), &slotBytes)) {
      // An I/O error is not the same as a bad record: stop here and let the next
      // wake-up retry, rather than reporting the slot as dealt with and losing it.
      break;
    }
    const std::string line = lineFromSlot(slotBytes);
    item.valid = !line.empty() && parseRecord(line, &item.reading);
    if (!item.valid && corrupt_ < UINT32_MAX) ++corrupt_;
    items.push_back(item);
  }
  return items;
}

bool ReadingQueue::commit(size_t slots) {
  if (storage_ == nullptr || !started_) return false;
  if (slots == 0) return true;
  const size_t capacity = storage_->capacity();
  const size_t advance = slots < depth_ ? slots : depth_;
  head_ = (head_ + advance) % capacity;
  depth_ -= advance;
  return saveMeta();
}

size_t ReadingQueue::pruneTooOld(int64_t nowEpoch, int64_t maxAgeSeconds) {
  if (storage_ == nullptr || !started_) return 0;
  if (nowEpoch < 0 || maxAgeSeconds < 0) return 0;
  size_t dropped = 0;

  // Records are appended in time order, so everything expired is a prefix. Stop at
  // the first record that is still inside the window - or at the first that has no
  // date yet, since a boot-relative record is waiting for the clock, not expired.
  while (depth_ > 0) {
    std::string slotBytes;
    if (!storage_->readSlot(slotAt(0), &slotBytes)) break;
    const std::string line = lineFromSlot(slotBytes);
    Reading record;
    const bool parsed = !line.empty() && parseRecord(line, &record);
    if (parsed && !record.timeIsAbsolute) break;
    if (parsed && nowEpoch - record.recordedAt <= maxAgeSeconds) break;

    // An unparseable slot at the head is dropped here too: it can never be sent,
    // and leaving it would stall this prune every time it ran.
    head_ = (head_ + 1) % storage_->capacity();
    --depth_;
    ++dropped;
    if (parsed && droppedTooOld_ < UINT32_MAX) ++droppedTooOld_;
  }

  if (dropped > 0) saveMeta();
  return dropped;
}

size_t ReadingQueue::rebase(int64_t bootEpochSeconds) {
  if (storage_ == nullptr || !started_) return 0;
  size_t rebased = 0;

  for (size_t i = 0; i < depth_; ++i) {
    const size_t slot = slotAt(i);
    std::string slotBytes;
    if (!storage_->readSlot(slot, &slotBytes)) continue;
    const std::string line = lineFromSlot(slotBytes);
    if (line.empty()) continue;

    Reading record;
    if (!parseRecord(line, &record)) continue;
    if (record.timeIsAbsolute) continue;

    if (!rebaseToAbsolute(&record, bootEpochSeconds)) continue;
    const std::string updated = serialiseRecord(record);
    if (updated.empty()) continue;
    if (storage_->writeSlot(slot, padToSlot(updated))) ++rebased;
  }
  return rebased;
}

QueueStats ReadingQueue::stats() const {
  QueueStats out;
  out.depth = depth_;
  out.capacity = storage_ != nullptr ? storage_->capacity() : 0;
  out.overwritten = overwritten_;
  out.droppedTooOld = droppedTooOld_;
  out.corrupt = corrupt_;
  return out;
}

}  // namespace truemed
