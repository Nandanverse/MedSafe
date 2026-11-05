#include "truemed/policy.h"

#include "truemed/reading.h"

namespace truemed {
namespace {

// Samples to skip before the next radio attempt: 1, 2, 4, 8, then capped.
uint16_t backoffSamples(uint8_t consecutiveFailures) {
  if (consecutiveFailures == 0) return 0;
  uint16_t skip = 1;
  for (uint8_t i = 1; i < consecutiveFailures && skip < kMaxBackoffSamples; ++i) {
    skip = static_cast<uint16_t>(skip * 2);
  }
  return skip > kMaxBackoffSamples ? kMaxBackoffSamples : skip;
}

}  // namespace

bool isVaccineBreach(int64_t tempHundredths) {
  return tempHundredths < kVaccineMinHundredths || tempHundredths > kVaccineMaxHundredths;
}

bool isSensorFaultValue(int64_t tempHundredths) {
  return tempHundredths < kSensorMinHundredths || tempHundredths > kSensorMaxHundredths;
}

SampleOutcome observeSample(PolicyState* state, bool sensorOk, int64_t tempHundredths,
                            size_t queueDepth) {
  SampleOutcome outcome;
  if (state == nullptr) return outcome;

  if (!sensorOk || isSensorFaultValue(tempHundredths)) {
    outcome.sensorFault = true;
    outcome.storeReading = false;
    // A dead probe is not an all-clear. The alarm latch is left exactly as it was,
    // so a box that was already in breach keeps sounding, and the debounce
    // counters are left alone so that a flaky bus cannot walk the latch out of
    // breach one failed read at a time. Silence here would be indistinguishable
    // from "everything is fine", which is the worst thing this device could say.
    ++state->sensorFaults;
    outcome.alarmActive = state->alarm == AlarmState::kBreach;
    // Still worth a connection: the operator needs to know the probe failed, and
    // the backlog may hold real readings from before it did.
    outcome.uploadNow = queueDepth > 0 && state->samplesSinceUpload >= kSamplesPerUpload;
    ++state->samplesSinceUpload;
    ++state->samplesSinceAttempt;
    if (outcome.uploadNow && state->consecutiveUploadFailures > 0 &&
        state->samplesSinceAttempt <= backoffSamples(state->consecutiveUploadFailures)) {
      outcome.uploadNow = false;
    }
    return outcome;
  }

  outcome.storeReading = true;

  if (isVaccineBreach(tempHundredths)) {
    state->consecutiveInWindow = 0;
    if (state->consecutiveOutOfWindow < 255) ++state->consecutiveOutOfWindow;
    if (state->alarm == AlarmState::kNormal &&
        state->consecutiveOutOfWindow >= kSamplesToRaiseAlarm) {
      state->alarm = AlarmState::kBreach;
      outcome.breachEntered = true;
    }
  } else {
    state->consecutiveOutOfWindow = 0;
    if (state->consecutiveInWindow < 255) ++state->consecutiveInWindow;
    if (state->alarm == AlarmState::kBreach &&
        state->consecutiveInWindow >= kSamplesToClearAlarm) {
      state->alarm = AlarmState::kNormal;
      outcome.breachCleared = true;
    }
  }
  outcome.alarmActive = state->alarm == AlarmState::kBreach;

  ++state->samplesSinceUpload;
  ++state->samplesSinceAttempt;

  const bool cadenceDue = state->samplesSinceUpload >= kSamplesPerUpload;
  const bool backlogPressing = queueDepth >= kForceUploadQueueDepth;
  const bool backoffAllows =
      state->consecutiveUploadFailures == 0 ||
      state->samplesSinceAttempt > backoffSamples(state->consecutiveUploadFailures);

  outcome.uploadNow = (cadenceDue || backlogPressing) && backoffAllows;

  // A breach edge bypasses both the cadence and the backoff. If the radio has
  // been failing for an hour and the fridge has just gone warm, the right move is
  // to try anyway - the attempt costs one radio wake-up and the information is
  // worth vastly more than the charge.
  if (outcome.breachEntered) outcome.uploadNow = true;

  return outcome;
}

void noteUploadResult(PolicyState* state, bool success) {
  if (state == nullptr) return;
  state->samplesSinceAttempt = 0;
  if (success) {
    state->samplesSinceUpload = 0;
    state->consecutiveUploadFailures = 0;
    ++state->uploadsSucceeded;
  } else if (state->consecutiveUploadFailures < 255) {
    ++state->consecutiveUploadFailures;
  }
}

uint32_t sleepSecondsAfter(uint32_t awakeMilliseconds) {
  const uint32_t awakeSeconds = awakeMilliseconds / 1000u;
  if (awakeSeconds >= kSampleIntervalSeconds - 1u) {
    // The wake-up overran its own budget - a very long upload of a big backlog.
    // Sleep briefly rather than not at all: a zero-length deep sleep is a reboot
    // loop, and continuing to run would drop the cadence to whatever the network
    // felt like.
    return 1;
  }
  return kSampleIntervalSeconds - awakeSeconds;
}

bool isBacklogTooOld(int64_t recordedAt, int64_t nowEpoch) {
  if (recordedAt < 0 || nowEpoch < 0) return false;
  return nowEpoch - recordedAt > kMaxBacklogAgeSeconds;
}

int batteryPctFromMillivolts(int millivolts) {
  // Below ~2.5 V the ESP32 would not be running, so such a reading is a broken
  // divider or an unconnected ADC pin, not a flat battery. Omitting the field is
  // honest; reporting 0% would put a false "replace the battery" on a dashboard.
  if (millivolts < 2500 || millivolts > 5500) return Reading::kBatteryUnknown;

  if (millivolts <= kBatteryEmptyMillivolts) return 0;
  if (millivolts >= kBatteryFullMillivolts) return 100;

  const int span = kBatteryFullMillivolts - kBatteryEmptyMillivolts;
  const int above = millivolts - kBatteryEmptyMillivolts;
  // Integer rounding to nearest, so 3750 mV reads 50 rather than 49.
  return (above * 100 + span / 2) / span;
}

}  // namespace truemed
