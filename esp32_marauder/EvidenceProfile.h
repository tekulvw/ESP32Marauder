#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace passive_evidence {
enum class ProfileKind { Survey, WifiOnly, Focused, Fixed, BleOnly };
struct ScanProfile {
  ProfileKind kind = ProfileKind::Survey;
  uint8_t channels[11] = {11, 6, 1, 10, 9, 8, 7, 5, 4, 3, 2};
  uint8_t count = 11;
  uint16_t wifiDwellMs = 250;
  uint16_t bleWindowMs = 500;
  const char* name() const {
    switch (kind) {
      case ProfileKind::WifiOnly: return "wifi-only";
      case ProfileKind::Focused: return "focused";
      case ProfileKind::Fixed: return "fixed";
      case ProfileKind::BleOnly: return "ble-only";
      default: return "survey";
    }
  }
};
// Exact bounded decimal parsing; rejects signs, whitespace, empty/overflow input.
inline bool profileNumber(const char*& cursor, unsigned& value, unsigned limit) {
  value = 0;
  if (*cursor < '0' || *cursor > '9') return false;
  while (*cursor >= '0' && *cursor <= '9') {
    value = value * 10 + (*cursor++ - '0');
    if (value > limit) return false;
  }
  return true;
}
// Arguments after "evidence start ", or empty for the backward-compatible default.
inline bool parseProfile(const char* input, ScanProfile& result) {
  ScanProfile parsed;
  if (!*input) { result = parsed; return true; }
  const char* space = strchr(input, ' ');
  if (!space) return false;
  size_t length = static_cast<size_t>(space - input);
  const char* names[] = {"survey", "wifi-only", "focused", "fixed", "ble-only"};
  bool found = false;
  for (unsigned i = 0; i < 5; ++i) {
    if (strlen(names[i]) == length && !strncmp(input, names[i], length)) {
      parsed.kind = static_cast<ProfileKind>(i); found = true; break;
    }
  }
  if (!found) return false;
  const char* cursor = space + 1;
  unsigned dwell;
  if (!profileNumber(cursor, dwell, 1000) || dwell < 50 || *cursor++ != ' ') return false;
  parsed.wifiDwellMs = dwell;
  parsed.bleWindowMs = (parsed.kind == ProfileKind::Survey || parsed.kind == ProfileKind::BleOnly) ? 500 : 0;
  if (parsed.kind == ProfileKind::Focused) parsed.count = 3;
  if (parsed.kind == ProfileKind::BleOnly) parsed.count = 0;
  if (!strcmp(cursor, "-")) {
    if (parsed.kind == ProfileKind::Fixed) return false;
  } else {
    uint8_t channels[11];
    unsigned count = 0, mask = 0;
    do {
      unsigned channel;
      if (count == 11 || !profileNumber(cursor, channel, 11) || !channel || (mask & (1U << channel))) return false;
      channels[count++] = channel; mask |= 1U << channel;
      if (!*cursor) break;
      if (*cursor++ != ',') return false;
    } while (true);
    if (parsed.kind == ProfileKind::BleOnly) return false;
    if ((parsed.kind == ProfileKind::Survey || parsed.kind == ProfileKind::WifiOnly) &&
        (count != parsed.count || memcmp(channels, parsed.channels, count))) return false;
    if (parsed.kind == ProfileKind::Fixed && count != 1) return false;
    parsed.count = count;
    memcpy(parsed.channels, channels, count);
  }
  result = parsed; return true;
}
struct ScanWindow {
  bool ble = false;
  uint8_t index = 0;
};
inline ScanWindow firstWindow(const ScanProfile& profile) { return {profile.count == 0, 0}; }
inline ScanWindow nextWindow(const ScanProfile& profile, ScanWindow window) {
  if (window.ble) return firstWindow(profile);
  if (window.index + 1 < profile.count) return {false, static_cast<uint8_t>(window.index + 1)};
  return {profile.bleWindowMs != 0, 0};
}
inline uint64_t windowDurationUs(const ScanProfile& profile, ScanWindow window) {
  return static_cast<uint64_t>(window.ble ? profile.bleWindowMs : profile.wifiDwellMs) * 1000;
}
}  // namespace passive_evidence
