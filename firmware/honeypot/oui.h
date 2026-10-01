// Small, illustrative OUI (MAC vendor-prefix) table for the honeypot dashboard.
// This is NOT the full IEEE registry (~35k entries) - just common consumer vendors,
// enough to label most real gear. Modern phones randomize their MAC, which the
// locally-administered bit tells us directly, so vendor lookup only applies to the
// devices that present a real, globally-assigned address.
#pragma once
#include <Arduino.h>

struct OuiEntry {
  uint32_t prefix;  // first 3 MAC octets, e.g. 0xB827EB
  const char* vendor;
};

static const OuiEntry OUI_TABLE[] = {
  // Apple (a handful of its many prefixes)
  {0x000393, "Apple"}, {0x001B63, "Apple"}, {0x0025BC, "Apple"}, {0x3C0754, "Apple"},
  {0xA45E60, "Apple"}, {0xF01898, "Apple"}, {0xDCA904, "Apple"}, {0x88665A, "Apple"}, {0xF0DBF8, "Apple"},
  // Samsung
  {0x0012FB, "Samsung"}, {0x001599, "Samsung"}, {0x3423BA, "Samsung"}, {0x5C0A5B, "Samsung"},
  {0x8C7712, "Samsung"}, {0xE8508B, "Samsung"},
  // Google / Nest
  {0x001A11, "Google"}, {0x3C5AB4, "Google"}, {0xF4F5D8, "Google"}, {0x546009, "Google"}, {0x1CF29A, "Google"},
  // Espressif (ESP32/ESP8266 - likely other IoT or test boards)
  {0x240AC4, "Espressif"}, {0x30AEA4, "Espressif"}, {0x7CDFA1, "Espressif"}, {0xA4CF12, "Espressif"},
  {0x246F28, "Espressif"}, {0x84CCA8, "Espressif"}, {0x083AF2, "Espressif"}, {0x348518, "Espressif"},
  // Intel (laptops)
  {0x001B21, "Intel"}, {0x3CA9F4, "Intel"}, {0x7C7A91, "Intel"}, {0xA088B4, "Intel"}, {0x3413E8, "Intel"},
  // Raspberry Pi
  {0xB827EB, "Raspberry Pi"}, {0xDCA632, "Raspberry Pi"}, {0xE45F01, "Raspberry Pi"}, {0x28CDC1, "Raspberry Pi"},
  // Amazon (Echo/Fire)
  {0x44650D, "Amazon"}, {0xF0272D, "Amazon"}, {0x6837E9, "Amazon"}, {0x0C47C9, "Amazon"},
  // Microsoft (Surface/Xbox)
  {0x0017FA, "Microsoft"}, {0x281878, "Microsoft"}, {0x7C1E52, "Microsoft"},
  // TP-Link
  {0x50C7BF, "TP-Link"}, {0x14CC20, "TP-Link"}, {0xA42BB0, "TP-Link"},
  // Xiaomi
  {0x640980, "Xiaomi"}, {0x286C07, "Xiaomi"}, {0x508F4C, "Xiaomi"},
  // Sonos
  {0x000E58, "Sonos"}, {0x48A6B8, "Sonos"}, {0x949F3E, "Sonos"},
  // Ubiquiti / networking
  {0x24A43C, "Ubiquiti"}, {0x788A20, "Ubiquiti"}, {0xFCECDA, "Ubiquiti"},
};

// Returns a vendor name, or "randomized" for a locally-administered (privacy) MAC,
// or "unknown" for a real address not in this small table. Sets *randomized.
inline const char* ouiLookup(const uint8_t* mac, bool* randomized) {
  // Bit 0x02 of the first octet = locally administered. Modern iOS/Android set this
  // when they rotate to a private MAC, so it is a strong "randomized" signal.
  *randomized = (mac[0] & 0x02) != 0;
  if (*randomized) return "randomized";
  uint32_t prefix = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];
  for (const auto& e : OUI_TABLE)
    if (e.prefix == prefix) return e.vendor;
  return "unknown";
}
