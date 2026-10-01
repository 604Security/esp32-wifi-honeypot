# esp32-wifi-honeypot

A defensive Wi-Fi honeypot / rogue-device **metadata sensor** on the Seeed XIAO ESP32S3 (XIAOML Kit).
Authorized/defensive use only: own network or an authorized engagement, metadata only, **no credential
capture, no real-brand SSID spoofing**. Shares the board + toolchain with the `petbot` / `ai-petbot` / SIA projects.

## Firmware

- `firmware/honeypot/honeypot.ino` — AP+STA; rotating open decoy SSIDs; promiscuous probe sniffer;
  AP station polling for RSSI/IP; captive DNS + neutral page; HTTP dashboard; SD event log; OLED status.
- `firmware/honeypot/page.h` — `DASH_HTML` (operator dashboard, served over the mgmt link) and
  `NEUTRAL_HTML` (what a joined device sees; generic spinner).
- `firmware/honeypot/oui.h` — small OUI vendor table + `ouiLookup()` (sets a `randomized` flag from the
  locally-administered bit `mac[0] & 0x02`).
- `firmware/honeypot/secrets.h` — management Wi-Fi (gitignored; copy from `.example`). 2.4 GHz only.
- Build: `make honeypot` (or `make build SKETCH=firmware/honeypot`). Compiles ~833 KB / 72 KB RAM.

## Design notes

- **One radio.** AP+STA share the STA's channel. The decoy AP therefore broadcasts on the management
  network's channel. Continuous probe sniffing happens on that channel; `Deep scan` hops 1/6/11 (3 s each),
  which drops the STA briefly, then `WiFi.reconnect()`.
- **Operator vs captive routing:** one httpd on port 80. `isApSide()` checks the destination IP via
  `getsockname` — clients that connected to `192.168.4.1` (the SoftAP) get the neutral page + logging;
  anything to the STA IP gets the dashboard. Wildcard `/*` catch-all is registered last.
- **Metadata path:** promiscuous RX cb (`snifferCb`, filter = MGMT, frame `0x40` = probe req) pushes to a
  FreeRTOS queue; `loop()` drains it into the `contacts[]` table (mutex-guarded, shared with httpd handlers).
  `WiFi.onEvent` catches AP assoc/disassoc; `pollStations()` enriches with RSSI + IP via
  `esp_wifi_ap_get_sta_list` + `esp_netif_get_sta_list`.
- **SD:** events appended as JSONL to `/honeypot/events.jsonl`, streamed by `/log.jsonl`. GPIO21 is SD CS
  (and the user LED) — the LED is left unused to avoid the conflict.

## Hardware / toolchain

Same as the petbot projects: XIAO ESP32S3, esp32 core **2.0.17**, PSRAM = OPI PSRAM, U8g2 for the OLED,
`arduino-cli` via the repo `Makefile`. Upload uses `--no-stub` (the esptool stub drops the USB link on this
box). Plug the board directly into the laptop, not a dock. Read serial non-interactively with
`stty -F /dev/ttyACM0 115200 raw -echo; timeout 5 cat /dev/ttyACM0` (not `arduino-cli monitor` under a pipe).

## Status

v1 builds clean (2026-09-30). Not yet verified on hardware. Next: fill `secrets.h`, `make honeypot`,
confirm the dashboard, decoy association, and probe capture. Ideas: DHCP hostname/option-55 fingerprinting,
deauth-frame detection (rogue-AP/attack sensing), CSV export, per-device detail view.
