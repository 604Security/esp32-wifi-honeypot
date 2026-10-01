# esp32-wifi-honeypot

A small **defensive Wi-Fi honeypot / rogue-device sensor** for the Seeed XIAO ESP32S3
([XIAOML Kit](https://www.seeedstudio.com/The-XIAOML-Kit.html)). It advertises a rotating set of
**open decoy SSIDs**, lets devices associate, serves a neutral "checking connection" page, and records
**metadata** about everything it sees — on a live web dashboard and to the microSD card.

> **Authorized / defensive use only.** This is for detection and research on **your own network** or an
> **engagement you're authorized to run**. It records metadata; it does **not** impersonate real services
> or capture passwords (that would be an evil-twin attack, not a honeypot). Keep decoy SSID names generic —
> don't spoof a real network's name.

## What it collects

Per device seen:
- **MAC address** → vendor via OUI lookup, or a **`randomized`** flag for privacy MACs (modern phones)
- **RSSI** (signal strength) + best-ever — rough "how close"
- **first / last seen**, times seen, assigned IP
- **probed SSIDs** — the networks a device is searching for (passive sniffing); a strong fingerprint
- **HTTP User-Agent / Host** from the captive page, if it connects and its browser opens

## How it works

- **AP + STA at once.** The sensor joins your management Wi-Fi (`secrets.h`) so you reach the dashboard,
  and broadcasts the decoy AP at the same time. One radio → both share a channel.
- **Rotating open decoys.** Cycles through a configurable list of generic open SSIDs (every ~3 min, only
  while nobody's connected). Devices that join get the neutral page; the DHCP/HTTP hit is logged.
- **Passive probe sniffer.** Promiscuous mode logs probe-request frames from nearby devices on the current
  channel. **Deep scan** hops 1/6/11 to sweep the band (pauses the dashboard ~9 s).
- **Dashboard** at `http://honeypot.local` (or the IP it prints): live contact table, signal bars,
  vendor/randomized chips, probed-SSID chips, sniffer toggle, decoy-name editor, log download.
- **OLED** shows status and flashes on each new device.

## Run it

```sh
cp firmware/honeypot/secrets.h.example firmware/honeypot/secrets.h   # your 2.4 GHz management Wi-Fi
make honeypot                                                        # build + flash
make monitor                                                         # watch it; it prints the dashboard URL
```

Then open the dashboard URL (or `http://honeypot.local`). Logs are at `/honeypot/events.jsonl` on the SD card,
downloadable from the dashboard.

## Notes & limits

- Single radio: the decoy AP sits on the **management channel**, so same-channel probe capture is continuous;
  band-wide capture needs Deep scan, which briefly drops the link.
- The OUI table in `oui.h` is a **small illustrative list**, not the full IEEE registry — most phones show
  `randomized` anyway, which is itself the useful signal.
- Hostname/DHCP-fingerprint capture is a future enhancement; v1 covers MAC/OUI, RSSI, probes, and HTTP UA.

See [CLAUDE.md](CLAUDE.md) for toolchain and hardware details.
