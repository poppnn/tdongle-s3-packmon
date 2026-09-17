# poppn packmon

WiFi packet monitor and deauthentication-attack detector for the **LilyGO T-Dongle S3**.

Plug it into any USB port and it becomes a standalone 802.11 monitor: it hops channels 1–13,
graphs live packet rate on the built-in 160×80 display, and raises a full-screen alert with the
attacker's MAC, channel and RSSI the moment it sees a deauth or disassoc frame.

**[→ Flash it from your browser](https://poppnn.github.io/tdongle-s3-packmon/)** — no toolchain needed.

---

## Features

- Promiscuous 802.11 capture on channels 1–13, hopping every 500 ms
- Six pages cycled with the dongle's own button — nothing to configure
- Deauth / disassoc detection: full-screen alert over any page, strobing LED, serial log
- Beacon parsing builds a live table of nearby networks (SSID, channel, encryption, RSSI)
- Per-channel activity bars so you can see which channel the noise is on
- Channel lock to stop hopping and stare at one channel
- **SD logging** — readable CSV logs, appended across boots, enabled automatically when a card is present
- **Handshake capture** — EAPOL frames saved as standard `.pcap` for Wireshark / hashcat
- **USB Mass Storage** — mount the SD card on a PC or phone straight from the dongle, no reader needed
- **[Browser log viewer](https://poppnn.github.io/tdongle-s3-packmon/viewer.html)** — turns the CSVs into spider charts and timelines
- APA102 status LED shifts colour with traffic load, red strobe under attack
- Rendered through a framebuffer at ~30 fps: no flicker, animated transitions throughout

## Pages

| Page | Shows |
|---|---|
| **LIVE** | packets/sec, total packets, deauth count, 30 s rate graph |
| **CHANNELS** | activity bar per channel 1–13, busiest channel and its share |
| **NETWORKS** | nearby APs sorted by signal — SSID, lock, channel, RSSI bars |
| **THREATS** | deauth total and the last three events with MAC, channel, RSSI, age |
| **SYSTEM** | uptime, packet total, network count, mgmt/data split, free RAM, fps |
| **USB** | mount the SD card as a USB drive on a PC / phone |

Every page carries the current channel and live RSSI in its header.

## Controls

The dongle's BOOT button is the only control:

| Action | Effect |
|---|---|
| Tap | next page |
| Hold ~0.6 s | lock / unlock the current channel |
| Keep holding to 2.5 s | clear all counters and tables |
| Hold on the **USB** page | mount / eject the SD card as a USB drive |

A progress bar along the bottom edge fills while you hold, so you can see which
threshold you are about to cross.

## Hardware

[LilyGO T-Dongle S3](https://github.com/Xinyuan-LilyGO/T-Dongle-S3) — ESP32-S3 USB dongle with an
ST7735 0.96" display, APA102 RGB LED and a microSD slot.

| Function | GPIO |
|---|---|
| Display MOSI | 3 |
| Display SCLK | 5 |
| Display CS | 4 |
| Display DC | 2 |
| Display RST | 1 |
| Backlight | 38 |
| LED data | 40 |
| LED clock | 39 |
| Button | 0 |
| SD CLK | 12 |
| SD CMD | 16 |
| SD D0 | 14 |

## Flashing

### Web flasher (easiest)

Open **<https://poppnn.github.io/tdongle-s3-packmon/>** in desktop Chrome, Edge or Opera
(Web Serial is not available in Firefox or Safari), hold **BOOT** while plugging the dongle in,
and click Install.

### From source

Requires [PlatformIO](https://platformio.org/).

```bash
git clone https://github.com/poppnn/tdongle-s3-packmon.git
cd tdongle-s3-packmon
pio run -t upload
pio device monitor
```

## Serial output

115200 baud over USB CDC. Every detection prints immediately:

```
[DEAUTH] #7  src=AA:BB:CC:DD:EE:FF  dst=FF:FF:FF:FF:FF:FF  ch=6  rssi=-42 dBm
```

and a heartbeat lands every 10 s, so a host can log the run without watching the screen:

```
[stat] pkts=48213 (mgmt=9120 ctrl=6034 data=33059 beacon=8871) deauth=0 aps=14 rate=412/s ch=9 dropped=0 heap=241184
```

## Serial console

The USB serial port is also a **command console** — everything the button does, plus queries, driven
from a laptop or phone terminal (115200 baud, pick the CDC serial port). Type `help` for the list.

| Command | Effect |
|---|---|
| `help` / `status` | list commands / one-line summary of everything |
| `page <name\|next\|prev\|0-5>` | switch page |
| `channel <1-13>` · `lock` · `unlock` | lock to a channel / stop / resume hopping |
| `nets` · `threats` | list networks / deauth events |
| `reset` | clear all counters and tables |
| `usb on` · `usb off` | mount / eject the SD card as a USB drive |
| `sd` · `reboot` | logging status / restart |

Full reference with examples: **[docs/SERIAL.md](docs/SERIAL.md)**.

## How it works

The promiscuous callback runs in the WiFi task and stays short: it bumps counters and pushes
richer frames (beacons, deauths) into a single-producer ring buffer. `loop()` drains that ring,
so the network and threat tables are only ever touched from one task and need no locking. If the
ring fills under heavy traffic, events are dropped rather than blocking the radio — the count
shows up as `dropped` in the heartbeat.

The UI draws into a 160×80 framebuffer (25 KB) and flushes it once per frame. That is what makes
animation possible at all: partial redraws straight to the panel flicker, a single flush does not.

A deauth frame takes over the screen for 5 s regardless of which page you are on, with a shrinking
bar showing when it will hand the page back. It then slides onto **THREATS** rather than returning
to the page you were on, so the overlay gives you the headline — how strong the attacker is, right
now — and the page you land on gives the history behind it. Button taps are ignored while the
overlay is up.

## SD-card logging

Logging is **opt-in by hardware**: on boot, during the splash, packmon probes for a microSD card
(SD_MMC, 1-bit: CLK 12, CMD 16, D0 14). If one is present it logs the whole session; if not, it
runs exactly as before and never touches the card again. The splash shows `SD OK  logging sNNNN`
or `no SD  logging off`, and the SYSTEM page shows the state live.

When a card is found, a single `packmon-logs/` folder is created at the card root. The files have
**fixed names and are appended to on every boot**, so you build one combined dataset over time
instead of a new file each session. Each row carries a `session` number (an incrementing counter
kept in `session.txt`), and the pcap simply gets more packets after its one-time global header — so
the runs stay separable even though timestamps (`HH:MM:SS.mmm`) restart at zero each boot (no RTC).

### `packmon-logs/` — one folder, appended across boots

| File | One row per | Columns |
|---|---|---|
| `events.csv` | deauth / disassoc frame | `session, time, type, channel, rssi, src, dst` |
| `networks.csv` | network first seen | `session, time, bssid, ssid, channel, rssi, security` |
| `stats.csv` | 5-second snapshot | `session, time, total, mgmt, ctrl, data, beacon, deauth, rate, ch1..ch13` |
| `capture.pcap` | captured 802.11 frame | libpcap (link type 105), handshakes + a beacon per network |

The CSVs are kept open for the session and flushed every 3 s, so a yanked card loses at most the last
few seconds. SSIDs are sanitised (commas, quotes and control bytes stripped) so the CSV never breaks.
Because the stats counters are cumulative *within* a boot and reset on the next, the viewer sums each
session's final row rather than reading the last line of the file.

### `capture.pcap` — handshake captures

EAPOL frames from WPA/WPA2 four-way handshakes travel in the clear as data frames, so they are
visible in monitor mode. Each one is appended to `capture.pcap` (libpcap, link type 105 = IEEE
802.11), along with one beacon per network so the capture carries the SSID. Open it in Wireshark, or
convert it for cracking:

```bash
hcxpcapngtool -o handshake.22000 capture.pcap
hashcat -m 22000 handshake.22000 wordlist.txt
```

Capture is best-effort: channel hopping means you only catch a handshake if the dongle is on that
network's channel when a device (re)connects — **lock the channel** (hold the button) on the target
to raise your odds. This is receive-only; packmon never sends deauth frames to force a reconnect.

## USB Mass Storage

Rather than pull the microSD out, you can read it directly over the dongle's USB port. Open the
**USB** page and hold the button: the card mounts on your computer or phone as an ordinary USB drive.
Copy off `packmon-logs/`, drop the CSVs into the viewer, then hold again to eject.

- **Logging pauses while mounted.** The host owns the filesystem, so packmon closes its log files and
  stops writing until you eject; on eject it remounts and resumes as a new session (appended to the
  same files). Sector reads/writes from the host go straight to the card via the ESP-IDF sdmmc driver.
- This needs TinyUSB, so the firmware builds with `ARDUINO_USB_MODE=0` and starts USB manually in
  `setup()` (CDC for the serial console + the Mass-Storage interface). The dongle therefore always
  enumerates as a **composite device**: a small serial port (the debug console) plus a card reader
  that shows "no media" until you mount it.
- Flashing is unaffected — hold **BOOT** while plugging in to enter the ROM bootloader as usual.

## Log viewer

`docs/viewer.html` (live at **<https://poppnn.github.io/tdongle-s3-packmon/viewer.html>**) is a
single self-contained page — drop a whole session onto it (the CSVs **and** the `.pcap` files) and it
renders everything, entirely in your browser with nothing uploaded:

- a **spider / radar chart** of per-channel activity (the "toile d'araignée")
- a second radar of the frame-type mix (mgmt / ctrl / data / beacon / deauth)
- a traffic timeline (packets/s and cumulative deauth on a dual axis)
- a deauth-event bar chart coloured by signal strength
- a sortable table of every network seen
- a **handshake decoder** for the `.pcap` files: it parses the 802.11 frames client-side and, per
  AP + client pair, shows the SSID (matched from a captured beacon), both MACs, which of the four
  EAPOL messages M1–M4 were caught, and whether the pair is **crackable** (has an ANonce from M1/M3
  and a MIC from M2/M4)

Because the logs combine many boots, a **session chip bar** appears when more than one session is
present: click **All** to join everything (the default), or pick individual sessions to isolate one
boot or join any subset — every chart, card and table updates to the current selection.

There is a **Load demo data** button to see the whole layout — two sessions plus a synthetic
four-way handshake — without a card.

## Rebuilding the web flasher image

The browser flasher serves a single merged image at offset `0x0`:

```bash
pio run
esptool.py --chip esp32s3 merge_bin -o docs/firmware/poppn-packmon.bin \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0     .pio/build/lilygo-t-dongle-s3/bootloader.bin \
  0x8000  .pio/build/lilygo-t-dongle-s3/partitions.bin \
  0xe000  ~/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin \
  0x10000 .pio/build/lilygo-t-dongle-s3/firmware.bin
```

GitHub Pages serves `docs/` on the `main` branch.

## Legal

packmon is **receive-only**. It never transmits deauth frames or any other attack traffic — it only
listens and reports. Passive radio monitoring is nonetheless regulated in some jurisdictions: check
your local law, and only monitor networks you own or are authorised to test.

## Licence

MIT — see [LICENSE](LICENSE).
