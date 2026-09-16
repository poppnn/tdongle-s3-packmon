# poppn packmon

WiFi packet monitor and deauthentication-attack detector for the **LilyGO T-Dongle S3**.

Plug it into any USB port and it becomes a standalone 802.11 monitor: it hops channels 1–13,
graphs live packet rate on the built-in 160×80 display, and raises a full-screen alert with the
attacker's MAC, channel and RSSI the moment it sees a deauth or disassoc frame.

**[→ Flash it from your browser](https://poppnn.github.io/tdongle-s3-packmon/)** — no toolchain needed.

---

## Features

- Promiscuous 802.11 capture on channels 1–13, hopping every 500 ms
- Live packet-rate graph (120 samples @ 200 ms ≈ 24 s window) with gradient history
- Deauth / disassoc detection: full-screen red alert, flashing border, strobing LED
- Attacker source MAC, destination MAC, channel and RSSI reported on screen and over serial
- Running counters for total packets and deauth frames
- APA102 status LED — breathing cyan when idle, red strobe under attack
- Animated boot splash

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

115200 baud over USB CDC. Each detection prints:

```
[DEAUTH] #7  src=AA:BB:CC:DD:EE:FF  dst=FF:FF:FF:FF:FF:FF  ch=6  rssi=-42 dBm
```

## Reading the display

**Normal view** — header shows current channel and last RSSI; the green graph is packet rate over
the last ~24 s with the peak value on the left axis; below it, total packets and deauth count; the
bottom line shows the last attacker's MAC suffix, channel and signal strength.

**Alert view** — triggered for 5 s after each deauth frame: flashing red border, large RSSI readout
(how close the attacker is), channel, and the full source MAC.

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
