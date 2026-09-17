#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <Arduino_GFX_Library.h>
#include <FastLED.h>
#include <FS.h>
#include <SD_MMC.h>
#include <stdarg.h>
#include "USB.h"
#include "USBCDC.h"
#include "USBMSC.h"
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"
#include "esp_timer.h"

// TinyUSB CDC serial (USB_MODE=0, CDC not started on boot). Registered and
// started manually in setup() so the Mass-Storage interface can be added
// alongside it. Debug output goes here instead of the hardware UART.
USBCDC USBSerial;
#define Serial USBSerial

// ─── Pin config (official LilyGO T-Dongle S3) ─────────────────────────────
#define PIN_MOSI  3
#define PIN_SCLK  5
#define PIN_CS    4
#define PIN_DC    2
#define PIN_RST   1
#define PIN_BL    38
#define PIN_LED_DATA  40
#define PIN_LED_CLK   39
#define PIN_BTN   0

// microSD in 1-bit SD_MMC mode (official T-Dongle S3 wiring)
#define PIN_SD_CLK  12
#define PIN_SD_CMD  16
#define PIN_SD_D0   14

#define SCR_W 160
#define SCR_H 80

// ─── Display: everything is drawn into a framebuffer, then flushed once ────
// A single flush per frame means no tearing and no flicker, which is what
// lets the whole UI animate instead of blinking a few times a second.
Arduino_DataBus *bus   = new Arduino_ESP32SPI(PIN_DC, PIN_CS, PIN_SCLK, PIN_MOSI, -1);
Arduino_G       *panel = new Arduino_ST7735(bus, PIN_RST, 3, true, 80, 160, 26, 1, 26, 1);
Arduino_Canvas  *gfx   = new Arduino_Canvas(SCR_W, SCR_H, panel, 0, 0);

CRGB led;

// ─── Timing ────────────────────────────────────────────────────────────────
#define FRAME_MS          33      // ~30 fps
#define CHANNEL_HOP_MS    500
#define MAX_CHANNELS      13
#define SAMPLE_MS         200     // graph sample period
#define GRAPH_W           152
#define ALERT_MS          5000
#define HOLD_LOCK_MS      600
#define HOLD_RESET_MS     2500
#define SLIDE_MS          240

// ─── Palette ───────────────────────────────────────────────────────────────
#define C565(r, g, b) ((uint16_t)((((r) & 0xF8) << 8) | (((g) & 0xFC) << 3) | ((b) >> 3)))

static const uint16_t C_BG        = C565(  8,   8,  10);
static const uint16_t C_PANEL     = C565( 22,  24,  26);
static const uint16_t C_ROW       = C565( 16,  18,  20);
static const uint16_t C_SEP       = C565( 40,  44,  46);
static const uint16_t C_DIM       = C565( 56,  60,  62);
static const uint16_t C_LABEL     = C565(107, 112, 110);
static const uint16_t C_TEXT      = C565(222, 226, 224);
static const uint16_t C_ACCENT    = C565(  0, 255, 189);
static const uint16_t C_ACCENT_D  = C565(  0, 110,  84);
static const uint16_t C_BLUE      = C565( 74, 142, 255);
static const uint16_t C_OK        = C565( 33, 206,  33);
static const uint16_t C_WARN      = C565(255, 161,   0);
static const uint16_t C_DANGER    = C565(255,  32,  32);
static const uint16_t C_ALERT_BG  = C565( 48,   0,   0);

// ─── 802.11 frame layout ───────────────────────────────────────────────────
typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration:16;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    unsigned seq_ctrl:16;
} __attribute__((packed)) wifi_hdr_t;

#define FC_TYPE(fc)    (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc) (((fc) >> 4) & 0xF)
#define TYPE_MGMT   0
#define TYPE_CTRL   1
#define TYPE_DATA   2
#define SUB_ASSOC_REQ    0
#define SUB_ASSOC_RESP   1
#define SUB_REASSOC_REQ  2
#define SUB_REASSOC_RESP 3
#define SUB_PROBE_REQ    4
#define SUB_PROBE_RESP   5
#define SUB_BEACON       8
#define SUB_DISASSOC    10
#define SUB_AUTH        11
#define SUB_DEAUTH      12

// ─── Counters (written by the sniffer task, read by the UI) ────────────────
volatile uint32_t s_total = 0, s_mgmt = 0, s_ctrl = 0, s_data = 0;
volatile uint32_t s_beacon = 0, s_deauth = 0, s_eapol = 0;
volatile uint32_t s_ch[MAX_CHANNELS + 1] = {0};
volatile int8_t   s_rssi = 0;
volatile uint32_t ev_dropped = 0;

// ─── Handshake capture ─────────────────────────────────────────────────────
// The WiFi callback cannot touch the SD card, so EAPOL frames (and one
// beacon per network, to name the SSID) are copied whole into this ring and
// written to a .pcapng from loop(). Enabled only when a card mounted at boot.
#define HS_RING    32
#define HS_MAXLEN  300
typedef struct {
    uint16_t len;
    int8_t   rssi;
    uint8_t  channel;
    uint64_t ts_us;             // capture time, monotonic microseconds
    uint8_t  data[HS_MAXLEN];
} rawframe_t;
static rawframe_t hs_ring[HS_RING];
static volatile uint16_t hs_head = 0, hs_tail = 0;
volatile uint32_t hs_dropped = 0;
volatile uint32_t hs_saved   = 0;    // frames written to the capture

// One beacon per BSSID is enough to name a network, so beacons/probe-responses
// are de-duplicated; everything else useful (auth, assoc, EAPOL) is captured
// as it arrives.
#define CAP_BSSIDS 32
static uint8_t cap_bssid[CAP_BSSIDS][6];
static int     cap_bssid_n = 0;
static uint64_t ts_base = 0;         // per-session offset for monotonic ts

// EAPOL handshake completeness per AP+client, so the LIVE page can say whether
// what we caught is actually usable. msgs is a bitmask: bit0..3 = M1..M4. A
// pair is usable when it has an ANonce (M1 or M3) and a MIC (M2 or M4).
#define HSST_MAX 12
typedef struct { uint8_t ap[6], sta[6]; uint8_t msgs; } hsst_t;
static hsst_t hsst[HSST_MAX];
static int hsst_n = 0;
volatile uint8_t hs_pairs = 0;       // distinct AP+client pairs with any EAPOL
volatile uint8_t hs_ok    = 0;       // pairs that are usable/crackable

// Which of the four handshake messages a Key Information field describes.
static inline uint8_t eapol_msg(uint16_t ki) {
    bool mic = ki & 0x0100, ack = ki & 0x0080, inst = ki & 0x0040, sec = ki & 0x0200;
    if (ack && !mic)          return 1;
    if (!ack && mic && !sec)  return 2;
    if (ack && mic && inst)   return 3;
    if (!ack && mic && sec)   return 4;
    return 0;
}

static bool sd_ok = false;   // decided once, during the boot splash

// ─── USB Mass Storage ──────────────────────────────────────────────────────
// On demand, the card is handed to the host (PC/phone) as a USB drive. While
// mounted, packmon stops touching the card (logging paused) and the host owns
// the filesystem; sector reads/writes go straight to the card via the IDF
// sdmmc driver. Toggled from the USB page.
static USBMSC  msc;
static bool    msc_registered = false;  // MSC interface present in USB descriptor
static volatile bool msc_mode = false;  // card currently exposed to the host
static sdmmc_card_t *msc_card = nullptr;
static volatile uint32_t msc_rd = 0, msc_wr = 0, msc_act_ts = 0;

// ─── Event queue ───────────────────────────────────────────────────────────
// The promiscuous callback stays short: it bumps counters and hands richer
// frames to the UI task through a single-producer ring, so the tables below
// are only ever touched from loop() and need no locking.
#define EV_AP     1
#define EV_DEAUTH 2
#define EV_RING   48

typedef struct {
    uint8_t  kind;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  ssid_len;
    uint8_t  sub;        // mgmt subtype (deauth vs disassoc)
    uint16_t caps;
    uint8_t  bssid[6];
    uint8_t  dst[6];
    char     ssid[32];
} evt_t;

static evt_t ev_ring[EV_RING];
static volatile uint16_t ev_head = 0, ev_tail = 0;

// ─── Discovered networks ───────────────────────────────────────────────────
#define MAX_APS 24
typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    bool     enc;
    uint32_t last_seen;
    uint32_t frames;
} ap_t;
static ap_t aps[MAX_APS];
static int  ap_count = 0;

// ─── Deauth history ────────────────────────────────────────────────────────
#define MAX_THREATS 8
typedef struct {
    uint8_t  src[6];
    uint8_t  dst[6];
    uint8_t  channel;
    int8_t   rssi;
    uint32_t ts;
} threat_t;
static threat_t threats[MAX_THREATS];
static int threat_count = 0, threat_next = 0;

// ─── UI state ──────────────────────────────────────────────────────────────
enum { PAGE_LIVE, PAGE_CHANNELS, PAGE_NETWORKS, PAGE_THREATS, PAGE_HS, PAGE_SYSTEM, PAGE_USB, PAGE_COUNT };
static const char *PAGE_NAME[PAGE_COUNT] = { "LIVE", "CHANNELS", "NETWORKS", "THREATS", "HANDSHAKE", "SYSTEM", "USB" };

static int   page = PAGE_LIVE, page_from = PAGE_LIVE;
static int   slide_dir = 1;
static float slide = 0.0f;          // 1 -> 0 while a page transition plays
static float pager_pos = 0.0f;      // animated page index for the bottom indicator

static uint16_t graph[GRAPH_W] = {0};
static int      graph_idx = 0;
static uint32_t last_snapshot = 0;

static int   current_channel = 1;
static bool  ch_lock = false;
static float ch_bar[MAX_CHANNELS + 1] = {0};    // eased bar heights
static float ch_recent[MAX_CHANNELS + 1] = {0}; // decaying activity

static float f_rate = 0, f_rssi = 0, f_scale = 1;
static float net_scroll = 0;
static uint32_t rate_window_ts = 0, rate_window_base = 0;
static uint32_t last_rate = 0;

static uint32_t alert_ts = 0;
static bool     alert_on = false;
static bool     alert_jump = false;   // land on THREATS once the alert releases
static uint8_t  alert_ch = 0;
static int8_t   alert_rssi = 0;
static uint8_t  alert_src[6] = {0};

static char     toast_msg[24] = {0};
static uint32_t toast_ts = 0;

static uint32_t fps = 0, fps_frames = 0, fps_ts = 0;
static uint32_t boot_ms = 0;

// ─── Small helpers ─────────────────────────────────────────────────────────
static inline float clampf(float v, float lo, float hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

// Exponential approach — the single reason every number on screen glides
// instead of snapping between frames.
static inline float ease(float cur, float target, float k) {
    return cur + (target - cur) * k;
}

static uint16_t lerp565(uint16_t a, uint16_t b, float t) {
    t = clampf(t, 0.0f, 1.0f);
    int ar = (a >> 11) & 0x1F, ag = (a >> 5) & 0x3F, ab = a & 0x1F;
    int br = (b >> 11) & 0x1F, bg = (b >> 5) & 0x3F, bb = b & 0x1F;
    int r = ar + (int)((br - ar) * t + 0.5f);
    int g = ag + (int)((bg - ag) * t + 0.5f);
    int l = ab + (int)((bb - ab) * t + 0.5f);
    return (uint16_t)((r << 11) | (g << 5) | l);
}

// Continuous dim-to-bright green gradient across `span` pixels.
// Interpolates over the full 6-bit green channel (RGB565) so neighbouring
// pixels never jump more than one shade — no visible banding.
static uint16_t grad_green_at(int pos, int span) {
    const int G_DIM = 11, G_BRIGHT = 63;
    if (span < 2) return (uint16_t)(G_BRIGHT << 5);
    if (pos < 0) pos = 0;
    if (pos > span - 1) pos = span - 1;
    int last = span - 1;
    int g = G_DIM + ((G_BRIGHT - G_DIM) * pos + last / 2) / last;
    return (uint16_t)(g << 5);
}

static void fmt_num(char *b, size_t n, uint32_t v) {
    if (v < 10000)         snprintf(b, n, "%u", v);
    else if (v < 1000000)  snprintf(b, n, "%u.%uk", v / 1000, (v % 1000) / 100);
    else                   snprintf(b, n, "%u.%uM", v / 1000000, (v % 1000000) / 100000);
}

static void fmt_uptime(char *b, size_t n, uint32_t ms) {
    uint32_t s = ms / 1000;
    if (s < 60)      snprintf(b, n, "%us", s);
    else if (s < 3600) snprintf(b, n, "%um%02us", s / 60, s % 60);
    else             snprintf(b, n, "%uh%02um", s / 3600, (s % 3600) / 60);
}

static String mac2str(const volatile uint8_t *mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

static int rssi_level(int8_t r) {
    if (r >= -52) return 4;
    if (r >= -64) return 3;
    if (r >= -74) return 2;
    if (r >= -85) return 1;
    return 0;
}

static uint16_t rssi_color(int8_t r) {
    if (r >= -60) return C_ACCENT;
    if (r >= -75) return C_WARN;
    return C_DANGER;
}

// ─── SD logging ────────────────────────────────────────────────────────────
// All under /packmon-logs, with fixed names appended to across boots:
// events.csv, networks.csv, stats.csv and capture.pcapng. Each row carries a
// `session` number so the combined data stays separable. CSV is chosen so the
// raw files are readable in any text editor or spreadsheet; the bundled viewer
// turns them into charts. Files are kept open for the whole session and
// flushed on a timer, so no line is lost to a yank but the card is not
// hammered per write.
static int  log_session = 0;
static File f_events, f_nets, f_stats, f_hs;
static bool log_dirty = false;

// Uptime as HH:MM:SS.mmm — there is no RTC, so every timestamp is relative to
// power-on. Human-legible and still sortable.
static void log_stamp(char *b, size_t n, uint32_t ms) {
    uint32_t s = ms / 1000, msr = ms % 1000;
    snprintf(b, n, "%02u:%02u:%02u.%03u", s / 3600, (s / 60) % 60, s % 60, msr);
}

static void log_csv_ssid(File &f, const char *ssid) {
    // Keep SSIDs from breaking the CSV: drop commas, quotes and control bytes.
    if (!ssid || !ssid[0]) { f.print("<hidden>"); return; }
    for (const char *p = ssid; *p; p++) {
        char c = *p;
        if (c == ',' || c == '"' || c < 0x20) c = ' ';
        f.write((uint8_t)c);
    }
}

static void log_event(const uint8_t *src, const uint8_t *dst, uint8_t sub,
                      uint8_t ch, int8_t rssi) {
    if (!sd_ok || !f_events) return;
    char ts[16]; log_stamp(ts, sizeof(ts), millis());
    f_events.printf("%d,%s,%s,%u,%d,%02X:%02X:%02X:%02X:%02X:%02X,"
                    "%02X:%02X:%02X:%02X:%02X:%02X\n",
                    log_session, ts, sub == SUB_DEAUTH ? "deauth" : "disassoc", ch, rssi,
                    src[0], src[1], src[2], src[3], src[4], src[5],
                    dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
    log_dirty = true;
}

static void log_network(const ap_t *a) {
    if (!sd_ok || !f_nets) return;
    char ts[16]; log_stamp(ts, sizeof(ts), millis());
    f_nets.printf("%d,%s,%02X:%02X:%02X:%02X:%02X:%02X,",
                  log_session, ts, a->bssid[0], a->bssid[1], a->bssid[2],
                  a->bssid[3], a->bssid[4], a->bssid[5]);
    log_csv_ssid(f_nets, a->ssid);
    f_nets.printf(",%u,%d,%s\n", a->channel, a->rssi, a->enc ? "enc" : "open");
    log_dirty = true;
}

static void log_stats(uint32_t rate) {
    if (!sd_ok || !f_stats) return;
    char ts[16]; log_stamp(ts, sizeof(ts), millis());
    f_stats.printf("%d,%s,%u,%u,%u,%u,%u,%u,%u",
                   log_session, ts, s_total, s_mgmt, s_ctrl, s_data, s_beacon, s_deauth, rate);
    for (int c = 1; c <= MAX_CHANNELS; c++) f_stats.printf(",%u", s_ch[c]);
    f_stats.print("\n");
    log_dirty = true;
}

static void log_flush() {
    if (!sd_ok || !log_dirty) return;
    if (f_events) f_events.flush();
    if (f_nets)   f_nets.flush();
    if (f_stats)  f_stats.flush();
    if (f_hs)     f_hs.flush();
    log_dirty = false;
}

// ── pcapng writer ──────────────────────────────────────────────────────────
// pcapng (not classic pcap) so hcxpcapngtool is happy: a Section Header Block
// and an Interface Description Block once, then an Enhanced Packet Block per
// frame with a proper 64-bit microsecond timestamp. Link type is RADIOTAP
// (127); each frame is prefixed with a radiotap header carrying channel and
// signal, which the plain 802.11 link type could not convey.
static void pn_u32(File &f, uint32_t v) {
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    f.write(b, 4);
}

// LINKTYPE_IEEE802_11_RADIOTAP = 127
static void pcapng_write_header(File &f) {
    // Section Header Block
    pn_u32(f, 0x0A0D0D0A);       // block type
    pn_u32(f, 28);               // block total length
    pn_u32(f, 0x1A2B3C4D);       // byte-order magic
    pn_u32(f, 0x00000001);       // version major=1, minor=0 (LE u16 each)
    pn_u32(f, 0xFFFFFFFF);       // section length (unknown) low
    pn_u32(f, 0xFFFFFFFF);       //                          high
    pn_u32(f, 28);               // block total length
    // Interface Description Block, with microsecond timestamp resolution
    pn_u32(f, 0x00000001);       // block type
    pn_u32(f, 32);               // block total length
    pn_u32(f, 0x0000007F);       // linktype 127 (low 16) + reserved
    pn_u32(f, 0);                // snaplen (0 = no limit)
    // option if_tsresol = 6 (10^-6 s): code 9, len 1, value 6, padded
    pn_u32(f, 0x00010009);       // opt code 9, opt len 1
    pn_u32(f, 0x00000006);       // value 6 + 3 pad bytes
    pn_u32(f, 0x00000000);       // opt endofopt (code 0, len 0)
    pn_u32(f, 32);               // block total length
}

// Radiotap header: present = Flags(bit1) | Channel(bit3) | dBm AntSignal(bit5).
// ESP32 promiscuous frames include the 4-byte FCS (counted in sig_len), so the
// Flags field advertises "FCS at end" — otherwise tools treat it as payload
// and flag every frame malformed. 15 bytes (one pad before the aligned
// Channel field).
static int build_radiotap(uint8_t *rt, uint8_t channel, int8_t rssi) {
    rt[0] = 0; rt[1] = 0;                 // version, pad
    rt[2] = 15; rt[3] = 0;                // it_len = 15
    rt[4] = 0x2A; rt[5] = 0; rt[6] = 0; rt[7] = 0;  // it_present: bits 1,3,5
    rt[8] = 0x10;                         // Flags: FCS present at end
    rt[9] = 0;                            // pad to 2-byte align for Channel
    uint16_t freq = 2412 + (channel >= 1 && channel <= 13 ? (channel - 1) * 5 : 0);
    if (channel == 14) freq = 2484;
    rt[10] = (uint8_t)freq; rt[11] = (uint8_t)(freq >> 8);   // channel frequency
    rt[12] = 0xC0; rt[13] = 0x00;         // channel flags: 2GHz + OFDM
    rt[14] = (uint8_t)rssi;               // dBm antenna signal (signed)
    return 15;
}

// Drain captured frames to the .pcapng as Enhanced Packet Blocks. In loop().
static void hs_drain() {
    if (!sd_ok || !f_hs) return;
    uint8_t rt[16];
    while (hs_tail != hs_head) {
        rawframe_t *r = &hs_ring[hs_tail];
        int rtlen = build_radiotap(rt, r->channel, r->rssi);
        uint32_t caplen = rtlen + r->len;
        uint32_t pad = (4 - (caplen & 3)) & 3;
        uint32_t total = 32 + caplen + pad;
        uint64_t ts = r->ts_us;
        pn_u32(f_hs, 0x00000006);            // EPB type
        pn_u32(f_hs, total);                 // block total length
        pn_u32(f_hs, 0);                     // interface id
        pn_u32(f_hs, (uint32_t)(ts >> 32));  // timestamp high
        pn_u32(f_hs, (uint32_t)ts);          // timestamp low
        pn_u32(f_hs, caplen);                // captured length
        pn_u32(f_hs, caplen);                // original length
        f_hs.write(rt, rtlen);
        f_hs.write(r->data, r->len);
        for (uint32_t i = 0; i < pad; i++) f_hs.write((uint8_t)0);
        pn_u32(f_hs, total);                 // block total length (repeat)
        hs_saved++;
        log_dirty = true;
        hs_tail = (uint16_t)((hs_tail + 1) % HS_RING);
    }
}

static int sd_next_session() {
    int n = 1;
    File r = SD_MMC.open("/packmon-logs/session.txt", FILE_READ);
    if (r) { n = r.parseInt() + 1; r.close(); }
    if (n < 1) n = 1;
    File w = SD_MMC.open("/packmon-logs/session.txt", FILE_WRITE);
    if (w) { w.printf("%d", n); w.close(); }
    return n;
}

// Mount the card and open the session-shared log files. Called once from the
// splash; everything logging-related keys off the sd_ok it returns.
//
// Files have fixed names and are opened for APPEND, so every boot adds to the
// same growing dataset instead of leaving a trail of per-session files. A
// `session` column (and, for the pcapng, simply more packet blocks after the single
// global header) keeps the runs separable — the timestamps restart at zero
// each boot because there is no RTC.
static bool sd_init() {
    SD_MMC.setPins(PIN_SD_CLK, PIN_SD_CMD, PIN_SD_D0);
    if (!SD_MMC.begin("/sdcard", true, false, 20000)) return false;   // 1-bit
    if (SD_MMC.cardType() == CARD_NONE) { SD_MMC.end(); return false; }

    SD_MMC.mkdir("/packmon-logs");
    log_session = sd_next_session();

    // Per-session timestamp base keeps the appended pcapng monotonically
    // increasing across boots (esp_timer resets to 0 each boot). One day per
    // session — a session would have to run 24 h to overlap the next.
    ts_base = (uint64_t)log_session * 86400ULL * 1000000ULL;
    cap_bssid_n = 0;

    // Whether to write the header is decided from exists() *before* opening:
    // File::size() straight after a FILE_APPEND open proved unreliable on this
    // hardware, which could leave a file (including the pcapng) with no header.
    bool ev_new = !SD_MMC.exists("/packmon-logs/events.csv");
    bool nt_new = !SD_MMC.exists("/packmon-logs/networks.csv");
    bool st_new = !SD_MMC.exists("/packmon-logs/stats.csv");
    bool hs_new = !SD_MMC.exists("/packmon-logs/capture.pcapng");

    f_events = SD_MMC.open("/packmon-logs/events.csv", FILE_APPEND);
    if (f_events && ev_new)
        f_events.print("session,time,type,channel,rssi,src,dst\n");

    f_nets = SD_MMC.open("/packmon-logs/networks.csv", FILE_APPEND);
    if (f_nets && nt_new)
        f_nets.print("session,time,bssid,ssid,channel,rssi,security\n");

    f_stats = SD_MMC.open("/packmon-logs/stats.csv", FILE_APPEND);
    if (f_stats && st_new) {
        f_stats.print("session,time,total,mgmt,ctrl,data,beacon,deauth,rate");
        for (int c = 1; c <= MAX_CHANNELS; c++) f_stats.printf(",ch%d", c);
        f_stats.print("\n");
    }

    // pcapng section/interface headers: written once when the file is first
    // created; later boots append their packet blocks after them.
    f_hs = SD_MMC.open("/packmon-logs/capture.pcapng", FILE_APPEND);
    if (f_hs && hs_new) pcapng_write_header(f_hs);

    log_dirty = true;
    return f_events && f_stats;
}

// ─── USB Mass Storage ──────────────────────────────────────────────────────
// Host block I/O goes straight to the card. These run in the TinyUSB task, so
// they only touch msc_card (valid only while msc_mode is true) and counters.
static int32_t on_msc_read(uint32_t lba, uint32_t offset, void *buffer, uint32_t bufsize) {
    if (!msc_card) return -1;
    uint32_t ss = msc_card->csd.sector_size;
    if (sdmmc_read_sectors(msc_card, buffer, lba + offset / ss, bufsize / ss) != ESP_OK) return -1;
    msc_rd++; msc_act_ts = millis();
    return bufsize;
}
static int32_t on_msc_write(uint32_t lba, uint32_t offset, uint8_t *buffer, uint32_t bufsize) {
    if (!msc_card) return -1;
    uint32_t ss = msc_card->csd.sector_size;
    if (sdmmc_write_sectors(msc_card, buffer, lba + offset / ss, bufsize / ss) != ESP_OK) return -1;
    msc_wr++; msc_act_ts = millis();
    return bufsize;
}
static bool on_msc_startstop(uint8_t, bool, bool) { return true; }

// Bring up a raw sdmmc card handle for sector access (1-bit, same pins).
static bool sd_raw_open() {
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    host.max_freq_khz = 20000;
    host.flags = SDMMC_HOST_FLAG_1BIT;
    if (sdmmc_host_init() != ESP_OK) return false;
    sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
    slot.width = 1;
    slot.clk = (gpio_num_t)PIN_SD_CLK;
    slot.cmd = (gpio_num_t)PIN_SD_CMD;
    slot.d0  = (gpio_num_t)PIN_SD_D0;
    if (sdmmc_host_init_slot(SDMMC_HOST_SLOT_1, &slot) != ESP_OK) { sdmmc_host_deinit(); return false; }
    msc_card = (sdmmc_card_t *)malloc(sizeof(sdmmc_card_t));
    if (!msc_card) { sdmmc_host_deinit(); return false; }
    if (sdmmc_card_init(&host, msc_card) != ESP_OK) {
        free(msc_card); msc_card = nullptr; sdmmc_host_deinit(); return false;
    }
    return true;
}

// Enter USB-drive mode: close logs, release the Arduino mount, hand the raw
// card to the host. Logging is off (sd_ok false) until we exit.
static bool msc_enter() {
    if (msc_mode || !msc_registered) return false;
    log_flush();
    if (f_events) f_events.close();
    if (f_nets)   f_nets.close();
    if (f_stats)  f_stats.close();
    if (f_hs)     f_hs.close();
    sd_ok = false;
    SD_MMC.end();
    if (!sd_raw_open()) { sd_ok = sd_init(); return false; }  // recover on failure
    msc_rd = msc_wr = 0;
    msc.mediaPresent(true);
    msc_mode = true;
    Serial.println("[usb] mass storage mode on");
    return true;
}

// Leave USB-drive mode: hide media from the host, release the raw card, remount
// for logging (as a fresh session, appended to the same files).
static void msc_exit() {
    if (!msc_mode) return;
    msc.mediaPresent(false);
    msc_mode = false;
    delay(50);                       // let any in-flight host op finish
    if (msc_card) { free(msc_card); msc_card = nullptr; }
    sdmmc_host_deinit();
    sd_ok = sd_init();
    Serial.println("[usb] mass storage mode off");
}

// ─── Text helpers ──────────────────────────────────────────────────────────
static void txt(int x, int y, uint16_t color, uint8_t size, const char *fmt, ...) {
    char b[64];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
    gfx->setTextColor(color);
    gfx->setTextSize(size);
    gfx->setCursor(x, y);
    gfx->print(b);
}

static void txt_r(int xr, int y, uint16_t color, uint8_t size, const char *fmt, ...) {
    char b[64];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
    gfx->setTextColor(color);
    gfx->setTextSize(size);
    gfx->setCursor(xr - (int)strlen(b) * 6 * size, y);
    gfx->print(b);
}

static void txt_c(int xc, int y, uint16_t color, uint8_t size, const char *fmt, ...) {
    char b[64];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
    gfx->setTextColor(color);
    gfx->setTextSize(size);
    gfx->setCursor(xc - (int)strlen(b) * 3 * size, y);
    gfx->print(b);
}

static void draw_lock(int x, int y, uint16_t c) {
    gfx->drawFastHLine(x + 1, y, 2, c);
    gfx->drawPixel(x, y + 1, c);
    gfx->drawPixel(x + 3, y + 1, c);
    gfx->fillRect(x, y + 2, 4, 4, c);
}

static void draw_rssi_bars(int x, int y, int8_t rssi) {
    int lvl = rssi_level(rssi);
    uint16_t on = rssi_color(rssi);
    for (int i = 0; i < 4; i++) {
        int h = 2 + i * 2;
        gfx->fillRect(x + i * 4, y + 8 - h, 3, h, i < lvl ? on : C_SEP);
    }
}

// ─── Promiscuous callback ──────────────────────────────────────────────────
static inline void ev_push(const evt_t *e) {
    uint16_t nh = (uint16_t)((ev_head + 1) % EV_RING);
    if (nh == ev_tail) { ev_dropped++; return; }
    memcpy(&ev_ring[ev_head], e, sizeof(evt_t));
    ev_head = nh;
}

// Copy a raw 802.11 frame into the capture ring for the .pcapng, tagging it
// with signal, channel and a monotonic timestamp so hcxpcapngtool can build a
// proper radiotap header and EAPOL timings.
static inline void cap_push(const uint8_t *frame, int len, int8_t rssi, uint8_t ch) {
    uint16_t nh = (uint16_t)((hs_head + 1) % HS_RING);
    if (nh == hs_tail) { hs_dropped++; return; }
    int n = len > HS_MAXLEN ? HS_MAXLEN : len;
    hs_ring[hs_head].len     = n;
    hs_ring[hs_head].rssi    = rssi;
    hs_ring[hs_head].channel = ch;
    hs_ring[hs_head].ts_us   = ts_base + (uint64_t)esp_timer_get_time();
    memcpy(hs_ring[hs_head].data, frame, n);
    hs_head = nh;
}

// True for the management frames worth keeping for handshake / PSK recovery.
static inline bool cap_want_mgmt(uint8_t sub) {
    return sub == SUB_AUTH || sub == SUB_ASSOC_REQ || sub == SUB_ASSOC_RESP ||
           sub == SUB_REASSOC_REQ || sub == SUB_REASSOC_RESP ||
           sub == SUB_PROBE_REQ || sub == SUB_DEAUTH || sub == SUB_DISASSOC;
}

void IRAM_ATTR pkt_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t *rx = &pkt->rx_ctrl;
    int len = rx->sig_len;
    if (len < (int)sizeof(wifi_hdr_t)) return;

    s_rssi = rx->rssi;
    s_total++;
    if (current_channel >= 1 && current_channel <= MAX_CHANNELS) s_ch[current_channel]++;

    wifi_hdr_t *h = (wifi_hdr_t *)pkt->payload;
    uint16_t fc  = h->frame_ctrl;
    uint8_t  ft  = FC_TYPE(fc);
    uint8_t  sub = FC_SUBTYPE(fc);

    if (ft == TYPE_CTRL) { s_ctrl++; return; }

    if (ft == TYPE_DATA) {
        s_data++;
        // EAPOL detection for handshake capture. The 4-way handshake travels
        // in the clear as data frames carrying an LLC/SNAP header with
        // ethertype 0x888E, so it is visible even on WPA2 networks.
        if (sd_ok) {
            int hdr = 24;
            if (sub & 0x08) hdr += 2;                        // QoS data: +2
            if (((fc >> 8) & 1) && ((fc >> 9) & 1)) hdr += 6; // 4-addr WDS
            if (len >= hdr + 8) {
                const uint8_t *l = pkt->payload + hdr;
                if (l[0] == 0xAA && l[1] == 0xAA && l[2] == 0x03 &&
                    l[6] == 0x88 && l[7] == 0x8E) {
                    s_eapol++;
                    cap_push(pkt->payload, len, rx->rssi, current_channel);
                    // Classify the message and track handshake completeness.
                    if (len >= hdr + 15) {
                        uint8_t m = eapol_msg((uint16_t)((l[13] << 8) | l[14]));
                        if (m) {
                            bool fromds = (fc >> 9) & 1;
                            const uint8_t *ap  = fromds ? h->addr2 : h->addr1;
                            const uint8_t *sta = fromds ? h->addr1 : h->addr2;
                            int s = -1;
                            for (int i = 0; i < hsst_n; i++)
                                if (!memcmp(hsst[i].ap, ap, 6) && !memcmp(hsst[i].sta, sta, 6)) { s = i; break; }
                            if (s < 0 && hsst_n < HSST_MAX) {
                                s = hsst_n++;
                                memcpy(hsst[s].ap, ap, 6);
                                memcpy(hsst[s].sta, sta, 6);
                                hsst[s].msgs = 0;
                            }
                            if (s >= 0) {
                                hsst[s].msgs |= (uint8_t)(1 << (m - 1));
                                uint8_t pairs = 0, ok = 0;
                                for (int i = 0; i < hsst_n; i++) {
                                    pairs++;
                                    uint8_t g = hsst[i].msgs;
                                    if ((g & 0x5) && (g & 0xA)) ok++;   // (M1|M3) & (M2|M4)
                                }
                                hs_pairs = pairs;
                                hs_ok = ok;
                            }
                        }
                    }
                }
            }
        }
        return;
    }

    if (ft != TYPE_MGMT) return;

    s_mgmt++;

    if (sub == SUB_BEACON || sub == SUB_PROBE_RESP) {
        s_beacon++;
        evt_t e;
        memset(&e, 0, sizeof(e));
        e.kind    = EV_AP;
        e.rssi    = rx->rssi;
        e.channel = current_channel;
        memcpy(e.bssid, h->addr2, 6);

        const uint8_t *p = pkt->payload;
        if (len >= 36) {
            e.caps = (uint16_t)(p[34] | (p[35] << 8));
            int i = 36, guard = 0;
            while (i + 2 <= len && guard++ < 24) {
                uint8_t tag = p[i], tlen = p[i + 1];
                if (i + 2 + tlen > len) break;
                if (tag == 0) {
                    uint8_t n = tlen > 32 ? 32 : tlen;
                    memcpy(e.ssid, p + i + 2, n);
                    e.ssid_len = n;
                } else if (tag == 3 && tlen >= 1) {
                    uint8_t c = p[i + 2];
                    if (c >= 1 && c <= MAX_CHANNELS) e.channel = c;
                }
                i += 2 + tlen;
            }
        }
        ev_push(&e);

        // Capture one beacon/probe-response per BSSID — enough to carry the
        // ESSID for the handshake without flooding the file with beacons.
        if (sd_ok) {
            bool seen = false;
            for (int i = 0; i < cap_bssid_n; i++)
                if (memcmp(cap_bssid[i], h->addr2, 6) == 0) { seen = true; break; }
            if (!seen && cap_bssid_n < CAP_BSSIDS) {
                memcpy(cap_bssid[cap_bssid_n++], h->addr2, 6);
                cap_push(pkt->payload, len, rx->rssi, e.channel);
            }
        }
        return;
    }

    if (sub == SUB_DEAUTH || sub == SUB_DISASSOC) {
        s_deauth++;
        evt_t e;
        memset(&e, 0, sizeof(e));
        e.kind    = EV_DEAUTH;
        e.sub     = sub;
        e.rssi    = rx->rssi;
        e.channel = current_channel;
        memcpy(e.bssid, h->addr2, 6);
        memcpy(e.dst,   h->addr1, 6);
        ev_push(&e);
    }

    // Auth / (re)assoc / probe-req / deauth frames carry the RSN info and
    // sequencing hcx needs to recover the PSK — capture them all.
    if (sd_ok && cap_want_mgmt(sub)) cap_push(pkt->payload, len, rx->rssi, current_channel);
}

// ─── Table updates (UI task only) ──────────────────────────────────────────
static void ap_update(const evt_t *e) {
    for (int i = 0; i < ap_count; i++) {
        if (memcmp(aps[i].bssid, e->bssid, 6) == 0) {
            aps[i].rssi      = (int8_t)((aps[i].rssi * 3 + e->rssi) / 4);
            aps[i].channel   = e->channel;
            aps[i].last_seen = millis();
            aps[i].frames++;
            if (e->ssid_len && aps[i].ssid[0] == '\0') {
                memcpy(aps[i].ssid, e->ssid, e->ssid_len);
                aps[i].ssid[e->ssid_len] = '\0';
            }
            return;
        }
    }

    int slot = ap_count;
    if (ap_count < MAX_APS) {
        ap_count++;
    } else {
        // Table full: evict whatever we have not heard from in the longest.
        uint32_t oldest = UINT32_MAX;
        slot = 0;
        for (int i = 0; i < MAX_APS; i++) {
            if (aps[i].last_seen < oldest) { oldest = aps[i].last_seen; slot = i; }
        }
    }

    memset(&aps[slot], 0, sizeof(ap_t));
    memcpy(aps[slot].bssid, e->bssid, 6);
    if (e->ssid_len) {
        memcpy(aps[slot].ssid, e->ssid, e->ssid_len);
        aps[slot].ssid[e->ssid_len] = '\0';
    }
    aps[slot].channel   = e->channel;
    aps[slot].rssi      = e->rssi;
    aps[slot].enc       = (e->caps & 0x0010) != 0;
    aps[slot].last_seen = millis();
    aps[slot].frames    = 1;
    log_network(&aps[slot]);
}

static void threat_add(const evt_t *e) {
    threat_t *t = &threats[threat_next];
    memcpy(t->src, e->bssid, 6);
    memcpy(t->dst, e->dst, 6);
    t->channel = e->channel;
    t->rssi    = e->rssi;
    t->ts      = millis();
    threat_next = (threat_next + 1) % MAX_THREATS;
    if (threat_count < MAX_THREATS) threat_count++;

    alert_ts   = millis();
    alert_on   = true;
    alert_jump = false;   // full-screen alert only; no auto-switch to THREATS
    alert_ch   = e->channel;
    alert_rssi = e->rssi;
    memcpy(alert_src, e->bssid, 6);

    log_event(t->src, t->dst, e->sub, t->channel, t->rssi);

    Serial.printf("[DEAUTH] #%u  src=%s  dst=%s  ch=%d  rssi=%d dBm\n",
                  s_deauth, mac2str(t->src).c_str(), mac2str(t->dst).c_str(),
                  t->channel, t->rssi);
}

static void drain_events() {
    while (ev_tail != ev_head) {
        evt_t *e = &ev_ring[ev_tail];
        if (e->kind == EV_AP)          ap_update(e);
        else if (e->kind == EV_DEAUTH) threat_add(e);
        ev_tail = (uint16_t)((ev_tail + 1) % EV_RING);
    }
}

// Networks still worth showing — anything silent for two minutes is gone.
static int ap_active() {
    int n = 0;
    uint32_t now = millis();
    for (int i = 0; i < ap_count; i++) if (now - aps[i].last_seen <= 120000) n++;
    return n;
}

// Strongest-first ordering, recomputed only when drawn.
static int ap_sorted(int *idx) {
    int n = 0;
    uint32_t now = millis();
    for (int i = 0; i < ap_count; i++) {
        if (now - aps[i].last_seen > 120000) continue;   // aged out
        idx[n++] = i;
    }
    for (int i = 1; i < n; i++) {
        int k = idx[i], j = i - 1;
        while (j >= 0 && aps[idx[j]].rssi < aps[k].rssi) { idx[j + 1] = idx[j]; j--; }
        idx[j + 1] = k;
    }
    return n;
}

// ─── Chrome ────────────────────────────────────────────────────────────────
static void toast(const char *msg) {
    strncpy(toast_msg, msg, sizeof(toast_msg) - 1);
    toast_msg[sizeof(toast_msg) - 1] = '\0';
    toast_ts = millis();
}

static void draw_header(int ox, const char *title) {
    gfx->fillRect(ox, 0, SCR_W, 11, C_PANEL);
    gfx->drawFastHLine(ox, 11, SCR_W, C_SEP);
    txt(ox + 4, 2, C_ACCENT, 1, title);
    gfx->drawFastHLine(ox + 4, 10, (int)strlen(title) * 6, C_ACCENT);

    // Channel and live signal strength ride in the header on every page.
    txt_r(ox + SCR_W - 4, 2, rssi_color((int8_t)f_rssi), 1, "%d", (int)f_rssi);
    txt_r(ox + SCR_W - 30, 2, ch_lock ? C_WARN : C_LABEL, 1, "CH%02d", current_channel);
    if (ch_lock) draw_lock(ox + SCR_W - 64, 2, C_WARN);
}

static void draw_pager() {
    const int n = PAGE_COUNT;
    const int gap = 3, y = 77, h = 2;
    int seg = (SCR_W - 8 - (n - 1) * gap) / n;
    for (int i = 0; i < n; i++) {
        gfx->fillRect(4 + i * (seg + gap), y, seg, h, C_SEP);
    }
    // The lit segment tracks the animated page index, so it glides with the
    // page rather than jumping when the transition ends.
    float x = 4.0f + pager_pos * (seg + gap);
    gfx->fillRect((int)(x + 0.5f), y, seg, h, C_ACCENT);
}

static void draw_toast() {
    uint32_t age = millis() - toast_ts;
    if (!toast_msg[0] || age > 1600) return;
    float t = age < 160 ? (float)age / 160.0f
            : (age > 1440 ? 1.0f - (float)(age - 1440) / 160.0f : 1.0f);
    t = clampf(t, 0.0f, 1.0f);

    int w = (int)strlen(toast_msg) * 6 + 16;
    int x = (SCR_W - w) / 2;
    int y = (int)(SCR_H - 4 + (1.0f - t) * 20) - 14;
    gfx->fillRoundRect(x, y, w, 14, 3, C_PANEL);
    gfx->drawRoundRect(x, y, w, 14, 3, lerp565(C_PANEL, C_ACCENT, t));
    txt_c(SCR_W / 2, y + 4, lerp565(C_PANEL, C_TEXT, t), 1, toast_msg);
}

static void draw_hold_progress(uint32_t held) {
    if (held < 300) return;
    float t = clampf((float)held / (float)HOLD_RESET_MS, 0.0f, 1.0f);
    uint16_t c = held >= HOLD_LOCK_MS ? C_WARN : C_ACCENT_D;
    if (t >= 1.0f) c = C_DANGER;
    gfx->fillRect(0, SCR_H - 3, (int)(SCR_W * t), 3, c);
}

// ─── Page: LIVE ────────────────────────────────────────────────────────────
static void page_live(int ox) {
    draw_header(ox, PAGE_NAME[PAGE_LIVE]);

    uint16_t rate_c = f_rate > 400 ? C_DANGER : (f_rate > 120 ? C_WARN : C_ACCENT);
    txt(ox + 4, 15, rate_c, 3, "%d", (int)(f_rate + 0.5f));
    txt(ox + 4, 41, C_LABEL, 1, "PKT/S");

    char b[16];
    fmt_num(b, sizeof(b), s_total);
    txt_r(ox + SCR_W - 4, 15, C_LABEL, 1, "TOTAL");
    txt_r(ox + SCR_W - 4, 25, C_TEXT, 2, b);

    uint32_t d = s_deauth;
    txt_r(ox + SCR_W - 4, 43, d ? C_DANGER : C_LABEL, 1, "DEAUTH %u", d);

    // Handshake status: how many EAPOL frames, and whether any captured
    // handshake is actually usable (has an ANonce + a MIC).
    int hy = 50;
    if (s_eapol == 0) {
        txt(ox + 4, hy, C_SEP, 1, "HS  no EAPOL yet");
    } else {
        txt(ox + 4, hy, C_LABEL, 1, "EAPOL");
        txt(ox + 42, hy, C_TEXT, 1, "%u", s_eapol);
        if (hs_ok > 0)
            txt(ox + 74, hy, C_OK,   1, "USABLE %u/%u", hs_ok, hs_pairs);
        else
            txt(ox + 74, hy, C_WARN, 1, "PARTIAL %u", hs_pairs);
    }

    // Area chart: gradient body with a bright tip, scaled on an eased max so
    // the whole plot does not jump when a new peak arrives.
    const int gx = ox + 4, gy = 59, gh = 14;
    gfx->fillRect(gx, gy, GRAPH_W, gh, C_ROW);

    uint16_t peak = 1;
    for (int i = 0; i < GRAPH_W; i++) if (graph[i] > peak) peak = graph[i];
    f_scale = ease(f_scale, (float)peak, 0.08f);
    float scale = f_scale < 1.0f ? 1.0f : f_scale;

    for (int i = 0; i < GRAPH_W; i++) {
        int idx = (graph_idx + 1 + i) % GRAPH_W;
        int h = (int)((float)graph[idx] / scale * (gh - 1) + 0.5f);
        if (h <= 0) continue;
        if (h > gh) h = gh;
        gfx->drawFastVLine(gx + i, gy + gh - h, h, grad_green_at(i, GRAPH_W));
        gfx->drawPixel(gx + i, gy + gh - h, C_ACCENT);
    }
    gfx->drawFastHLine(gx, gy + gh, GRAPH_W, C_SEP);
}

// ─── Page: CHANNELS ────────────────────────────────────────────────────────
static void page_channels(int ox) {
    draw_header(ox, PAGE_NAME[PAGE_CHANNELS]);

    float mx = 1.0f;
    int busiest = 1;
    for (int c = 1; c <= MAX_CHANNELS; c++) {
        if (ch_recent[c] > mx) { mx = ch_recent[c]; busiest = c; }
    }

    uint32_t tot = 0;
    for (int c = 1; c <= MAX_CHANNELS; c++) tot += s_ch[c];
    int pct = tot ? (int)((uint64_t)s_ch[busiest] * 100 / tot) : 0;

    txt(ox + 4, 14, C_LABEL, 1, "BUSIEST");
    txt(ox + 52, 14, C_ACCENT, 1, "CH%02d", busiest);
    txt_r(ox + SCR_W - 4, 14, C_TEXT, 1, "%d%%", pct);

    const int base = 64, top = 26, maxh = base - top;
    const int slot = 11, bw = 8;
    const int x0 = ox + (SCR_W - (MAX_CHANNELS * slot - (slot - bw))) / 2;

    for (int c = 1; c <= MAX_CHANNELS; c++) {
        int x = x0 + (c - 1) * slot;
        int h = (int)(ch_bar[c] / mx * maxh + 0.5f);
        if (h < 1) h = 1;
        if (h > maxh) h = maxh;

        gfx->fillRect(x, top, bw, maxh, C_ROW);
        for (int r = 0; r < h; r++) {
            gfx->drawFastHLine(x, base - 1 - r, bw, grad_green_at(r, maxh));
        }
        if (c == current_channel) {
            gfx->drawRect(x - 1, top - 1, bw + 2, maxh + 2, C_ACCENT);
            gfx->fillRect(x, base, bw, 1, C_ACCENT);
        }
        if (c == 1 || c == 4 || c == 7 || c == 10 || c == 13) {
            txt_c(x + bw / 2, 66, c == current_channel ? C_ACCENT : C_LABEL, 1, "%d", c);
        }
    }
    gfx->drawFastHLine(ox + 4, base, SCR_W - 8, C_SEP);
}

// ─── Page: NETWORKS ────────────────────────────────────────────────────────
static void page_networks(int ox) {
    int idx[MAX_APS];
    int n = ap_sorted(idx);

    if (n == 0) {
        draw_header(ox, PAGE_NAME[PAGE_NETWORKS]);
        int dots = (millis() / 400) % 4;
        txt_c(ox + SCR_W / 2, 34, C_LABEL, 1, "SCANNING%.*s", dots, "...");
        txt_c(ox + SCR_W / 2, 46, C_SEP, 1, "listening for beacons");
        return;
    }

    const int rows = 5, rh = 12, y0 = 13;

    // More networks than rows: creep through the list instead of paging, so
    // nothing ever snaps.
    float max_scroll = (float)(n > rows ? n - rows : 0);
    if (max_scroll > 0) {
        float t = (float)((millis() / 100) % (uint32_t)((max_scroll + 1) * 25)) / 25.0f;
        net_scroll = ease(net_scroll, clampf(t, 0.0f, max_scroll), 0.06f);
    } else {
        net_scroll = 0;
    }

    int first = (int)net_scroll;
    int off = (int)((net_scroll - first) * rh);

    for (int r = 0; r <= rows; r++) {
        int i = first + r;
        if (i >= n) break;
        ap_t *a = &aps[idx[i]];
        int y = y0 + r * rh - off;
        if (y + rh <= y0 || y >= 76) continue;

        if (i & 1) gfx->fillRect(ox, y, SCR_W, rh - 1, C_ROW);

        const char *name = a->ssid[0] ? a->ssid : "<hidden>";
        char nm[14];
        strncpy(nm, name, sizeof(nm) - 1);
        nm[sizeof(nm) - 1] = '\0';
        txt(ox + 4, y + 2, a->ssid[0] ? C_TEXT : C_DIM, 1, nm);

        if (a->enc) draw_lock(ox + 86, y + 2, C_LABEL);
        txt(ox + 94, y + 2, C_BLUE, 1, "%02d", a->channel);
        draw_rssi_bars(ox + 110, y + 1, a->rssi);
        txt_r(ox + SCR_W - 4, y + 2, rssi_color(a->rssi), 1, "%d", a->rssi);
    }

    // Mask what bled past the content area, then lay the header back on top
    // so a row mid-scroll can never paint over it.
    gfx->fillRect(ox, 76, SCR_W, SCR_H - 76, C_BG);
    draw_header(ox, PAGE_NAME[PAGE_NETWORKS]);
    txt(ox + 56, 2, C_DIM, 1, "%d", n);
}

// ─── Page: THREATS ─────────────────────────────────────────────────────────
static void page_threats(int ox) {
    draw_header(ox, PAGE_NAME[PAGE_THREATS]);

    if (threat_count == 0) {
        // Gentle pulse so the page still feels alive while nothing happens.
        float pulse = 0.5f + 0.5f * sinf(millis() * 0.0022f);
        txt_c(ox + SCR_W / 2, 24, lerp565(C_ACCENT_D, C_OK, pulse), 3, "CLEAR");
        txt_c(ox + SCR_W / 2, 50, C_LABEL, 1, "no deauth frames seen");
        char up[16];
        fmt_uptime(up, sizeof(up), millis() - boot_ms);
        txt_c(ox + SCR_W / 2, 62, C_SEP, 1, "watching %d ch for %s", MAX_CHANNELS, up);
        return;
    }

    txt(ox + 4, 14, C_DANGER, 2, "%u", s_deauth);
    txt(ox + 4, 32, C_LABEL, 1, "FRAMES");
    txt_r(ox + SCR_W - 4, 14, C_LABEL, 1, "LAST %d", threat_count);

    uint32_t now = millis();
    int shown = 0;
    for (int k = 1; k <= MAX_THREATS && shown < 3; k++) {
        int i = (threat_next - k + MAX_THREATS) % MAX_THREATS;
        if (k > threat_count) break;
        threat_t *t = &threats[i];
        int y = 42 + shown * 11;

        if (shown & 1) gfx->fillRect(ox, y - 1, SCR_W, 10, C_ROW);
        txt(ox + 4, y, rssi_color(t->rssi), 1, "%d", t->rssi);
        txt(ox + 30, y, C_BLUE, 1, "CH%02d", t->channel);
        txt(ox + 62, y, C_TEXT, 1, "%02X%02X%02X", t->src[3], t->src[4], t->src[5]);
        char age[12];
        fmt_uptime(age, sizeof(age), now - t->ts);
        txt_r(ox + SCR_W - 4, y, C_LABEL, 1, age);
        shown++;
    }
}

// ─── Page: HANDSHAKE ───────────────────────────────────────────────────────
static void page_hs(int ox) {
    draw_header(ox, PAGE_NAME[PAGE_HS]);

    // Summary line: EAPOL count and overall usable status.
    txt(ox + 4, 14, C_LABEL, 1, "EAPOL");
    txt(ox + 44, 14, C_TEXT, 1, "%u", s_eapol);
    if (hs_ok > 0)          txt_r(ox + SCR_W - 4, 14, C_OK,   1, "USABLE %u/%u", hs_ok, hs_pairs);
    else if (hs_pairs > 0)  txt_r(ox + SCR_W - 4, 14, C_WARN, 1, "PARTIAL %u", hs_pairs);
    else                    txt_r(ox + SCR_W - 4, 14, C_SEP,  1, "waiting");
    gfx->drawFastHLine(ox + 4, 23, SCR_W - 8, C_SEP);

    if (hsst_n == 0) {
        txt_c(ox + SCR_W / 2, 38, C_SEP, 1, "no EAPOL captured yet");
        txt_c(ox + SCR_W / 2, 50, C_LABEL, 1, "lock a channel and wait");
        txt_c(ox + SCR_W / 2, 60, C_SEP, 1, "for a client to connect");
        return;
    }

    // Column legend: the four M-boxes = messages M1..M4.
    txt(ox + 2, 25, C_LABEL, 1, "NET");
    for (int m = 0; m < 4; m++) txt(ox + 73 + m * 9, 25, C_LABEL, 1, "%d", m + 1);
    txt_r(ox + SCR_W - 2, 25, C_LABEL, 1, "USE");

    // One row per AP+client pair (newest tracked first up to 4).
    const int y0 = 35, rh = 10;
    int n = hsst_n < 4 ? hsst_n : 4;
    for (int i = 0; i < n; i++) {
        hsst_t *p = &hsst[i];
        int y = y0 + i * rh;

        const char *name = nullptr;
        for (int a = 0; a < ap_count; a++)
            if (!memcmp(aps[a].bssid, p->ap, 6) && aps[a].ssid[0]) { name = aps[a].ssid; break; }
        char nm[12];
        if (name) { strncpy(nm, name, 11); nm[11] = '\0'; }
        else snprintf(nm, sizeof(nm), "%02X%02X%02X", p->ap[3], p->ap[4], p->ap[5]);
        txt(ox + 2, y, C_TEXT, 1, nm);

        for (int m = 0; m < 4; m++) {
            bool on = p->msgs & (1 << m);
            gfx->fillRect(ox + 72 + m * 9, y - 1, 7, 8, on ? C_ACCENT : C_ROW);
            gfx->drawRect(ox + 72 + m * 9, y - 1, 7, 8, C_SEP);
        }
        bool ok = (p->msgs & 0x5) && (p->msgs & 0xA);
        txt_r(ox + SCR_W - 2, y, ok ? C_OK : C_WARN, 1, ok ? "OK" : "--");
    }
}

// ─── Page: SYSTEM ──────────────────────────────────────────────────────────
static void page_system(int ox) {
    draw_header(ox, PAGE_NAME[PAGE_SYSTEM]);

    char v[20];
    const int y0 = 14, rh = 9;
    int r = 0;

    fmt_uptime(v, sizeof(v), millis() - boot_ms);
    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "UPTIME");
    txt_r(ox + SCR_W - 4, y0 + r * rh, C_TEXT, 1, v); r++;

    fmt_num(v, sizeof(v), s_total);
    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "PACKETS");
    txt_r(ox + SCR_W - 4, y0 + r * rh, C_TEXT, 1, v); r++;

    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "NETWORKS");
    txt_r(ox + SCR_W - 4, y0 + r * rh, C_TEXT, 1, "%d", ap_active()); r++;

    char m[12], d[12];
    fmt_num(m, sizeof(m), s_mgmt);
    fmt_num(d, sizeof(d), s_data);
    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "MGMT/DATA");
    txt_r(ox + SCR_W - 4, y0 + r * rh, C_TEXT, 1, "%s/%s", m, d); r++;

    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "EAPOL/HS");
    txt_r(ox + SCR_W - 4, y0 + r * rh, s_eapol ? C_ACCENT : C_TEXT, 1,
          "%u/%u", s_eapol, hs_saved); r++;

    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "LOG");
    if (sd_ok) txt_r(ox + SCR_W - 4, y0 + r * rh, C_ACCENT, 1, "SD s%04d", log_session);
    else       txt_r(ox + SCR_W - 4, y0 + r * rh, C_SEP, 1, "off"); r++;

    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "RAM/FPS");
    txt_r(ox + SCR_W - 4, y0 + r * rh, fps >= 24 ? C_OK : C_WARN, 1,
          "%uK %uf", ESP.getFreeHeap() / 1024, fps);
}

// ─── Page: USB (mass storage) ──────────────────────────────────────────────
static void page_usb(int ox) {
    draw_header(ox, PAGE_NAME[PAGE_USB]);

    if (msc_mode) {
        // Big, unambiguous "you can read the card now" state.
        bool active = (millis() - msc_act_ts) < 400;
        float pulse = 0.5f + 0.5f * sinf(millis() * 0.006f);
        txt_c(ox + SCR_W / 2, 18, lerp565(C_BLUE, C_TEXT, pulse), 2, "USB DRIVE");
        txt_c(ox + SCR_W / 2, 37, active ? C_ACCENT : C_LABEL, 1,
              active ? "host is reading/writing" : "mounted on host");

        // Read/write activity counters.
        txt(ox + 8, 49, C_LABEL, 1, "RD");
        txt(ox + 26, 49, C_TEXT, 1, "%u", msc_rd);
        txt_r(ox + SCR_W - 8, 49, C_LABEL, 1, "WR %u", msc_wr);

        // Live blocks, blue while active.
        int cx = ox + SCR_W / 2, bx = cx - 30;
        for (int i = 0; i < 6; i++) {
            bool on = active && (((millis() / 90) % 6) == (uint32_t)i);
            gfx->fillRect(bx + i * 10, 60, 7, 4, on ? C_BLUE : C_SEP);
        }
        txt_c(ox + SCR_W / 2, 67, C_WARN, 1, "hold btn to eject");
        return;
    }

    if (!sd_ok && !msc_registered) {
        txt_c(ox + SCR_W / 2, 30, C_SEP, 1, "no card detected");
        txt_c(ox + SCR_W / 2, 42, C_LABEL, 1, "insert one and reboot");
        return;
    }

    txt(ox + 4, 16, C_LABEL, 1, "Mount the card as a USB");
    txt(ox + 4, 26, C_LABEL, 1, "drive on your PC or phone.");

    uint64_t mb = SD_MMC.cardSize() / (1024ULL * 1024ULL);
    txt(ox + 4, 40, C_LABEL, 1, "CARD");
    if (mb >= 1024) txt_r(ox + SCR_W - 4, 40, C_TEXT, 1, "%.1f GB", mb / 1024.0f);
    else            txt_r(ox + SCR_W - 4, 40, C_TEXT, 1, "%u MB", (uint32_t)mb);

    txt(ox + 4, 50, C_LABEL, 1, "LOGGING");
    txt_r(ox + SCR_W - 4, 50, C_WARN, 1, "pauses while mounted");

    txt_c(ox + SCR_W / 2, 66, C_ACCENT, 1, "hold btn to mount");
}

// ─── Deauth alert overlay ──────────────────────────────────────────────────
static void render_alert() {
    uint32_t age = millis() - alert_ts;
    float pulse = 0.5f + 0.5f * sinf(age * 0.012f);

    gfx->fillScreen(C_ALERT_BG);
    uint16_t border = lerp565(C_DANGER, C_WARN, pulse);
    gfx->drawRect(0, 0, SCR_W, SCR_H, border);
    gfx->drawRect(1, 1, SCR_W - 2, SCR_H - 2, border);

    txt_c(SCR_W / 2, 6, lerp565(C_WARN, C_TEXT, pulse), 1, "!! DEAUTH ATTACK !!");

    char b[8];
    snprintf(b, sizeof(b), "%d", (int)alert_rssi);
    txt_c(SCR_W / 2, 20, C_TEXT, 3, b);
    txt_c(SCR_W / 2, 45, C_WARN, 1, "dBm");

    txt(6, 58, C_LABEL, 1, "CH");
    txt(24, 58, C_TEXT, 1, "%02d", alert_ch);
    txt_r(SCR_W - 6, 58, C_WARN, 1, "%02X:%02X:%02X:%02X:%02X:%02X",
          alert_src[0], alert_src[1], alert_src[2],
          alert_src[3], alert_src[4], alert_src[5]);

    // Time left before the overlay releases the screen.
    float left = 1.0f - clampf((float)age / (float)ALERT_MS, 0.0f, 1.0f);
    gfx->fillRect(2, SCR_H - 4, (int)((SCR_W - 4) * left), 2, border);
}

// ─── Frame composition ─────────────────────────────────────────────────────
static void draw_page(int p, int ox) {
    switch (p) {
        case PAGE_LIVE:     page_live(ox);     break;
        case PAGE_CHANNELS: page_channels(ox); break;
        case PAGE_NETWORKS: page_networks(ox); break;
        case PAGE_THREATS:  page_threats(ox);  break;
        case PAGE_HS:       page_hs(ox);       break;
        case PAGE_SYSTEM:   page_system(ox);   break;
        case PAGE_USB:      page_usb(ox);      break;
    }
}

static void render(uint32_t held) {
    if (alert_on) { render_alert(); gfx->flush(); return; }

    gfx->fillScreen(C_BG);

    if (slide > 0.001f) {
        // Ease-out cubic on the way in; both pages are drawn each frame so the
        // transition is a real slide rather than a cut.
        float e = 1.0f - powf(slide, 3.0f);
        int nx = (int)(slide_dir * SCR_W * (1.0f - e));
        draw_page(page, nx);
        draw_page(page_from, nx - slide_dir * SCR_W);
    } else {
        draw_page(page, 0);
    }

    draw_pager();
    if (held) draw_hold_progress(held);
    draw_toast();
    gfx->flush();
}

// ─── Splash ────────────────────────────────────────────────────────────────
static void led_set(uint8_t r, uint8_t g, uint8_t b) {
    led = CRGB(r, g, b);
    FastLED.show();
}

static void splash_screen() {
    const char *name = "poppn";
    const int cw = 12, total = 5 * cw;
    const int sx = (SCR_W - total) / 2;

    bool sd_done = false;
    char sd_line[26] = {0};

    for (int f = 0; f <= 72; f++) {
        float t = (float)f / 72.0f;

        // Look for a card while the bar fills — logging is armed for the whole
        // run based on what is present now, at boot, and nothing later.
        if (!sd_done && f >= 30) {
            sd_done = true;
            sd_ok = sd_init();
            if (sd_ok) snprintf(sd_line, sizeof(sd_line), "SD OK  logging s%04d", log_session);
            else       snprintf(sd_line, sizeof(sd_line), "no SD  logging off");
        }

        gfx->fillScreen(C_BG);

        // Letters fade up one after another.
        for (int i = 0; i < 5; i++) {
            float a = clampf(t * 4.0f - i * 0.45f, 0.0f, 1.0f);
            if (a <= 0) continue;
            gfx->setTextSize(2);
            gfx->setTextColor(lerp565(C_BG, C_ACCENT, a));
            gfx->setCursor(sx + i * cw, (int)(20 + (1.0f - a) * 4));
            gfx->print(name[i]);
        }

        // Underline sweeps out from the centre.
        float u = clampf((t - 0.35f) / 0.3f, 0.0f, 1.0f);
        if (u > 0) {
            int w = (int)(total * u);
            gfx->drawFastHLine(sx + (total - w) / 2, 40, w, C_ACCENT_D);
        }

        float s = clampf((t - 0.5f) / 0.25f, 0.0f, 1.0f);
        if (s > 0) txt_c(SCR_W / 2, 50, lerp565(C_BG, C_LABEL, s), 1, "WiFi Packet Monitor");

        // Once the card is probed, its verdict replaces the version line.
        if (sd_done) {
            txt_c(SCR_W / 2, 61, sd_ok ? C_ACCENT : C_SEP, 1, sd_line);
        } else {
            float v = clampf((t - 0.62f) / 0.25f, 0.0f, 1.0f);
            if (v > 0) txt_c(SCR_W / 2, 61, lerp565(C_BG, C_SEP, v), 1, "T-Dongle S3  v5");
        }

        // Loading bar, one green shade per pixel.
        float l = clampf((t - 0.45f) / 0.5f, 0.0f, 1.0f);
        const int bw = 100, bx = (SCR_W - bw) / 2, by = 72;
        gfx->drawRect(bx - 1, by - 1, bw + 2, 6, C_SEP);
        int filled = (int)(bw * l);
        for (int i = 0; i < filled; i++) {
            gfx->drawFastVLine(bx + i, by, 4, grad_green_at(i, bw));
        }

        gfx->flush();
        uint8_t br = (uint8_t)(6 + 24 * (0.5f + 0.5f * sinf(t * 6.28f)));
        led_set(0, br, (uint8_t)(br * 0.8f));
        delay(14);
    }
    delay(450);
}

// ─── WiFi ──────────────────────────────────────────────────────────────────
static void wifi_sniffer_init() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(pkt_callback);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
}

static void reset_stats() {
    s_total = s_mgmt = s_ctrl = s_data = s_beacon = s_deauth = s_eapol = 0;
    for (int c = 0; c <= MAX_CHANNELS; c++) { s_ch[c] = 0; ch_recent[c] = 0; ch_bar[c] = 0; }
    memset(graph, 0, sizeof(graph));
    memset(aps, 0, sizeof(aps));
    ap_count = threat_count = threat_next = 0;
    hsst_n = 0; hs_pairs = hs_ok = 0; cap_bssid_n = 0;
    alert_on = alert_jump = false;
    last_snapshot = 0;
    rate_window_base = 0;
    last_rate = 0;
    ev_dropped = 0;
}

static void goto_page(int p) {
    page_from = page;
    slide_dir = (p > page || (page == PAGE_COUNT - 1 && p == 0)) ? 1 : -1;
    page = (p + PAGE_COUNT) % PAGE_COUNT;
    slide = 1.0f;
}

// ─── Serial console ────────────────────────────────────────────────────────
// A line-based command interface over the USB serial port. Mirrors everything
// the button can do, plus queries. Type `help` for the list. Full reference
// lives in docs/SERIAL.md.
static void serial_set_channel(int c) {
    if (c < 1 || c > MAX_CHANNELS) { Serial.println("err: channel 1-13"); return; }
    ch_lock = true;
    current_channel = c;
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    Serial.printf("ok: locked to channel %d\n", c);
}

static void serial_list_nets() {
    int idx[MAX_APS];
    int n = ap_sorted(idx);
    Serial.printf("networks: %d\n", n);
    for (int i = 0; i < n; i++) {
        ap_t *a = &aps[idx[i]];
        Serial.printf("  %-20s %s ch=%-2d rssi=%-4d %s\n",
                      a->ssid[0] ? a->ssid : "<hidden>",
                      mac2str(a->bssid).c_str(), a->channel, a->rssi,
                      a->enc ? "enc" : "open");
    }
}

static void serial_list_threats() {
    Serial.printf("deauth events: %u (last %d kept)\n", s_deauth, threat_count);
    uint32_t now = millis();
    for (int k = 1; k <= MAX_THREATS && k <= threat_count; k++) {
        int i = (threat_next - k + MAX_THREATS) % MAX_THREATS;
        threat_t *t = &threats[i];
        Serial.printf("  src=%s dst=%s ch=%d rssi=%d age=%us\n",
                      mac2str(t->src).c_str(), mac2str(t->dst).c_str(),
                      t->channel, t->rssi, (now - t->ts) / 1000);
    }
}

static void serial_status() {
    Serial.printf("status: up=%us ch=%d%s pkts=%u (mgmt=%u ctrl=%u data=%u beacon=%u) "
                  "deauth=%u eapol=%u hs=%u/%u aps=%u rate=%u/s page=%s sd=%s usb=%s heap=%u\n",
                  (millis() - boot_ms) / 1000, current_channel, ch_lock ? "(lock)" : "",
                  s_total, s_mgmt, s_ctrl, s_data, s_beacon, s_deauth, s_eapol,
                  hs_ok, hs_pairs, ap_active(), last_rate, PAGE_NAME[page],
                  sd_ok ? "on" : "off", msc_mode ? "mounted" : "idle",
                  ESP.getFreeHeap());
}

static void serial_help() {
    Serial.println(F(
        "commands:\n"
        "  help                 this list\n"
        "  status               one-line summary of everything\n"
        "  page <name|next|prev|0-6>   switch page (live/channels/networks/threats/handshake/system/usb)\n"
        "  channel <1-13>       lock to a channel\n"
        "  lock | unlock | hop  stop / resume channel hopping\n"
        "  nets                 list discovered networks\n"
        "  threats              list captured deauth events\n"
        "  reset                clear all counters and tables\n"
        "  usb on | usb off     mount / eject the SD card as a USB drive\n"
        "  sd                   logging / card status\n"
        "  reboot               restart the device"));
}

static void serial_exec(char *line) {
    // Tokenise on spaces.
    char *cmd = strtok(line, " \t");
    if (!cmd) return;
    char *arg = strtok(nullptr, " \t");

    if (!strcasecmp(cmd, "help") || !strcasecmp(cmd, "?")) { serial_help(); return; }
    if (!strcasecmp(cmd, "status")) { serial_status(); return; }
    if (!strcasecmp(cmd, "nets") || !strcasecmp(cmd, "networks")) { serial_list_nets(); return; }
    if (!strcasecmp(cmd, "threats")) { serial_list_threats(); return; }

    if (!strcasecmp(cmd, "reset")) { reset_stats(); Serial.println("ok: cleared"); return; }
    if (!strcasecmp(cmd, "lock"))   { ch_lock = true;  Serial.println("ok: locked");   return; }
    if (!strcasecmp(cmd, "unlock") || !strcasecmp(cmd, "hop")) { ch_lock = false; Serial.println("ok: hopping"); return; }
    if (!strcasecmp(cmd, "reboot") || !strcasecmp(cmd, "restart")) { Serial.println("rebooting..."); delay(50); ESP.restart(); return; }

    if (!strcasecmp(cmd, "channel") || !strcasecmp(cmd, "ch")) {
        if (!arg) { Serial.println("usage: channel <1-13>"); return; }
        serial_set_channel(atoi(arg));
        return;
    }

    if (!strcasecmp(cmd, "sd") || !strcasecmp(cmd, "log")) {
        if (sd_ok) Serial.printf("sd: logging on, session %d, eapol=%u hs=%u\n", log_session, s_eapol, hs_saved);
        else if (msc_mode) Serial.println("sd: mounted as USB drive (logging paused)");
        else Serial.println("sd: no card / logging off");
        return;
    }

    if (!strcasecmp(cmd, "usb")) {
        if (arg && !strcasecmp(arg, "on")) {
            if (msc_mode) Serial.println("usb: already mounted");
            else if (!msc_registered) Serial.println("usb: no card at boot");
            else Serial.println(msc_enter() ? "usb: mounted (logging paused)" : "usb: mount failed");
        } else if (arg && !strcasecmp(arg, "off")) {
            if (!msc_mode) Serial.println("usb: not mounted");
            else { msc_exit(); Serial.println("usb: ejected, logging resumed"); }
        } else Serial.println("usage: usb on | usb off");
        return;
    }

    if (!strcasecmp(cmd, "page")) {
        if (!arg) { Serial.printf("page: %s\n", PAGE_NAME[page]); return; }
        if (!strcasecmp(arg, "next")) { goto_page(page + 1); }
        else if (!strcasecmp(arg, "prev")) { goto_page(page - 1); }
        else if (arg[0] >= '0' && arg[0] <= '9') { goto_page(atoi(arg) % PAGE_COUNT); }
        else {
            int found = -1;
            for (int i = 0; i < PAGE_COUNT; i++) if (!strcasecmp(arg, PAGE_NAME[i])) found = i;
            if (found < 0) { Serial.println("err: unknown page"); return; }
            goto_page(found);
        }
        Serial.printf("ok: page %s\n", PAGE_NAME[page]);
        return;
    }

    Serial.printf("unknown command '%s' - type help\n", cmd);
}

// Non-blocking line reader, called every loop.
static void serial_poll() {
    static char buf[80];
    static uint8_t len = 0;
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            if (len) { buf[len] = '\0'; serial_exec(buf); len = 0; }
        } else if (len < sizeof(buf) - 1) {
            buf[len++] = c;
        }
    }
}

// ─── Setup ─────────────────────────────────────────────────────────────────
void setup() {
    delay(300);

    pinMode(PIN_BTN, INPUT_PULLUP);

    FastLED.addLeds<APA102, PIN_LED_DATA, PIN_LED_CLK, BGR>(&led, 1);
    FastLED.setBrightness(30);
    led_set(0, 0, 30);

    pinMode(PIN_RST, OUTPUT);
    digitalWrite(PIN_RST, HIGH); delay(50);
    digitalWrite(PIN_RST, LOW);  delay(150);
    digitalWrite(PIN_RST, HIGH); delay(300);

    if (!gfx->begin(27000000)) {
        Serial.println("[poppn] FATAL: framebuffer allocation failed");
    }
    gfx->fillScreen(C_BG);
    gfx->flush();

    pinMode(PIN_BL, OUTPUT);
    digitalWrite(PIN_BL, LOW);

    splash_screen();   // probes the card, sets sd_ok / log_session

    // USB composite: CDC (serial) always, plus a Mass-Storage interface when a
    // card is present. Both interfaces must be registered before USB.begin(),
    // which is why CDC is not started on boot. MSC starts with no media; the
    // card is only exposed once the user mounts it from the USB page.
    USBSerial.begin(115200);
    if (sd_ok) {
        uint32_t sectors = (uint32_t)(SD_MMC.cardSize() / 512ULL);
        msc.vendorID("poppn");
        msc.productID("packmon SD");
        msc.productRevision("1.0");
        msc.onRead(on_msc_read);
        msc.onWrite(on_msc_write);
        msc.onStartStop(on_msc_startstop);
        msc.mediaPresent(false);
        msc_registered = msc.begin(sectors, 512);
    }
    USB.begin();
    Serial.println("[poppn] Starting...");

    boot_ms = millis();
    fps_ts = rate_window_ts = boot_ms;
    wifi_sniffer_init();
    Serial.printf("[poppn] Sniffer started, free heap %u\n", ESP.getFreeHeap());
    Serial.println("[poppn] serial console ready - type 'help'");
}

// ─── Loop ──────────────────────────────────────────────────────────────────
static uint32_t last_hop = 0, last_sample = 0, last_frame = 0, last_decay = 0;
static bool     btn_down = false, fired_lock = false, fired_reset = false;
static uint32_t btn_t0 = 0;

void loop() {
    uint32_t now = millis();

    serial_poll();
    drain_events();

    // Channel hopping
    if (!ch_lock && now - last_hop >= CHANNEL_HOP_MS) {
        last_hop = now;
        current_channel = (current_channel % MAX_CHANNELS) + 1;
        esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    }

    // Graph sampling
    if (now - last_sample >= SAMPLE_MS) {
        last_sample = now;
        uint32_t cur = s_total;
        uint32_t delta = cur - last_snapshot;
        last_snapshot = cur;
        graph[graph_idx] = delta > 65535 ? 65535 : (uint16_t)delta;
        graph_idx = (graph_idx + 1) % GRAPH_W;
    }

    // Packets per second over a rolling 1 s window
    if (now - rate_window_ts >= 1000) {
        uint32_t cur = s_total;
        last_rate = cur - rate_window_base;
        rate_window_base = cur;
        rate_window_ts = now;
    }

    // Move captured handshake frames onto the card, log a stats row every 5 s,
    // and flush all open files every 3 s. All SD access lives here in loop().
    if (sd_ok) {
        hs_drain();
        static uint32_t last_stat_log = 0, last_flush = 0;
        if (now - last_stat_log >= 5000) { last_stat_log = now; log_stats(last_rate); }
        if (now - last_flush >= 3000)    { last_flush = now; log_flush(); }
    }

    // Per-channel activity decays so the bars show recent load, not history
    if (now - last_decay >= 500) {
        last_decay = now;
        static uint32_t prev_ch[MAX_CHANNELS + 1] = {0};
        for (int c = 1; c <= MAX_CHANNELS; c++) {
            uint32_t cur = s_ch[c];
            ch_recent[c] = ch_recent[c] * 0.75f + (float)(cur - prev_ch[c]);
            prev_ch[c] = cur;
        }
    }

    // Button: tap = next page, hold = lock channel, keep holding = reset.
    // On the USB page the hold instead toggles mass-storage mode.
    bool down = (digitalRead(PIN_BTN) == LOW);
    uint32_t held = 0;
    if (down && !btn_down) {
        btn_down = true; btn_t0 = now; fired_lock = fired_reset = false;
    }
    if (down) {
        held = now - btn_t0;
        if (held >= HOLD_LOCK_MS && !fired_lock) {
            fired_lock = true;
            if (page == PAGE_USB) {
                if (msc_mode)            { msc_exit(); toast("USB EJECTED"); }
                else if (msc_registered) { toast(msc_enter() ? "USB DRIVE ON" : "USB FAILED"); }
                else                       toast("NO CARD");
            } else {
                ch_lock = !ch_lock;
                toast(ch_lock ? "CHANNEL LOCKED" : "HOPPING RESUMED");
            }
        }
        // No stats reset on the USB page — the hold there means eject/mount.
        if (held >= HOLD_RESET_MS && !fired_reset && page != PAGE_USB) {
            fired_reset = true;
            reset_stats();
            toast("STATS CLEARED");
        }
    } else if (btn_down) {
        // Taps are swallowed while the alert owns the screen, or while the card
        // is mounted (the USB status must stay put), otherwise they would
        // shuffle a page nobody can see and fight the jump below.
        if (now - btn_t0 < HOLD_LOCK_MS && !alert_on && !msc_mode) goto_page(page + 1);
        btn_down = false;
    }

    // When the alert lets go of the screen, slide onto THREATS rather than
    // back to whatever page was up: the overlay gives the headline, the page
    // gives the history behind it.
    if (alert_on && now - alert_ts > ALERT_MS) {
        alert_on = false;
        if (alert_jump) {
            alert_jump = false;
            if (page != PAGE_THREATS) goto_page(PAGE_THREATS);
        }
    }

    // Periodic heartbeat, so a host logging the serial port gets the picture
    // without having to read the screen.
    static uint32_t last_beat = 0;
    if (now - last_beat >= 10000) {
        last_beat = now;
        Serial.printf("[stat] pkts=%u (mgmt=%u ctrl=%u data=%u beacon=%u) deauth=%u "
                      "aps=%u rate=%u/s ch=%d%s eapol=%u hs=%u sd=%s dropped=%u heap=%u\n",
                      s_total, s_mgmt, s_ctrl, s_data, s_beacon, s_deauth,
                      ap_active(), last_rate, current_channel, ch_lock ? " LOCK" : "",
                      s_eapol, hs_saved, sd_ok ? "on" : "off",
                      ev_dropped, ESP.getFreeHeap());
    }

    // LED: idle breathing tinted by traffic, hard red strobe under attack.
    // Throttled — loop() spins far faster than the LED needs refreshing.
    static uint32_t last_led = 0;
    if (now - last_led >= 20) {
        last_led = now;
        if (msc_mode) {
            // Blue for USB-drive mode; brief white flash on host access.
            if (millis() - msc_act_ts < 120) led_set(60, 60, 60);
            else { uint8_t b = (uint8_t)(6 + 18 * (0.5f + 0.5f * sinf(now * 0.004f))); led_set(0, 0, b); }
        } else if (alert_on) {
            led_set(((now / 150) % 2) ? 90 : 0, 0, 0);
        } else {
            float b = 8.0f + 10.0f * (0.5f + 0.5f * sinf(now * 0.003f));
            float load = clampf(f_rate / 300.0f, 0.0f, 1.0f);
            led_set((uint8_t)(b * load),
                    (uint8_t)(b * (1.0f - load * 0.5f)),
                    (uint8_t)(b * 0.6f * (1.0f - load)));
        }
    }

    // Frame
    if (now - last_frame >= FRAME_MS) {
        last_frame = now;

        f_rate = ease(f_rate, (float)last_rate, 0.12f);
        f_rssi = ease(f_rssi, (float)s_rssi, 0.15f);
        for (int c = 1; c <= MAX_CHANNELS; c++) ch_bar[c] = ease(ch_bar[c], ch_recent[c], 0.15f);
        pager_pos = ease(pager_pos, (float)page, 0.22f);
        if (slide > 0.001f) {
            slide -= (float)FRAME_MS / (float)SLIDE_MS;
            if (slide < 0) slide = 0;
        }

        render(down ? held : 0);

        fps_frames++;
        if (now - fps_ts >= 1000) { fps = fps_frames; fps_frames = 0; fps_ts = now; }
    }
}
