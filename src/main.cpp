#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <Arduino_GFX_Library.h>
#include <FastLED.h>
#include <stdarg.h>

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
#define SUB_PROBE_RESP 5
#define SUB_BEACON     8
#define SUB_DISASSOC  10
#define SUB_DEAUTH    12

// ─── Counters (written by the sniffer task, read by the UI) ────────────────
volatile uint32_t s_total = 0, s_mgmt = 0, s_ctrl = 0, s_data = 0;
volatile uint32_t s_beacon = 0, s_deauth = 0;
volatile uint32_t s_ch[MAX_CHANNELS + 1] = {0};
volatile int8_t   s_rssi = 0;
volatile uint32_t ev_dropped = 0;

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
enum { PAGE_LIVE, PAGE_CHANNELS, PAGE_NETWORKS, PAGE_THREATS, PAGE_SYSTEM, PAGE_COUNT };
static const char *PAGE_NAME[PAGE_COUNT] = { "LIVE", "CHANNELS", "NETWORKS", "THREATS", "SYSTEM" };

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
    if (ft == TYPE_DATA) { s_data++; return; }
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
        return;
    }

    if (sub == SUB_DEAUTH || sub == SUB_DISASSOC) {
        s_deauth++;
        evt_t e;
        memset(&e, 0, sizeof(e));
        e.kind    = EV_DEAUTH;
        e.rssi    = rx->rssi;
        e.channel = current_channel;
        memcpy(e.bssid, h->addr2, 6);
        memcpy(e.dst,   h->addr1, 6);
        ev_push(&e);
    }
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
    alert_jump = true;
    alert_ch   = e->channel;
    alert_rssi = e->rssi;
    memcpy(alert_src, e->bssid, 6);

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

    // Area chart: gradient body with a bright tip, scaled on an eased max so
    // the whole plot does not jump when a new peak arrives.
    const int gx = ox + 4, gy = 52, gh = 20;
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

// ─── Page: SYSTEM ──────────────────────────────────────────────────────────
static void page_system(int ox) {
    draw_header(ox, PAGE_NAME[PAGE_SYSTEM]);

    char v[20];
    const int y0 = 15, rh = 10;
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

    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "FREE RAM");
    txt_r(ox + SCR_W - 4, y0 + r * rh, C_TEXT, 1, "%uK", ESP.getFreeHeap() / 1024); r++;

    txt(ox + 4, y0 + r * rh, C_LABEL, 1, "FPS");
    txt_r(ox + SCR_W - 4, y0 + r * rh, fps >= 24 ? C_OK : C_WARN, 1, "%u", fps);
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
        case PAGE_SYSTEM:   page_system(ox);   break;
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

    for (int f = 0; f <= 72; f++) {
        float t = (float)f / 72.0f;
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
        float v = clampf((t - 0.62f) / 0.25f, 0.0f, 1.0f);
        if (v > 0) txt_c(SCR_W / 2, 61, lerp565(C_BG, C_SEP, v), 1, "T-Dongle S3  v4");

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
    delay(250);
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
    s_total = s_mgmt = s_ctrl = s_data = s_beacon = s_deauth = 0;
    for (int c = 0; c <= MAX_CHANNELS; c++) { s_ch[c] = 0; ch_recent[c] = 0; ch_bar[c] = 0; }
    memset(graph, 0, sizeof(graph));
    memset(aps, 0, sizeof(aps));
    ap_count = threat_count = threat_next = 0;
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

// ─── Setup ─────────────────────────────────────────────────────────────────
void setup() {
    delay(300);
    Serial.begin(115200);
    Serial.println("[poppn] Starting...");

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

    splash_screen();

    boot_ms = millis();
    fps_ts = rate_window_ts = boot_ms;
    wifi_sniffer_init();
    Serial.printf("[poppn] Sniffer started, free heap %u\n", ESP.getFreeHeap());
}

// ─── Loop ──────────────────────────────────────────────────────────────────
static uint32_t last_hop = 0, last_sample = 0, last_frame = 0, last_decay = 0;
static bool     btn_down = false, fired_lock = false, fired_reset = false;
static uint32_t btn_t0 = 0;

void loop() {
    uint32_t now = millis();

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

    // Button: tap = next page, hold = lock channel, keep holding = reset
    bool down = (digitalRead(PIN_BTN) == LOW);
    uint32_t held = 0;
    if (down && !btn_down) {
        btn_down = true; btn_t0 = now; fired_lock = fired_reset = false;
    }
    if (down) {
        held = now - btn_t0;
        if (held >= HOLD_LOCK_MS && !fired_lock) {
            fired_lock = true;
            ch_lock = !ch_lock;
            toast(ch_lock ? "CHANNEL LOCKED" : "HOPPING RESUMED");
        }
        if (held >= HOLD_RESET_MS && !fired_reset) {
            fired_reset = true;
            reset_stats();
            toast("STATS CLEARED");
        }
    } else if (btn_down) {
        // Taps are swallowed while the alert owns the screen, otherwise they
        // would shuffle a page nobody can see and fight the jump below.
        if (now - btn_t0 < HOLD_LOCK_MS && !alert_on) goto_page(page + 1);
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
                      "aps=%u rate=%u/s ch=%d%s dropped=%u heap=%u\n",
                      s_total, s_mgmt, s_ctrl, s_data, s_beacon, s_deauth,
                      ap_active(), last_rate, current_channel, ch_lock ? " LOCK" : "",
                      ev_dropped, ESP.getFreeHeap());
    }

    // LED: idle breathing tinted by traffic, hard red strobe under attack.
    // Throttled — loop() spins far faster than the LED needs refreshing.
    static uint32_t last_led = 0;
    if (now - last_led >= 20) {
        last_led = now;
        if (alert_on) {
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
