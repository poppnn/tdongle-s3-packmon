#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <Arduino_GFX_Library.h>
#include <FastLED.h>

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

// ─── Display ───────────────────────────────────────────────────────────────
Arduino_DataBus *bus = new Arduino_ESP32SPI(PIN_DC, PIN_CS, PIN_SCLK, PIN_MOSI, -1);
Arduino_ST7735 *gfx = new Arduino_ST7735(bus, PIN_RST, 3, true, 80, 160, 26, 1, 26, 1);

#define SCR_W 160
#define SCR_H 80

// ─── APA102 LED ────────────────────────────────────────────────────────────
CRGB led;

// ─── Config ────────────────────────────────────────────────────────────────
#define CHANNEL_HOP_MS    500
#define MAX_CHANNELS      13
#define DISPLAY_UPDATE_MS 280
#define GRAPH_W           120
#define GRAPH_H           30
#define GRAPH_X           36
#define GRAPH_Y           14

// ─── WiFi frame parsing ────────────────────────────────────────────────────
typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration:16;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    unsigned seq_ctrl:16;
} __attribute__((packed)) wifi_mgmt_hdr_t;

#define FC_TYPE(fc)    (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc) (((fc) >> 4) & 0xF)
#define TYPE_MGMT   0
#define TYPE_CTRL   1
#define TYPE_DATA   2
#define SUBTYPE_DEAUTH   12
#define SUBTYPE_DISASSOC 10
#define SUBTYPE_BEACON   8

// ─── Stats ─────────────────────────────────────────────────────────────────
volatile uint32_t pkt_count      = 0;
volatile uint32_t pkt_deauth     = 0;
volatile int8_t   last_rssi      = 0;
volatile int8_t   deauth_rssi    = 0;
volatile uint8_t  deauth_channel = 0;
volatile uint8_t  deauth_src[6]  = {0};
volatile uint8_t  deauth_dst[6]  = {0};
volatile bool     deauth_alert   = false;
volatile uint32_t deauth_ts      = 0;

uint16_t graph[GRAPH_W] = {0};
int graph_idx = 0;
uint32_t last_pkt_snapshot = 0;
int current_channel = 1;
bool first_render = true;
bool was_alert = false;

// ─── Dark theme ────────────────────────────────────────────────────────────
#define C_BG       0x0841
#define C_HEADER   0x1926
#define C_HDR_TXT  0x07F7
#define C_GRAPH_BG 0x1082
#define C_DEAUTH   0xF800
#define C_ALERT_BG 0x4000
#define C_LABEL    0x6B6D
#define C_VALUE    0xDEFB
#define C_OK       0x2664
#define C_WARN     0xFD00
#define C_ACCENT   0x4C7F
#define C_SEP      0x2124

// Smooth gradient: 8 shades from dim to bright green
static const uint16_t grad_green[8] = {
    0x0160, 0x01C0, 0x0260, 0x0320, 0x03E0, 0x0500, 0x0620, 0x07E0
};

// ─── Helpers ───────────────────────────────────────────────────────────────
static String mac2str(const volatile uint8_t *mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

static uint16_t graph_color(int pos) {
    // pos 0 = oldest, GRAPH_W-1 = newest
    // map to 8 gradient steps
    int step = (pos * 7) / (GRAPH_W - 1);
    if (step < 0) step = 0;
    if (step > 7) step = 7;
    return grad_green[step];
}

// ─── Promiscuous callback ──────────────────────────────────────────────────
void IRAM_ATTR pkt_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t *rx = &pkt->rx_ctrl;
    if (rx->sig_len < sizeof(wifi_mgmt_hdr_t)) return;

    last_rssi = rx->rssi;
    pkt_count++;

    wifi_mgmt_hdr_t *hdr = (wifi_mgmt_hdr_t *)pkt->payload;
    uint16_t fc = hdr->frame_ctrl;

    if (FC_TYPE(fc) == TYPE_MGMT) {
        uint8_t sub = FC_SUBTYPE(fc);
        if (sub == SUBTYPE_DEAUTH || sub == SUBTYPE_DISASSOC) {
            pkt_deauth++;
            deauth_rssi    = rx->rssi;
            deauth_channel = current_channel;
            deauth_ts      = millis();
            deauth_alert   = true;
            memcpy((void*)deauth_src, hdr->addr2, 6);
            memcpy((void*)deauth_dst, hdr->addr1, 6);
        }
    }
}

// ─── WiFi init ─────────────────────────────────────────────────────────────
void wifi_sniffer_init() {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(pkt_callback);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
}

// ─── LED ───────────────────────────────────────────────────────────────────
void led_set(uint8_t r, uint8_t g, uint8_t b) {
    led = CRGB(r, g, b);
    FastLED.show();
}

// ─── Draw graph with smooth gradient ───────────────────────────────────────
void draw_graph() {
    gfx->fillRect(GRAPH_X, GRAPH_Y, GRAPH_W, GRAPH_H, C_GRAPH_BG);
    gfx->drawRect(GRAPH_X - 1, GRAPH_Y - 1, GRAPH_W + 2, GRAPH_H + 2, C_SEP);

    uint16_t mx = 1;
    for (int i = 0; i < GRAPH_W; i++) {
        if (graph[i] > mx) mx = graph[i];
    }

    for (int i = 0; i < GRAPH_W; i++) {
        int idx = (graph_idx + 1 + i) % GRAPH_W;
        int h = (int)((uint32_t)graph[idx] * (GRAPH_H - 1) / mx);
        if (h > 0) {
            gfx->drawFastVLine(GRAPH_X + i, GRAPH_Y + GRAPH_H - 1 - h, h, graph_color(i));
        }
    }

    // Y-axis max
    gfx->fillRect(0, GRAPH_Y, GRAPH_X - 2, 10, C_BG);
    gfx->setTextColor(C_LABEL, C_BG);
    gfx->setTextSize(1);
    gfx->setCursor(0, GRAPH_Y);
    char buf[6];
    if (mx >= 1000) snprintf(buf, sizeof(buf), "%uk", mx / 1000);
    else snprintf(buf, sizeof(buf), "%u", mx);
    gfx->print(buf);
}

// ─── Render: normal ────────────────────────────────────────────────────────
void render_normal() {
    if (first_render || was_alert) {
        gfx->fillScreen(C_BG);
        first_render = false;
        was_alert = false;
    }

    gfx->setTextSize(1);

    // Header
    gfx->fillRect(0, 0, SCR_W, 12, C_HEADER);
    gfx->setTextColor(C_HDR_TXT, C_HEADER);
    gfx->setCursor(2, 2);
    gfx->print("POPPN");

    char hdr_buf[24];
    snprintf(hdr_buf, sizeof(hdr_buf), "CH:%-2d %ddBm", current_channel, (int)last_rssi);
    gfx->setCursor(42, 2);
    gfx->print(hdr_buf);

    if (deauth_alert) {
        gfx->fillRect(SCR_W - 22, 1, 21, 10, C_DEAUTH);
        gfx->setTextColor(C_VALUE, C_DEAUTH);
        gfx->setCursor(SCR_W - 20, 2);
        gfx->print("!!!");
    }

    // Graph
    draw_graph();

    // Stats
    int y = GRAPH_Y + GRAPH_H + 3;
    gfx->fillRect(0, y, SCR_W, 10, C_BG);
    gfx->setTextColor(C_LABEL, C_BG);
    gfx->setCursor(2, y);
    gfx->print("Pkts:");
    gfx->setTextColor(C_VALUE, C_BG);
    char buf[12];
    snprintf(buf, sizeof(buf), "%-8u", pkt_count);
    gfx->setCursor(35, y);
    gfx->print(buf);

    gfx->setTextColor(C_DEAUTH, C_BG);
    gfx->setCursor(95, y);
    gfx->print("Deauth:");
    snprintf(buf, sizeof(buf), "%-4u", pkt_deauth);
    gfx->setCursor(140, y);
    gfx->print(buf);

    // Separator
    y += 11;
    gfx->drawFastHLine(2, y, SCR_W - 4, C_SEP);

    // Bottom
    y += 3;
    gfx->fillRect(0, y, SCR_W, SCR_H - y, C_BG);
    if (pkt_deauth > 0) {
        gfx->setTextColor(C_LABEL, C_BG);
        gfx->setCursor(2, y);
        gfx->print("Last:");
        gfx->setTextColor(C_WARN, C_BG);
        gfx->setCursor(35, y);
        char mac_buf[9];
        snprintf(mac_buf, sizeof(mac_buf), "%02X%02X%02X", deauth_src[3], deauth_src[4], deauth_src[5]);
        gfx->print(mac_buf);
        gfx->setTextColor(C_ACCENT, C_BG);
        gfx->setCursor(80, y);
        gfx->print("ch:");
        gfx->setTextColor(C_VALUE, C_BG);
        gfx->print(deauth_channel);
        gfx->setTextColor(C_ACCENT, C_BG);
        gfx->setCursor(115, y);
        gfx->print("dBm:");
        gfx->setTextColor(C_DEAUTH, C_BG);
        gfx->print(deauth_rssi);
    } else {
        gfx->setTextColor(C_OK, C_BG);
        gfx->setCursor(2, y);
        gfx->print("No deauth detected");
    }
}

// ─── Render: deauth alert ──────────────────────────────────────────────────
void render_deauth_alert() {
    if (!was_alert) {
        gfx->fillScreen(C_ALERT_BG);
        was_alert = true;
    }

    uint32_t t = millis();
    uint16_t border_color = ((t / 300) % 2) ? C_DEAUTH : C_WARN;
    gfx->drawRect(0, 0, SCR_W, SCR_H, border_color);
    gfx->drawRect(1, 1, SCR_W - 2, SCR_H - 2, border_color);

    gfx->setTextSize(1);
    gfx->fillRect(20, 2, 120, 10, C_ALERT_BG);
    gfx->setTextColor(C_DEAUTH, C_ALERT_BG);
    gfx->setCursor(24, 2);
    gfx->print("!! DEAUTH ATTACK !!");

    gfx->fillRect(20, 16, SCR_W - 40, 28, C_ALERT_BG);
    gfx->setTextSize(3);
    char rssi_buf[8];
    snprintf(rssi_buf, sizeof(rssi_buf), "%d", (int)deauth_rssi);
    int tw = strlen(rssi_buf) * 18;
    gfx->setTextColor(C_VALUE, C_ALERT_BG);
    gfx->setCursor((SCR_W - tw) / 2, 18);
    gfx->print(rssi_buf);

    gfx->setTextSize(1);
    gfx->setTextColor(C_WARN, C_ALERT_BG);
    gfx->setCursor((SCR_W - 18) / 2, 44);
    gfx->print("dBm");

    gfx->fillRect(2, 54, SCR_W - 4, 24, C_ALERT_BG);
    gfx->setTextColor(C_ACCENT, C_ALERT_BG);
    gfx->setCursor(2, 56);
    gfx->print("CH:");
    gfx->setTextSize(2);
    gfx->setTextColor(C_VALUE, C_ALERT_BG);
    gfx->setCursor(22, 53);
    gfx->print(deauth_channel);

    gfx->setTextSize(1);
    gfx->setTextColor(C_ACCENT, C_ALERT_BG);
    gfx->setCursor(60, 56);
    gfx->print("SRC:");
    gfx->setTextColor(C_WARN, C_ALERT_BG);
    char mac_buf[18];
    snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             deauth_src[0], deauth_src[1], deauth_src[2],
             deauth_src[3], deauth_src[4], deauth_src[5]);
    gfx->setCursor(60, 68);
    gfx->print(mac_buf);
}

// ─── Animated splash screen ───────────────────────────────────────────────
void splash_screen() {
    gfx->fillScreen(C_BG);

    // Fade in "poppn" letter by letter with LED pulse
    const char* name = "poppn";
    int total_w = 5 * 12;  // 5 chars at size 2 = ~60px
    int start_x = (SCR_W - total_w) / 2;

    for (int i = 0; i < 5; i++) {
        // LED pulse cyan for each letter
        led_set(0, 0, 60);
        delay(40);
        led_set(0, 0, 10);

        gfx->setTextSize(2);
        gfx->setTextColor(C_HDR_TXT, C_BG);
        gfx->setCursor(start_x + i * 12, 20);
        gfx->print(name[i]);
        delay(180);
    }

    delay(300);

    // Underline animation
    int line_y = 40;
    for (int x = start_x; x < start_x + total_w; x += 2) {
        gfx->drawFastHLine(start_x, line_y, x - start_x, C_ACCENT);
        delay(8);
    }

    delay(200);

    // Subtitle fade in
    gfx->setTextSize(1);
    gfx->setTextColor(C_LABEL, C_BG);
    gfx->setCursor(28, 50);
    gfx->print("WiFi Packet Monitor");
    delay(400);

    gfx->setTextColor(C_SEP, C_BG);
    gfx->setCursor(35, 62);
    gfx->print("T-Dongle S3  v3");
    delay(400);

    // Loading bar
    int bar_y = 73;
    int bar_w = 100;
    int bar_x = (SCR_W - bar_w) / 2;
    gfx->drawRect(bar_x - 1, bar_y - 1, bar_w + 2, 6, C_SEP);

    for (int i = 0; i < bar_w; i++) {
        uint16_t c = graph_color((i * (GRAPH_W - 1)) / bar_w);
        gfx->drawFastVLine(bar_x + i, bar_y, 4, c);
        // LED breathes during loading
        uint8_t br = (uint8_t)(15 + 15 * sin(i * 0.1));
        led_set(0, br, br);
        delay(20);
    }

    delay(500);
    led_set(0, 30, 0);
}

// ─── Setup ─────────────────────────────────────────────────────────────────
void setup() {
    delay(1000);
    Serial.begin(115200);
    Serial.println("[poppn] Starting...");

    // APA102 LED init
    FastLED.addLeds<APA102, PIN_LED_DATA, PIN_LED_CLK, BGR>(&led, 1);
    FastLED.setBrightness(30);
    led_set(0, 0, 30);

    // Hard reset display
    pinMode(PIN_RST, OUTPUT);
    digitalWrite(PIN_RST, HIGH);
    delay(50);
    digitalWrite(PIN_RST, LOW);
    delay(150);
    digitalWrite(PIN_RST, HIGH);
    delay(300);

    gfx->begin(27000000);
    delay(100);
    gfx->fillScreen(C_BG);

    // Backlight ON
    pinMode(PIN_BL, OUTPUT);
    digitalWrite(PIN_BL, LOW);

    // Animated splash
    splash_screen();

    // Init sniffer
    memset(graph, 0, sizeof(graph));
    wifi_sniffer_init();
    Serial.println("[poppn] Sniffer started");
}

// ─── Loop ──────────────────────────────────────────────────────────────────
uint32_t last_hop    = 0;
uint32_t last_render = 0;
uint32_t last_graph  = 0;
#define GRAPH_INTERVAL_MS 200

void loop() {
    uint32_t now = millis();

    if (now - last_hop >= CHANNEL_HOP_MS) {
        last_hop = now;
        current_channel = (current_channel % MAX_CHANNELS) + 1;
        esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    }

    if (now - last_graph >= GRAPH_INTERVAL_MS) {
        last_graph = now;
        uint32_t cur = pkt_count;
        uint32_t delta = cur - last_pkt_snapshot;
        last_pkt_snapshot = cur;
        graph[graph_idx] = (delta > 65535) ? 65535 : (uint16_t)delta;
        graph_idx = (graph_idx + 1) % GRAPH_W;
    }

    // LED
    if (deauth_alert) {
        if ((now / 200) % 2) led_set(80, 0, 0);
        else led_set(0, 0, 0);
        if (now - deauth_ts > 5000) deauth_alert = false;
    } else {
        // Soft breathing cyan
        uint8_t br = (uint8_t)(10 + 10 * sin(now * 0.003));
        led_set(0, br / 2, br);
    }

    // Display
    if (now - last_render >= DISPLAY_UPDATE_MS) {
        last_render = now;
        if (deauth_alert && (now - deauth_ts < 5000)) {
            render_deauth_alert();
        } else {
            render_normal();
        }
    }

    // Serial
    static uint32_t last_deauth_log = 0;
    if (pkt_deauth != last_deauth_log) {
        last_deauth_log = pkt_deauth;
        Serial.printf("[DEAUTH] #%u  src=%s  dst=%s  ch=%d  rssi=%d dBm\n",
                      pkt_deauth,
                      mac2str(deauth_src).c_str(),
                      mac2str(deauth_dst).c_str(),
                      deauth_channel, deauth_rssi);
    }
}
