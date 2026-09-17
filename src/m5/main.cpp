// poppn packmon — M5StickC Plus2 edition
// WiFi packet monitor + deauth detector + handshake capture, storing logs in
// the device's internal flash (LittleFS) and serving them over a built-in
// WebUI (SoftAP). No SD card and no USB Mass Storage on this board (ESP32,
// USB-UART bridge), so the WebUI is how you get the data off.
#include <M5Unified.h>
#include <WiFi.h>
#include <WebServer.h>
#include "esp_wifi.h"
#include <LittleFS.h>
#include <FS.h>
#include "esp_timer.h"
#include <stdarg.h>

// ─── Display (landscape 240x135, flicker-free via a full-screen sprite) ─────
#define SCR_W 240
#define SCR_H 135
static M5Canvas cv(&M5.Display);

#define C565(r, g, b) ((uint16_t)((((r) & 0xF8) << 8) | (((g) & 0xFC) << 3) | ((b) >> 3)))
static const uint16_t C_BG=C565(8,8,10), C_PANEL=C565(22,24,26), C_ROW=C565(16,18,20),
    C_SEP=C565(40,44,46), C_LABEL=C565(107,112,110), C_TEXT=C565(222,226,224),
    C_ACCENT=C565(0,255,189), C_ACCENT_D=C565(0,110,84), C_BLUE=C565(74,142,255),
    C_OK=C565(33,206,33), C_WARN=C565(255,161,0), C_DANGER=C565(255,32,32),
    C_ALERT_BG=C565(48,0,0), C_DIM=C565(56,60,62);

// ─── Timing ─────────────────────────────────────────────────────────────────
#define FRAME_MS       40
#define CHANNEL_HOP_MS 500
#define MAX_CHANNELS   13
#define SAMPLE_MS      200
#define GRAPH_W        220
#define ALERT_MS       5000

// ─── 802.11 ──────────────────────────────────────────────────────────────────
typedef struct { unsigned fc:16; unsigned dur:16; uint8_t a1[6],a2[6],a3[6]; unsigned seq:16; }
    __attribute__((packed)) wifi_hdr_t;
#define FC_TYPE(fc)    (((fc)>>2)&0x3)
#define FC_SUBTYPE(fc) (((fc)>>4)&0xF)
#define TYPE_MGMT 0
#define TYPE_CTRL 1
#define TYPE_DATA 2
#define SUB_ASSOC_REQ 0
#define SUB_ASSOC_RESP 1
#define SUB_REASSOC_REQ 2
#define SUB_REASSOC_RESP 3
#define SUB_PROBE_REQ 4
#define SUB_PROBE_RESP 5
#define SUB_BEACON 8
#define SUB_DISASSOC 10
#define SUB_AUTH 11
#define SUB_DEAUTH 12

// ─── Counters ─────────────────────────────────────────────────────────────────
volatile uint32_t s_total=0,s_mgmt=0,s_ctrl=0,s_data=0,s_beacon=0,s_deauth=0,s_eapol=0;
volatile uint32_t s_ch[MAX_CHANNELS+1]={0};
volatile int8_t   s_rssi=0;
volatile uint32_t ev_dropped=0, hs_dropped=0, hs_saved=0;

// ─── Capture ring (EAPOL/auth/assoc/beacon frames -> pcapng) ─────────────────
#define HS_RING 24
#define HS_MAXLEN 512
typedef struct { uint16_t len; int8_t rssi; uint8_t channel; uint64_t ts_us; uint8_t data[HS_MAXLEN]; } rawframe_t;
static rawframe_t hs_ring[HS_RING];
static volatile uint16_t hs_head=0, hs_tail=0;
static uint8_t cap_bssid[32][6]; static int cap_bssid_n=0;
static uint64_t ts_base=0;
static bool fs_ok=false, cap_full=false;

// EAPOL handshake completeness per AP+client (bit0..3 = M1..M4)
typedef struct { uint8_t ap[6],sta[6]; uint8_t msgs; } hsst_t;
static hsst_t hsst[12]; static int hsst_n=0;
volatile uint8_t hs_pairs=0, hs_ok=0;

static inline uint8_t eapol_msg(uint16_t ki){
    bool mic=ki&0x100,ack=ki&0x80,inst=ki&0x40,sec=ki&0x200;
    if(ack&&!mic)return 1; if(!ack&&mic&&!sec)return 2;
    if(ack&&mic&&inst)return 3; if(!ack&&mic&&sec)return 4; return 0;
}

// ─── Event queue (callback -> loop) ──────────────────────────────────────────
#define EV_AP 1
#define EV_DEAUTH 2
#define EV_RING 48
typedef struct { uint8_t kind,channel; int8_t rssi; uint8_t ssid_len,sub; uint16_t caps;
    uint8_t bssid[6],dst[6]; char ssid[32]; } evt_t;
static evt_t ev_ring[EV_RING];
static volatile uint16_t ev_head=0, ev_tail=0;

// ─── Networks / threats tables ───────────────────────────────────────────────
#define MAX_APS 24
typedef struct { uint8_t bssid[6]; char ssid[33]; uint8_t channel; int8_t rssi; bool enc;
    uint32_t last_seen, frames; } ap_t;
static ap_t aps[MAX_APS]; static int ap_count=0;

#define MAX_THREATS 8
typedef struct { uint8_t src[6],dst[6]; uint8_t channel; int8_t rssi; uint32_t ts; } threat_t;
static threat_t threats[MAX_THREATS]; static int threat_count=0, threat_next=0;

// ─── UI / state ──────────────────────────────────────────────────────────────
enum { PAGE_LIVE, PAGE_NETWORKS, PAGE_THREATS, PAGE_HS, PAGE_WEBUI, PAGE_COUNT };
static const char* PAGE_NAME[PAGE_COUNT]={"LIVE","NETWORKS","THREATS","HANDSHAKE","WEB UI"};
static int page=PAGE_LIVE;
static uint16_t graph[GRAPH_W]={0}; static int graph_idx=0; static uint32_t last_snapshot=0;
static int current_channel=1; static bool ch_lock=false;
static float f_rate=0, f_scale=1;
static uint32_t rate_window_ts=0, rate_window_base=0, last_rate=0;
static uint32_t alert_ts=0; static bool alert_on=false; static uint8_t alert_ch=0;
static int8_t alert_rssi=0; static uint8_t alert_src[6]={0};
static uint32_t boot_ms=0;
static int log_session=0;

// ─── WebUI ───────────────────────────────────────────────────────────────────
static WebServer server(80);
static bool webui_on=false;
static char ap_ssid[24]={0};
static const char* AP_PASS="packmon123";

// ─── Logging (LittleFS) ──────────────────────────────────────────────────────
static File f_events, f_nets, f_stats, f_hs;
static bool log_dirty=false;

// ─── Helpers ─────────────────────────────────────────────────────────────────
static inline float clampf(float v,float lo,float hi){return v<lo?lo:(v>hi?hi:v);}
static inline float ease(float c,float t,float k){return c+(t-c)*k;}
static uint16_t lerp565(uint16_t a,uint16_t b,float t){
    t=clampf(t,0,1); int ar=(a>>11)&31,ag=(a>>5)&63,ab=a&31,br=(b>>11)&31,bg=(b>>5)&63,bb=b&31;
    return ((ar+(int)((br-ar)*t+.5f))<<11)|((ag+(int)((bg-ag)*t+.5f))<<5)|(ab+(int)((bb-ab)*t+.5f));
}
static uint16_t grad_green_at(int pos,int span){
    const int D=11,B=63; if(span<2)return B<<5; pos=pos<0?0:(pos>span-1?span-1:pos);
    return (uint16_t)((D+((B-D)*pos+(span-1)/2)/(span-1))<<5);
}
static void fmt_num(char*b,size_t n,uint32_t v){
    if(v<10000)snprintf(b,n,"%u",v); else if(v<1000000)snprintf(b,n,"%u.%uk",v/1000,(v%1000)/100);
    else snprintf(b,n,"%u.%uM",v/1000000,(v%1000000)/100000);
}
static void fmt_up(char*b,size_t n,uint32_t ms){uint32_t s=ms/1000;
    if(s<60)snprintf(b,n,"%us",s); else if(s<3600)snprintf(b,n,"%um%02us",s/60,s%60);
    else snprintf(b,n,"%uh%02um",s/3600,(s%3600)/60);}
static String mac2str(const volatile uint8_t*m){char b[18];
    snprintf(b,sizeof(b),"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]);return String(b);}
static uint16_t rssi_color(int8_t r){return r>=-60?C_ACCENT:(r>=-75?C_WARN:C_DANGER);}

static void txt(int x,int y,uint16_t c,uint8_t s,const char*fmt,...){
    char b[64]; va_list a; va_start(a,fmt); vsnprintf(b,sizeof(b),fmt,a); va_end(a);
    cv.setTextColor(c); cv.setTextSize(s); cv.setCursor(x,y); cv.print(b);
}
static void txt_r(int xr,int y,uint16_t c,uint8_t s,const char*fmt,...){
    char b[64]; va_list a; va_start(a,fmt); vsnprintf(b,sizeof(b),fmt,a); va_end(a);
    cv.setTextColor(c); cv.setTextSize(s); cv.setCursor(xr-(int)strlen(b)*6*s,y); cv.print(b);
}
static void txt_c(int xc,int y,uint16_t c,uint8_t s,const char*fmt,...){
    char b[64]; va_list a; va_start(a,fmt); vsnprintf(b,sizeof(b),fmt,a); va_end(a);
    cv.setTextColor(c); cv.setTextSize(s); cv.setCursor(xc-(int)strlen(b)*3*s,y); cv.print(b);
}

// ─── Promiscuous callback ────────────────────────────────────────────────────
static inline void ev_push(const evt_t*e){ uint16_t nh=(ev_head+1)%EV_RING;
    if(nh==ev_tail){ev_dropped++;return;} memcpy(&ev_ring[ev_head],e,sizeof(evt_t)); ev_head=nh; }
static inline void cap_push(const uint8_t*f,int len,int8_t rssi,uint8_t ch){
    if(cap_full) return;
    uint16_t nh=(hs_head+1)%HS_RING; if(nh==hs_tail){hs_dropped++;return;}
    int n=len>HS_MAXLEN?HS_MAXLEN:len;
    hs_ring[hs_head].len=n; hs_ring[hs_head].rssi=rssi; hs_ring[hs_head].channel=ch;
    hs_ring[hs_head].ts_us=ts_base+(uint64_t)esp_timer_get_time();
    memcpy(hs_ring[hs_head].data,f,n); hs_head=nh;
}
static inline bool cap_want_mgmt(uint8_t s){
    return s==SUB_AUTH||s==SUB_ASSOC_REQ||s==SUB_ASSOC_RESP||s==SUB_REASSOC_REQ||
           s==SUB_REASSOC_RESP||s==SUB_PROBE_REQ;
}

void IRAM_ATTR pkt_cb(void*buf, wifi_promiscuous_pkt_type_t type){
    wifi_promiscuous_pkt_t*pkt=(wifi_promiscuous_pkt_t*)buf;
    int len=pkt->rx_ctrl.sig_len; if(len<(int)sizeof(wifi_hdr_t))return;
    int8_t rssi=pkt->rx_ctrl.rssi; s_rssi=rssi; s_total++;
    if(current_channel>=1&&current_channel<=MAX_CHANNELS)s_ch[current_channel]++;
    wifi_hdr_t*h=(wifi_hdr_t*)pkt->payload; uint16_t fc=h->fc;
    uint8_t ft=FC_TYPE(fc), sub=FC_SUBTYPE(fc);

    if(ft==TYPE_CTRL){s_ctrl++;return;}
    if(ft==TYPE_DATA){ s_data++;
        if(fs_ok){ int hdr=24; if(sub&0x08)hdr+=2; if(((fc>>8)&1)&&((fc>>9)&1))hdr+=6;
            if(len>=hdr+8){ const uint8_t*l=pkt->payload+hdr;
                if(l[0]==0xAA&&l[1]==0xAA&&l[2]==0x03&&l[6]==0x88&&l[7]==0x8E){
                    s_eapol++; cap_push(pkt->payload,len,rssi,current_channel);
                    if(len>=hdr+15){ uint8_t m=eapol_msg((l[13]<<8)|l[14]);
                        if(m){ bool fromds=(fc>>9)&1;
                            const uint8_t*ap=fromds?h->a2:h->a1; const uint8_t*sta=fromds?h->a1:h->a2;
                            int s=-1; for(int i=0;i<hsst_n;i++) if(!memcmp(hsst[i].ap,ap,6)&&!memcmp(hsst[i].sta,sta,6)){s=i;break;}
                            if(s<0&&hsst_n<12){s=hsst_n++;memcpy(hsst[s].ap,ap,6);memcpy(hsst[s].sta,sta,6);hsst[s].msgs=0;}
                            if(s>=0){ hsst[s].msgs|=(1<<(m-1)); uint8_t p=0,ok=0;
                                for(int i=0;i<hsst_n;i++){p++; uint8_t g=hsst[i].msgs; if((g&0x5)&&(g&0xA))ok++;}
                                hs_pairs=p; hs_ok=ok; } } } } } }
        return; }
    if(ft!=TYPE_MGMT)return; s_mgmt++;

    if(sub==SUB_BEACON||sub==SUB_PROBE_RESP){ s_beacon++;
        evt_t e; memset(&e,0,sizeof(e)); e.kind=EV_AP; e.rssi=rssi; e.channel=current_channel;
        memcpy(e.bssid,h->a2,6); const uint8_t*p=pkt->payload;
        if(len>=36){ e.caps=p[34]|(p[35]<<8); int i=36,g=0;
            while(i+2<=len&&g++<24){ uint8_t tag=p[i],tl=p[i+1]; if(i+2+tl>len)break;
                if(tag==0){uint8_t n=tl>32?32:tl; memcpy(e.ssid,p+i+2,n); e.ssid_len=n;}
                else if(tag==3&&tl>=1){uint8_t c=p[i+2]; if(c>=1&&c<=MAX_CHANNELS)e.channel=c;}
                i+=2+tl; } }
        ev_push(&e);
        if(fs_ok){ bool seen=false; for(int i=0;i<cap_bssid_n;i++) if(!memcmp(cap_bssid[i],h->a2,6)){seen=true;break;}
            if(!seen&&cap_bssid_n<32){memcpy(cap_bssid[cap_bssid_n++],h->a2,6); cap_push(pkt->payload,len,rssi,e.channel);} }
        return; }

    if(sub==SUB_DEAUTH||sub==SUB_DISASSOC){ s_deauth++;
        evt_t e; memset(&e,0,sizeof(e)); e.kind=EV_DEAUTH; e.sub=sub; e.rssi=rssi;
        e.channel=current_channel; memcpy(e.bssid,h->a2,6); memcpy(e.dst,h->a1,6); ev_push(&e); }

    if(fs_ok&&cap_want_mgmt(sub)) cap_push(pkt->payload,len,rssi,current_channel);
}

// ─── Tables (loop task) ──────────────────────────────────────────────────────
static void ap_update(const evt_t*e){
    for(int i=0;i<ap_count;i++) if(!memcmp(aps[i].bssid,e->bssid,6)){
        aps[i].rssi=(aps[i].rssi*3+e->rssi)/4; aps[i].channel=e->channel; aps[i].last_seen=millis();
        aps[i].frames++; if(e->ssid_len&&!aps[i].ssid[0]){memcpy(aps[i].ssid,e->ssid,e->ssid_len);aps[i].ssid[e->ssid_len]=0;} return; }
    int slot=ap_count;
    if(ap_count<MAX_APS)ap_count++;
    else{uint32_t old=UINT32_MAX;slot=0;for(int i=0;i<MAX_APS;i++)if(aps[i].last_seen<old){old=aps[i].last_seen;slot=i;}}
    memset(&aps[slot],0,sizeof(ap_t)); memcpy(aps[slot].bssid,e->bssid,6);
    if(e->ssid_len){memcpy(aps[slot].ssid,e->ssid,e->ssid_len);aps[slot].ssid[e->ssid_len]=0;}
    aps[slot].channel=e->channel; aps[slot].rssi=e->rssi; aps[slot].enc=(e->caps&0x10)!=0;
    aps[slot].last_seen=millis(); aps[slot].frames=1;
    if(fs_ok&&f_nets){ char ts[16]; uint32_t ms=millis();
        snprintf(ts,sizeof(ts),"%02u:%02u:%02u.%03u",ms/3600000,(ms/60000)%60,(ms/1000)%60,ms%1000);
        f_nets.printf("%d,%s,%02X:%02X:%02X:%02X:%02X:%02X,",log_session,ts,
            aps[slot].bssid[0],aps[slot].bssid[1],aps[slot].bssid[2],aps[slot].bssid[3],aps[slot].bssid[4],aps[slot].bssid[5]);
        if(aps[slot].ssid[0]){for(char*q=aps[slot].ssid;*q;q++){char c=*q; if(c==','||c=='"'||c<0x20)c=' '; f_nets.write((uint8_t)c);}}
        else f_nets.print("<hidden>");
        f_nets.printf(",%u,%d,%s\n",aps[slot].channel,aps[slot].rssi,aps[slot].enc?"enc":"open"); log_dirty=true; }
}
static void threat_add(const evt_t*e){
    threat_t*t=&threats[threat_next]; memcpy(t->src,e->bssid,6); memcpy(t->dst,e->dst,6);
    t->channel=e->channel; t->rssi=e->rssi; t->ts=millis();
    threat_next=(threat_next+1)%MAX_THREATS; if(threat_count<MAX_THREATS)threat_count++;
    alert_ts=millis(); alert_on=true; alert_ch=e->channel; alert_rssi=e->rssi; memcpy(alert_src,e->bssid,6);
    if(fs_ok&&f_events){ char ts[16]; uint32_t ms=millis();
        snprintf(ts,sizeof(ts),"%02u:%02u:%02u.%03u",ms/3600000,(ms/60000)%60,(ms/1000)%60,ms%1000);
        f_events.printf("%d,%s,%s,%u,%d,%s,%s\n",log_session,ts,e->sub==SUB_DEAUTH?"deauth":"disassoc",
            e->channel,e->rssi,mac2str(t->src).c_str(),mac2str(t->dst).c_str()); log_dirty=true; }
}
static void drain_events(){
    while(ev_tail!=ev_head){ evt_t*e=&ev_ring[ev_tail];
        if(e->kind==EV_AP)ap_update(e); else if(e->kind==EV_DEAUTH)threat_add(e);
        ev_tail=(ev_tail+1)%EV_RING; }
}
static int ap_active(){int n=0;uint32_t now=millis();for(int i=0;i<ap_count;i++)if(now-aps[i].last_seen<=120000)n++;return n;}
static int ap_sorted(int*idx){int n=0;uint32_t now=millis();
    for(int i=0;i<ap_count;i++)if(now-aps[i].last_seen<=120000)idx[n++]=i;
    for(int i=1;i<n;i++){int k=idx[i],j=i-1;while(j>=0&&aps[idx[j]].rssi<aps[k].rssi){idx[j+1]=idx[j];j--;}idx[j+1]=k;} return n;}

// ─── pcapng writer ───────────────────────────────────────────────────────────
static void pn(File&f,uint32_t v){uint8_t b[4]={(uint8_t)v,(uint8_t)(v>>8),(uint8_t)(v>>16),(uint8_t)(v>>24)};f.write(b,4);}
static void pcapng_header(File&f){
    pn(f,0x0A0D0D0A);pn(f,28);pn(f,0x1A2B3C4D);pn(f,0x00000001);pn(f,0xFFFFFFFF);pn(f,0xFFFFFFFF);pn(f,28);
    pn(f,0x00000001);pn(f,32);pn(f,0x0000007F);pn(f,0);pn(f,0x00010009);pn(f,0x00000006);pn(f,0);pn(f,32);
}
static int build_radiotap(uint8_t*rt,uint8_t ch,int8_t rssi){
    rt[0]=0;rt[1]=0;rt[2]=15;rt[3]=0;rt[4]=0x2A;rt[5]=0;rt[6]=0;rt[7]=0;rt[8]=0x10;rt[9]=0;
    uint16_t fr=2412+(ch>=1&&ch<=13?(ch-1)*5:0); if(ch==14)fr=2484;
    rt[10]=fr;rt[11]=fr>>8;rt[12]=0xC0;rt[13]=0;rt[14]=(uint8_t)rssi; return 15;
}
static void hs_drain(){
    if(!fs_ok||!f_hs)return; uint8_t rt[16];
    while(hs_tail!=hs_head){
        if(!cap_full && f_hs.size() > 4400000){ cap_full=true; }   // leave headroom in the ~5.6 MB FS
        rawframe_t*r=&hs_ring[hs_tail];
        if(!cap_full){ int rl=build_radiotap(rt,r->channel,r->rssi);
            uint32_t cap=rl+r->len, pad=(4-(cap&3))&3, tot=32+cap+pad; uint64_t ts=r->ts_us;
            pn(f_hs,0x00000006);pn(f_hs,tot);pn(f_hs,0);pn(f_hs,ts>>32);pn(f_hs,(uint32_t)ts);
            pn(f_hs,cap);pn(f_hs,cap); f_hs.write(rt,rl); f_hs.write(r->data,r->len);
            for(uint32_t i=0;i<pad;i++)f_hs.write((uint8_t)0); pn(f_hs,tot);
            hs_saved++; log_dirty=true; }
        hs_tail=(hs_tail+1)%HS_RING;
    }
}
static void log_stats(uint32_t rate){
    if(!fs_ok||!f_stats)return; char ts[16]; uint32_t ms=millis();
    snprintf(ts,sizeof(ts),"%02u:%02u:%02u.%03u",ms/3600000,(ms/60000)%60,(ms/1000)%60,ms%1000);
    f_stats.printf("%d,%s,%u,%u,%u,%u,%u,%u,%u",log_session,ts,s_total,s_mgmt,s_ctrl,s_data,s_beacon,s_deauth,rate);
    for(int c=1;c<=MAX_CHANNELS;c++)f_stats.printf(",%u",s_ch[c]); f_stats.print("\n"); log_dirty=true;
}
static void log_flush(){ if(!fs_ok||!log_dirty)return;
    if(f_events)f_events.flush(); if(f_nets)f_nets.flush(); if(f_stats)f_stats.flush(); if(f_hs)f_hs.flush(); log_dirty=false; }

static int next_session(){ int n=1; File r=LittleFS.open("/session.txt",FILE_READ);
    if(r){n=r.parseInt()+1;r.close();} if(n<1)n=1;
    File w=LittleFS.open("/session.txt",FILE_WRITE); if(w){w.printf("%d",n);w.close();} return n; }

static bool logs_open(){
    log_session=next_session();
    ts_base=(uint64_t)log_session*86400ULL*1000000ULL; cap_bssid_n=0;
    bool en=!LittleFS.exists("/events.csv"), nn=!LittleFS.exists("/networks.csv"),
         sn=!LittleFS.exists("/stats.csv"), hn=!LittleFS.exists("/capture.pcapng");
    f_events=LittleFS.open("/events.csv",FILE_APPEND); if(f_events&&en)f_events.print("session,time,type,channel,rssi,src,dst\n");
    f_nets=LittleFS.open("/networks.csv",FILE_APPEND); if(f_nets&&nn)f_nets.print("session,time,bssid,ssid,channel,rssi,security\n");
    f_stats=LittleFS.open("/stats.csv",FILE_APPEND);
    if(f_stats&&sn){f_stats.print("session,time,total,mgmt,ctrl,data,beacon,deauth,rate");
        for(int c=1;c<=MAX_CHANNELS;c++)f_stats.printf(",ch%d",c); f_stats.print("\n");}
    f_hs=LittleFS.open("/capture.pcapng",FILE_APPEND); if(f_hs&&hn)pcapng_header(f_hs);
    log_dirty=true; return f_events&&f_stats;
}

// ─── Sniffer ─────────────────────────────────────────────────────────────────
static void sniffer_start(){
    WiFi.mode(WIFI_STA); WiFi.disconnect();
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filt={.filter_mask=WIFI_PROMIS_FILTER_MASK_ALL};
    esp_wifi_set_promiscuous_filter(&filt); esp_wifi_set_promiscuous_rx_cb(pkt_cb);
    esp_wifi_set_promiscuous(true); esp_wifi_set_channel(current_channel,WIFI_SECOND_CHAN_NONE);
}
static void sniffer_stop(){ esp_wifi_set_promiscuous(false); }

// ─── WebUI ───────────────────────────────────────────────────────────────────
static const char DASH[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>poppn packmon</title>
<style>body{margin:0;background:#080808;color:#dedede;font-family:ui-monospace,Menlo,Consolas,monospace}
.w{max-width:640px;margin:0 auto;padding:20px 14px 60px}h1{color:#00ffbd;text-align:center;margin:6px 0}
.s{text-align:center;color:#6b6d6b;font-size:12px;margin-bottom:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:18px}
.c{background:#121212;border:1px solid #262626;border-radius:10px;padding:12px}.c .k{color:#6b6d6b;font-size:10px;text-transform:uppercase;letter-spacing:.1em}
.c .v{font-size:20px;font-weight:700;margin-top:3px}.acc{color:#00ffbd}.dan{color:#ff2020}
h2{font-size:12px;letter-spacing:.15em;text-transform:uppercase;color:#6b6d6b}
a{color:#4a8eff}table{width:100%;border-collapse:collapse;font-size:13px}td{padding:7px 6px;border-bottom:1px solid #1c1c1c}
.b{display:inline-block;background:#00ffbd;color:#041410;font-weight:700;text-decoration:none;padding:6px 12px;border-radius:6px}</style>
</head><body><div class=w><h1>poppn packmon</h1><div class=s>M5StickC Plus2 · local logs</div>
<div class=cards id=cards></div>
<h2>Files</h2><table id=files></table>
<p style=margin-top:20px><a class=b href="/dl?f=capture.pcapng">Download capture.pcapng</a></p>
<p style=color:#6b6d6b;font-size:12px>Sniffing is paused while this Web UI is on. Turn it off on the device (Btn B) to resume capture.</p>
</div><script>
async function tick(){try{let s=await(await fetch('/api/stats')).json();
document.getElementById('cards').innerHTML=[['Packets',s.total,'acc'],['Networks',s.aps,''],['Deauth',s.deauth,s.deauth?'dan':''],
['EAPOL',s.eapol,'acc'],['Handshakes',s.hs_ok+'/'+s.hs_pairs,s.hs_ok?'acc':''],['Uptime',s.up,'']].map(c=>
`<div class=c><div class=k>${c[0]}</div><div class="v ${c[2]}">${c[1]}</div></div>`).join('');
let f=await(await fetch('/list')).json();
document.getElementById('files').innerHTML=f.map(x=>`<tr><td>${x.n}</td><td>${(x.s/1024).toFixed(1)} KB</td><td><a href="/dl?f=${x.n}">download</a></td></tr>`).join('');
}catch(e){}}
tick();setInterval(tick,2000);
</script></body></html>)HTML";

static String jesc(const char*s){String o;for(;*s;s++){char c=*s;if(c=='"'||c=='\\')o+='\\';o+=c;}return o;}
static void web_stats(){
    char up[16]; fmt_up(up,sizeof(up),millis()-boot_ms);
    String j="{"; j+="\"total\":"+String(s_total)+",\"aps\":"+String(ap_active())+
        ",\"deauth\":"+String(s_deauth)+",\"eapol\":"+String(s_eapol)+
        ",\"hs_ok\":"+String(hs_ok)+",\"hs_pairs\":"+String(hs_pairs)+
        ",\"up\":\""+up+"\"}";
    server.send(200,"application/json",j);
}
static void web_list(){
    String j="["; bool first=true; File d=LittleFS.open("/");
    for(File e=d.openNextFile(); e; e=d.openNextFile()){
        String n=e.name(); if(n.startsWith("/"))n=n.substring(1);
        if(n=="session.txt"){e.close();continue;}
        if(!first)j+=","; first=false;
        j+="{\"n\":\""+jesc(n.c_str())+"\",\"s\":"+String((uint32_t)e.size())+"}"; e.close();
    }
    j+="]"; server.send(200,"application/json",j);
}
static void web_dl(){
    if(!server.hasArg("f")){server.send(400,"text/plain","missing f");return;}
    String f="/"+server.arg("f"); if(f.indexOf("..")>=0){server.send(400,"text/plain","bad");return;}
    File file=LittleFS.open(f,FILE_READ); if(!file){server.send(404,"text/plain","not found");return;}
    const char* ct = f.endsWith(".csv")?"text/csv":(f.endsWith(".pcapng")?"application/vnd.tcpdump.pcap":"application/octet-stream");
    server.streamFile(file,ct); file.close();
}
static void webui_start(){
    sniffer_stop();
    log_flush();
    uint8_t mac[6]; WiFi.macAddress(mac);
    snprintf(ap_ssid,sizeof(ap_ssid),"packmon-%02X%02X",mac[4],mac[5]);
    WiFi.mode(WIFI_AP); WiFi.softAP(ap_ssid,AP_PASS);
    server.on("/",[](){server.send_P(200,"text/html",DASH);});
    server.on("/api/stats",web_stats); server.on("/list",web_list); server.on("/dl",web_dl);
    server.begin(); webui_on=true;
}
static void webui_stop(){ server.stop(); WiFi.softAPdisconnect(true); webui_on=false; sniffer_start(); }

// ─── Pages ───────────────────────────────────────────────────────────────────
static void header(const char*t){
    cv.fillRect(0,0,SCR_W,14,C_PANEL); cv.drawFastHLine(0,14,SCR_W,C_SEP);
    txt(4,3,C_ACCENT,1,t); cv.drawFastHLine(4,12,(int)strlen(t)*6,C_ACCENT);
    txt_r(SCR_W-4,3,rssi_color(s_rssi),1,"%d",(int)s_rssi);
    txt_r(SCR_W-40,3,ch_lock?C_WARN:C_LABEL,1,"CH%02d",current_channel);
}
static void page_live(){
    header("LIVE");
    uint16_t rc=f_rate>400?C_DANGER:(f_rate>120?C_WARN:C_ACCENT);
    txt(6,20,rc,4,"%d",(int)(f_rate+.5f)); txt(6,54,C_LABEL,1,"PKT/S");
    char b[16]; fmt_num(b,sizeof(b),s_total);
    txt_r(SCR_W-6,20,C_LABEL,1,"TOTAL"); txt_r(SCR_W-6,30,C_TEXT,2,b);
    txt_r(SCR_W-6,52,s_deauth?C_DANGER:C_LABEL,1,"DEAUTH %u",s_deauth);
    // EAPOL / usable
    if(s_eapol==0) txt(6,68,C_SEP,1,"HS  no EAPOL yet");
    else { txt(6,68,C_LABEL,1,"EAPOL"); txt(52,68,C_TEXT,1,"%u",s_eapol);
        if(hs_ok>0)txt(96,68,C_OK,1,"USABLE %u/%u",hs_ok,hs_pairs); else txt(96,68,C_WARN,1,"PARTIAL %u",hs_pairs); }
    // rate graph
    const int gx=6,gy=82,gh=44,gw=GRAPH_W;
    cv.fillRect(gx,gy,gw,gh,C_ROW);
    uint16_t pk=1; for(int i=0;i<gw;i++)if(graph[i]>pk)pk=graph[i];
    f_scale=ease(f_scale,(float)pk,0.08f); float sc=f_scale<1?1:f_scale;
    for(int i=0;i<gw;i++){int idx=(graph_idx+1+i)%gw; int h=(int)((float)graph[idx]/sc*(gh-1)+.5f);
        if(h<=0)continue; if(h>gh)h=gh; cv.drawFastVLine(gx+i,gy+gh-h,h,grad_green_at(i,gw)); cv.drawPixel(gx+i,gy+gh-h,C_ACCENT);}
    cv.drawFastHLine(gx,gy+gh,gw,C_SEP);
    txt_c(SCR_W/2,gy+gh+3,C_SEP,1,"BtnA:page  BtnB:Web UI");
}
static void page_networks(){
    int idx[MAX_APS]; int n=ap_sorted(idx); header("NETWORKS");
    txt(56,3,C_DIM,1,"%d",n);
    if(n==0){int d=(millis()/400)%4; txt_c(SCR_W/2,60,C_LABEL,1,"SCANNING%.*s",d,"..."); return;}
    int rows=9, y0=18, rh=13;
    for(int r=0;r<rows&&r<n;r++){ ap_t*a=&aps[idx[r]]; int y=y0+r*rh;
        if(r&1)cv.fillRect(0,y-1,SCR_W,rh,C_ROW);
        char nm[18]; strncpy(nm,a->ssid[0]?a->ssid:"<hidden>",17); nm[17]=0;
        txt(4,y,a->ssid[0]?C_TEXT:C_SEP,1,nm);
        txt(150,y,C_BLUE,1,"%02d",a->channel);
        txt(170,y,a->enc?C_WARN:C_OK,1,a->enc?"enc":"opn");
        txt_r(SCR_W-4,y,rssi_color(a->rssi),1,"%d",a->rssi); }
}
static void page_threats(){
    header("THREATS");
    if(threat_count==0){ txt_c(SCR_W/2,50,C_OK,3,"CLEAR");
        txt_c(SCR_W/2,80,C_LABEL,1,"no deauth frames seen"); return; }
    txt(6,20,C_DANGER,3,"%u",s_deauth); txt(6,48,C_LABEL,1,"DEAUTH FRAMES");
    uint32_t now=millis(); int shown=0;
    for(int k=1;k<=MAX_THREATS&&shown<5;k++){ if(k>threat_count)break;
        int i=(threat_next-k+MAX_THREATS)%MAX_THREATS; threat_t*t=&threats[i]; int y=64+shown*13;
        if(shown&1)cv.fillRect(0,y-1,SCR_W,13,C_ROW);
        txt(4,y,rssi_color(t->rssi),1,"%d",t->rssi); txt(40,y,C_BLUE,1,"CH%02d",t->channel);
        txt(80,y,C_TEXT,1,"%02X:%02X:%02X",t->src[3],t->src[4],t->src[5]);
        char age[12]; fmt_up(age,sizeof(age),now-t->ts); txt_r(SCR_W-4,y,C_LABEL,1,age); shown++; }
}
static void page_hs(){
    header("HANDSHAKE");
    txt(6,20,C_LABEL,1,"EAPOL"); txt(52,20,C_TEXT,1,"%u",s_eapol);
    if(hs_ok>0)txt_r(SCR_W-6,20,C_OK,1,"USABLE %u/%u",hs_ok,hs_pairs);
    else if(hs_pairs>0)txt_r(SCR_W-6,20,C_WARN,1,"PARTIAL %u",hs_pairs);
    else txt_r(SCR_W-6,20,C_SEP,1,"waiting");
    cv.drawFastHLine(6,31,SCR_W-12,C_SEP);
    if(hsst_n==0){ txt_c(SCR_W/2,60,C_SEP,1,"no EAPOL captured yet");
        txt_c(SCR_W/2,74,C_LABEL,1,"lock a channel and wait"); return; }
    txt(4,34,C_LABEL,1,"NET"); for(int m=0;m<4;m++)txt(120+m*14,34,C_LABEL,1,"%d",m+1);
    txt_r(SCR_W-4,34,C_LABEL,1,"USE");
    int y0=46, rh=13, n=hsst_n<6?hsst_n:6;
    for(int i=0;i<n;i++){ hsst_t*p=&hsst[i]; int y=y0+i*rh;
        const char*name=nullptr; for(int a=0;a<ap_count;a++)if(!memcmp(aps[a].bssid,p->ap,6)&&aps[a].ssid[0]){name=aps[a].ssid;break;}
        char nm[16]; if(name){strncpy(nm,name,15);nm[15]=0;} else snprintf(nm,sizeof(nm),"%02X%02X%02X",p->ap[3],p->ap[4],p->ap[5]);
        txt(4,y,C_TEXT,1,nm);
        for(int m=0;m<4;m++){bool on=p->msgs&(1<<m); cv.fillRect(120+m*14,y-1,11,9,on?C_ACCENT:C_ROW); cv.drawRect(120+m*14,y-1,11,9,C_SEP);}
        bool ok=(p->msgs&0x5)&&(p->msgs&0xA); txt_r(SCR_W-4,y,ok?C_OK:C_WARN,1,ok?"OK":"--"); }
}
static void page_webui(){
    header("WEB UI");
    if(webui_on){
        txt_c(SCR_W/2,22,C_ACCENT,2,"WEB UI ON");
        txt(10,46,C_LABEL,1,"1. Join WiFi network:");
        txt_c(SCR_W/2,58,C_TEXT,2,ap_ssid);
        txt(10,78,C_LABEL,1,"2. Password:"); txt_r(SCR_W-10,78,C_TEXT,1,AP_PASS);
        txt(10,90,C_LABEL,1,"3. Open in browser:"); txt_r(SCR_W-10,90,C_ACCENT,1,"192.168.4.1");
        txt_c(SCR_W/2,116,C_WARN,1,"sniffing paused - BtnB to resume");
    } else {
        txt_c(SCR_W/2,40,C_LABEL,1,"Share the logs over WiFi.");
        txt_c(SCR_W/2,60,C_TEXT,1,"Press BtnB to start a hotspot");
        txt_c(SCR_W/2,72,C_TEXT,1,"and browse the data.");
        char b[24]; fmt_num(b,sizeof(b),(uint32_t)(f_hs?f_hs.size():0));
        txt_c(SCR_W/2,100,C_SEP,1,"capture.pcapng: %s B%s",b,cap_full?" (full)":"");
    }
}
static void render_alert(){
    uint32_t age=millis()-alert_ts; float pulse=0.5f+0.5f*sinf(age*0.012f);
    cv.fillScreen(C_ALERT_BG); uint16_t bc=lerp565(C_DANGER,C_WARN,pulse);
    cv.drawRect(0,0,SCR_W,SCR_H,bc); cv.drawRect(1,1,SCR_W-2,SCR_H-2,bc);
    txt_c(SCR_W/2,12,lerp565(C_WARN,C_TEXT,pulse),2,"!! DEAUTH !!");
    char b[8]; snprintf(b,sizeof(b),"%d",(int)alert_rssi);
    txt_c(SCR_W/2,40,C_TEXT,4,b); txt_c(SCR_W/2,80,C_WARN,1,"dBm");
    txt(10,100,C_LABEL,1,"CH"); txt(30,100,C_TEXT,1,"%02d",alert_ch);
    txt_r(SCR_W-10,100,C_WARN,1,"%02X:%02X:%02X:%02X:%02X:%02X",
        alert_src[0],alert_src[1],alert_src[2],alert_src[3],alert_src[4],alert_src[5]);
    float left=1.0f-clampf((float)age/ALERT_MS,0,1); cv.fillRect(2,SCR_H-4,(int)((SCR_W-4)*left),2,bc);
}
static void render(){
    if(alert_on){render_alert();cv.pushSprite(0,0);return;}
    cv.fillScreen(C_BG);
    switch(page){case PAGE_LIVE:page_live();break;case PAGE_NETWORKS:page_networks();break;
        case PAGE_THREATS:page_threats();break;case PAGE_HS:page_hs();break;case PAGE_WEBUI:page_webui();break;}
    // page dots
    for(int i=0;i<PAGE_COUNT;i++)cv.fillRect(SCR_W/2-PAGE_COUNT*6/2+i*6,SCR_H-3,4,2,i==page?C_ACCENT:C_SEP);
    cv.pushSprite(0,0);
}

// ─── Setup / loop ────────────────────────────────────────────────────────────
void setup(){
    auto cfg=M5.config(); M5.begin(cfg);
    M5.Display.setRotation(1); M5.Display.setBrightness(120);
    cv.setColorDepth(16); cv.createSprite(SCR_W,SCR_H);
    cv.fillScreen(C_BG); txt_c(SCR_W/2,60,C_ACCENT,3,"poppn"); cv.pushSprite(0,0);

    Serial.begin(115200);
    fs_ok = LittleFS.begin(true);         // format on first run
    if(fs_ok) fs_ok = logs_open();

    boot_ms=millis(); rate_window_ts=boot_ms;
    sniffer_start();
    delay(400);
}

static uint32_t last_hop=0,last_sample=0,last_frame=0,last_flush=0,last_statlog=0;

void loop(){
    M5.update();
    uint32_t now=millis();

    if(webui_on){ server.handleClient(); }
    else {
        drain_events();
        if(!ch_lock && now-last_hop>=CHANNEL_HOP_MS){ last_hop=now;
            current_channel=(current_channel%MAX_CHANNELS)+1; esp_wifi_set_channel(current_channel,WIFI_SECOND_CHAN_NONE); }
        if(now-last_sample>=SAMPLE_MS){ last_sample=now; uint32_t d=s_total-last_snapshot; last_snapshot=s_total;
            graph[graph_idx]=d>65535?65535:(uint16_t)d; graph_idx=(graph_idx+1)%GRAPH_W; }
        if(now-rate_window_ts>=1000){ last_rate=s_total-rate_window_base; rate_window_base=s_total; rate_window_ts=now; }
        if(fs_ok){ hs_drain();
            if(now-last_statlog>=5000){last_statlog=now;log_stats(last_rate);}
            if(now-last_flush>=3000){last_flush=now;log_flush();} }
        if(alert_on&&now-alert_ts>ALERT_MS)alert_on=false;
    }

    // Buttons: A = next page, A(long) = channel lock, B = toggle Web UI
    if(M5.BtnA.wasClicked() && !webui_on) page=(page+1)%PAGE_COUNT;
    if(M5.BtnA.wasHold() && !webui_on) ch_lock=!ch_lock;
    if(M5.BtnB.wasClicked()){
        if(webui_on){ webui_stop(); page=PAGE_WEBUI; }
        else { if(fs_ok){ webui_start(); page=PAGE_WEBUI; } }
    }

    f_rate=ease(f_rate,(float)last_rate,0.12f);

    if(now-last_frame>=FRAME_MS){ last_frame=now; render(); }
}
