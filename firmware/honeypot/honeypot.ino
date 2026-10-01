// esp32-wifi-honeypot - a defensive Wi-Fi honeypot / rogue-device sensor.
//
// PURPOSE: detection and research on your OWN network or an AUTHORIZED engagement.
// It advertises a rotating set of OPEN decoy SSIDs, lets devices associate, serves a
// neutral "checking connection" page, and records METADATA about what shows up:
//   - MAC address + vendor (OUI) or a "randomized" flag for privacy MACs
//   - signal strength (RSSI), first/last seen, how many times, assigned IP
//   - the SSIDs nearby devices are probing for (passive promiscuous sniffing)
//   - HTTP User-Agent / Host from the captive page
// It does NOT impersonate real services or capture credentials - that would be an
// evil-twin attack, not a honeypot. Keep SSID names generic (no real-brand spoofing).
//
// Board: Seeed XIAO ESP32S3 (XIAOML Kit). esp32 core 2.0.17, PSRAM = OPI PSRAM, library U8g2.
// Management link: joins your Wi-Fi (secrets.h) so you reach the dashboard; the decoy AP
// runs at the same time (AP+STA share one radio/channel).
// Flash: make honeypot  ->  open the dashboard URL it prints, or http://honeypot.local

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_http_server.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <Wire.h>
#include <U8g2lib.h>
#include <SD.h>
#include <SPI.h>
#include <FS.h>
#include <time.h>
#include <lwip/sockets.h>
#include "secrets.h"
#include "oui.h"
#include "page.h"

// ---------------------------------------------------------------- config
const int SD_CS = 21;          // microSD CS (also the user LED pin; we leave the LED alone)
const uint8_t OLED_ADDR = 0x3C;
const char* TIMEZONE = "PST8PDT,M3.2.0,M11.1.0";   // case-file timestamps (Vancouver)
IPAddress AP_IP(192, 168, 4, 1);

// Rotating OPEN decoy SSIDs. Generic, enticing names - never real-brand names.
String decoySsids[6] = {"Free_WiFi", "Guest_Network", "Public_WiFi", "Coffee_Shop_WiFi", "Airport_WiFi", ""};
int decoyCount = 5;
int decoyIdx = 0;
const unsigned long ROTATE_MS = 180000;   // rotate the decoy SSID every 3 min, only while nobody is joined
unsigned long lastRotate = 0;

#define MAX_CONTACTS 60
#define MAX_PROBES_PER 6

struct Contact {
  bool used = false;
  uint8_t mac[6];
  bool randomized = false;
  int8_t rssiLast = 0;
  int8_t rssiBest = -128;
  time_t firstSeen = 0;
  time_t lastSeen = 0;
  uint32_t seen = 0;
  bool associated = false;
  uint32_t ip = 0;
  char joined[33] = "";
  char probes[MAX_PROBES_PER][33];
  uint8_t probeCount = 0;
  char ua[80] = "";
  char host[48] = "";
  bool fresh = false;   // set when newly created, cleared after the OLED shows it
};

Contact contacts[MAX_CONTACTS];
SemaphoreHandle_t contactsLock;
uint32_t totalSeen = 0;      // distinct devices ever recorded
uint32_t probeFrames = 0;    // probe requests sniffed

// passive probe sniffer -> queue -> processed in loop()
struct ProbeEvt {
  uint8_t mac[6];
  int8_t rssi;
  char ssid[33];
};
QueueHandle_t probeQ;
volatile bool snifferOn = true;

volatile bool applyDecoyReq = false;   // set by the web handler, applied in loop() (off the httpd task)

// deep (channel-hopping) scan
volatile bool deepScanReq = false;
volatile bool deepScanning = false;
volatile int deepScanCh = 0;

// SD
bool sdOk = false;
SemaphoreHandle_t sdLock;

// OLED
U8G2_SSD1306_72X40_ER_F_HW_I2C u8g2(U8G2_R2, U8X8_PIN_NONE);
bool screenOk = false;
char lastLabel[20] = "";
int8_t lastRssi = 0;
unsigned long newFlashUntil = 0;

DNSServer dnsServer;
httpd_handle_t server = nullptr;

void startDecoy(int idx);   // defined below

// ---------------------------------------------------------------- helpers
String macStr(const uint8_t* m) {
  char b[18];
  snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
  return b;
}

String ipStr(uint32_t ip) {
  if (!ip) return "";
  return String((int)(ip & 0xff)) + "." + (int)((ip >> 8) & 0xff) + "." + (int)((ip >> 16) & 0xff) + "." + (int)((ip >> 24) & 0xff);
}

time_t nowEpoch() {
  time_t t = time(nullptr);
  return t > 1700000000 ? t : 0;   // 0 until NTP sets the clock
}

String jsonEscape(const String& s) {
  String o;
  for (char c : s) {
    if (c == '"' || c == '\\') o += '\\';
    if ((uint8_t)c >= 32 && (uint8_t)c < 127) o += c;
  }
  return o;
}

// caller must hold contactsLock. Returns the slot for this MAC, creating/evicting as needed.
Contact* findOrCreate(const uint8_t* mac, bool* created) {
  int freeIdx = -1, lruIdx = 0;
  time_t lru = 0x7fffffff;
  for (int i = 0; i < MAX_CONTACTS; i++) {
    if (contacts[i].used && memcmp(contacts[i].mac, mac, 6) == 0) {
      if (created) *created = false;
      return &contacts[i];
    }
    if (!contacts[i].used && freeIdx < 0) freeIdx = i;
    if (contacts[i].used && contacts[i].lastSeen < lru) { lru = contacts[i].lastSeen; lruIdx = i; }
  }
  int idx = freeIdx >= 0 ? freeIdx : lruIdx;
  Contact& c = contacts[idx];
  c = Contact();
  c.used = true;
  memcpy(c.mac, mac, 6);
  ouiLookup(mac, &c.randomized);
  c.firstSeen = nowEpoch();
  c.fresh = true;
  if (created) *created = true;
  totalSeen++;
  return &c;
}

int countAssociated() {
  int n = 0;
  for (auto& c : contacts) if (c.used && c.associated) n++;
  return n;
}
int countUsed() {
  int n = 0;
  for (auto& c : contacts) if (c.used) n++;
  return n;
}

// ---------------------------------------------------------------- SD logging (append one JSON line per event)
void logEvent(const String& line) {
  Serial.println("[evt] " + line);
  if (!sdOk) return;
  if (xSemaphoreTake(sdLock, pdMS_TO_TICKS(200)) != pdTRUE) return;
  File f = SD.open("/honeypot/events.jsonl", FILE_APPEND);
  if (f) { f.println(line); f.close(); }
  xSemaphoreGive(sdLock);
}

void onNewDevice(Contact* c, const char* how) {
  strncpy(lastLabel, c->randomized ? "randomized" : ouiLookup(c->mac, &c->randomized), sizeof(lastLabel) - 1);
  lastRssi = c->rssiLast;
  newFlashUntil = millis() + 2500;
  bool rnd = false;
  logEvent(String("{\"t\":") + (long)nowEpoch() + ",\"ev\":\"new\",\"how\":\"" + how + "\",\"mac\":\"" + macStr(c->mac) +
           "\",\"vendor\":\"" + ouiLookup(c->mac, &rnd) + "\",\"rssi\":" + c->rssiLast + "}");
}

// ---------------------------------------------------------------- passive probe sniffer
void IRAM_ATTR snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t* ppkt = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* p = ppkt->payload;
  if (p[0] != 0x40) return;                 // frame control: mgmt / probe-request, version 0
  if (ppkt->rx_ctrl.sig_len < 26) return;
  ProbeEvt e;
  memcpy(e.mac, p + 10, 6);                  // addr2 = source
  e.rssi = ppkt->rx_ctrl.rssi;
  e.ssid[0] = 0;
  uint8_t ssidLen = p[25];                   // first IE is SSID: p[24]=id(0), p[25]=len
  if (p[24] == 0 && ssidLen > 0 && ssidLen <= 32 && (26 + ssidLen) <= ppkt->rx_ctrl.sig_len) {
    memcpy(e.ssid, p + 26, ssidLen);
    e.ssid[ssidLen] = 0;
  }
  probeFrames++;
  xQueueSendFromISR(probeQ, &e, nullptr);
}

void handleProbe(const ProbeEvt& e) {
  xSemaphoreTake(contactsLock, portMAX_DELAY);
  bool created = false;
  Contact* c = findOrCreate(e.mac, &created);
  c->lastSeen = nowEpoch();
  c->seen++;
  c->rssiLast = e.rssi;
  if (e.rssi > c->rssiBest) c->rssiBest = e.rssi;
  if (e.ssid[0]) {   // record a distinct probed SSID
    bool have = false;
    for (int i = 0; i < c->probeCount; i++) if (strcmp(c->probes[i], e.ssid) == 0) { have = true; break; }
    if (!have && c->probeCount < MAX_PROBES_PER) strncpy(c->probes[c->probeCount++], e.ssid, 32);
  }
  xSemaphoreGive(contactsLock);
  if (created) onNewDevice(c, "probe");
}

// ---------------------------------------------------------------- association tracking
void onApConnect(WiFiEvent_t event, WiFiEventInfo_t info) {
  const uint8_t* mac = info.wifi_ap_staconnected.mac;
  xSemaphoreTake(contactsLock, portMAX_DELAY);
  bool created = false;
  Contact* c = findOrCreate(mac, &created);
  c->associated = true;
  c->lastSeen = nowEpoch();
  c->seen++;
  strncpy(c->joined, decoySsids[decoyIdx].c_str(), 32);
  xSemaphoreGive(contactsLock);
  if (created) onNewDevice(c, "assoc");
  bool rnd = false;
  logEvent(String("{\"t\":") + (long)nowEpoch() + ",\"ev\":\"assoc\",\"mac\":\"" + macStr(mac) +
           "\",\"vendor\":\"" + ouiLookup(mac, &rnd) + "\",\"ssid\":\"" + jsonEscape(decoySsids[decoyIdx]) + "\"}");
}

void onApDisconnect(WiFiEvent_t event, WiFiEventInfo_t info) {
  const uint8_t* mac = info.wifi_ap_stadisconnected.mac;
  xSemaphoreTake(contactsLock, portMAX_DELAY);
  for (auto& c : contacts)
    if (c.used && memcmp(c.mac, mac, 6) == 0) { c.associated = false; c.lastSeen = nowEpoch(); }
  xSemaphoreGive(contactsLock);
}

// Poll the AP station table for live RSSI + assigned IP, and attach them by MAC.
void pollStations() {
  wifi_sta_list_t staList;
  if (esp_wifi_ap_get_sta_list(&staList) != ESP_OK) return;
  esp_netif_sta_list_t netList;
  bool haveIp = (esp_netif_get_sta_list(&staList, &netList) == ESP_OK);
  xSemaphoreTake(contactsLock, portMAX_DELAY);
  for (int i = 0; i < staList.num; i++) {
    bool created = false;
    Contact* c = findOrCreate(staList.sta[i].mac, &created);
    c->associated = true;
    c->rssiLast = staList.sta[i].rssi;
    if (staList.sta[i].rssi > c->rssiBest) c->rssiBest = staList.sta[i].rssi;
    c->lastSeen = nowEpoch();
    if (!c->joined[0]) strncpy(c->joined, decoySsids[decoyIdx].c_str(), 32);
    if (haveIp)
      for (int j = 0; j < netList.num; j++)
        if (memcmp(netList.sta[j].mac, staList.sta[i].mac, 6) == 0) c->ip = netList.sta[j].ip.addr;
  }
  xSemaphoreGive(contactsLock);
}

// ---------------------------------------------------------------- web: tell the AP (captive) side from the operator side
uint32_t reqLocalIp(httpd_req_t* req) {
  int fd = httpd_req_to_sockfd(req);
  struct sockaddr_in6 sa;
  socklen_t sl = sizeof(sa);
  if (getsockname(fd, (struct sockaddr*)&sa, &sl) != 0) return 0;
  if (sa.sin6_family == AF_INET) return ((struct sockaddr_in*)&sa)->sin_addr.s_addr;
  uint8_t* a = (uint8_t*)&sa.sin6_addr;   // IPv4-mapped IPv6: last 4 bytes
  return *(uint32_t*)(a + 12);
}
uint32_t reqPeerIp(httpd_req_t* req) {
  int fd = httpd_req_to_sockfd(req);
  struct sockaddr_in6 sa;
  socklen_t sl = sizeof(sa);
  if (getpeername(fd, (struct sockaddr*)&sa, &sl) != 0) return 0;
  if (sa.sin6_family == AF_INET) return ((struct sockaddr_in*)&sa)->sin_addr.s_addr;
  uint8_t* a = (uint8_t*)&sa.sin6_addr;
  return *(uint32_t*)(a + 12);
}
bool isApSide(httpd_req_t* req) {
  // A joined device has a 192.168.4.x address (our SoftAP DHCP range); the operator reaches
  // us over the management LAN (a different subnet). Key off the client's source IP.
  uint32_t ip = reqPeerIp(req);
  return (ip & 0x00FFFFFF) == 0x0004A8C0;   // 192.168.4.x (little-endian bytes C0 A8 04 xx)
}

esp_err_t sendJson(httpd_req_t* req, const String& body) {
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");
  return httpd_resp_send(req, body.c_str(), body.length());
}

// A connecting device's browser lands here. Neutral page, and we log its fingerprint.
esp_err_t captiveHandler(httpd_req_t* req) {
  char ua[80] = "", host[48] = "";
  httpd_req_get_hdr_value_str(req, "User-Agent", ua, sizeof(ua));
  httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host));
  uint32_t ip = reqPeerIp(req);
  if (ip) {
    xSemaphoreTake(contactsLock, portMAX_DELAY);
    for (auto& c : contacts)
      if (c.used && c.ip == ip) {
        if (ua[0]) strncpy(c.ua, ua, sizeof(c.ua) - 1);
        if (host[0]) strncpy(c.host, host, sizeof(c.host) - 1);
        c.lastSeen = nowEpoch();
      }
    xSemaphoreGive(contactsLock);
  }
  logEvent(String("{\"t\":") + (long)nowEpoch() + ",\"ev\":\"http\",\"ip\":\"" + ipStr(ip) +
           "\",\"host\":\"" + jsonEscape(host) + "\",\"ua\":\"" + jsonEscape(ua) + "\"}");
  httpd_resp_set_type(req, "text/html");
  return httpd_resp_send(req, NEUTRAL_HTML, HTTPD_RESP_USE_STRLEN);
}

esp_err_t rootHandler(httpd_req_t* req) {
  if (isApSide(req)) return captiveHandler(req);
  httpd_resp_set_type(req, "text/html");
  return httpd_resp_send(req, DASH_HTML, HTTPD_RESP_USE_STRLEN);
}

esp_err_t stateHandler(httpd_req_t* req) {
  String j = "{";
  j += "\"ssid\":\"" + jsonEscape(decoySsids[decoyIdx]) + "\",";
  j += "\"channel\":" + String(WiFi.channel()) + ",";
  j += "\"mgmtIp\":\"" + WiFi.localIP().toString() + "\",";
  j += "\"apIp\":\"" + AP_IP.toString() + "\",";
  j += "\"uptime\":" + String(millis() / 1000) + ",";
  j += "\"contacts\":" + String(countUsed()) + ",";
  j += "\"associated\":" + String(countAssociated()) + ",";
  j += "\"totalSeen\":" + String(totalSeen) + ",";
  j += "\"probeFrames\":" + String(probeFrames) + ",";
  j += "\"sniffer\":" + String(snifferOn ? "true" : "false") + ",";
  j += "\"deepScan\":" + String(deepScanning ? "true" : "false") + ",";
  j += "\"sd\":" + String(sdOk ? "true" : "false") + ",";
  j += "\"now\":" + String((long)nowEpoch()) + ",";
  j += "\"decoys\":[";
  for (int i = 0; i < decoyCount; i++) j += (i ? "," : "") + String("\"") + jsonEscape(decoySsids[i]) + "\"";
  j += "]}";
  return sendJson(req, j);
}

esp_err_t contactsHandler(httpd_req_t* req) {
  String j = "[";
  xSemaphoreTake(contactsLock, portMAX_DELAY);
  bool first = true;
  for (auto& c : contacts) {
    if (!c.used) continue;
    bool rnd = false;
    const char* vendor = ouiLookup(c.mac, &rnd);
    j += first ? "{" : ",{";
    first = false;
    j += "\"mac\":\"" + macStr(c.mac) + "\",";
    j += "\"vendor\":\"" + String(vendor) + "\",";
    j += "\"randomized\":" + String(c.randomized ? "true" : "false") + ",";
    j += "\"rssi\":" + String(c.rssiLast) + ",\"best\":" + String(c.rssiBest) + ",";
    j += "\"first\":" + String((long)c.firstSeen) + ",\"last\":" + String((long)c.lastSeen) + ",";
    j += "\"seen\":" + String(c.seen) + ",";
    j += "\"assoc\":" + String(c.associated ? "true" : "false") + ",";
    j += "\"ip\":\"" + ipStr(c.ip) + "\",";
    j += "\"joined\":\"" + jsonEscape(c.joined) + "\",";
    j += "\"ua\":\"" + jsonEscape(c.ua) + "\",\"host\":\"" + jsonEscape(c.host) + "\",";
    j += "\"probes\":[";
    for (int i = 0; i < c.probeCount; i++) j += (i ? "," : "") + String("\"") + jsonEscape(c.probes[i]) + "\"";
    j += "]}";
  }
  xSemaphoreGive(contactsLock);
  j += "]";
  return sendJson(req, j);
}

bool qparam(httpd_req_t* req, const char* key, char* out, size_t len) {
  char q[256];
  out[0] = 0;
  if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK) return false;
  return httpd_query_key_value(q, key, out, len) == ESP_OK;
}

esp_err_t snifferHandler(httpd_req_t* req) {
  char v[4];
  if (qparam(req, "on", v, sizeof(v))) {
    snifferOn = (v[0] == '1');
    esp_wifi_set_promiscuous(snifferOn);
  }
  return sendJson(req, String("{\"sniffer\":") + (snifferOn ? "true" : "false") + "}");
}

esp_err_t clearHandler(httpd_req_t* req) {
  xSemaphoreTake(contactsLock, portMAX_DELAY);
  for (auto& c : contacts) c = Contact();
  xSemaphoreGive(contactsLock);
  return sendJson(req, "{\"cleared\":true}");
}

esp_err_t scanHandler(httpd_req_t* req) {
  deepScanReq = true;
  return sendJson(req, "{\"deepScan\":\"starting\"}");
}

esp_err_t ssidsHandler(httpd_req_t* req) {
  char v[200];
  if (qparam(req, "set", v, sizeof(v)) && v[0]) {
    // URL-decode %xx and '+' in place
    char* o = v;
    for (char* p = v; *p; p++) {
      if (*p == '+') *o++ = ' ';
      else if (*p == '%' && isxdigit(p[1]) && isxdigit(p[2])) { char h[3] = {p[1], p[2], 0}; *o++ = (char)strtol(h, nullptr, 16); p += 2; }
      else *o++ = *p;
    }
    *o = 0;
    int n = 0;
    char* tok = strtok(v, ",");
    while (tok && n < 5) {
      while (*tok == ' ') tok++;
      if (*tok) { decoySsids[n] = String(tok).substring(0, 32); n++; }
      tok = strtok(nullptr, ",");
    }
    if (n) { decoyCount = n; applyDecoyReq = true; }   // loop() applies it (keeps WiFi calls off the web task)
  }
  return stateHandler(req);
}

esp_err_t logHandler(httpd_req_t* req) {
  httpd_resp_set_type(req, "application/x-ndjson");
  httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=honeypot-events.jsonl");
  if (!sdOk) { httpd_resp_sendstr(req, ""); return ESP_OK; }
  if (xSemaphoreTake(sdLock, pdMS_TO_TICKS(500)) != pdTRUE) { httpd_resp_send_500(req); return ESP_FAIL; }
  File f = SD.open("/honeypot/events.jsonl");
  if (!f) { xSemaphoreGive(sdLock); httpd_resp_sendstr(req, ""); return ESP_OK; }
  static char chunk[1024];
  int n;
  while ((n = f.read((uint8_t*)chunk, sizeof(chunk))) > 0) httpd_resp_send_chunk(req, chunk, n);
  f.close();
  xSemaphoreGive(sdLock);
  httpd_resp_send_chunk(req, nullptr, 0);
  return ESP_OK;
}

// catch-all: OS captive-detection URLs and anything else from the AP side -> neutral page
esp_err_t catchAll(httpd_req_t* req) {
  if (isApSide(req)) return captiveHandler(req);
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", "/");
  return httpd_resp_send(req, nullptr, 0);
}

void startWeb() {
  httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
  cfg.max_uri_handlers = 16;
  cfg.stack_size = 10240;
  cfg.lru_purge_enable = true;
  cfg.uri_match_fn = httpd_uri_match_wildcard;
  if (httpd_start(&server, &cfg) != ESP_OK) return;
  auto reg = [&](const char* uri, esp_err_t (*fn)(httpd_req_t*)) {
    httpd_uri_t u = {uri, HTTP_GET, fn, nullptr};
    httpd_register_uri_handler(server, &u);
  };
  reg("/api/state", stateHandler);
  reg("/api/contacts", contactsHandler);
  reg("/api/sniffer", snifferHandler);
  reg("/api/clear", clearHandler);
  reg("/api/scan", scanHandler);
  reg("/api/ssids", ssidsHandler);
  reg("/log.jsonl", logHandler);
  reg("/", rootHandler);
  reg("/*", catchAll);   // registered last: only matches what the specific routes did not
}

// ---------------------------------------------------------------- OLED
void drawScreen() {
  if (!screenOk) return;
  u8g2.clearBuffer();
  unsigned long now = millis();

  if (deepScanning) {
    u8g2.setFont(u8g2_font_6x10_tr);
    u8g2.drawStr(4, 10, "DEEP SCAN");
    u8g2.setFont(u8g2_font_5x8_tr);
    char b[20];
    snprintf(b, sizeof(b), "ch %d", deepScanCh);
    u8g2.drawStr(4, 24, b);
    u8g2.drawFrame(2, 30, 68, 6);
    u8g2.drawBox(2, 30, (deepScanCh * 68) / 11, 6);
    u8g2.sendBuffer();
    return;
  }

  bool flash = now < newFlashUntil && (now / 250) % 2;
  if (flash) { u8g2.drawBox(0, 0, 72, 40); u8g2.setDrawColor(0); }
  u8g2.setFont(u8g2_font_6x10_tr);
  u8g2.drawStr(2, 9, now < newFlashUntil ? "NEW DEVICE" : "HONEYPOT");
  u8g2.setFont(u8g2_font_4x6_tr);
  char b[24];
  snprintf(b, sizeof(b), "%.11s", decoySsids[decoyIdx].c_str());
  u8g2.drawStr(2, 16, b);
  u8g2.drawHLine(0, 19, 72);
  u8g2.setFont(u8g2_font_5x8_tr);
  snprintf(b, sizeof(b), "seen %lu", (unsigned long)totalSeen);
  u8g2.drawStr(2, 28, b);
  snprintf(b, sizeof(b), "assoc %d", countAssociated());
  u8g2.drawStr(2, 38, b);
  if (lastLabel[0]) {
    u8g2.setFont(u8g2_font_4x6_tr);
    snprintf(b, sizeof(b), "%.10s", lastLabel);
    u8g2.drawStr(40, 28, b);
    snprintf(b, sizeof(b), "%ddBm", lastRssi);
    u8g2.drawStr(40, 37, b);
  }
  u8g2.setDrawColor(1);
  u8g2.sendBuffer();
}

// ---------------------------------------------------------------- decoy AP
void startDecoy(int idx) {
  decoyIdx = idx;
  WiFi.softAP(decoySsids[idx].c_str());   // open network (no password)
  Serial.printf("[ap] broadcasting decoy \"%s\" on channel %d\n", decoySsids[idx].c_str(), WiFi.channel());
}

void runDeepScan() {
  deepScanning = true;
  esp_wifi_set_promiscuous(true);
  const int chans[] = {1, 6, 11};
  for (int k = 0; k < 3; k++) {
    deepScanCh = chans[k];
    esp_wifi_set_channel(chans[k], WIFI_SECOND_CHAN_NONE);
    unsigned long t0 = millis();
    while (millis() - t0 < 3000) {
      ProbeEvt e;
      while (xQueueReceive(probeQ, &e, 0) == pdTRUE) handleProbe(e);
      drawScreen();
      delay(20);
    }
  }
  esp_wifi_set_promiscuous(snifferOn);
  WiFi.reconnect();   // rejoin the management network, back to its channel
  deepScanning = false;
  deepScanReq = false;
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("\nesp32-wifi-honeypot starting...");

  for (auto& c : contacts) c.used = false;
  contactsLock = xSemaphoreCreateMutex();
  sdLock = xSemaphoreCreateMutex();
  probeQ = xQueueCreate(24, sizeof(ProbeEvt));

  Wire.begin();
  Wire.beginTransmission(OLED_ADDR);
  screenOk = (Wire.endTransmission() == 0);
  if (screenOk) { u8g2.begin(); u8g2.setBusClock(400000); }

  if (SD.begin(SD_CS)) { sdOk = true; if (!SD.exists("/honeypot")) SD.mkdir("/honeypot"); }
  Serial.printf("[sd] %s\n", sdOk ? "ready" : "not present (logging to serial only)");

  WiFi.onEvent(onApConnect, ARDUINO_EVENT_WIFI_AP_STACONNECTED);
  WiFi.onEvent(onApDisconnect, ARDUINO_EVENT_WIFI_AP_STADISCONNECTED);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(AP_IP, AP_IP, IPAddress(255, 255, 255, 0));
  startDecoy(0);

  WiFi.begin(MGMT_WIFI_SSID, MGMT_WIFI_PASSWORD);
  Serial.printf("[sta] joining management network \"%s\"", MGMT_WIFI_SSID);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(300); Serial.print("."); drawScreen(); }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[sta] connected, dashboard at http://%s/  (or http://honeypot.local/)\n", WiFi.localIP().toString().c_str());
    configTzTime(TIMEZONE, "pool.ntp.org", "time.nist.gov");
    MDNS.begin("honeypot");
    MDNS.addService("http", "tcp", 80);
  } else {
    Serial.println("[sta] NOT connected - check secrets.h (2.4 GHz). Decoy AP + sniffer still run.");
  }

  dnsServer.start(53, "*", AP_IP);   // captive DNS: send every lookup to the AP
  startWeb();

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);
  esp_wifi_set_promiscuous(true);

  Serial.println("[ok] honeypot sensor running. Passive probe sniffing + decoy AP active.");
}

void loop() {
  if (deepScanReq && !deepScanning) runDeepScan();
  if (applyDecoyReq) { applyDecoyReq = false; lastRotate = millis(); startDecoy(0); }

  dnsServer.processNextRequest();

  ProbeEvt e;
  while (xQueueReceive(probeQ, &e, 0) == pdTRUE) handleProbe(e);

  static unsigned long lastPoll = 0;
  if (millis() - lastPoll > 1500) { lastPoll = millis(); pollStations(); }

  // rotate the decoy SSID periodically, but only while nobody is connected
  if (millis() - lastRotate > ROTATE_MS && WiFi.softAPgetStationNum() == 0) {
    lastRotate = millis();
    startDecoy((decoyIdx + 1) % decoyCount);
  }

  static unsigned long lastDraw = 0;
  if (millis() - lastDraw > 120) { lastDraw = millis(); drawScreen(); }

  delay(5);
}
