// shield: see shield.h
#define _GNU_SOURCE
#include "ui.h"
#include "shield.h"
#include <bearssl.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile int f_trackers = 1, f_mac = 1, f_https = 1, f_weather = 0, f_dns = 0;

static const char *DNS_NAMES[4] = { "Network (DHCP)", "Quad9 9.9.9.9", "Cloudflare 1.1.1.1", "Mullvad 194.242.2.2" };
static const char *DNS_IPS[4] = { 0, "9.9.9.9", "1.1.1.1", "194.242.2.2" };

bool shield_trackers_on(void) { return f_trackers; }
bool shield_mac_random(void) { return f_mac; }
bool shield_https_only(void) { return f_https; }
bool shield_weather_on(void) { return f_weather; }
int shield_dns_choice(void) { return f_dns; }
const char *shield_dns_name(int c) { return DNS_NAMES[c & 3]; }
const char *shield_dns_override(void) { return DNS_IPS[f_dns & 3]; }

void shield_set(const char *w, int v) {
    if (!strcmp(w, "trackers")) { f_trackers = v; store_seti("sh.trackers", v); }
    else if (!strcmp(w, "mac")) { f_mac = v; store_seti("sh.mac", v); }
    else if (!strcmp(w, "https")) { f_https = v; store_seti("sh.https", v); }
    else if (!strcmp(w, "weather")) { f_weather = v; store_seti("sh.weather", v); }
    else if (!strcmp(w, "dns")) { f_dns = v & 3; store_seti("sh.dns", f_dns); }
}

// ---- blocklist ----------------------------------------------------------------------------------
static const char *BUILTIN[] = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com", "googletagmanager.com",
    "googletagservices.com", "app-measurement.com", "crashlytics.com", "adservice.google.com", "2mdn.net", "adnxs.com",
    "adsrvr.org", "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "scorecardresearch.com", "quantserve.com",
    "hotjar.com", "mixpanel.com", "segment.io", "amplitude.com", "appsflyer.com", "adjust.com", "flurry.com", "mopub.com",
    "applovin.com", "vungle.com", "chartboost.com", "inmobi.com", "ironsrc.com", "supersonicads.com", "tapjoy.com",
    "moatads.com", "adform.net", "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com", "amazon-adsystem.com",
    "advertising.com", "yieldmo.com", "smartadserver.com", "clarity.ms", "ads-twitter.com", "ads.tiktok.com",
    "analytics.tiktok.com", "log.byteoversea.com", "an.facebook.com", "pixel.facebook.com", "vortex.data.microsoft.com",
    "watson.telemetry.microsoft.com", "settings-win.data.microsoft.com", "mc.yandex.ru", "an.yandex.ru", "appmetrica.yandex.com",
    "hm.baidu.com", "umeng.com", "fullstory.com", "mouseflow.com", "luckyorange.com", "nr-data.net", "optimizely.com",
    "braze.com", "appboy.com", "kochava.com", "singular.net", "adcolony.com", "startapp.com", "smaato.net", "pangleglobal.com",
    "ad.doubleclick.net", "pagead2.googlesyndication.com", "stats.g.doubleclick.net", "bat.bing.com", "ads.linkedin.com",
    "analytics.google.com", "ssl.google-analytics.com", "unityads.unity3d.com", "config.uca.cloud.unity3d.com",
    "tracking.miui.com", "data.mistat.xiaomi.com", "iot-eu-logser.realme.com", "samsung-com.112.2o7.net",
    "metrics.icloud.com", "iadsdk.apple.com", "adtrafficquality.google", "sentry.io", "bugsnag.com", "ads.yahoo.com",
    "analytics.yahoo.com", "geo.yahoo.com", "bidswitch.net", "3lift.com", "sharethrough.com", "indexww.com", "lijit.com",
    "mathtag.com", "bluekai.com", "demdex.net", "everesttech.net", "krxd.net", "exelator.com", "agkn.com", "rlcdn.com",
    "tapad.com", "liveramp.com", "id5-sync.com", "adsymptotic.com", 0,
};

typedef struct { char **slot; unsigned cap; int n; } Set;
static Set cur;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long nblocked;
static char recent[8][64];
static int nrecent, rhead;
static time_t custom_mtime;

static unsigned hash_s(const char *s, size_t n) {
    unsigned h = 2166136261u;
    for (size_t i = 0; i < n; i++) h = (h ^ (unsigned char)s[i]) * 16777619u;
    return h;
}
static void set_add(Set *s, const char *d, size_t n) {
    if (s->n * 2 >= (int)s->cap) {
        unsigned nc = s->cap ? s->cap * 2 : 1024;
        char **ns = calloc(nc, sizeof *ns);
        for (unsigned i = 0; i < s->cap; i++) if (s->slot[i]) {
            unsigned h = hash_s(s->slot[i], strlen(s->slot[i])) & (nc - 1);
            while (ns[h]) h = (h + 1) & (nc - 1);
            ns[h] = s->slot[i];
        }
        free(s->slot);
        s->slot = ns; s->cap = nc;
    }
    unsigned h = hash_s(d, n) & (s->cap - 1);
    while (s->slot[h]) {
        if (strlen(s->slot[h]) == n && !memcmp(s->slot[h], d, n)) return;
        h = (h + 1) & (s->cap - 1);
    }
    s->slot[h] = strndup(d, n);
    s->n++;
}
static bool set_has(const Set *s, const char *d, size_t n) {
    if (!s->cap) return false;
    unsigned h = hash_s(d, n) & (s->cap - 1);
    while (s->slot[h]) {
        if (strlen(s->slot[h]) == n && !memcmp(s->slot[h], d, n)) return true;
        h = (h + 1) & (s->cap - 1);
    }
    return false;
}
static void set_free(Set *s) {
    for (unsigned i = 0; i < s->cap; i++) free(s->slot[i]);
    free(s->slot);
    memset(s, 0, sizeof *s);
}

static void load_custom(Set *s) {
    FILE *f = fopen("/data/shield/custom.txt", "r");
    if (!f) return;
    char line[300];
    while (fgets(line, sizeof line, f) && s->n < 400000) {
        char *p = line;
        char *hash = strchr(p, '#');
        if (hash) *hash = 0;
        while (isspace((unsigned char)*p)) p++;
        // hosts format: "0.0.0.0 domain" / "127.0.0.1 domain"
        if (isdigit((unsigned char)*p)) {
            char *sp = p;
            while (*sp && !isspace((unsigned char)*sp)) sp++;
            p = sp;
            while (isspace((unsigned char)*p)) p++;
        }
        char *e = p;
        while (*e && !isspace((unsigned char)*e)) { *e = tolower((unsigned char)*e); e++; }
        if (e - p >= 4 && memchr(p, '.', e - p)) set_add(s, p, e - p);
    }
    fclose(f);
}

void shield_reload(void) {
    Set n = {0};
    for (int i = 0; BUILTIN[i]; i++) set_add(&n, BUILTIN[i], strlen(BUILTIN[i]));
    load_custom(&n);
    struct stat st;
    pthread_mutex_lock(&mu);
    Set old = cur;
    cur = n;
    custom_mtime = stat("/data/shield/custom.txt", &st) ? 0 : st.st_mtime;
    pthread_mutex_unlock(&mu);
    set_free(&old);
}

void shield_init(void) {
    f_trackers = store_geti("sh.trackers", 1);
    f_mac = store_geti("sh.mac", 1);
    f_https = store_geti("sh.https", 1);
    f_weather = store_geti("sh.weather", 0);     // privacy first: the lock-screen weather asks the internet, off by default
    f_dns = store_geti("sh.dns", 0) & 3;
    mkdir("/data/shield", 0755);
    shield_reload();
}

bool shield_blocked_host(const char *host) {
    if (!f_trackers || !host || !*host) return false;
    char h[256];
    size_t n = strlen(host);
    if (n >= sizeof h) return false;
    for (size_t i = 0; i < n; i++) h[i] = tolower((unsigned char)host[i]);
    h[n] = 0;
    while (n && h[n - 1] == '.') h[--n] = 0;
    bool hit = false;
    pthread_mutex_lock(&mu);
    // pick up edits to the custom list (cheap stat, at most once per lookup burst)
    static time_t last_check;
    time_t t = time(0);
    if (t != last_check) {
        last_check = t;
        struct stat st;
        time_t m = stat("/data/shield/custom.txt", &st) ? 0 : st.st_mtime;
        if (m != custom_mtime) {
            pthread_mutex_unlock(&mu);
            shield_reload();
            pthread_mutex_lock(&mu);
        }
    }
    for (size_t i = 0; i < n && !hit; i++) {
        if (i == 0 || h[i - 1] == '.') {
            if (strchr(h + i, '.') && set_has(&cur, h + i, n - i)) hit = true;
        }
    }
    if (hit) {
        nblocked++;
        snprintf(recent[rhead], sizeof recent[0], "%s", h);
        rhead = (rhead + 1) % 8;
        if (nrecent < 8) nrecent++;
    }
    pthread_mutex_unlock(&mu);
    return hit;
}
long shield_block_count(void) { return nblocked; }
int shield_blocklist_size(void) { pthread_mutex_lock(&mu); int n = cur.n; pthread_mutex_unlock(&mu); return n; }
int shield_recent_blocked(char out[][64], int max) {
    pthread_mutex_lock(&mu);
    int n = nrecent < max ? nrecent : max;
    for (int i = 0; i < n; i++) snprintf(out[i], 64, "%s", recent[((rhead - 1 - i) % 8 + 8) % 8]);
    pthread_mutex_unlock(&mu);
    return n;
}

char *shield_upgrade_url(const char *url) {
    if (!f_https || strncasecmp(url, "http://", 7)) return 0;
    const char *h = url + 7;
    // local / private hosts cannot present a public certificate: leave them alone
    if (!strncmp(h, "localhost", 9) || !strncmp(h, "127.", 4) || !strncmp(h, "10.", 3) || !strncmp(h, "192.168.", 8) || !strncmp(h, "172.16.", 7))
        return 0;
    return strfmt("https://%s", h);
}

// ---- PIN ----------------------------------------------------------------------------------------------
static void pin_hash(const unsigned char salt[16], const char *pin, unsigned char out[32]) {
    br_sha256_context c;
    br_sha256_init(&c);
    br_sha256_update(&c, salt, 16);
    br_sha256_update(&c, pin, strlen(pin));
    br_sha256_out(&c, out);
    for (int i = 0; i < 40000; i++) {
        br_sha256_init(&c);
        br_sha256_update(&c, out, 32);
        br_sha256_update(&c, salt, 16);
        br_sha256_update(&c, pin, strlen(pin));
        br_sha256_out(&c, out);
    }
}
static void to_hex(const unsigned char *b, int n, char *o) { for (int i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", b[i]); }
static int from_hex(const char *s, unsigned char *b, int n) {
    for (int i = 0; i < n; i++) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1; b[i] = (unsigned char)v; }
    return 0;
}

bool shield_pin_enabled(void) { const char *p = store_get("sh.pin"); return p && strlen(p) == 32 + 1 + 64; }

int shield_pin_lock_left(void) {
    long until = store_geti("sh.pinl", 0);
    long left = until - (long)time(0);
    return left > 0 ? (int)left : 0;
}

int shield_pin_check(const char *pin) {
    if (!shield_pin_enabled()) return 0;
    if (shield_pin_lock_left() > 0) return 2;
    const char *s = store_get("sh.pin");
    unsigned char salt[16], want[32], got[32];
    if (from_hex(s, salt, 16) || from_hex(s + 33, want, 32)) return 1;
    pin_hash(salt, pin, got);
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) diff |= got[i] ^ want[i];
    if (!diff) { store_seti("sh.pinf", 0); return 0; }
    int fails = store_geti("sh.pinf", 0) + 1;
    store_seti("sh.pinf", fails);                       // persisted: rebooting does not reset the counter
    if (fails >= 5) {
        int shift = fails - 5 > 6 ? 6 : fails - 5;
        store_seti("sh.pinl", (int)time(0) + 30 * (1 << shift));
        return 2;
    }
    return 1;
}

bool shield_pin_set(const char *pin) {
    if (!*pin) { store_set("sh.pin", ""); store_seti("sh.pinf", 0); store_seti("sh.pinl", 0); return true; }
    size_t n = strlen(pin);
    if (n < 4 || n > 12) return false;
    for (size_t i = 0; i < n; i++) if (!isdigit((unsigned char)pin[i])) return false;
    unsigned char salt[16], h[32];
    getentropy(salt, 16);
    pin_hash(salt, pin, h);
    char v[100];
    to_hex(salt, 16, v);
    v[32] = '$';
    to_hex(h, 32, v + 33);
    store_set("sh.pin", v);
    store_seti("sh.pinf", 0);
    store_seti("sh.pinl", 0);
    return true;
}
