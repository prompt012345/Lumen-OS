// Shield: privacy dashboard (tracker blocking, private DNS, MAC randomisation, HTTPS-only,
// lock-screen PIN, what is listening on the phone) + the numeric pad shared with the lock screen.
#include "../ui.h"
#include "../shield.h"
#include <stdio.h>
#include <string.h>

// ---- shared PIN pad ----------------------------------------------------------------------------
#define PAD_ID 0x4E00
void pinpad_draw(Canvas *c, float y) {
    static const char *L[12] = { "1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "" };
    float kw = P(96), kh = P(64), gx = P(14), gy = P(12);
    float x0 = (SW - (3 * kw + 2 * gx)) / 2;
    for (int i = 0; i < 12; i++) {
        float x = x0 + (i % 3) * (kw + gx), yy = y + (i / 3) * (kh + gy);
        int id = PAD_ID + i;
        bool pr = pressed(id);
        uint32_t fill = i == 11 ? C_ORANGE : 0xFF2B2A28u;
        g_rrect(c, x, yy, kw, kh, P(16), P(16), pr ? C_LIME : fill);
        uint32_t fg = pr || i == 11 ? C_INK : C_PAPER;
        if (i == 9) icon(c, IC_BKSP, x + kw / 2 - P(12), yy + kh / 2 - P(12), P(24), fg);
        else if (i == 11) icon(c, IC_CHECK, x + kw / 2 - P(12), yy + kh / 2 - P(12), P(24), fg);
        else text_c(c, W600, P(26), 0, x + kw / 2, yy + kh / 2 + P(9), fg, L[i]);
        hit(id, x, yy, kw, kh);
    }
}
int pinpad_tap(float x, float y) {
    int id = hit_at(x, y);
    if (id < PAD_ID || id >= PAD_ID + 12) return 0;
    int i = id - PAD_ID;
    if (i == 9) return K_BACKSPACE;
    if (i == 11) return K_ENTER;
    return i == 10 ? '0' : '1' + i;
}
void pin_dots(Canvas *c, float cy, int n, uint32_t col) {
    int total = n < 4 ? 4 : n;
    float gap = P(26), w = total * gap;
    for (int i = 0; i < total; i++) {
        float x = (SW - w) / 2 + gap / 2 + i * gap;
        if (i < n) g_circle(c, x, cy, P(7), col);
        else g_ring(c, x, cy, P(6.5f), P(1.6f), c_alpha(col, 0.45f));
    }
}

// ---- dashboard -----------------------------------------------------------------------------------
static Gest g;
static Scroll sc;
static int pin_step;            // 0 none, 1 enter new, 2 confirm, 3 enter current (to remove)
static char pin_a[16], pin_b[16], pin_msg[80];
static double ports_t;
static int ports[16], nports;

static void scan_ports(void) {
    if (now() - ports_t < 2.0) return;
    ports_t = now();
    nports = 0;
    const char *files[2] = { "/proc/net/tcp", "/proc/net/tcp6" };
    for (int f = 0; f < 2; f++) {
        FILE *fp = fopen(files[f], "r");
        if (!fp) continue;
        char line[256];
        if (!fgets(line, sizeof line, fp)) { fclose(fp); continue; }
        while (fgets(line, sizeof line, fp)) {
            unsigned port, st;
            char a[48];
            if (sscanf(line, " %*d: %47[0-9A-Fa-f]:%x %*[0-9A-Fa-f:] %x", a, &port, &st) == 3 && st == 0x0A && nports < 16) {
                int dup = 0;
                for (int i = 0; i < nports; i++) if (ports[i] == (int)port) dup = 1;
                if (!dup) ports[nports++] = (int)port;
            }
        }
        fclose(fp);
    }
}

static void open_(void) { sc = (Scroll){ 0 }; pin_step = 0; pin_msg[0] = 0; }

static float toggle(Canvas *c, float x, float y, bool on) {
    float w = P(52), h = P(30);
    g_rrect(c, x, y, w, h, h / 2, h / 2, on ? C_LIME : 0xFF3A3936u);
    g_circle(c, x + (on ? w - h / 2 : h / 2), y + h / 2, h / 2 - P(4), on ? C_INK : C_PAPER);
    return w;
}

static float row(Canvas *c, float y, int id, const char *title, const char *sub, int on, const char *val) {
    float h = P(74), x = P(14), w = SW - P(28);
    bool pr = pressed(id);
    g_rrect(c, x, y, w, h, P(18), P(18), pr ? 0xFF2F2E2Bu : 0xFF232220u);
    text(c, W600, P(17), 0, x + P(18), y + P(31), C_PAPER, title);
    if (sub) text(c, W400, P(12.5f), 0, x + P(18), y + P(54), C_MUTED, sub);
    if (on >= 0) toggle(c, x + w - P(70), y + (h - P(30)) / 2, on);
    else if (val) text_r(c, W600, P(14), 0, x + w - P(18), y + h / 2 + P(5), C_LIME, val);
    hit(id, x, y, w, h);
    return y + h + P(10);
}

static float section(Canvas *c, float y, const char *t) {
    text(c, W800, P(12), 0.08f, P(20), y + P(22), C_MUTED, t);
    return y + P(34);
}

static void draw_pin(Canvas *c) {
    g_clear(c, C_INK);
    g_rect(c, 0, 0, SW, P(94), C_LILAC);
    status_line(c, 0, C_INK, true, false);
    btn_icon(c, 0xE90, P(14), P(40), P(44), IC_BACK, C_INK, 0);
    text(c, W800, P(24), -0.03f, P(70), P(78), C_INK, "Lock-screen PIN");
    const char *t = pin_step == 1 ? "Choose a PIN (4–12 digits)" : pin_step == 2 ? "Enter it again" : "Enter current PIN to remove it";
    text_c(c, W800, P(24), -0.02f, SW / 2, P(200), C_PAPER, t);
    const char *cur = pin_step == 2 ? pin_b : pin_a;
    pin_dots(c, P(262), (int)strlen(cur), C_LIME);
    if (pin_msg[0]) text_c(c, W600, P(14), 0, SW / 2, P(310), C_ORANGE, pin_msg);
    pinpad_draw(c, P(360));
    text_c(c, W400, P(12), 0, SW / 2, P(690), C_MUTED, "The PIN gates the lock screen. Data on the disk is not encrypted.");
}

static void draw(Canvas *c, float dt) {
    if (pin_step) { draw_pin(c); home_bar(c, C_PAPER); return; }
    scan_ports();
    g_clear(c, C_INK);
    float top = P(94);
    float total = P(20) + P(158) + P(34) * 4 + 6 * P(84) + P(140) + P(110);
    sc.max = total - (SH - top - P(30));
    scroll_step(&sc, dt);
    int clip[4] = { c->cx0, c->cy0, c->cx1, c->cy1 };
    g_clip(c, 0, top, SW, SH);
    float y = top + P(16) - sc.pos;

    // score card
    long nb = shield_block_count();
    g_rrect(c, P(14), y, SW - P(28), P(150), P(22), P(22), C_LILAC);
    char big[32];
    snprintf(big, sizeof big, "%ld", nb);
    text(c, W800, P(64), -0.05f, P(30), y + P(78), C_INK, big);
    text(c, W600, P(15), 0, P(32), y + P(104), C_INK, shield_trackers_on() ? "trackers blocked since boot" : "tracker blocking is OFF");
    char sub[80];
    snprintf(sub, sizeof sub, "%d domains in the blocklist · edit /data/shield/custom.txt", shield_blocklist_size());
    text(c, W400, P(11.5f), 0, P(32), y + P(128), C_INK, sub);
    icon(c, IC_SHIELD, SW - P(98), y + P(28), P(64), C_INK);
    y += P(164);

    y = section(c, y, "NETWORK");
    y = row(c, y, 0xE01, "Block trackers", "DNS-level: ads, analytics, telemetry", shield_trackers_on(), 0);
    char dnsv[40];
    snprintf(dnsv, sizeof dnsv, "%s", shield_dns_name(shield_dns_choice()));
    y = row(c, y, 0xE02, "DNS server", "plain UDP for now. Tap to switch provider", -1, dnsv);
    y = row(c, y, 0xE03, "Random MAC address", "new hardware address each boot, no hostname sent", shield_mac_random(), 0);
    y = row(c, y, 0xE04, "HTTPS-only browsing", "http:// links are upgraded to https://", shield_https_only(), 0);
    y = row(c, y, 0xE05, "Weather on lock screen", "asks wttr.in from your IP. Off = no request", shield_weather_on(), 0);

    y = section(c, y, "DEVICE");
    y = row(c, y, 0xE06, "Lock-screen PIN", shield_pin_enabled() ? "enabled · 5 wrong tries = lockout (survives reboot)" : "swipe-up unlocks without a code", -1, shield_pin_enabled() ? "ON" : "OFF");

    y = section(c, y, "EXPOSURE");
    g_rrect(c, P(14), y, SW - P(28), P(110), P(18), P(18), 0xFF232220u);
    NetInfo ni;
    net_info(&ni);
    char l1[120];
    if (nports == 0) snprintf(l1, sizeof l1, "No TCP port is listening");
    else {
        int o = snprintf(l1, sizeof l1, "Listening TCP:");
        for (int i = 0; i < nports && o < 100; i++) o += snprintf(l1 + o, sizeof l1 - o, " %d", ports[i]);
    }
    text(c, W600, P(15), 0, P(32), y + P(32), nports ? C_ORANGE : C_LIME, l1);
    char l2[120];
    snprintf(l2, sizeof l2, "MAC %s%s", ni.mac[0] ? ni.mac : "—", ni.mac[0] && strlen(ni.mac) > 1 && (strtol(ni.mac, 0, 16) & 2) ? "  (locally administered)" : "");
    text(c, WMONO, P(11.5f), 0, P(32), y + P(58), C_PAPER, l2);
    char l3[120];
    snprintf(l3, sizeof l3, "DNS %s", shield_dns_override() ? shield_dns_override() : ni.dns[0] ? ni.dns : "—");
    text(c, WMONO, P(11.5f), 0, P(32), y + P(80), C_PAPER, l3);
    y += P(124);

    char rb[8][64];
    int nr = shield_recent_blocked(rb, 6);
    y = section(c, y, "RECENTLY BLOCKED");
    for (int i = 0; i < nr; i++) text(c, WMONO, P(12), 0, P(24), y + P(18) + i * P(22), C_PAPER, rb[i]);
    if (!nr) text(c, W400, P(13), 0, P(24), y + P(18), C_MUTED, "nothing yet");
    c->cx0 = clip[0]; c->cy0 = clip[1]; c->cx1 = clip[2]; c->cy1 = clip[3];

    g_rect(c, 0, 0, SW, top, C_LILAC);
    status_line(c, 0, C_INK, true, false);
    text(c, W800, P(34), -0.04f, P(18), P(80), C_INK, "Shield");
    home_bar(c, C_PAPER);
}

static void pin_key(int k) {
    char *buf = pin_step == 2 ? pin_b : pin_a;
    int n = (int)strlen(buf);
    if (k == K_BACKSPACE) { if (n) buf[n - 1] = 0; return; }
    if (k >= '0' && k <= '9') { if (n < 12) { buf[n] = (char)k; buf[n + 1] = 0; } pin_msg[0] = 0; return; }
    if (k != K_ENTER) return;
    if (pin_step == 1) {
        if (n < 4) { snprintf(pin_msg, sizeof pin_msg, "At least 4 digits"); return; }
        pin_step = 2; pin_b[0] = 0; pin_msg[0] = 0;
    } else if (pin_step == 2) {
        if (strcmp(pin_a, pin_b)) { snprintf(pin_msg, sizeof pin_msg, "They do not match, start again"); pin_step = 1; pin_a[0] = pin_b[0] = 0; return; }
        shield_pin_set(pin_a);
        pin_step = 0; pin_a[0] = pin_b[0] = 0;
        notify("Shield", "Lock-screen PIN enabled");
    } else if (pin_step == 3) {
        int rc = shield_pin_check(pin_a);
        if (rc == 0) { shield_pin_set(""); pin_step = 0; notify("Shield", "PIN removed"); }
        else { snprintf(pin_msg, sizeof pin_msg, rc == 2 ? "Locked out, wait %d s" : "Wrong PIN", shield_pin_lock_left()); }
        pin_a[0] = 0;
    }
}

static void touch(InputEv *e) {
    int r = gest(&g, e);
    if (pin_step) {
        if (r == G_TAP) {
            int id = hit_at(e->x, e->y);
            if (id == 0xE90) { pin_step = 0; pin_a[0] = pin_b[0] = 0; return; }
            int k = pinpad_tap(e->x, e->y);
            if (k) pin_key(k);
        }
        return;
    }
    if (r == G_DRAG_START || r == G_DRAG) { if (g.vert) scroll_drag(&sc, r == G_DRAG_START ? g.y - g.y0 : g.dy); }
    else if (r == G_DRAG_END) { if (sc.held) scroll_fling(&sc, g.vy); }
    else if (r == G_TAP) {
        int id = hit_at(e->x, e->y);
        switch (id) {
        case 0xE01: shield_set("trackers", !shield_trackers_on()); break;
        case 0xE02: shield_set("dns", (shield_dns_choice() + 1) & 3); notify("Shield", "DNS changes apply to new lookups"); break;
        case 0xE03: shield_set("mac", !shield_mac_random()); notify("Shield", "MAC change applies at next boot"); break;
        case 0xE04: shield_set("https", !shield_https_only()); break;
        case 0xE05: shield_set("weather", !shield_weather_on()); break;
        case 0xE06: pin_step = shield_pin_enabled() ? 3 : 1; pin_a[0] = pin_b[0] = pin_msg[0] = 0; break;
        }
    }
}

static void key(int k) {
    if (pin_step && ((k >= '0' && k <= '9') || k == K_BACKSPACE || k == K_ENTER)) pin_key(k);
}

App app_shield = { "Shield", IC_SHIELD, open_, draw, touch, key, 0, false };
