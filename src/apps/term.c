// Terminal: a real Linux shell (busybox ash) on a pty, drawn by the vt emulator.
// The session keeps running while the app is closed (term_tick() drains the pty).
#define _GNU_SOURCE
#include "../ui.h"
#include "../vt.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static VT *vt;
static int mfd = -1;
static pid_t spid;
static int exited, exit_code;
static char errmsg[120];
static int kb_on = 1, ctrl_armed;
static float fs = 12.2f;                 // font size in logical px
static float view_off;                   // lines scrolled back (fractional while dragging)
static int last_sb;
static Gest g;
static Spring kb_y = { 1, 0, 1 };
static int tcols, trows;

static void reply_cb(void *ctx, const char *s, int n) {
    (void)ctx;
    if (mfd >= 0) { ssize_t r = write(mfd, s, n); (void)r; }
}

static void session_stop(void) {
    if (spid > 0) { kill(-spid, SIGHUP); kill(spid, SIGKILL); waitpid(spid, 0, 0); }
    spid = 0;
    if (mfd >= 0) close(mfd);
    mfd = -1;
}

static void session_start(int cols, int rows) {
    session_stop();
    exited = 0;
    errmsg[0] = 0;
    if (vt) vt_free(vt);
    vt = vt_new(cols, rows, 2000, reply_cb, 0);
    view_off = 0; last_sb = 0;
    int fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    char sn[64];
    if (fd < 0 || grantpt(fd) || unlockpt(fd) || ptsname_r(fd, sn, sizeof sn)) {
        snprintf(errmsg, sizeof errmsg, "cannot open a pty (%s). Is devpts mounted?", strerror(errno));
        if (fd >= 0) close(fd);
        exited = 1;
        return;
    }
    struct winsize ws = { (unsigned short)rows, (unsigned short)cols, 0, 0 };
    ioctl(fd, TIOCSWINSZ, &ws);
    mkdir("/data/home", 0700);
    const char *home = access("/data/home", W_OK) == 0 ? "/data/home" : "/";
    char homev[64], *env[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    snprintf(homev, sizeof homev, "HOME=%s", home);
    env[0] = homev;
    env[1] = "TERM=xterm-256color";
    env[2] = "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/data/bin";
    env[3] = "USER=root";
    env[4] = "LANG=C.UTF-8";
    env[5] = "LUMEN_APPS=/data/app";
    env[6] = "SHELL=/bin/sh";
    pid_t p = fork();
    if (p < 0) { snprintf(errmsg, sizeof errmsg, "fork failed: %s", strerror(errno)); close(fd); exited = 1; return; }
    if (p == 0) {
        setsid();
        int s = open(sn, O_RDWR);
        if (s < 0) _exit(127);
        ioctl(s, TIOCSCTTY, 0);
        dup2(s, 0); dup2(s, 1); dup2(s, 2);
        for (int i = 3; i < 1024; i++) close(i);
        signal(SIGPIPE, SIG_DFL);
        sigset_t all;
        sigemptyset(&all);
        sigprocmask(SIG_SETMASK, &all, 0);
        if (chdir(home)) { int r = chdir("/"); (void)r; }
        char *argv[] = { "-sh", 0 };
        execve("/bin/sh", argv, env);
        _exit(127);
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    mfd = fd;
    spid = p;
}

// drain the pty into the emulator; called every frame even when the app is closed
void term_tick(void) {
    if (mfd < 0 || !vt) return;
    unsigned char buf[8192];
    for (int rounds = 0; rounds < 16; rounds++) {
        ssize_t n = read(mfd, buf, sizeof buf);
        if (n > 0) vt_feed(vt, buf, (int)n);
        else {
            if (n < 0 && errno == EAGAIN) break;
            if (n == 0 || (n < 0 && errno != EINTR)) {      // EIO: the slave side closed
                int st = 0;
                if (spid > 0 && waitpid(spid, &st, WNOHANG) == spid) { exited = 1; exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st); spid = 0; }
                else if (spid > 0) kill(spid, SIGKILL);
                close(mfd); mfd = -1;
                exited = 1;
                break;
            }
        }
    }
    if (!exited && spid > 0) {
        int st = 0;
        if (waitpid(spid, &st, WNOHANG) == spid) { exited = 1; exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st); spid = 0; }
    }
    int sb = vt_sb_count(vt);
    if (view_off > 0 && sb > last_sb) view_off += sb - last_sb;   // keep the scrolled view steady
    if (view_off > sb) view_off = (float)sb;
    last_sb = sb;
}

static void send_bytes(const char *s, int n) {
    if (mfd < 0) return;
    while (n > 0) {
        ssize_t w = write(mfd, s, n);
        if (w < 0) { if (errno == EINTR) continue; if (errno == EAGAIN) { usleep(1000); continue; } break; }
        s += w; n -= (int)w;
    }
}

static void send_key(int k) {
    if (exited) {                               // any key restarts a dead session
        if (k == K_ENTER || k == ' ') session_start(tcols > 0 ? tcols : 50, trows > 0 ? trows : 30);
        return;
    }
    view_off = 0;
    char b[8];
    int n = 0;
    int app = vt ? vt_app_cursor(vt) : 0;
    if (ctrl_armed && k < 0x110000) {
        if (k >= 'a' && k <= 'z') k -= 96;
        else if (k >= 'A' && k <= 'Z') k -= 64;
        else if (k == '[') k = 27;
        else if (k == '\\') k = 28;
        else if (k == ']') k = 29;
        else if (k == ' ') k = 0;
        ctrl_armed = 0;
    }
    switch (k) {
    case K_ENTER: b[n++] = '\r'; break;
    case K_BACKSPACE: b[n++] = 0x7f; break;
    case K_TAB: b[n++] = '\t'; break;
    case K_ESC: b[n++] = 27; break;
    case K_UP: case K_DOWN: case K_RIGHT: case K_LEFT:
        b[n++] = 27; b[n++] = app ? 'O' : '[';
        b[n++] = k == K_UP ? 'A' : k == K_DOWN ? 'B' : k == K_RIGHT ? 'C' : 'D';
        break;
    case K_HOME: b[n++] = 27; b[n++] = '['; b[n++] = 'H'; break;
    case K_END: b[n++] = 27; b[n++] = '['; b[n++] = 'F'; break;
    case K_DEL: memcpy(b, "\033[3~", 4); n = 4; break;
    case K_PGUP: memcpy(b, "\033[5~", 4); n = 4; break;
    case K_PGDN: memcpy(b, "\033[6~", 4); n = 4; break;
    default:
        if (k >= 0x110000) return;
        if (k < 32) { b[n++] = (char)k; break; }           // already a control code (hardware Ctrl+x)
        n = utf8_put(b, k);
    }
    send_bytes(b, n);
}

static void open_(void) {
    if (!vt) session_start(50, 30);
    kb_y.t = kb_on ? 1 : 0;
}

#define EXTRA_N 11
static const struct { const char *label; int key; } EXTRA[EXTRA_N] = {
    { "esc", K_ESC }, { "tab", K_TAB }, { "ctrl", -1 }, { "←", K_LEFT }, { "↓", K_DOWN }, { "↑", K_UP }, { "→", K_RIGHT },
    { "|", '|' }, { "/", '/' }, { "-", '-' }, { "~", '~' },
};

static void draw(Canvas *c, float dt) {
    term_tick();
    spring_step(&kb_y, dt, 3.2f, 1.0f);
    float top = P(94);
    float kbt = SH - kb_height() * kb_y.x;
    float extra_h = P(40);
    float body_bottom = (kb_y.x > 0.01f ? kbt : SH - P(30)) - extra_h;
    float px = P(fs);
    float cw = text_w(WMONO, px, 0, "M"), lh = floorf(px * 1.3f);
    float pad = P(4);
    int cols = (int)((SW - 2 * pad) / cw), rows = (int)((body_bottom - top - pad) / lh);
    if (cols < 20) cols = 20;
    if (rows < 4) rows = 4;
    if (!vt) session_start(cols, rows);
    if ((cols != tcols || rows != trows) && vt) {
        tcols = cols; trows = rows;
        vt_resize(vt, cols, rows);
        if (mfd >= 0) { struct winsize ws = { (unsigned short)rows, (unsigned short)cols, 0, 0 }; ioctl(mfd, TIOCSWINSZ, &ws); }
    }

    g_clear(c, C_INK);
    // ---- cell grid ----
    int sc[4] = { c->cx0, c->cy0, c->cx1, c->cy1 };
    g_clip(c, 0, top, SW, body_bottom);
    int vo = (int)floorf(view_off + 0.5f);
    float ymid = top + pad;
    for (int r = 0; r < rows; r++) {
        const VCell *row = vt ? vt_row(vt, r - vo) : 0;
        if (!row) continue;
        float y = ymid + r * lh;
        int x = 0;
        int cx_ = vt_cursor_x(vt), cy_ = vt_cursor_y(vt) + vo;
        while (x < vt_cols(vt) && x < cols) {
            uint32_t fg = row[x].fg, bg = row[x].bg;
            uint8_t at = row[x].at;
            if (at & VA_REV) { uint32_t t = fg ? fg : C_PAPER; fg = bg ? bg : C_INK; bg = t; }
            int e = x + 1;
            while (e < cols && e < vt_cols(vt)) {
                uint32_t f2 = row[e].fg, b2 = row[e].bg;
                if (row[e].at != row[x].at || f2 != row[x].fg || b2 != row[x].bg) break;
                e++;
            }
            if (bg) g_rect(c, pad + x * cw, y, (e - x) * cw + 1, lh, bg);
            char buf[640];
            int o = 0, any = 0;
            for (int k = x; k < e && o < (int)sizeof buf - 5; k++) {
                uint32_t ch = row[k].ch ? row[k].ch : ' ';
                if (ch != ' ') any = 1;
                o += utf8_put(buf + o, (int)ch);
            }
            buf[o] = 0;
            if (any || (at & VA_UL)) {
                uint32_t col = fg ? fg : (at & VA_BOLD) ? 0xFFFFFFFFu : C_PAPER;
                if (at & VA_DIM) col = c_alpha(col, 0.6f);
                if (any) {
                    text(c, WMONO, px, 0, pad + x * cw, y + px * 0.98f, col, buf);
                    if (at & VA_BOLD) text(c, WMONO, px, 0, pad + x * cw + P(0.7f), y + px * 0.98f, col, buf);
                }
                if (at & VA_UL) g_rect(c, pad + x * cw, y + lh - P(2.5f), (e - x) * cw, P(1.3f), col);
            }
            (void)cx_; (void)cy_;
            x = e;
        }
    }
    // cursor
    if (vt && vo == 0 && !exited && vt_cursor_visible(vt) && fmod(now(), 1.0) < 0.62) {
        int cx = vt_cursor_x(vt), cy = vt_cursor_y(vt);
        const VCell *cell = vt_row(vt, cy);
        g_rect(c, pad + cx * cw, ymid + cy * lh, cw, lh, C_ORANGE);
        if (cell && cell[cx].ch > ' ') {
            char b[8];
            b[utf8_put(b, (int)cell[cx].ch)] = 0;
            text(c, WMONO, px, 0, pad + cx * cw, ymid + cy * lh + px * 0.98f, C_INK, b);
        }
    }
    if (vo > 0) {   // scrollback indicator
        char t[32];
        snprintf(t, sizeof t, "↑ %d lines back", vo);
        float w = text_w(WMONO, P(11), 0, t) + P(20);
        g_rrect(c, SW - w - P(10), top + P(8), w, P(28), P(14), P(14), C_ORANGE);
        text(c, WMONO, P(11), 0, SW - w, top + P(27), C_INK, t);
    }
    if (exited) {
        char t[200];
        if (errmsg[0]) snprintf(t, sizeof t, "%s", errmsg);
        else snprintf(t, sizeof t, "[session ended, exit %d] tap here or press Enter to restart", exit_code);
        float by = body_bottom - P(60);
        g_rrect(c, P(14), by, SW - P(28), P(48), P(14), P(14), C_ORANGE);
        text_c(c, W600, P(13), 0, SW / 2, by + P(29), C_INK, t);
        hit(0xD10, 0, top, SW, body_bottom - top);
    } else hit(0xD11, 0, top, SW, body_bottom - top);
    c->cx0 = sc[0]; c->cy0 = sc[1]; c->cx1 = sc[2]; c->cy1 = sc[3];

    // ---- extra key row ----
    float ey = body_bottom;
    g_rect(c, 0, ey, SW, extra_h, 0xFF1F1E1Cu);
    float kw = (SW - P(12)) / EXTRA_N;
    for (int i = 0; i < EXTRA_N; i++) {
        int id = 0x4C00 + i;
        bool on = EXTRA[i].key == -1 && ctrl_armed;
        bool pr = pressed(id);
        float x = P(6) + i * kw;
        g_rrect(c, x + P(2), ey + P(4), kw - P(4), extra_h - P(8), P(8), P(8), on || pr ? C_LIME : 0xFF2B2A28u);
        text_c(c, WMONO, P(13), 0, x + kw / 2, ey + extra_h / 2 + P(5), on || pr ? C_INK : C_PAPER, EXTRA[i].label);
        hit(id, x, ey, kw, extra_h);
    }
    // ---- header ----
    g_rect(c, 0, 0, SW, top, C_LILAC);
    status_line(c, 0, C_INK, true, false);
    text(c, W800, P(24), -0.03f, P(18), P(78), C_INK, "Terminal");
    char sz[16];
    snprintf(sz, sizeof sz, "%dx%d", tcols, trows);
    text(c, WMONO, P(10), 0, P(18), P(88), C_INK, sz);
    float bd = P(40), by = P(46);
    float bx = SW - P(14) - 4 * (bd + P(8));
    btn_text(c, 0xD01, bx, by, bd, bd, "A-", C_INK, 0);
    btn_text(c, 0xD02, bx + (bd + P(8)), by, bd, bd, "A+", C_INK, 0);
    btn_icon(c, 0xD03, bx + 2 * (bd + P(8)), by, bd, IC_KEYBOARD, C_INK, 0);
    btn_icon(c, 0xD04, bx + 3 * (bd + P(8)), by, bd, IC_REFRESH, C_INK, 0);
    if (kb_y.x > 0.01f) kb_draw(c, kbt, "return");
    else home_bar(c, C_PAPER);
}

static void touch(InputEv *e) {
    int r = gest(&g, e);
    if (r == G_DRAG_START || r == G_DRAG) {
        float lh = floorf(P(fs) * 1.3f);
        float dy = r == G_DRAG_START ? g.y - g.y0 : g.dy;
        if (g.vert && g.y0 < SH - kb_height() * kb_y.x - P(40) && vt && !vt_alt_screen(vt)) {
            view_off += dy / lh;
            if (view_off < 0) view_off = 0;
            if (view_off > vt_sb_count(vt)) view_off = (float)vt_sb_count(vt);
        } else if (g.vert && vt && vt_alt_screen(vt)) {          // full-screen apps: drag = arrow keys
            static float acc;
            acc += dy / lh;
            while (acc >= 1) { send_key(K_UP); acc -= 1; }
            while (acc <= -1) { send_key(K_DOWN); acc += 1; }
        }
    } else if (r == G_TAP) {
        int id = hit_at(e->x, e->y);
        if (kb_hit(id)) {
            int k = kb_tap(e->x, e->y);
            if (k) send_key(k);
        } else if (id >= 0x4C00 && id < 0x4C00 + EXTRA_N) {
            int k = EXTRA[id - 0x4C00].key;
            if (k == -1) ctrl_armed = !ctrl_armed;
            else send_key(k);
        } else if (id == 0xD01) { if (fs > 8) fs -= 1; }
        else if (id == 0xD02) { if (fs < 20) fs += 1; }
        else if (id == 0xD03) { kb_on = !kb_on; kb_y.t = kb_on; }
        else if (id == 0xD04) session_start(tcols > 0 ? tcols : 50, trows > 0 ? trows : 30);
        else if (id == 0xD10) session_start(tcols > 0 ? tcols : 50, trows > 0 ? trows : 30);
        else if (id == 0xD11) { if (!kb_on) { kb_on = 1; kb_y.t = 1; } }
    }
}

static void key(int k) { send_key(k); }

App app_term = { "Terminal", IC_TERM, open_, draw, touch, key, 0, true };
