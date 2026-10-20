// vt: see vt.h
#include "vt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { S_GROUND, S_ESC, S_CSI, S_OSC, S_CHARSET, S_STR };

struct VT {
    int cols, rows;
    VCell *scr, *main_saved;
    int alt;
    int cx, cy, wrap_pending;
    int scx, scy;                       // DECSC
    uint32_t sfg, sbg; uint8_t sat;
    int top, bot;
    uint32_t fg, bg; uint8_t at;
    int st, params[16], np, have, semi, priv;
    int esc_in_str;
    uint32_t cp; int need;
    int g0_graphics;
    int autowrap, cursor_vis, app_cursor, irm;
    // scrollback ring
    VCell *sb; int sbcap, sbn, sbhead;
    VTReply reply; void *ctx;
};

static const uint32_t ANSI16[16] = {
    0xFF1B1B1B, 0xFFFF5C4D, 0xFF8FD14F, 0xFFFFD84D, 0xFF5AA9FF, 0xFFC8B8FF, 0xFF4FD6C8, 0xFFE4E0D6,
    0xFF6B6860, 0xFFFF8A7A, 0xFFDFFF5E, 0xFFFFE98A, 0xFF7FD4FF, 0xFFE0D6FF, 0xFF8FF0E4, 0xFFFFFFFF,
};
uint32_t vt_palette(int i) {
    if (i < 16) return ANSI16[i < 0 ? 0 : i];
    if (i < 232) {
        int c = i - 16, r = c / 36, g = c / 6 % 6, b = c % 6;
        static const int L[6] = { 0, 95, 135, 175, 215, 255 };
        return 0xFF000000u | L[r] << 16 | L[g] << 8 | L[b];
    }
    int v = 8 + (i - 232) * 10;
    if (v > 255) v = 255;
    return 0xFF000000u | v << 16 | v << 8 | v;
}

static VCell blank(const VT *v) { return (VCell){ ' ', 0, v->bg, 0 }; }

static void clear_cells(VT *v, VCell *p, int n) {
    VCell b = blank(v);
    for (int i = 0; i < n; i++) p[i] = b;
}

VT *vt_new(int cols, int rows, int sb, VTReply reply, void *ctx) {
    VT *v = calloc(1, sizeof *v);
    v->cols = cols; v->rows = rows;
    v->scr = calloc((size_t)cols * rows, sizeof(VCell));
    v->top = 0; v->bot = rows - 1;
    v->autowrap = 1; v->cursor_vis = 1;
    v->reply = reply; v->ctx = ctx;
    v->sbcap = sb;
    if (sb) v->sb = calloc((size_t)sb * cols, sizeof(VCell));
    clear_cells(v, v->scr, cols * rows);
    return v;
}
void vt_free(VT *v) {
    if (!v) return;
    free(v->scr); free(v->main_saved); free(v->sb); free(v);
}

int vt_cols(const VT *v) { return v->cols; }
int vt_rows(const VT *v) { return v->rows; }
int vt_cursor_x(const VT *v) { return v->cx; }
int vt_cursor_y(const VT *v) { return v->cy; }
int vt_cursor_visible(const VT *v) { return v->cursor_vis; }
int vt_app_cursor(const VT *v) { return v->app_cursor; }
int vt_alt_screen(const VT *v) { return v->alt; }
int vt_sb_count(const VT *v) { return v->alt ? 0 : v->sbn; }

const VCell *vt_row(const VT *v, int r) {
    if (r >= 0) return r < v->rows ? v->scr + (size_t)r * v->cols : 0;
    int k = -r;                          // 1 = newest
    if (v->alt || k > v->sbn) return 0;
    int idx = ((v->sbhead - k) % v->sbcap + v->sbcap) % v->sbcap;
    return v->sb + (size_t)idx * v->cols;
}

static void push_sb(VT *v, const VCell *line) {
    if (!v->sb || v->alt) return;
    memcpy(v->sb + (size_t)v->sbhead * v->cols, line, sizeof(VCell) * v->cols);
    v->sbhead = (v->sbhead + 1) % v->sbcap;
    if (v->sbn < v->sbcap) v->sbn++;
}

static void scroll_up(VT *v, int n) {      // within the scroll region
    int h = v->bot - v->top + 1;
    if (n > h) n = h;
    for (int i = 0; i < n; i++) if (v->top == 0) push_sb(v, v->scr + (size_t)i * v->cols);
    memmove(v->scr + (size_t)v->top * v->cols, v->scr + (size_t)(v->top + n) * v->cols, sizeof(VCell) * v->cols * (h - n));
    clear_cells(v, v->scr + (size_t)(v->bot - n + 1) * v->cols, n * v->cols);
}
static void scroll_down(VT *v, int n) {
    int h = v->bot - v->top + 1;
    if (n > h) n = h;
    memmove(v->scr + (size_t)(v->top + n) * v->cols, v->scr + (size_t)v->top * v->cols, sizeof(VCell) * v->cols * (h - n));
    clear_cells(v, v->scr + (size_t)v->top * v->cols, n * v->cols);
}

void vt_resize(VT *v, int cols, int rows) {
    if (cols < 2) cols = 2;
    if (rows < 2) rows = 2;
    if (cols == v->cols && rows == v->rows) return;
    VCell *n = calloc((size_t)cols * rows, sizeof(VCell));
    VT tmp = *v;
    tmp.cols = cols; tmp.rows = rows;
    clear_cells(&tmp, n, cols * rows);
    // keep the bottom of the screen visible: lines pushed off the top go to scrollback
    int shift = 0;
    if (v->cy >= rows) shift = v->cy - rows + 1;
    for (int r = 0; r < shift && !v->alt; r++) {
        if (cols == v->cols) push_sb(v, v->scr + (size_t)r * v->cols);
    }
    for (int r = 0; r < rows && r + shift < v->rows; r++)
        memcpy(n + (size_t)r * cols, v->scr + (size_t)(r + shift) * v->cols, sizeof(VCell) * (cols < v->cols ? cols : v->cols));
    if (cols != v->cols) {                // no reflow: drop history rather than show torn lines
        free(v->sb);
        v->sb = v->sbcap ? calloc((size_t)v->sbcap * cols, sizeof(VCell)) : 0;
        v->sbn = v->sbhead = 0;
    }
    free(v->scr);
    if (v->main_saved) {                  // alt screen active: keep the saved main screen alive at the new size
        VCell *m = calloc((size_t)cols * rows, sizeof(VCell));
        clear_cells(&tmp, m, cols * rows);
        for (int r = 0; r < rows && r < v->rows; r++)
            memcpy(m + (size_t)r * cols, v->main_saved + (size_t)r * v->cols, sizeof(VCell) * (cols < v->cols ? cols : v->cols));
        free(v->main_saved);
        v->main_saved = m;
    }
    v->scr = n;
    v->cols = cols; v->rows = rows;
    v->cy -= shift;
    if (v->cy < 0) v->cy = 0;
    if (v->cx >= cols) v->cx = cols - 1;
    v->top = 0; v->bot = rows - 1;
    v->wrap_pending = 0;
}

static void reply(VT *v, const char *s) { if (v->reply) v->reply(v->ctx, s, (int)strlen(s)); }

static void newline(VT *v) {
    if (v->cy == v->bot) scroll_up(v, 1);
    else if (v->cy < v->rows - 1) v->cy++;
}

static uint32_t gfx(uint32_t c) {
    switch (c) {
    case 'j': return 0x2518; case 'k': return 0x2510; case 'l': return 0x250C; case 'm': return 0x2514;
    case 'n': return 0x253C; case 'q': return 0x2500; case 't': return 0x251C; case 'u': return 0x2524;
    case 'v': return 0x2534; case 'w': return 0x252C; case 'x': return 0x2502; case 'a': return 0x2592;
    case '`': return 0x25C6; case 'f': return 0x00B0; case 'g': return 0x00B1; case '~': return 0x00B7;
    }
    return c;
}

static void put_char(VT *v, uint32_t c) {
    if (v->g0_graphics) c = gfx(c);
    if (v->wrap_pending) {
        if (v->autowrap) { v->cx = 0; newline(v); }
        v->wrap_pending = 0;
    }
    if (v->irm) {
        VCell *row = v->scr + (size_t)v->cy * v->cols;
        memmove(row + v->cx + 1, row + v->cx, sizeof(VCell) * (v->cols - v->cx - 1));
    }
    VCell *p = v->scr + (size_t)v->cy * v->cols + v->cx;
    p->ch = c; p->fg = v->fg; p->bg = v->bg; p->at = v->at;
    if (v->cx == v->cols - 1) v->wrap_pending = 1;
    else v->cx++;
}

static int P(const VT *v, int i, int def) { return i < v->np && v->params[i] > 0 ? v->params[i] : def; }
static void goto_xy(VT *v, int x, int y) {
    v->cx = x < 0 ? 0 : x >= v->cols ? v->cols - 1 : x;
    v->cy = y < 0 ? 0 : y >= v->rows ? v->rows - 1 : y;
    v->wrap_pending = 0;
}

static void sgr(VT *v) {
    if (!v->np) { v->fg = v->bg = 0; v->at = 0; return; }
    for (int i = 0; i < v->np; i++) {
        int p = v->params[i];
        if (p == 0) { v->fg = v->bg = 0; v->at = 0; }
        else if (p == 1) v->at |= VA_BOLD;
        else if (p == 2) v->at |= VA_DIM;
        else if (p == 3) v->at |= VA_ITALIC;
        else if (p == 4) v->at |= VA_UL;
        else if (p == 7) v->at |= VA_REV;
        else if (p == 22) v->at &= ~(VA_BOLD | VA_DIM);
        else if (p == 23) v->at &= ~VA_ITALIC;
        else if (p == 24) v->at &= ~VA_UL;
        else if (p == 27) v->at &= ~VA_REV;
        else if (p >= 30 && p <= 37) v->fg = vt_palette(p - 30);
        else if (p >= 90 && p <= 97) v->fg = vt_palette(p - 90 + 8);
        else if (p >= 40 && p <= 47) v->bg = vt_palette(p - 40);
        else if (p >= 100 && p <= 107) v->bg = vt_palette(p - 100 + 8);
        else if (p == 39) v->fg = 0;
        else if (p == 49) v->bg = 0;
        else if (p == 38 || p == 48) {
            uint32_t col = 0;
            if (i + 2 < v->np && v->params[i + 1] == 5) { col = vt_palette(v->params[i + 2] & 255); i += 2; }
            else if (i + 4 < v->np && v->params[i + 1] == 2) {
                col = 0xFF000000u | (v->params[i + 2] & 255) << 16 | (v->params[i + 3] & 255) << 8 | (v->params[i + 4] & 255);
                i += 4;
            } else break;
            if (p == 38) v->fg = col; else v->bg = col;
        }
    }
}

static void set_alt(VT *v, int on) {
    if (on == v->alt) return;
    if (on) {
        v->main_saved = v->scr;
        v->scr = calloc((size_t)v->cols * v->rows, sizeof(VCell));
        clear_cells(v, v->scr, v->cols * v->rows);
        v->alt = 1;
        v->scx = v->cx; v->scy = v->cy;
    } else {
        free(v->scr);
        v->scr = v->main_saved;
        v->main_saved = 0;
        v->alt = 0;
        if (!v->scr) { v->scr = calloc((size_t)v->cols * v->rows, sizeof(VCell)); clear_cells(v, v->scr, v->cols * v->rows); }
        goto_xy(v, v->scx, v->scy);
    }
    v->top = 0; v->bot = v->rows - 1;
}

static void erase_range(VT *v, int y0, int x0, int y1, int x1) {   // inclusive-exclusive on the end
    for (int y = y0; y <= y1; y++) {
        int a = y == y0 ? x0 : 0, b = y == y1 ? x1 : v->cols;
        if (b > v->cols) b = v->cols;
        if (a < b) clear_cells(v, v->scr + (size_t)y * v->cols + a, b - a);
    }
}

static void csi(VT *v, int c) {
    char b[32];
    if (v->priv == '?' && (c == 'h' || c == 'l')) {
        int on = c == 'h';
        for (int i = 0; i < v->np; i++) {
            int m = v->params[i];
            if (m == 25) v->cursor_vis = on;
            else if (m == 1) v->app_cursor = on;
            else if (m == 7) v->autowrap = on;
            else if (m == 1049 || m == 1047 || m == 47) set_alt(v, on);
        }
        return;
    }
    if (v->priv) {
        if (v->priv == '>' && c == 'c') reply(v, "\033[>0;0;0c");
        return;
    }
    switch (c) {
    case 'A': goto_xy(v, v->cx, v->cy - P(v, 0, 1)); break;
    case 'B': case 'e': goto_xy(v, v->cx, v->cy + P(v, 0, 1)); break;
    case 'C': case 'a': goto_xy(v, v->cx + P(v, 0, 1), v->cy); break;
    case 'D': goto_xy(v, v->cx - P(v, 0, 1), v->cy); break;
    case 'E': goto_xy(v, 0, v->cy + P(v, 0, 1)); break;
    case 'F': goto_xy(v, 0, v->cy - P(v, 0, 1)); break;
    case 'G': case '`': goto_xy(v, P(v, 0, 1) - 1, v->cy); break;
    case 'd': goto_xy(v, v->cx, P(v, 0, 1) - 1); break;
    case 'H': case 'f': goto_xy(v, P(v, 1, 1) - 1, P(v, 0, 1) - 1); break;
    case 'J': {
        int m = v->np ? v->params[0] : 0;
        if (m == 0) erase_range(v, v->cy, v->cx, v->rows - 1, v->cols);
        else if (m == 1) erase_range(v, 0, 0, v->cy, v->cx + 1);
        else if (m == 2 || m == 3) {
            erase_range(v, 0, 0, v->rows - 1, v->cols);
            if (m == 3) v->sbn = 0;
        }
        break;
    }
    case 'K': {
        int m = v->np ? v->params[0] : 0;
        if (m == 0) erase_range(v, v->cy, v->cx, v->cy, v->cols);
        else if (m == 1) erase_range(v, v->cy, 0, v->cy, v->cx + 1);
        else if (m == 2) erase_range(v, v->cy, 0, v->cy, v->cols);
        break;
    }
    case 'L': if (v->cy >= v->top && v->cy <= v->bot) { int t = v->top; v->top = v->cy; scroll_down(v, P(v, 0, 1)); v->top = t; } break;
    case 'M': if (v->cy >= v->top && v->cy <= v->bot) { int t = v->top; v->top = v->cy; scroll_up(v, P(v, 0, 1)); v->top = t; } break;
    case 'P': {
        int n = P(v, 0, 1);
        if (n > v->cols - v->cx) n = v->cols - v->cx;
        VCell *row = v->scr + (size_t)v->cy * v->cols;
        memmove(row + v->cx, row + v->cx + n, sizeof(VCell) * (v->cols - v->cx - n));
        clear_cells(v, row + v->cols - n, n);
        break;
    }
    case '@': {
        int n = P(v, 0, 1);
        if (n > v->cols - v->cx) n = v->cols - v->cx;
        VCell *row = v->scr + (size_t)v->cy * v->cols;
        memmove(row + v->cx + n, row + v->cx, sizeof(VCell) * (v->cols - v->cx - n));
        clear_cells(v, row + v->cx, n);
        break;
    }
    case 'X': {
        int n = P(v, 0, 1);
        if (n > v->cols - v->cx) n = v->cols - v->cx;
        clear_cells(v, v->scr + (size_t)v->cy * v->cols + v->cx, n);
        break;
    }
    case 'S': scroll_up(v, P(v, 0, 1)); break;
    case 'T': scroll_down(v, P(v, 0, 1)); break;
    case 'm': sgr(v); break;
    case 'r': {
        int t = P(v, 0, 1) - 1, bt = P(v, 1, v->rows) - 1;
        if (t < 0) t = 0;
        if (bt >= v->rows) bt = v->rows - 1;
        if (t < bt) { v->top = t; v->bot = bt; }
        goto_xy(v, 0, 0);
        break;
    }
    case 's': v->scx = v->cx; v->scy = v->cy; break;
    case 'u': goto_xy(v, v->scx, v->scy); break;
    case 'h': if (v->np && v->params[0] == 4) v->irm = 1; break;
    case 'l': if (v->np && v->params[0] == 4) v->irm = 0; break;
    case 'n':
        if (v->np && v->params[0] == 6) { snprintf(b, sizeof b, "\033[%d;%dR", v->cy + 1, v->cx + 1); reply(v, b); }
        else if (v->np && v->params[0] == 5) reply(v, "\033[0n");
        break;
    case 'c': reply(v, "\033[?62;c"); break;
    default: break;
    }
}

static void esc_final(VT *v, int c) {
    switch (c) {
    case '7': v->scx = v->cx; v->scy = v->cy; v->sfg = v->fg; v->sbg = v->bg; v->sat = v->at; break;
    case '8': goto_xy(v, v->scx, v->scy); v->fg = v->sfg; v->bg = v->sbg; v->at = v->sat; break;
    case 'D': newline(v); break;
    case 'E': v->cx = 0; newline(v); break;
    case 'M': if (v->cy == v->top) scroll_down(v, 1); else if (v->cy > 0) v->cy--; break;
    case 'c': {
        set_alt(v, 0);
        v->fg = v->bg = 0; v->at = 0; v->top = 0; v->bot = v->rows - 1;
        erase_range(v, 0, 0, v->rows - 1, v->cols);
        goto_xy(v, 0, 0);
        v->autowrap = 1; v->cursor_vis = 1; v->app_cursor = 0; v->g0_graphics = 0; v->irm = 0;
        break;
    }
    default: break;
    }
}

void vt_feed(VT *v, const unsigned char *d, int n) {
    for (int i = 0; i < n; i++) {
        unsigned c = d[i];
        if (v->st == S_OSC || v->st == S_STR) {
            if (c == 7) v->st = S_GROUND;
            else if (c == 0x1b) v->esc_in_str = 1;
            else if (v->esc_in_str) { v->esc_in_str = 0; if (c == '\\') v->st = S_GROUND; }
            continue;
        }
        if (c == 0x1b) { v->st = S_ESC; v->need = 0; continue; }
        if (v->st == S_GROUND) {
            if (c < 0x20) {
                switch (c) {
                case '\n': case 0x0b: case 0x0c: newline(v); v->wrap_pending = 0; break;
                case '\r': v->cx = 0; v->wrap_pending = 0; break;
                case '\b': if (v->cx > 0) v->cx--; v->wrap_pending = 0; break;
                case '\t': { int x = (v->cx / 8 + 1) * 8; v->cx = x >= v->cols ? v->cols - 1 : x; v->wrap_pending = 0; break; }
                default: break;
                }
                continue;
            }
            if (c < 0x80) { v->need = 0; put_char(v, c); continue; }
            // UTF-8
            if (v->need == 0) {
                if ((c >> 5) == 6) { v->cp = c & 0x1f; v->need = 1; }
                else if ((c >> 4) == 14) { v->cp = c & 0x0f; v->need = 2; }
                else if ((c >> 3) == 30) { v->cp = c & 0x07; v->need = 3; }
                else put_char(v, 0xFFFD);
            } else if ((c & 0xc0) == 0x80) {
                v->cp = v->cp << 6 | (c & 0x3f);
                if (--v->need == 0) put_char(v, v->cp);
            } else { v->need = 0; put_char(v, 0xFFFD); i--; }
            continue;
        }
        if (v->st == S_ESC) {
            if (c == '[') { v->st = S_CSI; v->np = 0; v->have = 0; v->semi = 0; v->priv = 0; memset(v->params, 0, sizeof v->params); }
            else if (c == ']') { v->st = S_OSC; v->esc_in_str = 0; }
            else if (c == 'P' || c == '_' || c == '^' || c == 'X') { v->st = S_STR; v->esc_in_str = 0; }
            else if (c == '(' || c == ')' || c == '*' || c == '+' || c == '#' || c == '%') v->st = S_CHARSET, v->priv = c;
            else { esc_final(v, c); v->st = S_GROUND; }
            continue;
        }
        if (v->st == S_CHARSET) {
            if (v->priv == '(') v->g0_graphics = c == '0';
            v->st = S_GROUND;
            continue;
        }
        if (v->st == S_CSI) {
            if (c >= '0' && c <= '9') {
                if (!v->have) { if (v->np < 16) v->np++; v->have = 1; }
                v->semi = 0;
                if (v->np) { int *p = &v->params[v->np - 1]; if (*p < 100000) *p = *p * 10 + (int)(c - '0'); }
            } else if (c == ';' || c == ':') {
                if (!v->have && v->np < 16) v->np++;       // empty parameter between separators
                v->have = 0;
                v->semi = 1;
            } else if (c == '?' || c == '>' || c == '=' || c == '<') v->priv = c;
            else if (c >= 0x20 && c <= 0x2f) { /* intermediate: ignore */ }
            else if (c >= 0x40 && c <= 0x7e) { if (v->semi && !v->have && v->np < 16) v->np++; csi(v, c); v->st = S_GROUND; }
            else if (c < 0x20) { /* control inside CSI: ignore */ }
            continue;
        }
    }
}
