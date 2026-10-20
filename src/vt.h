// vt: a compact VT100/xterm terminal emulator (screen model + parser), no I/O and no
// drawing. Feed it the bytes a program writes to its pty; read the cell grid back.
#pragma once
#include <stdint.h>

typedef struct { uint32_t ch; uint32_t fg, bg; uint8_t at; } VCell;   // fg/bg: 0 = terminal default, else 0xFFRRGGBB
enum { VA_BOLD = 1, VA_UL = 2, VA_REV = 4, VA_DIM = 8, VA_ITALIC = 16 };

typedef struct VT VT;
typedef void (*VTReply)(void *ctx, const char *s, int n);   // bytes the terminal answers with (cursor report...)

VT *vt_new(int cols, int rows, int scrollback_lines, VTReply reply, void *ctx);
void vt_free(VT *v);
void vt_resize(VT *v, int cols, int rows);
void vt_feed(VT *v, const unsigned char *d, int n);

int vt_cols(const VT *v);
int vt_rows(const VT *v);
int vt_cursor_x(const VT *v);
int vt_cursor_y(const VT *v);
int vt_cursor_visible(const VT *v);
int vt_app_cursor(const VT *v);          // DECCKM: arrows send ESC O x instead of ESC [ x
int vt_alt_screen(const VT *v);
int vt_sb_count(const VT *v);            // lines of scrollback available
// row r: 0..rows-1 is the screen, -1 is the newest scrollback line, -2 the one before... (NULL if out of range)
const VCell *vt_row(const VT *v, int r);
uint32_t vt_palette(int idx);            // xterm 256-colour palette (Slab-tinted first 16), 0xFFRRGGBB
