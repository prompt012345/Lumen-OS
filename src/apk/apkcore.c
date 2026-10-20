// apkcore: see apkcore.h
#define _GNU_SOURCE
#include "apkcore.h"
#include "../net/net.h"
#include <bearssl.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_ENTRY (320u << 20)      // refuse to inflate a single entry past this

static inline uint16_t r16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static inline uint32_t r32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static inline uint64_t r64(const uint8_t *p) { return r32(p) | (uint64_t)r32(p + 4) << 32; }

static char *xdup(const char *s) { char *d = strdup(s ? s : ""); if (!d) abort(); return d; }

// ---- small growable arrays ---------------------------------------------------------------
#define GROW(arr, n) do { (arr) = realloc((arr), sizeof *(arr) * ((n) + 1)); if (!(arr)) abort(); } while (0)

static void add_find(ApkInfo *ai, int sev, const char *fmt, ...) {
    char buf[400];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    GROW(ai->finds, ai->nfinds);
    ai->finds[ai->nfinds].sev = sev;
    ai->finds[ai->nfinds].text = xdup(buf);
    ai->nfinds++;
}
static int add_str(char ***arr, int *n, const char *s) {
    for (int i = 0; i < *n; i++) if (!strcmp((*arr)[i], s)) return 0;
    GROW(*arr, *n);
    (*arr)[(*n)++] = xdup(s);
    return 1;
}

// ---- SHA-256 -------------------------------------------------------------------------------
static void hex(const uint8_t *b, int n, char *out, int colon) {
    static const char H[] = "0123456789ABCDEF";
    int o = 0;
    for (int i = 0; i < n; i++) {
        if (colon && i) out[o++] = ':';
        out[o++] = H[b[i] >> 4];
        out[o++] = H[b[i] & 15];
    }
    out[o] = 0;
}
static void sha256_hex(const uint8_t *d, size_t n, char out[65]) {
    br_sha256_context c;
    uint8_t h[32];
    br_sha256_init(&c);
    br_sha256_update(&c, d, n);
    br_sha256_out(&c, h);
    hex(h, 32, out, 0);
}

// ---- ZIP -------------------------------------------------------------------------------------
typedef struct { char name[300]; uint16_t method; uint32_t csize, usize, lho; } ZEnt;
typedef struct { const uint8_t *d; size_t n; ZEnt *e; int ne; size_t cd_off; } Zip;

static int zip_open(Zip *z, const uint8_t *d, size_t n, char *err, size_t en) {
    memset(z, 0, sizeof *z);
    z->d = d; z->n = n;
    if (n < 22) { snprintf(err, en, "file too small to be a zip"); return -1; }
    long i = (long)n - 22, lim = (long)n - 22 - 65535;
    if (lim < 0) lim = 0;
    for (; i >= lim; i--) if (r32(d + i) == 0x06054b50u) break;
    if (i < lim) { snprintf(err, en, "not a zip/apk (no end-of-central-directory)"); return -1; }
    int ne = r16(d + i + 10);
    uint32_t cdsz = r32(d + i + 12), cdoff = r32(d + i + 16);
    if (ne == 0xFFFF || cdoff == 0xFFFFFFFFu) { snprintf(err, en, "zip64 archives are not supported"); return -1; }
    if ((uint64_t)cdoff + cdsz > n) { snprintf(err, en, "corrupt central directory"); return -1; }
    z->e = calloc(ne ? ne : 1, sizeof *z->e);
    z->cd_off = cdoff;
    size_t p = cdoff;
    for (int k = 0; k < ne; k++) {
        if (p + 46 > n || r32(d + p) != 0x02014b50u) { snprintf(err, en, "corrupt central directory entry %d", k); free(z->e); z->e = 0; return -1; }
        ZEnt *e = &z->e[z->ne];
        e->method = r16(d + p + 10);
        e->csize = r32(d + p + 20);
        e->usize = r32(d + p + 24);
        int nl = r16(d + p + 28), xl = r16(d + p + 30), cl = r16(d + p + 32);
        e->lho = r32(d + p + 42);
        if (p + 46 + nl > n) break;
        int cp = nl < (int)sizeof e->name - 1 ? nl : (int)sizeof e->name - 1;
        memcpy(e->name, d + p + 46, cp);
        e->name[cp] = 0;
        z->ne++;
        p += 46 + nl + xl + cl;
    }
    return 0;
}
static void zip_close(Zip *z) { free(z->e); z->e = 0; }
static ZEnt *zip_find(Zip *z, const char *name) {
    for (int i = 0; i < z->ne; i++) if (!strcmp(z->e[i].name, name)) return &z->e[i];
    return 0;
}
// returns malloc'd contents (NUL-terminated extra byte), *len set; NULL on error
static uint8_t *zip_data(Zip *z, const ZEnt *e, size_t *len) {
    const uint8_t *d = z->d;
    if ((uint64_t)e->lho + 30 > z->n || r32(d + e->lho) != 0x04034b50u) return 0;
    size_t start = (size_t)e->lho + 30 + r16(d + e->lho + 26) + r16(d + e->lho + 28);
    if (start > z->n || (uint64_t)start + e->csize > z->n) return 0;
    if (e->usize > MAX_ENTRY) return 0;
    uint8_t *out;
    if (e->method == 0) {
        if (e->csize != e->usize) return 0;
        out = malloc((size_t)e->usize + 1);
        if (!out) return 0;
        memcpy(out, d + start, e->usize);
        *len = e->usize;
    } else if (e->method == 8) {
        size_t on = 0;
        int capped = 0;
        uint8_t *o = inflate_raw_max(d + start, e->csize, &on, (size_t)e->usize + 1, &capped);
        if (capped || on != e->usize) { free(o); return 0; }   // truncated, bombed or lying about its size
        out = realloc(o, on + 1);
        if (!out) return 0;
        *len = on;
    } else return 0;
    out[*len] = 0;
    return out;
}

// ---- Android binary XML ----------------------------------------------------------------------
typedef struct { uint32_t n; const uint8_t *offs, *data, *end; int utf8; } SPool;

static char *sp_str(const SPool *sp, uint32_t i) {
    if (i >= sp->n) return xdup("");
    uint32_t off = r32(sp->offs + 4 * (size_t)i);
    const uint8_t *s = sp->data + off;
    if (s >= sp->end) return xdup("");
    if (sp->utf8) {
        if (s + 2 > sp->end) return xdup("");
        uint32_t l = *s++;
        if (l & 0x80) { l = ((l & 0x7f) << 8) | *s++; }
        uint32_t bl = *s++;
        if (bl & 0x80) { bl = ((bl & 0x7f) << 8) | *s++; }
        if (s >= sp->end) return xdup("");
        if (s + bl > sp->end) bl = (uint32_t)(sp->end - s);
        char *o = malloc(bl + 1);
        memcpy(o, s, bl);
        o[bl] = 0;
        return o;
    }
    if (s + 2 > sp->end) return xdup("");
    uint32_t l = r16(s);
    s += 2;
    if (l & 0x8000) { l = ((l & 0x7fff) << 16) | r16(s); s += 2; }
    if (s + 2 * (size_t)l > sp->end) l = (uint32_t)((sp->end - s) / 2);
    char *o = malloc(l * 4 + 1), *w = o;
    for (uint32_t k = 0; k < l; k++) {
        uint32_t c = r16(s + 2 * k);
        if (c >= 0xD800 && c < 0xDC00 && k + 1 < l) {
            uint32_t c2 = r16(s + 2 * k + 2);
            if (c2 >= 0xDC00 && c2 < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (c2 - 0xDC00); k++; }
        }
        if (c < 0x80) *w++ = (char)c;
        else if (c < 0x800) { *w++ = (char)(0xc0 | c >> 6); *w++ = (char)(0x80 | (c & 63)); }
        else if (c < 0x10000) { *w++ = (char)(0xe0 | c >> 12); *w++ = (char)(0x80 | (c >> 6 & 63)); *w++ = (char)(0x80 | (c & 63)); }
        else { *w++ = (char)(0xf0 | c >> 18); *w++ = (char)(0x80 | (c >> 12 & 63)); *w++ = (char)(0x80 | (c >> 6 & 63)); *w++ = (char)(0x80 | (c & 63)); }
    }
    *w = 0;
    return o;
}

static const struct { uint32_t id; const char *name; } ATTR_IDS[] = {
    { 0x01010003, "name" }, { 0x01010001, "label" }, { 0x0101000f, "debuggable" }, { 0x01010010, "exported" },
    { 0x01010006, "permission" }, { 0x0101000e, "enabled" }, { 0x0101021b, "versionCode" }, { 0x0101021c, "versionName" },
    { 0x0101020c, "minSdkVersion" }, { 0x01010270, "targetSdkVersion" }, { 0x01010280, "allowBackup" },
    { 0x010104ec, "usesCleartextTraffic" }, { 0x01010272, "testOnly" }, { 0x01010527, "networkSecurityConfig" },
    { 0x01010202, "targetActivity" },
};

typedef struct { char *name; char *val; } Attr;

static int tri(const char *s) { return !s ? -1 : (!strcmp(s, "true") || !strcmp(s, "1")) ? 1 : 0; }
static const char *attr_get(Attr *a, int n, const char *name) {
    for (int i = 0; i < n; i++) if (!strcmp(a[i].name, name)) return a[i].val;
    return 0;
}

// permission table (suffix after android.permission.)
static const struct { const char *n; int lvl; } PERMS[] = {
    { "READ_CALENDAR", 1 }, { "WRITE_CALENDAR", 1 }, { "CAMERA", 1 }, { "READ_CONTACTS", 1 }, { "WRITE_CONTACTS", 1 },
    { "GET_ACCOUNTS", 1 }, { "ACCESS_FINE_LOCATION", 1 }, { "ACCESS_COARSE_LOCATION", 1 }, { "ACCESS_BACKGROUND_LOCATION", 2 },
    { "RECORD_AUDIO", 1 }, { "READ_PHONE_STATE", 1 }, { "READ_PHONE_NUMBERS", 1 }, { "CALL_PHONE", 1 }, { "READ_CALL_LOG", 2 },
    { "WRITE_CALL_LOG", 2 }, { "ADD_VOICEMAIL", 1 }, { "USE_SIP", 1 }, { "PROCESS_OUTGOING_CALLS", 2 }, { "ANSWER_PHONE_CALLS", 1 },
    { "SEND_SMS", 2 }, { "RECEIVE_SMS", 2 }, { "READ_SMS", 2 }, { "RECEIVE_WAP_PUSH", 1 }, { "RECEIVE_MMS", 1 },
    { "READ_EXTERNAL_STORAGE", 1 }, { "WRITE_EXTERNAL_STORAGE", 1 }, { "ACCESS_MEDIA_LOCATION", 1 }, { "BODY_SENSORS", 1 },
    { "ACTIVITY_RECOGNITION", 1 }, { "READ_MEDIA_IMAGES", 1 }, { "READ_MEDIA_VIDEO", 1 }, { "READ_MEDIA_AUDIO", 1 },
    { "POST_NOTIFICATIONS", 1 }, { "NEARBY_WIFI_DEVICES", 1 }, { "BLUETOOTH_SCAN", 1 }, { "BLUETOOTH_CONNECT", 1 },
    { "BLUETOOTH_ADVERTISE", 1 }, { "SYSTEM_ALERT_WINDOW", 2 }, { "REQUEST_INSTALL_PACKAGES", 2 }, { "BIND_ACCESSIBILITY_SERVICE", 2 },
    { "BIND_DEVICE_ADMIN", 2 }, { "MANAGE_EXTERNAL_STORAGE", 2 }, { "READ_LOGS", 2 }, { "INSTALL_PACKAGES", 2 }, { "DELETE_PACKAGES", 2 },
    { "WRITE_SECURE_SETTINGS", 2 }, { "QUERY_ALL_PACKAGES", 2 }, { "BIND_NOTIFICATION_LISTENER_SERVICE", 2 }, { "PACKAGE_USAGE_STATS", 2 },
    { "BIND_VPN_SERVICE", 2 }, { "MOUNT_UNMOUNT_FILESYSTEMS", 2 }, { "WRITE_SETTINGS", 2 }, { "REBOOT", 2 }, { "CHANGE_COMPONENT_ENABLED_STATE", 2 },
    { "RECORD_BACKGROUND_AUDIO", 2 },
};
int apk_perm_level(const char *name) {
    const char *suf = strrchr(name, '.');
    if (!suf || strncmp(name, "android.permission.", 19)) return 0;
    suf++;
    for (size_t i = 0; i < sizeof PERMS / sizeof PERMS[0]; i++) if (!strcmp(PERMS[i].n, suf)) return PERMS[i].lvl;
    return 0;
}

static void add_perm(ApkInfo *ai, const char *name) {
    for (int i = 0; i < ai->nperms; i++) if (!strcmp(ai->perms[i].name, name)) return;
    GROW(ai->perms, ai->nperms);
    ai->perms[ai->nperms].name = xdup(name);
    ai->perms[ai->nperms].level = apk_perm_level(name);
    ai->nperms++;
}

static char *full_class(const ApkInfo *ai, const char *n) {
    char b[400];
    if (n[0] == '.') snprintf(b, sizeof b, "%s%s", ai->package, n);
    else if (!strchr(n, '.')) snprintf(b, sizeof b, "%s.%s", ai->package, n);
    else snprintf(b, sizeof b, "%s", n);
    return xdup(b);
}

static int parse_manifest(const uint8_t *d, size_t n, ApkInfo *ai) {
    if (n < 16 || r16(d) != 0x0003) return -1;
    SPool sp = {0};
    uint32_t *resmap = 0;
    uint32_t nres = 0;
    char *stack[40] = {0};
    int depth = 0;
    int cur_comp = -1, in_filter = 0, f_main = 0, f_launcher = 0, in_app = 0;
    char *alias_target = 0;
    size_t p = 8;
    while (p + 8 <= n) {
        uint16_t type = r16(d + p);
        uint32_t sz = r32(d + p + 4);
        if (sz < 8 || p + sz > n) break;
        const uint8_t *c = d + p;
        if (type == 0x0001 && sz >= 28) {
            sp.n = r32(c + 8);
            uint32_t flags = r32(c + 16), sstart = r32(c + 20);
            sp.utf8 = (flags & 0x100) != 0;
            if ((uint64_t)28 + 4ull * sp.n > sz || sstart >= sz) { sp.n = 0; }
            else { sp.offs = c + 28; sp.data = c + sstart; sp.end = c + sz; }
        } else if (type == 0x0180) {
            nres = (sz - 8) / 4;
            free(resmap);
            resmap = malloc(sizeof(uint32_t) * (nres + 1));
            for (uint32_t k = 0; k < nres; k++) resmap[k] = r32(c + 8 + 4 * k);
        } else if (type == 0x0102 && sz >= 36 && sp.n) {
            uint32_t nameidx = r32(c + 20);
            int astart = r16(c + 24), asize = r16(c + 26), acount = r16(c + 28);
            if (asize < 20) asize = 20;
            char *el = sp_str(&sp, nameidx);
            Attr at[48];
            int na = 0;
            for (int k = 0; k < acount && na < 48; k++) {
                const uint8_t *a = c + 16 + astart + (size_t)k * asize;
                if (a + 20 > d + n) break;
                uint32_t an = r32(a + 4), raw = r32(a + 8), data = r32(a + 16);
                int vt = a[15];
                char *nm = sp_str(&sp, an);
                if (!nm[0] && resmap && an < nres) {
                    for (size_t q = 0; q < sizeof ATTR_IDS / sizeof ATTR_IDS[0]; q++)
                        if (ATTR_IDS[q].id == resmap[an]) { free(nm); nm = xdup(ATTR_IDS[q].name); break; }
                }
                char *val;
                if (vt == 0x03) val = sp_str(&sp, data);
                else if (vt == 0x12) val = xdup(data ? "true" : "false");
                else if (vt == 0x10) { char b[24]; snprintf(b, sizeof b, "%d", (int)data); val = xdup(b); }
                else if (vt == 0x11) { char b[24]; snprintf(b, sizeof b, "%u", data); val = xdup(b); }
                else if (vt == 0x01) { char b[24]; snprintf(b, sizeof b, "@0x%08x", data); val = xdup(b); }
                else if (raw != 0xFFFFFFFFu) val = sp_str(&sp, raw);
                else val = xdup("");
                at[na].name = nm; at[na].val = val; na++;
            }
            const char *parent = depth > 0 ? stack[depth - 1] : "";
            if (!strcmp(el, "manifest")) {
                const char *v;
                if ((v = attr_get(at, na, "package"))) snprintf(ai->package, sizeof ai->package, "%s", v);
                if ((v = attr_get(at, na, "versionName"))) snprintf(ai->vname, sizeof ai->vname, "%s", v);
                if ((v = attr_get(at, na, "versionCode"))) ai->vcode = (uint32_t)strtoul(v, 0, 10);
                if ((v = attr_get(at, na, "testOnly"))) ai->test_only = tri(v);
            } else if (!strcmp(el, "uses-sdk")) {
                const char *v;
                if ((v = attr_get(at, na, "minSdkVersion"))) ai->min_sdk = atoi(v);
                if ((v = attr_get(at, na, "targetSdkVersion"))) ai->target_sdk = atoi(v);
            } else if (!strcmp(el, "uses-permission") || !strcmp(el, "uses-permission-sdk-23") || !strcmp(el, "uses-permission-sdk-m")) {
                const char *v = attr_get(at, na, "name");
                if (v && v[0]) add_perm(ai, v);
            } else if (!strcmp(el, "application")) {
                in_app = 1;
                const char *v;
                if ((v = attr_get(at, na, "label")) && v[0] && v[0] != '@') snprintf(ai->label, sizeof ai->label, "%s", v);
                if ((v = attr_get(at, na, "debuggable"))) ai->debuggable = tri(v);
                if ((v = attr_get(at, na, "allowBackup"))) ai->allow_backup = tri(v);
                if ((v = attr_get(at, na, "usesCleartextTraffic"))) ai->cleartext = tri(v);
                if ((v = attr_get(at, na, "testOnly"))) ai->test_only = tri(v);
                if (attr_get(at, na, "networkSecurityConfig")) ai->netsec = 1;
            } else if (in_app && (!strcmp(el, "activity") || !strcmp(el, "activity-alias") || !strcmp(el, "service") ||
                                  !strcmp(el, "receiver") || !strcmp(el, "provider")) && !strcmp(parent, "application")) {
                const char *nm = attr_get(at, na, "name");
                GROW(ai->comps, ai->ncomps);
                ApkComp *cp = &ai->comps[ai->ncomps];
                cp->name = full_class(ai, nm ? nm : "?");
                cp->kind = !strcmp(el, "service") ? 's' : !strcmp(el, "receiver") ? 'r' : !strcmp(el, "provider") ? 'p' : 'a';
                cp->exported = tri(attr_get(at, na, "exported"));
                cp->filter = 0;
                const char *pm = attr_get(at, na, "permission");
                cp->perm = pm && pm[0] ? xdup(pm) : 0;
                cur_comp = ai->ncomps++;
                free(alias_target);
                alias_target = 0;
                if (!strcmp(el, "activity-alias")) {
                    const char *t = attr_get(at, na, "targetActivity");
                    if (t) alias_target = full_class(ai, t);
                }
            } else if (!strcmp(el, "intent-filter") && cur_comp >= 0) {
                ai->comps[cur_comp].filter = 1;
                in_filter = 1; f_main = f_launcher = 0;
            } else if (in_filter && !strcmp(el, "action")) {
                const char *v = attr_get(at, na, "name");
                if (v && !strcmp(v, "android.intent.action.MAIN")) f_main = 1;
            } else if (in_filter && !strcmp(el, "category")) {
                const char *v = attr_get(at, na, "name");
                if (v && (!strcmp(v, "android.intent.category.LAUNCHER") || !strcmp(v, "android.intent.category.LEANBACK_LAUNCHER"))) f_launcher = 1;
            }
            if (depth < 40) stack[depth] = el; else free(el);
            depth++;
            for (int k = 0; k < na; k++) { free(at[k].name); free(at[k].val); }
        } else if (type == 0x0103) {
            if (depth > 0) {
                depth--;
                if (depth < 40) {
                    const char *el = stack[depth];
                    if (!strcmp(el, "intent-filter")) {
                        if (in_filter && f_main && f_launcher && cur_comp >= 0 && ai->comps[cur_comp].kind == 'a' && !ai->launcher[0])
                            snprintf(ai->launcher, sizeof ai->launcher, "%s", alias_target ? alias_target : ai->comps[cur_comp].name);
                        in_filter = 0;
                    } else if (!strcmp(el, "activity") || !strcmp(el, "activity-alias") || !strcmp(el, "service") ||
                               !strcmp(el, "receiver") || !strcmp(el, "provider")) cur_comp = -1;
                    else if (!strcmp(el, "application")) in_app = 0;
                    free(stack[depth]);
                    stack[depth] = 0;
                }
            }
        }
        p += sz;
    }
    for (int i = 0; i < 40; i++) free(stack[i]);
    free(alias_target);
    free(resmap);
    return ai->package[0] ? 0 : -1;
}

// ---- DER / X.509 ------------------------------------------------------------------------------
// reads one TLV at p (limit end). returns total bytes consumed or 0.
static size_t der_tlv(const uint8_t *p, const uint8_t *end, int *tag, const uint8_t **val, size_t *vlen) {
    if (p + 2 > end) return 0;
    *tag = p[0];
    size_t l = p[1], hdr = 2;
    if (l & 0x80) {
        int nb = l & 0x7f;
        if (nb == 0 || nb > 4 || p + 2 + nb > end) return 0;
        l = 0;
        for (int i = 0; i < nb; i++) l = (l << 8) | p[2 + i];
        hdr = 2 + nb;
    }
    if (p + hdr + l > end) return 0;
    *val = p + hdr;
    *vlen = l;
    return hdr + l;
}

static void der_time(const uint8_t *v, size_t l, int tag, char out[16]) {
    out[0] = 0;
    if (tag == 0x17 && l >= 6) {   // UTCTime YYMMDD...
        int yy = (v[0] - '0') * 10 + (v[1] - '0');
        snprintf(out, 16, "%d%c%c-%c%c-%c%c", yy >= 50 ? 19 : 20, v[0], v[1], v[2], v[3], v[4], v[5]);
    } else if (tag == 0x18 && l >= 8) {   // GeneralizedTime YYYYMMDD...
        snprintf(out, 16, "%c%c%c%c-%c%c-%c%c", v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
    }
}

// fills subject/validity from a DER certificate, and its SHA-256
static void parse_cert(const uint8_t *der, size_t dlen, ApkInfo *ai) {
    sha256_hex(der, dlen, ai->signer_sha256);
    // keep colon form out of the struct; report prints it grouped
    int tag; const uint8_t *v; size_t vl;
    if (!der_tlv(der, der + dlen, &tag, &v, &vl) || tag != 0x30) return;
    const uint8_t *tbs; size_t tl;
    if (!der_tlv(v, v + vl, &tag, &tbs, &tl) || tag != 0x30) return;
    const uint8_t *p = tbs, *end = tbs + tl;
    size_t k;
    // optional [0] version
    if ((k = der_tlv(p, end, &tag, &v, &vl)) && tag == 0xA0) p += k;
    // serial, sigalg, issuer
    for (int i = 0; i < 3; i++) { if (!(k = der_tlv(p, end, &tag, &v, &vl))) return; p += k; }
    // validity
    if (!(k = der_tlv(p, end, &tag, &v, &vl)) || tag != 0x30) return;
    {
        const uint8_t *q = v, *qe = v + vl;
        const uint8_t *tv; size_t tvl; int tt;
        size_t kk = der_tlv(q, qe, &tt, &tv, &tvl);
        if (kk) { der_time(tv, tvl, tt, ai->signer_from); q += kk; }
        kk = der_tlv(q, qe, &tt, &tv, &tvl);
        if (kk) der_time(tv, tvl, tt, ai->signer_to);
    }
    p += k;
    // subject
    if (!(k = der_tlv(p, end, &tag, &v, &vl)) || tag != 0x30) return;
    char subj[256] = "";
    int so = 0;
    const uint8_t *q = v, *qe = v + vl;
    while (q < qe) {
        const uint8_t *sv; size_t sl; int st;
        size_t kk = der_tlv(q, qe, &st, &sv, &sl);   // SET
        if (!kk) break;
        q += kk;
        const uint8_t *av; size_t al; int at_;
        if (!der_tlv(sv, sv + sl, &at_, &av, &al)) continue;   // SEQ
        const uint8_t *ov; size_t ol; int ot;
        size_t k1 = der_tlv(av, av + al, &ot, &ov, &ol);
        if (!k1 || ot != 6) continue;
        const uint8_t *vv; size_t vln; int vt;
        if (!der_tlv(av + k1, av + al, &vt, &vv, &vln)) continue;
        const char *key = 0;
        if (ol == 3 && ov[0] == 0x55 && ov[1] == 0x04) {
            switch (ov[2]) { case 3: key = "CN"; break; case 6: key = "C"; break; case 7: key = "L"; break; case 8: key = "ST"; break; case 10: key = "O"; break; case 11: key = "OU"; break; }
        } else if (ol == 9) key = "E";
        if (!key) continue;
        so += snprintf(subj + so, sizeof subj - so, "%s%s=%.*s", so ? ", " : "", key, (int)(vln > 80 ? 80 : vln), (const char *)vv);
        if (so >= (int)sizeof subj - 1) break;
    }
    snprintf(ai->signer_subject, sizeof ai->signer_subject, "%s", subj);
    if (strstr(subj, "CN=Android Debug")) ai->debug_cert = 1;
}

// PKCS#7 SignedData (META-INF/*.RSA): first certificate
static int pkcs7_first_cert(const uint8_t *b, size_t n, const uint8_t **cert, size_t *clen) {
    int tag; const uint8_t *v; size_t vl, k;
    if (!der_tlv(b, b + n, &tag, &v, &vl) || tag != 0x30) return -1;          // ContentInfo
    const uint8_t *p = v, *end = v + vl;
    if (!(k = der_tlv(p, end, &tag, &v, &vl)) || tag != 6) return -1;          // OID
    p += k;
    if (!(k = der_tlv(p, end, &tag, &v, &vl)) || tag != 0xA0) return -1;       // [0] content
    if (!der_tlv(v, v + vl, &tag, &v, &vl) || tag != 0x30) return -1;          // SignedData
    p = v; end = v + vl;
    for (int i = 0; i < 3; i++) {                                              // version, digestAlgs, contentInfo
        if (!(k = der_tlv(p, end, &tag, &v, &vl))) return -1;
        p += k;
    }
    if (!(k = der_tlv(p, end, &tag, &v, &vl)) || tag != 0xA0) return -1;       // [0] certificates
    const uint8_t *cs = v;
    size_t ck = der_tlv(cs, cs + vl, &tag, &v, &vl);
    if (!ck || tag != 0x30) return -1;
    *cert = cs; *clen = ck;
    return 0;
}

// APK Signing Block (v2/v3): first signer's first certificate
static int sigblock_cert(const uint8_t *d, size_t n, size_t cdoff, ApkInfo *ai, const uint8_t **cert, size_t *clen) {
    if (cdoff < 32 || cdoff > n || memcmp(d + cdoff - 16, "APK Sig Block 42", 16)) return -1;
    uint64_t bsz = r64(d + cdoff - 24);
    if (bsz < 24 || bsz + 8 > cdoff) return -1;
    size_t start = cdoff - bsz - 8;
    size_t p = start + 8, end = cdoff - 24;
    int found = -1;
    while (p + 12 <= end) {
        uint64_t len = r64(d + p);
        if (len < 4 || p + 8 + len > end) break;
        uint32_t id = r32(d + p + 8);
        const uint8_t *val = d + p + 12;
        size_t vlen = (size_t)len - 4;
        if (id == 0x7109871au) ai->sig_v2 = 1;
        if (id == 0xf05368c0u || id == 0x1b93ad61u) ai->sig_v3 = 1;
        if ((id == 0x7109871au || id == 0xf05368c0u || id == 0x1b93ad61u) && found < 0 && vlen >= 8) {
            // signers(u32 len) { signer(u32 len) { signed_data(u32 len) { digests(u32 len), certs(u32 len) { cert(u32 len) } } } }
            const uint8_t *q = val, *qe = val + vlen;
            #define ENTER() do { if (q + 4 > qe) goto next; uint32_t L = r32(q); q += 4; if (L > (size_t)(qe - q)) goto next; qe = q + L; } while (0)
            ENTER();                        // signers
            ENTER();                        // first signer
            ENTER();                        // signed data
            if (q + 4 > qe) goto next;
            { uint32_t dl = r32(q); q += 4; if (dl > (size_t)(qe - q)) goto next; q += dl; }   // skip digests
            ENTER();                        // certificates
            if (q + 4 > qe) goto next;
            { uint32_t cl = r32(q); q += 4; if (cl > (size_t)(qe - q)) goto next; *cert = q; *clen = cl; found = 0; }
            #undef ENTER
        }
    next:
        p += 8 + (size_t)len;
    }
    return found;
}

// ---- dex string scan ---------------------------------------------------------------------------
static const struct { const char *needle, *name; } TRACKERS[] = {
    { "com/google/firebase/analytics", "Google Firebase Analytics" }, { "com/google/android/gms/measurement", "Google Analytics for Firebase" },
    { "com/google/android/gms/analytics", "Google Analytics" }, { "com/google/android/gms/ads", "Google AdMob" },
    { "com/google/firebase/crashlytics", "Firebase Crashlytics" }, { "com/crashlytics/android", "Crashlytics" },
    { "com/facebook/ads", "Facebook Ads" }, { "com/facebook/appevents", "Facebook App Events" }, { "com/facebook/FacebookSdk", "Facebook SDK" },
    { "com/appsflyer", "AppsFlyer" }, { "com/adjust/sdk", "Adjust" }, { "io/branch/referral", "Branch" }, { "com/mixpanel", "Mixpanel" },
    { "com/amplitude", "Amplitude" }, { "com/segment/analytics", "Segment" }, { "com/flurry", "Flurry" }, { "com/unity3d/ads", "Unity Ads" },
    { "com/applovin", "AppLovin" }, { "com/ironsource", "ironSource" }, { "com/vungle", "Vungle" }, { "com/chartboost", "Chartboost" },
    { "com/inmobi", "InMobi" }, { "com/mopub", "MoPub" }, { "io/sentry", "Sentry" }, { "com/onesignal", "OneSignal" },
    { "com/braze", "Braze" }, { "com/appboy", "Appboy (Braze)" }, { "com/microsoft/appcenter", "Microsoft App Center" }, { "com/tapjoy", "Tapjoy" },
    { "com/yandex/metrica", "Yandex Metrica" }, { "com/baidu/mobstat", "Baidu Mobstat" }, { "com/umeng", "Umeng" },
    { "com/startapp", "StartApp" }, { "com/smaato", "Smaato" }, { "com/bytedance/sdk", "ByteDance / Pangle" }, { "com/kochava", "Kochava" },
    { "com/singular/sdk", "Singular" }, { "com/leanplum", "Leanplum" }, { "com/clevertap", "CleverTap" }, { "io/intercom", "Intercom" },
};

static const struct { const char *needle; int sev; const char *text; } CODE_SIGNS[] = {
    { "ALLOW_ALL_HOSTNAME_VERIFIER", SEV_HIGH, "TLS hostname verification can be disabled (ALLOW_ALL_HOSTNAME_VERIFIER referenced)" },
    { "addJavascriptInterface", SEV_MED, "WebView JavaScript bridge (addJavascriptInterface) referenced" },
    { "setAllowUniversalAccessFromFileURLs", SEV_MED, "WebView universal file access (setAllowUniversalAccessFromFileURLs) referenced" },
    { "DexClassLoader", SEV_MED, "dynamic code loading (DexClassLoader) referenced" },
    { "AES/ECB", SEV_MED, "AES in ECB mode referenced (weak, leaks patterns)" },
    { "Landroid/webkit/WebViewClient;->onReceivedSslError", SEV_LOW, "custom WebView SSL error handler (check it does not proceed())" },
};

static int is_b64url(int c) { return isalnum(c) || c == '_' || c == '-'; }

static const char *SKIP_HOSTS[] = { "schemas.android.com", "www.w3.org", "xmlpull.org", "ns.adobe.com", "localhost", "127.0.0.1", "10.0.2.2",
    "www.apache.org", "apache.org", "java.sun.com", "xml.org", "schemas.microsoft.com", "www.slf4j.org", "purl.org", "www.opengis.net",
    "ns.useplus.org", "www.iec.ch", "www.google.com/schemas", "maven.apache.org", "xml.apache.org", "javax.xml", 0 };

static void scan_dex(const uint8_t *d, size_t n, ApkInfo *ai) {
    for (size_t i = 0; i < sizeof TRACKERS / sizeof TRACKERS[0]; i++)
        if (memmem(d, n, TRACKERS[i].needle, strlen(TRACKERS[i].needle))) add_str(&ai->trackers, &ai->ntrackers, TRACKERS[i].name);
    for (size_t i = 0; i < sizeof CODE_SIGNS / sizeof CODE_SIGNS[0]; i++) {
                if (memmem(d, n, CODE_SIGNS[i].needle, strlen(CODE_SIGNS[i].needle))) {
            int dup = 0;
            for (int k = 0; k < ai->nfinds; k++) if (!strcmp(ai->finds[k].text, CODE_SIGNS[i].text)) dup = 1;
            if (!dup) add_find(ai, CODE_SIGNS[i].sev, "%s", CODE_SIGNS[i].text);
        }
    }
    // hard-coded secrets (high-signal patterns only)
    const uint8_t *p = d, *end = d + n;
    int nk = 0;
    while (nk < 4 && (p = memmem(p, end - p, "AIza", 4))) {
        if (p + 39 <= end) {
            int ok = 1;
            for (int i = 4; i < 39; i++) if (!is_b64url(p[i])) { ok = 0; break; }
            if (ok) { add_find(ai, SEV_HIGH, "Google API key embedded in code: %.8s...%.4s", (const char *)p, (const char *)p + 35); nk++; }
        }
        p += 4;
    }
    p = d; nk = 0;
    while (nk < 3 && (p = memmem(p, end - p, "AKIA", 4))) {
        if (p + 20 <= end) {
            int ok = 1;
            for (int i = 4; i < 20; i++) if (!(isupper(p[i]) || isdigit(p[i]))) { ok = 0; break; }
            if (ok) { add_find(ai, SEV_HIGH, "AWS access key id embedded in code: %.8s...", (const char *)p); nk++; }
        }
        p += 4;
    }
    if (memmem(d, n, "-----BEGIN RSA PRIVATE KEY-----", 31) || memmem(d, n, "-----BEGIN PRIVATE KEY-----", 27) ||
        memmem(d, n, "-----BEGIN EC PRIVATE KEY-----", 30))
        add_find(ai, SEV_HIGH, "private key material embedded in code");
    if ((p = memmem(d, n, "firebaseio.com", 14))) {
        const uint8_t *s = p;
        while (s > d && p - s < 60 && (isalnum(s[-1]) || s[-1] == '-' || s[-1] == '/' || s[-1] == ':' || s[-1] == '.')) s--;
        char u[100];
        int l = (int)(p + 14 - s);
        if (l > 99) l = 99;
        memcpy(u, s, l); u[l] = 0;
        add_find(ai, SEV_MED, "Firebase Realtime Database URL: %s (test it for open read/write rules)", u);
    }
    // cleartext endpoints
    p = d;
    while (ai->nurls < 12 && (p = memmem(p, end - p, "http://", 7))) {
        const uint8_t *s = p + 7, *e = s;
        while (e < end && e - s < 110 && *e > 32 && *e < 127 && *e != '"' && *e != '\'' && *e != '<' && *e != '>' && *e != '\\') e++;
        char u[140];
        int l = (int)(e - p);
        if (l > 7 && l < 130) {
            memcpy(u, p, l); u[l] = 0;
            const char *host = u + 7;
            int skip = 0;
            for (int i = 0; SKIP_HOSTS[i]; i++) if (!strncmp(host, SKIP_HOSTS[i], strlen(SKIP_HOSTS[i]))) skip = 1;
            if (!skip && strchr(host, '.') && !strchr(u, '%') && !strchr(u, '{')) add_str(&ai->urls, &ai->nurls, u);
        }
        p += 7;
    }
}

// ---- analysis --------------------------------------------------------------------------------------
static int is_dex_name(const char *n) {
    if (strncmp(n, "classes", 7)) return 0;
    const char *q = n + 7;
    while (isdigit((unsigned char)*q)) q++;
    return !strcmp(q, ".dex");
}
static int has_suffix_ci(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && !strcasecmp(s + a - b, suf);
}

const char *apk_risk_label(int r) { return r < 25 ? "LOW" : r < 50 ? "MEDIUM" : r < 75 ? "HIGH" : "CRITICAL"; }

static void score(ApkInfo *ai) {
    int s = 0, nd = 0, hr = 0;
    for (int i = 0; i < ai->nperms; i++) { if (ai->perms[i].level == 1) nd++; else if (ai->perms[i].level == 2) hr++; }
    s += nd * 2 > 14 ? 14 : nd * 2;
    s += hr * 7 > 28 ? 28 : hr * 7;
    for (int i = 0; i < ai->nfinds; i++) {
        int v = ai->finds[i].sev;
        s += v == SEV_HIGH ? 12 : v == SEV_MED ? 6 : v == SEV_LOW ? 2 : 0;
    }
    s += ai->ntrackers * 3 > 15 ? 15 : ai->ntrackers * 3;
    if (s > 100) s = 100;
    ai->risk = s;
}

int apk_analyze(const char *path, ApkInfo *ai, char *err, size_t en) {
    memset(ai, 0, sizeof *ai);
    ai->debuggable = ai->allow_backup = ai->cleartext = ai->test_only = ai->netsec = -1;
    snprintf(ai->path, sizeof ai->path, "%s", path);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { snprintf(err, en, "cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) || st.st_size < 22) { close(fd); snprintf(err, en, "file is empty or unreadable"); return -1; }
    size_t n = (size_t)st.st_size;
    const uint8_t *d = mmap(0, n, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (d == MAP_FAILED) { snprintf(err, en, "cannot map file (%s)", strerror(errno)); return -1; }
    ai->size = n;
    sha256_hex(d, n, ai->sha256);

    Zip z;
    int rc = -1;
    if (zip_open(&z, d, n, err, en)) goto out;
    ai->nentries = z.ne;

    // manifest
    ZEnt *me = zip_find(&z, "AndroidManifest.xml");
    if (!me) { snprintf(err, en, "no AndroidManifest.xml: this is not an Android package"); goto out_zip; }
    size_t ml;
    uint8_t *mf = zip_data(&z, me, &ml);
    if (!mf) { snprintf(err, en, "cannot read AndroidManifest.xml (corrupt or unsupported compression)"); goto out_zip; }
    int pr = parse_manifest(mf, ml, ai);
    free(mf);
    if (pr) { snprintf(err, en, "AndroidManifest.xml is unreadable (obfuscated or not binary XML)"); goto out_zip; }

    // native libraries, dex files, signature files
    const uint8_t *cert = 0; size_t clen = 0;
    uint8_t *v1blob = 0; size_t v1len = 0;
    for (int i = 0; i < z.ne; i++) {
        const char *nm = z.e[i].name;
        if (!strncmp(nm, "lib/", 4)) {
            const char *abi = nm + 4, *sl = strchr(abi, '/');
            if (sl && sl > abi) {
                char a[32];
                int l = (int)(sl - abi);
                if (l < (int)sizeof a) {
                    snprintf(a, sizeof a, "%.*s", l, abi);
                    if (!strstr(ai->abis, a)) { size_t o = strlen(ai->abis); snprintf(ai->abis + o, sizeof ai->abis - o, "%s%s", o ? " " : "", a); }
                }
            }
        } else if (is_dex_name(nm)) ai->ndex++;
        else if (!strncmp(nm, "META-INF/", 9) && !strchr(nm + 9, '/') &&
                 (has_suffix_ci(nm, ".RSA") || has_suffix_ci(nm, ".DSA") || has_suffix_ci(nm, ".EC")) && !v1blob) {
            v1blob = zip_data(&z, &z.e[i], &v1len);
            if (v1blob) ai->sig_v1 = 1;
        }
    }
    int have_cert = sigblock_cert(d, n, z.cd_off, ai, &cert, &clen) == 0;
    if (have_cert) parse_cert(cert, clen, ai);
    else if (v1blob && pkcs7_first_cert(v1blob, v1len, &cert, &clen) == 0) { parse_cert(cert, clen, ai); have_cert = 1; }
    free(v1blob);

    // code scan
    for (int i = 0; i < z.ne; i++) {
        if (!is_dex_name(z.e[i].name)) continue;
        size_t dl;
        uint8_t *dx = zip_data(&z, &z.e[i], &dl);
        if (!dx) { add_find(ai, SEV_LOW, "%s could not be read (corrupt or packed); code checks skipped for it", z.e[i].name); continue; }
        scan_dex(dx, dl, ai);
        free(dx);
    }

    // findings from the manifest
    if (ai->debuggable == 1) add_find(ai, SEV_HIGH, "android:debuggable=true: a debugger or run-as can read the app's private data");
    if (ai->test_only == 1) add_find(ai, SEV_MED, "android:testOnly=true: test build, not meant for distribution");
    if (ai->allow_backup != 0) add_find(ai, ai->allow_backup == 1 ? SEV_MED : SEV_LOW, "allowBackup %s: app data can be extracted with adb backup", ai->allow_backup == 1 ? "is true" : "not set (defaults to true)");
    if (ai->cleartext == 1) add_find(ai, SEV_MED, "usesCleartextTraffic=true: plain HTTP is allowed");
    else if (ai->cleartext == -1 && ai->target_sdk && ai->target_sdk < 28 && ai->netsec != 1) add_find(ai, SEV_LOW, "targets API %d (<28): plain HTTP is allowed by default", ai->target_sdk);
    if (ai->target_sdk && ai->target_sdk < 23) add_find(ai, SEV_MED, "targets API %d (<23): legacy permission model, all permissions granted at install", ai->target_sdk);
    int exp = 0, expprov = 0;
    for (int i = 0; i < ai->ncomps; i++) {
        ApkComp *c = &ai->comps[i];
        int e = c->exported == 1 || (c->exported == -1 && ((c->filter && (!ai->target_sdk || ai->target_sdk < 31)) || (c->kind == 'p' && ai->target_sdk && ai->target_sdk < 17)));
        c->exported = e;
        if (e && !c->perm && !(c->kind == 'a' && !strcmp(c->name, ai->launcher))) { exp++; if (c->kind == 'p') expprov++; }
    }
    if (expprov) add_find(ai, SEV_HIGH, "%d exported content provider(s) without a permission (data exposure, injection surface)", expprov);
    if (exp) add_find(ai, SEV_MED, "%d exported component(s) without a permission (reachable by any app)", exp);
    int hr = 0;
    for (int i = 0; i < ai->nperms; i++) hr += ai->perms[i].level == 2;
    if (hr) add_find(ai, SEV_MED, "%d high-risk permission(s) requested (overlay, accessibility, SMS, install, logs...)", hr);
    if (!have_cert) add_find(ai, SEV_HIGH, "no signing certificate found: package is unsigned or uses an unsupported scheme");
    if (ai->debug_cert) add_find(ai, SEV_HIGH, "signed with the public Android debug key: anyone can re-sign and impersonate this app");
    if (ai->sig_v1 && !ai->sig_v2 && !ai->sig_v3) add_find(ai, SEV_LOW, "only the legacy v1 (JAR) signature is present: weaker against tampering (Janus-style attacks)");
    if (ai->nurls) add_find(ai, SEV_LOW, "%d cleartext http:// endpoint(s) found in code (see list)", ai->nurls);
    add_find(ai, SEV_INFO, "signature fingerprint is shown but NOT cryptographically verified against the file contents");
    score(ai);
    rc = 0;
out_zip:
    zip_close(&z);
out:
    munmap((void *)d, n);
    return rc;
}

void apk_info_free(ApkInfo *ai) {
    for (int i = 0; i < ai->nperms; i++) free(ai->perms[i].name);
    for (int i = 0; i < ai->ncomps; i++) { free(ai->comps[i].name); free(ai->comps[i].perm); }
    for (int i = 0; i < ai->ntrackers; i++) free(ai->trackers[i]);
    for (int i = 0; i < ai->nurls; i++) free(ai->urls[i]);
    for (int i = 0; i < ai->nfinds; i++) free(ai->finds[i].text);
    free(ai->perms); free(ai->comps); free(ai->trackers); free(ai->urls); free(ai->finds);
    memset(ai, 0, sizeof *ai);
}

// ---- text report ----------------------------------------------------------------------------------------
typedef struct { char *b; size_t n, cap; } SB;
static void sb_add(SB *s, const char *fmt, ...) {
    va_list ap;
    for (;;) {
        va_start(ap, fmt);
        int w = vsnprintf(s->b + s->n, s->cap - s->n, fmt, ap);
        va_end(ap);
        if (w >= 0 && (size_t)w < s->cap - s->n) { s->n += w; return; }
        s->cap = s->cap * 2 + 1024;
        s->b = realloc(s->b, s->cap);
        if (!s->b) abort();
    }
}
static void fp_colon(const char *hex64, char *out, size_t n) {
    size_t o = 0;
    for (int i = 0; hex64[i] && o + 3 < n; i += 2) {
        if (i) out[o++] = ':';
        out[o++] = hex64[i];
        out[o++] = hex64[i + 1];
    }
    out[o] = 0;
}
char *apk_report(const ApkInfo *ai) {
    SB s = { malloc(2048), 0, 2048 };
    s.b[0] = 0;
    const char *tag[] = { "info", "low ", "MED ", "HIGH" };
    sb_add(&s, "%s  %s (%u)\n", ai->label[0] ? ai->label : ai->package, ai->vname[0] ? ai->vname : "?", ai->vcode);
    sb_add(&s, "  package   %s\n", ai->package);
    sb_add(&s, "  file      %s  (%.1f MB)\n", ai->path, ai->size / 1048576.0);
    sb_add(&s, "  sha-256   %s\n", ai->sha256);
    sb_add(&s, "  sdk       min %d, target %d\n", ai->min_sdk, ai->target_sdk);
    sb_add(&s, "  launcher  %s\n", ai->launcher[0] ? ai->launcher : "(none: no launcher activity)");
    char fp[100];
    fp_colon(ai->signer_sha256, fp, sizeof fp);
    sb_add(&s, "  signer    %s\n", ai->signer_subject[0] ? ai->signer_subject : "(none)");
    if (ai->signer_sha256[0]) sb_add(&s, "            sha-256 %s\n            valid %s -> %s\n", fp, ai->signer_from, ai->signer_to);
    sb_add(&s, "  schemes   %s%s%s\n", ai->sig_v1 ? "v1 " : "", ai->sig_v2 ? "v2 " : "", ai->sig_v3 ? "v3" : "");
    sb_add(&s, "  code      %d dex, native: %s\n", ai->ndex, ai->abis[0] ? ai->abis : "none");
    sb_add(&s, "  RISK      %s (%d/100)\n\n", apk_risk_label(ai->risk), ai->risk);
    sb_add(&s, "Findings (%d)\n", ai->nfinds);
    for (int sev = SEV_HIGH; sev >= SEV_INFO; sev--)
        for (int i = 0; i < ai->nfinds; i++) if (ai->finds[i].sev == sev) sb_add(&s, "  [%s] %s\n", tag[sev], ai->finds[i].text);
    sb_add(&s, "\nPermissions (%d)\n", ai->nperms);
    for (int lv = 2; lv >= 0; lv--)
        for (int i = 0; i < ai->nperms; i++) if (ai->perms[i].level == lv) sb_add(&s, "  %s %s\n", lv == 2 ? "!!" : lv == 1 ? " !" : "  ", ai->perms[i].name);
    sb_add(&s, "\nTrackers / ad SDKs (%d)\n", ai->ntrackers);
    for (int i = 0; i < ai->ntrackers; i++) sb_add(&s, "  %s\n", ai->trackers[i]);
    if (!ai->ntrackers) sb_add(&s, "  none of the known signatures matched\n");
    if (ai->nurls) { sb_add(&s, "\nCleartext endpoints (%d)\n", ai->nurls); for (int i = 0; i < ai->nurls; i++) sb_add(&s, "  %s\n", ai->urls[i]); }
    sb_add(&s, "\nComponents (%d), exported ones listed\n", ai->ncomps);
    for (int i = 0; i < ai->ncomps; i++) {
        const ApkComp *c = &ai->comps[i];
        if (c->exported) sb_add(&s, "  %-9s %s%s%s\n", c->kind == 'a' ? "activity" : c->kind == 's' ? "service" : c->kind == 'r' ? "receiver" : "provider",
                                c->name, c->perm ? "  perm=" : "", c->perm ? c->perm : "");
    }
    return s.b;
}

// ---- package store ------------------------------------------------------------------------------------------
int apk_valid_package_name(const char *s) {
    size_t n = strlen(s);
    if (n < 3 || n > 150 || s[0] == '.' || strstr(s, "..") || !strchr(s, '.')) return 0;
    for (size_t i = 0; i < n; i++) if (!(isalnum((unsigned char)s[i]) || s[i] == '.' || s[i] == '_')) return 0;
    return 1;
}

static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *f) { (void)sb; (void)flag; (void)f; return remove(p); }
static int rm_rf(const char *dir) { return nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS); }

static int mkdirs(const char *path) {
    char b[600];
    snprintf(b, sizeof b, "%s", path);
    for (char *p = b + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(b, 0755); *p = '/'; }
    return mkdir(b, 0755) && errno != EEXIST ? -1 : 0;
}

static int read_kv(const char *file, const char *key, char *out, size_t n) {
    FILE *f = fopen(file, "r");
    if (!f) return -1;
    char line[600];
    size_t kl = strlen(key);
    int ok = -1;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, key, kl) && line[kl] == '=') {
            line[strcspn(line, "\n")] = 0;
            snprintf(out, n, "%s", line + kl + 1);
            ok = 0;
            break;
        }
    }
    fclose(f);
    return ok;
}

int apk_installed_get(const char *root, const char *pkg, ApkInstalled *o) {
    char f[700], v[300];
    if (!apk_valid_package_name(pkg)) return -1;
    snprintf(f, sizeof f, "%s/%s/info.txt", root, pkg);
    if (access(f, R_OK)) return -1;
    memset(o, 0, sizeof *o);
    snprintf(o->pkg, sizeof o->pkg, "%s", pkg);
    if (!read_kv(f, "label", v, sizeof v)) snprintf(o->label, sizeof o->label, "%s", v);
    if (!read_kv(f, "version", v, sizeof v)) snprintf(o->version, sizeof o->version, "%s", v);
    if (!read_kv(f, "sha256", v, sizeof v)) snprintf(o->sha256, sizeof o->sha256, "%s", v);
    if (!read_kv(f, "signer", v, sizeof v)) snprintf(o->signer, sizeof o->signer, "%s", v);
    if (!read_kv(f, "risk", v, sizeof v)) o->risk = atoi(v);
    if (!read_kv(f, "installed", v, sizeof v)) o->when = atol(v);
    snprintf(f, sizeof f, "%s/%s/base.apk", root, pkg);
    struct stat st;
    if (!stat(f, &st)) o->size = st.st_size;
    return 0;
}

int apk_installed_list(const char *root, ApkInstalled **out) {
    DIR *d = opendir(root);
    *out = 0;
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        ApkInstalled t;
        if (apk_installed_get(root, e->d_name, &t)) continue;
        *out = realloc(*out, sizeof **out * (n + 1));
        (*out)[n++] = t;
    }
    closedir(d);
    return n;
}

int apk_uninstall(const char *root, const char *pkg) {
    if (!apk_valid_package_name(pkg)) return -1;
    char d[700];
    snprintf(d, sizeof d, "%s/%s", root, pkg);
    if (access(d, F_OK)) return -1;
    return rm_rf(d);
}

static int copy_file(const char *src, const char *dst, ApkProgress prog, void *ctx, char *err, size_t en) {
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0) { snprintf(err, en, "cannot read %s: %s", src, strerror(errno)); return -1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out < 0) { snprintf(err, en, "cannot write %s: %s", dst, strerror(errno)); close(in); return -1; }
    struct stat st;
    fstat(in, &st);
    char *buf = malloc(1 << 18);          // heap, not TLS: every thread would otherwise carry 256 KB
    if (!buf) { close(in); close(out); snprintf(err, en, "out of memory"); return -1; }
    const size_t bufn = 1 << 18;
    uint64_t done = 0;
    ssize_t r;
    int rc = 0;
    while ((r = read(in, buf, bufn)) > 0) {
        for (ssize_t w = 0; w < r;) {
            ssize_t x = write(out, buf + w, r - w);
            if (x <= 0) { snprintf(err, en, "write failed (%s): storage full?", strerror(errno)); rc = -1; goto done; }
            w += x;
        }
        done += r;
        if (prog && st.st_size) prog(ctx, (int)(done * 90 / st.st_size));
    }
    if (r < 0) { snprintf(err, en, "read failed: %s", strerror(errno)); rc = -1; }
done:
    free(buf);
    fsync(out);
    close(in); close(out);
    return rc;
}

int apk_install(const char *path, const char *root, const ApkInfo *ai, int force, ApkProgress prog, void *ctx, char *err, size_t en) {
    if (!apk_valid_package_name(ai->package)) { snprintf(err, en, "refusing unsafe package name"); return -1; }
    char dir[700], f[760];
    snprintf(dir, sizeof dir, "%s/%s", root, ai->package);
    ApkInstalled old;
    int upgrade = apk_installed_get(root, ai->package, &old) == 0;
    if (upgrade && !force && old.signer[0] && ai->signer_sha256[0] && strcmp(old.signer, ai->signer_sha256)) {
        snprintf(err, en, "signature mismatch: %s is installed with a different signing key. Possible tampered or repackaged APK. Uninstall first to override.", ai->package);
        return -2;
    }
    if (mkdirs(root)) { snprintf(err, en, "cannot create %s: %s", root, strerror(errno)); return -1; }
    char tmp[760];
    snprintf(tmp, sizeof tmp, "%s/.%s.new", root, ai->package);
    rm_rf(tmp);
    if (mkdirs(tmp)) { snprintf(err, en, "cannot create %s: %s", tmp, strerror(errno)); return -1; }
    snprintf(f, sizeof f, "%s/base.apk", tmp);
    if (copy_file(path, f, prog, ctx, err, en)) { rm_rf(tmp); return -1; }

    // native libraries for the best ABI
    int fd = open(f, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && !fstat(fd, &st) && st.st_size > 22) {
        const uint8_t *d = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (d != MAP_FAILED) {
            Zip z;
            char e2[128];
            if (!zip_open(&z, d, st.st_size, e2, sizeof e2)) {
                const char *prefs[] = { "arm64-v8a", "armeabi-v7a", "x86_64", "x86", 0 };
                const char *abi = 0;
                for (int pi = 0; prefs[pi] && !abi; pi++) {
                    char pre[40];
                    snprintf(pre, sizeof pre, "lib/%s/", prefs[pi]);
                    for (int i = 0; i < z.ne; i++) if (!strncmp(z.e[i].name, pre, strlen(pre))) { abi = prefs[pi]; break; }
                }
                if (abi) {
                    char pre[40], ld[780];
                    snprintf(pre, sizeof pre, "lib/%s/", abi);
                    snprintf(ld, sizeof ld, "%s/lib", tmp);
                    mkdir(ld, 0755);
                    for (int i = 0; i < z.ne; i++) {
                        const char *nm = z.e[i].name;
                        if (strncmp(nm, pre, strlen(pre))) continue;
                        const char *base = nm + strlen(pre);
                        if (!*base || strchr(base, '/') || base[0] == '.' || strlen(base) > 100 || !has_suffix_ci(base, ".so")) continue;
                        size_t l;
                        uint8_t *dat = zip_data(&z, &z.e[i], &l);
                        if (!dat) continue;
                        char of[900];
                        snprintf(of, sizeof of, "%s/%s", ld, base);
                        FILE *o = fopen(of, "wb");
                        if (o) { fwrite(dat, 1, l, o); fclose(o); }
                        free(dat);
                        if (prog) prog(ctx, 90 + (int)(9 * (i + 1) / z.ne));
                    }
                }
                zip_close(&z);
            }
            munmap((void *)d, st.st_size);
        }
    }
    if (fd >= 0) close(fd);

    snprintf(f, sizeof f, "%s/info.txt", tmp);
    FILE *fi = fopen(f, "w");
    if (!fi) { snprintf(err, en, "cannot write info: %s", strerror(errno)); rm_rf(tmp); return -1; }
    fprintf(fi, "package=%s\nlabel=%s\nversion=%s (%u)\nsha256=%s\nsigner=%s\nrisk=%d\ninstalled=%ld\nlauncher=%s\nmin_sdk=%d\ntarget_sdk=%d\nabis=%s\n",
            ai->package, ai->label[0] ? ai->label : ai->package, ai->vname, ai->vcode, ai->sha256, ai->signer_sha256, ai->risk,
            (long)time(0), ai->launcher, ai->min_sdk, ai->target_sdk, ai->abis);
    fclose(fi);
    // swap into place
    if (upgrade) rm_rf(dir);
    if (rename(tmp, dir)) { snprintf(err, en, "cannot finalize install: %s", strerror(errno)); rm_rf(tmp); return -1; }
    if (prog) prog(ctx, 100);
    return 0;
}
