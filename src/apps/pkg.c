// Packages: find, audit and install .apk files. Everything heavy is apkcore.c (shared with the
// `pm` / `apkinfo` terminal tools). Installing stores the package under /data/app/<name>; running
// it needs an Android runtime, which this build does not ship (see open_pkg()).
#define _GNU_SOURCE
#include "../ui.h"
#include "../apk/apkcore.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROOT "/data/app"
#define BRIDGE "http://10.0.2.2:8765"

typedef struct { char name[128]; char path[300]; long size; } FileEnt;
static FileEnt files[48];
static int nfiles;
static ApkInstalled *inst;
static int ninst;
static FileEnt br[48];
static int nbr, br_state;               // 0 idle, 1 loading, 2 ok, 3 unreachable

static ApkInfo an, job_an;
static int have_an, view;               // view 0 = list, 1 = detail
static int an_installed;                // the analysed apk is the installed copy
static Gest g;
static Scroll sc;
static char toast[260];
static double toast_t, confirm_t;
static int confirm_kind;                // 1 = uninstall, 2 = delete file, 3 = force install
static float content_h;

enum { J_NONE, J_ANALYZE, J_INSTALL, J_BRLIST, J_DOWNLOAD };
static struct { volatile int kind, busy, done, rc, pct; char arg[320], arg2[160], msg[300]; long expect; int force; } job;

static const char *wget_path(void) { return access("/usr/bin/wget", X_OK) == 0 ? "/usr/bin/wget" : "/bin/wget"; }
static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(toast, sizeof toast, fmt, ap);
    va_end(ap);
    toast_t = now();
}

static int has_apk_ext(const char *n) { size_t l = strlen(n); return l > 4 && !strcasecmp(n + l - 4, ".apk"); }
static int cmp_file(const void *a, const void *b) { return strcasecmp(((const FileEnt *)a)->name, ((const FileEnt *)b)->name); }

static void refresh(void) {
    free(inst);
    ninst = apk_installed_list(ROOT, &inst);
    nfiles = 0;
    static const char *dirs[] = { "/data/Download", "/data/apks", "/data/home", 0 };
    for (int d = 0; dirs[d]; d++) {
        DIR *dp = opendir(dirs[d]);
        if (!dp) continue;
        struct dirent *e;
        while ((e = readdir(dp)) && nfiles < 48) {
            if (e->d_name[0] == '.' || !has_apk_ext(e->d_name)) continue;
            FileEnt *f = &files[nfiles];
            snprintf(f->name, sizeof f->name, "%s", e->d_name);
            snprintf(f->path, sizeof f->path, "%s/%s", dirs[d], e->d_name);
            struct stat st;
            f->size = stat(f->path, &st) ? 0 : (long)st.st_size;
            nfiles++;
        }
        closedir(dp);
    }
    qsort(files, nfiles, sizeof *files, cmp_file);
}

// ---- background jobs ------------------------------------------------------------------------------
static void prog_cb(void *ctx, int pct) { (void)ctx; job.pct = pct; }

static void url_encode(const char *s, char *o, size_t n) {
    size_t w = 0;
    for (; *s && w + 4 < n; s++) {
        if (isalnum((unsigned char)*s) || *s == '.' || *s == '-' || *s == '_') o[w++] = *s;
        else w += snprintf(o + w, n - w, "%%%02X", (unsigned char)*s);
    }
    o[w] = 0;
}

static void *worker(void *arg) {
    (void)arg;
    job.rc = 0;
    job.msg[0] = 0;
    if (job.kind == J_ANALYZE) {
        apk_info_free(&job_an);
        job.rc = apk_analyze(job.arg, &job_an, job.msg, sizeof job.msg);
    } else if (job.kind == J_INSTALL) {
        job.rc = apk_install(job.arg, ROOT, &an, job.force, prog_cb, 0, job.msg, sizeof job.msg);
    } else if (job.kind == J_BRLIST) {
        nbr = 0;
        char cmd[200];
        snprintf(cmd, sizeof cmd, "%s -q -T 4 -O - " BRIDGE "/apks 2>/dev/null", wget_path());
        FILE *p = popen(cmd, "r");
        char line[300];
        int got = 0;
        if (p) {
            while (fgets(line, sizeof line, p) && nbr < 48) {
                char *tab = strchr(line, '\t');
                if (!tab) continue;
                *tab = 0;
                snprintf(br[nbr].name, sizeof br[nbr].name, "%s", line);
                br[nbr].size = atol(tab + 1);
                nbr++;
                got = 1;
            }
            int st = pclose(p);
            if (st != 0 && !got) job.rc = -1;
        } else job.rc = -1;
        br_state = job.rc ? 3 : 2;
    } else if (job.kind == J_DOWNLOAD) {
        char enc[400], url[500], part[360], dst[360];
        url_encode(job.arg2, enc, sizeof enc);
        snprintf(url, sizeof url, BRIDGE "/apk?name=%s", enc);
        mkdir("/data/Download", 0755);
        snprintf(dst, sizeof dst, "/data/Download/%s", job.arg2);
        snprintf(part, sizeof part, "%s.part", dst);
        pid_t p = fork();
        if (p == 0) {
            for (int i = 3; i < 256; i++) close(i);
            signal(SIGPIPE, SIG_DFL);
            int nul = open("/dev/null", O_RDWR);
            dup2(nul, 0); dup2(nul, 1); dup2(nul, 2);
            execl(wget_path(), "wget", "-q", "-T", "20", "-O", part, url, (char *)0);
            _exit(127);
        }
        int st = 0;
        while (p > 0 && waitpid(p, &st, WNOHANG) == 0) {
            struct stat s;
            if (!stat(part, &s) && job.expect > 0) job.pct = (int)(s.st_size * 100 / job.expect);
            usleep(150000);
        }
        if (p < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) { unlink(part); snprintf(job.msg, sizeof job.msg, "download failed (bridge reachable? file still there?)"); job.rc = -1; }
        else if (rename(part, dst)) { snprintf(job.msg, sizeof job.msg, "cannot save to /data/Download: %s", strerror(errno)); job.rc = -1; }
        else { snprintf(job.arg, sizeof job.arg, "%s", dst); }
    }
    job.done = 1;
    job.busy = 0;
    return 0;
}

static void start_job(int kind, const char *arg, const char *arg2) {
    if (job.busy) return;
    job.kind = kind; job.pct = 0; job.done = 0; job.busy = 1;
    snprintf(job.arg, sizeof job.arg, "%s", arg ? arg : "");
    snprintf(job.arg2, sizeof job.arg2, "%s", arg2 ? arg2 : "");
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_detach(t);
}

static void poll_job(void) {
    if (!job.done) return;
    job.done = 0;
    switch (job.kind) {
    case J_ANALYZE:
        if (job.rc) { say("Cannot read this APK: %s", job.msg); break; }
        apk_info_free(&an);
        an = job_an;
        memset(&job_an, 0, sizeof job_an);
        have_an = 1; view = 1; sc = (Scroll){ 0 };
        an_installed = !strncmp(an.path, ROOT "/", sizeof ROOT);
        break;
    case J_INSTALL:
        refresh();
        if (job.rc == -2) { say("%s", job.msg); confirm_kind = 3; confirm_t = now(); }
        else if (job.rc) say("Install failed: %s", job.msg);
        else { say("Installed %s %s", an.package, an.vname); notify("Packages", "Installed (stored, not runnable yet)"); }
        break;
    case J_DOWNLOAD:
        if (job.rc) say("%s", job.msg);
        else { refresh(); say("Downloaded, analysing..."); start_job(J_ANALYZE, job.arg, 0); }
        break;
    case J_BRLIST:
        break;
    }
}

// ---- UI helpers -------------------------------------------------------------------------------------
static uint32_t risk_col(int r) { return r < 25 ? C_LIME : r < 50 ? 0xFFFFD84Du : r < 75 ? C_ORANGE : 0xFFFF4D4Du; }
static uint32_t sev_col(int s) { return s == SEV_HIGH ? C_ORANGE : s == SEV_MED ? 0xFFFFD84Du : s == SEV_LOW ? C_SKY : C_MUTED; }

static float section(Canvas *c, float y, const char *t) {
    text(c, W800, P(12), 0.08f, P(20), y + P(22), C_MUTED, t);
    return y + P(34);
}

static float card(Canvas *c, float y, int id, const char *title, const char *sub, const char *chip, uint32_t chipcol) {
    float h = P(70), x = P(14), w = SW - P(28);
    bool pr = id && pressed(id);
    g_rrect(c, x, y, w, h, P(18), P(18), pr ? 0xFF2F2E2Bu : 0xFF232220u);
    char *t = text_ellipsize(W600, P(16.5f), title, w - P(36) - (chip ? P(86) : 0));
    text(c, W600, P(16.5f), 0, x + P(18), y + P(30), C_PAPER, t);
    free(t);
    if (sub) { char *s = text_ellipsize(W400, P(12.5f), sub, w - P(36)); text(c, W400, P(12.5f), 0, x + P(18), y + P(52), C_MUTED, s); free(s); }
    if (chip) {
        float cw = text_w(W800, P(11), 0.04f, chip) + P(18);
        g_rrect(c, x + w - cw - P(14), y + P(14), cw, P(26), P(13), P(13), chipcol);
        text_c(c, W800, P(11), 0.04f, x + w - cw / 2 - P(14), y + P(32), C_INK, chip);
    }
    if (id) hit(id, x, y, w, h);
    return y + h + P(9);
}

static float pill(Canvas *c, int id, float x, float y, float w, const char *label, uint32_t fill, uint32_t fg) {
    float h = P(46);
    bool pr = pressed(id);
    g_rrect(c, x, y, w, h, h / 2, h / 2, pr ? C_LIME : fill);
    text_c(c, W600, P(14.5f), 0, x + w / 2, y + h / 2 + P(5), pr ? C_INK : fg, label);
    hit(id, x, y, w, h);
    return x + w + P(8);
}

static void human(long b, char *o, size_t n) {
    if (b > 1 << 20) snprintf(o, n, "%.1f MB", b / 1048576.0);
    else snprintf(o, n, "%ld KB", (b + 1023) / 1024);
}

static void open_(void) {
    mkdir("/data/Download", 0755);
    refresh();
    view = 0; sc = (Scroll){ 0 };
    toast[0] = 0;
}

// ---- list screen ----------------------------------------------------------------------------------------
static void draw_list(Canvas *c, float top) {
    float y = top + P(14) - sc.pos;
    char sub[120];
    y = section(c, y, "INSTALLED");
    if (!ninst) { text(c, W400, P(13), 0, P(24), y + P(16), C_MUTED, "nothing installed yet"); y += P(34); }
    for (int i = 0; i < ninst; i++) {
        snprintf(sub, sizeof sub, "%s · %s", inst[i].version, inst[i].pkg);
        y = card(c, y, 0x1000 + i, inst[i].label[0] ? inst[i].label : inst[i].pkg, sub, apk_risk_label(inst[i].risk), risk_col(inst[i].risk));
    }
    y += P(6);
    y = section(c, y, "APK FILES ON THIS PHONE");
    if (!nfiles) { text(c, W400, P(13), 0, P(24), y + P(16), C_MUTED, "none in /data/Download or /data/apks"); y += P(34); }
    for (int i = 0; i < nfiles; i++) {
        char sz[24];
        human(files[i].size, sz, sizeof sz);
        snprintf(sub, sizeof sub, "%s · %s", sz, files[i].path);
        y = card(c, y, 0x1100 + i, files[i].name, sub, "AUDIT", 0xFF3A3936u);
    }
    y += P(6);
    y = section(c, y, "FROM YOUR COMPUTER (BRIDGE)");
    if (br_state == 0) {
        y = pill(c, 0x1301, P(14), y, SW - P(28), "Fetch list from ./apks on the Mac", 0xFF2B2A28u, C_PAPER) - P(8) + P(12);
        text(c, W400, P(12), 0, P(24), y + P(10), C_MUTED, "run.sh starts the bridge; drop .apk files in the apks/ folder next to it");
        y += P(30);
    } else if (br_state == 1) { text(c, W400, P(13), 0, P(24), y + P(16), C_MUTED, "asking the bridge..."); y += P(34); }
    else if (br_state == 3) {
        text(c, W400, P(13), 0, P(24), y + P(16), C_ORANGE, "bridge not reachable at 10.0.2.2:8765");
        y += P(30);
        y = pill(c, 0x1301, P(14), y, P(130), "Retry", 0xFF2B2A28u, C_PAPER) + P(0);
        y += P(56);
    } else {
        if (!nbr) { text(c, W400, P(13), 0, P(24), y + P(16), C_MUTED, "the apks/ folder is empty"); y += P(34); }
        for (int i = 0; i < nbr; i++) {
            char sz[24];
            human(br[i].size, sz, sizeof sz);
            y = card(c, y, 0x1200 + i, br[i].name, sz, "GET", C_SKY);
        }
    }
    y += P(18);
    char h1[200];
    snprintf(h1, sizeof h1, "Terminal: pm install FILE.apk · apkinfo FILE.apk · fetch URL -o /data/Download/x.apk");
    int st[4], ln[4];
    int nl = text_wrap(W400, P(12), h1, SW - P(48), st, ln, 4);
    for (int i = 0; i < nl; i++) text_n(c, W400, P(12), 0, P(24), y + P(14) + i * P(17), C_MUTED, h1 + st[i], ln[i]);
    y += P(14) + nl * P(17) + P(130);
    content_h = y - (top + P(14) - sc.pos);
}

// ---- detail screen -----------------------------------------------------------------------------------------
static float wrapped(Canvas *c, float y, float x, float w, int f, float px, uint32_t col, const char *s) {
    int st[16], ln[16];
    int nl = text_wrap(f, px, s, w, st, ln, 16);
    for (int i = 0; i < nl; i++) text_n(c, f, px, 0, x, y + px + i * px * 1.3f, col, s + st[i], ln[i]);
    return y + nl * px * 1.3f;
}

static void do_open(void) {
    static const char *rt[] = { "/system/bin/apk-runtime", "/data/runtime/launch", 0 };
    for (int i = 0; rt[i]; i++) {
        if (access(rt[i], X_OK)) continue;
        pid_t p = fork();
        if (p == 0) {
            for (int k = 3; k < 256; k++) close(k);
            signal(SIGPIPE, SIG_DFL);
            execl(rt[i], rt[i], an.package, an.launcher, (char *)0);
            _exit(127);
        }
        say("Launching %s via %s", an.package, rt[i]);
        return;
    }
    say("No Android runtime in this build. Lumen audits and stores APKs; running them needs a compatibility layer (/system/bin/apk-runtime).");
}

static void draw_detail(Canvas *c, float top) {
    if (!have_an) return;
    float y = top + P(14) - sc.pos, x = P(20), w = SW - P(40);
    const ApkInfo *a = &an;
    // title card
    g_rrect(c, P(14), y, SW - P(28), P(150), P(22), P(22), risk_col(a->risk));
    char *t = text_ellipsize(W800, P(26), a->label[0] ? a->label : a->package, SW - P(150));
    text(c, W800, P(26), -0.03f, P(30), y + P(44), C_INK, t);
    free(t);
    char l[200];
    snprintf(l, sizeof l, "%s · version %s (%u)", a->package, a->vname[0] ? a->vname : "?", a->vcode);
    char *e = text_ellipsize(W600, P(12.5f), l, SW - P(150));
    text(c, W600, P(12.5f), 0, P(30), y + P(68), C_INK, e);
    free(e);
    snprintf(l, sizeof l, "%s RISK", apk_risk_label(a->risk));
    text(c, W800, P(15), 0.04f, P(30), y + P(104), C_INK, l);
    g_rrect(c, P(30), y + P(116), SW - P(88), P(12), P(6), P(6), c_alpha(C_INK, 0.2f));
    g_rrect(c, P(30), y + P(116), (SW - P(88)) * a->risk / 100.0f, P(12), P(6), P(6), C_INK);
    snprintf(l, sizeof l, "%d", a->risk);
    text_r(c, W800, P(40), -0.04f, SW - P(30), y + P(70), C_INK, l);
    y += P(166);

    // actions
    bool installed_any = false;
    {
        ApkInstalled t2;
        installed_any = apk_installed_get(ROOT, a->package, &t2) == 0;
    }
    float bx = P(14);
    if (an_installed) {
        bx = pill(c, 0x1310, bx, y, P(110), "Open", C_LIME, C_INK);
        bx = pill(c, 0x1311, bx, y, P(150), confirm_kind == 1 && now() - confirm_t < 3 ? "Tap to confirm" : "Uninstall", 0xFF3A3936u, C_PAPER);
    } else {
        bx = pill(c, 0x1312, bx, y, P(150), installed_any ? "Update" : "Install", C_LIME, C_INK);
        if (!strncmp(a->path, "/data/Download/", 15))
            bx = pill(c, 0x1313, bx, y, P(150), confirm_kind == 2 && now() - confirm_t < 3 ? "Tap to confirm" : "Delete file", 0xFF3A3936u, C_PAPER);
    }
    if (confirm_kind == 3 && now() - confirm_t < 8) pill(c, 0x1314, bx, y, P(190), "Install anyway", C_ORANGE, C_INK);
    y += P(60);

    // findings
    y = section(c, y, "FINDINGS");
    for (int sv = SEV_HIGH; sv >= SEV_INFO; sv--)
        for (int i = 0; i < a->nfinds; i++) {
            if (a->finds[i].sev != sv) continue;
            g_circle(c, x + P(5), y + P(11), P(5), sev_col(sv));
            y = wrapped(c, y, x + P(20), w - P(20), W400, P(13.5f), sv == SEV_INFO ? C_MUTED : C_PAPER, a->finds[i].text) + P(10);
        }
    y += P(8);
    snprintf(l, sizeof l, "PERMISSIONS (%d)", a->nperms);
    y = section(c, y, l);
    for (int lv = 2; lv >= 0; lv--)
        for (int i = 0; i < a->nperms; i++) {
            if (a->perms[i].level != lv) continue;
            const char *n = strrchr(a->perms[i].name, '.');
            n = n ? n + 1 : a->perms[i].name;
            g_circle(c, x + P(5), y + P(9), P(4.5f), lv == 2 ? C_ORANGE : lv == 1 ? 0xFFFFD84Du : 0xFF55534Eu);
            text(c, WMONO, P(12), 0, x + P(20), y + P(14), lv ? C_PAPER : C_MUTED, n);
            y += P(22);
        }
    y += P(14);
    snprintf(l, sizeof l, "TRACKERS AND AD SDKS (%d)", a->ntrackers);
    y = section(c, y, l);
    for (int i = 0; i < a->ntrackers; i++) { text(c, W600, P(13.5f), 0, x + P(20), y + P(14), C_PAPER, a->trackers[i]); y += P(22); }
    if (!a->ntrackers) { text(c, W400, P(13), 0, x, y + P(14), C_MUTED, "none of the known signatures matched"); y += P(24); }
    if (a->nurls) {
        y += P(14);
        snprintf(l, sizeof l, "CLEARTEXT ENDPOINTS (%d)", a->nurls);
        y = section(c, y, l);
        for (int i = 0; i < a->nurls; i++) { char *u = text_ellipsize(WMONO, P(11), a->urls[i], w); text(c, WMONO, P(11), 0, x, y + P(13), C_PAPER, u); free(u); y += P(20); }
    }
    y += P(14);
    y = section(c, y, "SIGNER");
    y = wrapped(c, y, x, w, W400, P(13), C_PAPER, a->signer_subject[0] ? a->signer_subject : "no certificate found") + P(4);
    if (a->signer_sha256[0]) {
        char fp[100];
        snprintf(fp, sizeof fp, "%.32s", a->signer_sha256);
        text(c, WMONO, P(11), 0, x, y + P(14), C_MUTED, "sha-256");
        text(c, WMONO, P(11), 0, x, y + P(32), C_PAPER, fp);
        text(c, WMONO, P(11), 0, x, y + P(48), C_PAPER, a->signer_sha256 + 32);
        y += P(58);
        snprintf(l, sizeof l, "valid %s to %s · schemes %s%s%s", a->signer_from, a->signer_to, a->sig_v1 ? "v1 " : "", a->sig_v2 ? "v2 " : "", a->sig_v3 ? "v3" : "");
        text(c, W400, P(12), 0, x, y + P(14), C_MUTED, l);
        y += P(28);
    }
    y += P(10);
    y = section(c, y, "FILE");
    text(c, WMONO, P(11), 0, x, y + P(14), C_MUTED, "sha-256");
    char h1[40];
    snprintf(h1, sizeof h1, "%.32s", a->sha256);
    text(c, WMONO, P(11), 0, x, y + P(32), C_PAPER, h1);
    text(c, WMONO, P(11), 0, x, y + P(48), C_PAPER, a->sha256 + 32);
    snprintf(l, sizeof l, "sdk %d-%d · %d dex · native %s", a->min_sdk, a->target_sdk, a->ndex, a->abis[0] ? a->abis : "none");
    text(c, W400, P(12), 0, x, y + P(72), C_MUTED, l);
    y += P(110) + P(120);
    content_h = y - (top + P(14) - sc.pos);
}

static void draw(Canvas *c, float dt) {
    poll_job();
    g_clear(c, C_INK);
    float top = P(94);
    float vh = SH - top - P(30);
    sc.max = fmaxf(content_h - vh, 0);
    scroll_step(&sc, dt);
    int clip[4] = { c->cx0, c->cy0, c->cx1, c->cy1 };
    g_clip(c, 0, top, SW, SH);
    if (view == 0) draw_list(c, top); else draw_detail(c, top);
    c->cx0 = clip[0]; c->cy0 = clip[1]; c->cx1 = clip[2]; c->cy1 = clip[3];

    g_rect(c, 0, 0, SW, top, C_LILAC);
    status_line(c, 0, C_INK, true, false);
    if (view == 1) btn_icon(c, 0x1300, P(14), P(40), P(44), IC_BACK, C_INK, 0);
    text(c, W800, P(view ? 26 : 34), -0.04f, view ? P(70) : P(18), P(view ? 76 : 80), C_INK, view ? "Package audit" : "Packages");

    // progress / toast bar
    if (job.busy) {
        const char *m = job.kind == J_ANALYZE ? "Analysing..." : job.kind == J_INSTALL ? "Installing..." : job.kind == J_DOWNLOAD ? "Downloading..." : "Asking the bridge...";
        float by = SH - P(96);
        g_rrect(c, P(14), by, SW - P(28), P(52), P(16), P(16), C_PAPER);
        text(c, W600, P(14), 0, P(30), by + P(31), C_INK, m);
        if (job.kind == J_INSTALL || job.kind == J_DOWNLOAD) {
            g_rrect(c, SW - P(190), by + P(20), P(150), P(12), P(6), P(6), 0xFFCFCBC0u);
            g_rrect(c, SW - P(190), by + P(20), P(150) * job.pct / 100.0f, P(12), P(6), P(6), C_ORANGE);
        }
    } else if (toast[0] && now() - toast_t < 7) {
        int st[6], ln[6];
        int nl = text_wrap(W600, P(13), toast, SW - P(64), st, ln, 6);
        float hh = P(22) + nl * P(18), by = SH - P(50) - hh;
        g_rrect(c, P(14), by, SW - P(28), hh, P(16), P(16), C_PAPER);
        for (int i = 0; i < nl; i++) text_n(c, W600, P(13), 0, P(30), by + P(22) + i * P(18), C_INK, toast + st[i], ln[i]);
    }
    home_bar(c, C_PAPER);
}

static void touch(InputEv *e) {
    int r = gest(&g, e);
    if (r == G_DRAG_START || r == G_DRAG) { if (g.vert) scroll_drag(&sc, r == G_DRAG_START ? g.y - g.y0 : g.dy); }
    else if (r == G_DRAG_END) { if (sc.held) scroll_fling(&sc, g.vy); }
    else if (r == G_TAP) {
        int id = hit_at(e->x, e->y);
        if (job.busy) return;
        if (id == 0x1300) { view = 0; sc = (Scroll){ 0 }; refresh(); }
        else if (id >= 0x1000 && id < 0x1000 + ninst) {
            char p[400];
            snprintf(p, sizeof p, ROOT "/%s/base.apk", inst[id - 0x1000].pkg);
            start_job(J_ANALYZE, p, 0);
        } else if (id >= 0x1100 && id < 0x1100 + nfiles) start_job(J_ANALYZE, files[id - 0x1100].path, 0);
        else if (id >= 0x1200 && id < 0x1200 + nbr) { job.expect = br[id - 0x1200].size; start_job(J_DOWNLOAD, "", br[id - 0x1200].name); }
        else if (id == 0x1301) { br_state = 1; start_job(J_BRLIST, "", 0); }
        else if (id == 0x1310) do_open();
        else if (id == 0x1311) {
            if (confirm_kind == 1 && now() - confirm_t < 3) {
                apk_uninstall(ROOT, an.package);
                say("Removed %s", an.package);
                refresh(); view = 0; sc = (Scroll){ 0 }; confirm_kind = 0;
            } else { confirm_kind = 1; confirm_t = now(); }
        } else if (id == 0x1312) { job.force = 0; start_job(J_INSTALL, an.path, 0); }
        else if (id == 0x1313) {
            if (confirm_kind == 2 && now() - confirm_t < 3) { unlink(an.path); say("Deleted %s", an.path); refresh(); view = 0; confirm_kind = 0; }
            else { confirm_kind = 2; confirm_t = now(); }
        } else if (id == 0x1314) { job.force = 1; confirm_kind = 0; start_job(J_INSTALL, an.path, 0); }
    }
}

App app_pkg = { "Packages", IC_PKG, open_, draw, touch, 0, 0, false };
