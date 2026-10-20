// Command-line tools, shipped inside the single /init binary. /bin/<name> are symlinks to it and
// main() dispatches on argv[0], so they run as ordinary processes inside the Terminal.
//   apkinfo  static analysis of an .apk          pm     install / list / remove packages
//   scan     TCP port scanner + host sweep       sniff  packet capture (pcap output)
//   fetch    HTTPS GET with the built-in TLS stack
#define _GNU_SOURCE
#include "apk/apkcore.h"
#include "net/net.h"
#include "shield.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *apps_root(void) { const char *r = getenv("LUMEN_APPS"); return r && *r ? r : "/data/app"; }

// ---- apkinfo / pm --------------------------------------------------------------------------------
static int cmd_apkinfo(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: apkinfo FILE.apk\n  static analysis: manifest, permissions, signer, trackers, secrets, risk score\n"); return 2; }
    ApkInfo ai;
    char err[256];
    if (apk_analyze(argv[1], &ai, err, sizeof err)) { fprintf(stderr, "apkinfo: %s\n", err); return 1; }
    char *r = apk_report(&ai);
    fputs(r, stdout);
    free(r);
    apk_info_free(&ai);
    return 0;
}

static void pm_prog(void *ctx, int pct) { (void)ctx; fprintf(stderr, "\r  copying %3d%%", pct); fflush(stderr); }

static int cmd_pm(int argc, char **argv) {
    const char *root = apps_root();
    if (argc >= 3 && !strcmp(argv[1], "install")) {
        int force = 0, i = 2;
        if (!strcmp(argv[i], "-f")) { force = 1; i++; }
        if (i >= argc) { fprintf(stderr, "usage: pm install [-f] FILE.apk\n"); return 2; }
        ApkInfo ai;
        char err[400];
        if (apk_analyze(argv[i], &ai, err, sizeof err)) { fprintf(stderr, "pm: %s\n", err); return 1; }
        printf("%s %s  risk %s (%d/100)  signer %.16s\n", ai.package, ai.vname, apk_risk_label(ai.risk), ai.risk, ai.signer_sha256);
        int rc = apk_install(argv[i], root, &ai, force, pm_prog, 0, err, sizeof err);
        fprintf(stderr, "\n");
        if (rc) { fprintf(stderr, "pm: %s\n", err); apk_info_free(&ai); return rc == -2 ? 3 : 1; }
        printf("installed to %s/%s\n", root, ai.package);
        apk_info_free(&ai);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "uninstall")) {
        if (apk_uninstall(root, argv[2])) { fprintf(stderr, "pm: %s is not installed\n", argv[2]); return 1; }
        printf("removed %s\n", argv[2]);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "list")) {
        ApkInstalled *l;
        int n = apk_installed_list(root, &l);
        for (int i = 0; i < n; i++) printf("%-44s %-22s %s\n", l[i].pkg, l[i].version, apk_risk_label(l[i].risk));
        if (!n) printf("no packages installed in %s\n", root);
        free(l);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "path")) {
        ApkInstalled t;
        if (apk_installed_get(root, argv[2], &t)) { fprintf(stderr, "pm: %s is not installed\n", argv[2]); return 1; }
        printf("%s/%s/base.apk\n", root, argv[2]);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "info")) {
        char path[600];
        snprintf(path, sizeof path, "%s/%s/base.apk", root, argv[2]);
        char *av[2] = { "apkinfo", access(path, R_OK) ? argv[2] : path };
        return cmd_apkinfo(2, av);
    }
    fprintf(stderr, "usage: pm install [-f] FILE.apk | uninstall PKG | list | path PKG | info PKG|FILE.apk\n"
                    "  packages live in %s (override with LUMEN_APPS). Installing refuses an update signed\n"
                    "  with a different key unless -f is given.\n", root);
    return 2;
}

// ---- scan ----------------------------------------------------------------------------------------------
static const struct { int port; const char *name; } SERVICES[] = {
    { 21, "ftp" }, { 22, "ssh" }, { 23, "telnet" }, { 25, "smtp" }, { 53, "dns" }, { 80, "http" }, { 110, "pop3" }, { 111, "rpcbind" },
    { 123, "ntp" }, { 135, "msrpc" }, { 139, "netbios" }, { 143, "imap" }, { 161, "snmp" }, { 389, "ldap" }, { 443, "https" },
    { 445, "smb" }, { 465, "smtps" }, { 514, "syslog" }, { 587, "submission" }, { 631, "ipp" }, { 636, "ldaps" }, { 873, "rsync" },
    { 993, "imaps" }, { 995, "pop3s" }, { 1080, "socks" }, { 1433, "mssql" }, { 1521, "oracle" }, { 1723, "pptp" }, { 2049, "nfs" },
    { 2375, "docker" }, { 3000, "http-alt" }, { 3306, "mysql" }, { 3389, "rdp" }, { 5000, "upnp/http" }, { 5432, "postgres" },
    { 5555, "adb" }, { 5900, "vnc" }, { 5985, "winrm" }, { 6379, "redis" }, { 8000, "http-alt" }, { 8008, "http-alt" }, { 8080, "http-proxy" },
    { 8443, "https-alt" }, { 8765, "lumen-bridge" }, { 9000, "http-alt" }, { 9090, "http-alt" }, { 9200, "elasticsearch" },
    { 11211, "memcached" }, { 27017, "mongodb" }, { 0, 0 },
};
static const char *svc_name(int p) { for (int i = 0; SERVICES[i].port; i++) if (SERVICES[i].port == p) return SERVICES[i].name; return "?"; }

static int parse_ports(const char *spec, int *out, int max) {
    int n = 0;
    if (!strcmp(spec, "top")) {
        for (int i = 0; SERVICES[i].port && n < max; i++) out[n++] = SERVICES[i].port;
        static const int extra[] = { 81, 88, 119, 137, 179, 443, 548, 902, 1025, 1026, 1883, 2082, 2222, 4444, 5001, 5060, 5353, 5601, 6000, 7001, 7070, 8081, 8088, 8888, 9001, 9100, 10000, 32400, 0 };
        for (int i = 0; extra[i] && n < max; i++) { int dup = 0; for (int k = 0; k < n; k++) dup |= out[k] == extra[i]; if (!dup) out[n++] = extra[i]; }
        return n;
    }
    char *s = strdup(spec), *sv = 0;
    for (char *t = strtok_r(s, ",", &sv); t; t = strtok_r(0, ",", &sv)) {
        int a, b;
        if (sscanf(t, "%d-%d", &a, &b) == 2) { }
        else if (sscanf(t, "%d", &a) == 1) b = a;
        else continue;
        if (a < 1) a = 1;
        if (b > 65535) b = 65535;
        for (int p = a; p <= b && n < max; p++) out[n++] = p;
    }
    free(s);
    return n;
}

static int resolve4(const char *h, struct in_addr *a) {
    if (inet_aton(h, a)) return 0;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *r;
    if (getaddrinfo(h, 0, &hints, &r)) return -1;
    *a = ((struct sockaddr_in *)r->ai_addr)->sin_addr;
    freeaddrinfo(r);
    return 0;
}

typedef struct { int port, fd, state; double t0; } Probe;   // state 0 pending, 1 open, 2 closed, 3 filtered

static int cmd_scan(int argc, char **argv) {
    const char *ports = "top";
    int timeout = 900, banners = 0, sweep = 0, opt;
    optind = 1;
    while ((opt = getopt(argc, argv, "p:t:bs")) != -1) {
        if (opt == 'p') ports = optarg;
        else if (opt == 't') timeout = atoi(optarg);
        else if (opt == 'b') banners = 1;
        else if (opt == 's') sweep = 1;
        else goto usage;
    }
    if (optind >= argc) goto usage;
    const char *target = argv[optind];
    signal(SIGPIPE, SIG_IGN);

    if (sweep) {                              // host discovery on a CIDR: any TCP answer (even RST) means the host is up
        char t[100];
        snprintf(t, sizeof t, "%s", target);
        char *sl = strchr(t, '/');
        int bits = sl ? atoi(sl + 1) : 24;
        if (sl) *sl = 0;
        struct in_addr base;
        if (bits < 22 || bits > 30 || !inet_aton(t, &base)) { fprintf(stderr, "scan -s: give a CIDR between /22 and /30, e.g. 10.0.2.0/24\n"); return 2; }
        uint32_t net = ntohl(base.s_addr) & (~0u << (32 - bits)), cnt = 1u << (32 - bits);
        static const int sp[] = { 443, 80, 22, 445, 53 };
        int up = 0;
        for (uint32_t off = 1; off + 1 < cnt; off += 32) {
            struct { int fd; int host; int done; } pr[32 * 5];
            struct pollfd pf[32 * 5];
            int np = 0;
            for (uint32_t h = off; h < off + 32 && h + 1 < cnt; h++)
                for (int k = 0; k < 5; k++) {
                    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(sp[k]), .sin_addr.s_addr = htonl(net + h) };
                    connect(fd, (struct sockaddr *)&a, sizeof a);
                    pr[np].fd = fd; pr[np].host = (int)h; pr[np].done = 0;
                    pf[np].fd = fd; pf[np].events = POLLOUT;
                    np++;
                }
            int alive[256] = {0};
            poll(pf, np, 450);
            for (int i = 0; i < np; i++) {
                int e = 0; socklen_t el = sizeof e;
                if (pf[i].revents & (POLLOUT | POLLERR | POLLHUP)) {
                    getsockopt(pr[i].fd, SOL_SOCKET, SO_ERROR, &e, &el);
                    if (e == 0 || e == ECONNREFUSED) alive[pr[i].host - off] = 1;
                }
                close(pr[i].fd);
            }
            for (uint32_t h = off; h < off + 32 && h + 1 < cnt; h++)
                if (alive[h - off]) { struct in_addr a = { htonl(net + h) }; printf("%s is up\n", inet_ntoa(a)); up++; }
        }
        printf("%d host(s) up in %s/%d\n", up, t, bits);
        return 0;
    }

    struct in_addr addr;
    if (resolve4(target, &addr)) { fprintf(stderr, "scan: cannot resolve %s\n", target); return 1; }
    int pl[65536];
    int np = parse_ports(ports, pl, 65536);
    if (!np) goto usage;
    Probe *pr = calloc(np, sizeof *pr);
    for (int i = 0; i < np; i++) { pr[i].port = pl[i]; pr[i].fd = -1; }
    printf("scanning %s (%s), %d ports, timeout %d ms\n", target, inet_ntoa(addr), np, timeout);
    int nopen = 0, nclosed = 0, nfilt = 0;
    const int BATCH = 200;
    for (int b = 0; b < np; b += BATCH) {
        int e = b + BATCH < np ? b + BATCH : np;
        struct pollfd pf[BATCH];
        for (int i = b; i < e; i++) {
            pr[i].fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(pr[i].port), .sin_addr = addr };
            connect(pr[i].fd, (struct sockaddr *)&a, sizeof a);
            pf[i - b].fd = pr[i].fd; pf[i - b].events = POLLOUT;
        }
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            struct timespec t1;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            int el = (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
            if (el >= timeout) break;
            int pending = 0;
            for (int i = b; i < e; i++) if (!pr[i].state) pending++;
            if (!pending) break;
            poll(pf, e - b, 50);
            for (int i = b; i < e; i++) {
                if (pr[i].state || !(pf[i - b].revents & (POLLOUT | POLLERR | POLLHUP))) continue;
                int er = 0; socklen_t l = sizeof er;
                getsockopt(pr[i].fd, SOL_SOCKET, SO_ERROR, &er, &l);
                pr[i].state = er == 0 ? 1 : er == ECONNREFUSED ? 2 : 3;
                if (pr[i].state != 1) { close(pr[i].fd); pr[i].fd = -1; pf[i - b].fd = -1; }
            }
        }
        for (int i = b; i < e; i++) {
            if (pr[i].state == 0) { pr[i].state = 3; if (pr[i].fd >= 0) { close(pr[i].fd); pr[i].fd = -1; } }
            if (pr[i].state == 2) nclosed++;
            else if (pr[i].state == 3) nfilt++;
            else {
                nopen++;
                char banner[96] = "";
                if (banners) {
                    int p = pr[i].port;
                    if (p == 80 || p == 8080 || p == 8000 || p == 8008 || p == 3000 || p == 9000 || p == 8888 || p == 5000) {
                        const char *rq = "HEAD / HTTP/1.0\r\nUser-Agent: lumen-scan\r\n\r\n";
                        ssize_t w = write(pr[i].fd, rq, strlen(rq)); (void)w;
                    }
                    struct pollfd one = { pr[i].fd, POLLIN, 0 };
                    if (poll(&one, 1, 500) > 0) {
                        char buf[200];
                        ssize_t n = read(pr[i].fd, buf, sizeof buf - 1);
                        if (n > 0) {
                            buf[n] = 0;
                            char *nl = strpbrk(buf, "\r\n");
                            if (nl) *nl = 0;
                            for (char *q = buf; *q; q++) if ((unsigned char)*q < 32 || (unsigned char)*q > 126) *q = '.';
                            snprintf(banner, sizeof banner, "%s", buf);
                        }
                    }
                }
                printf("%5d/tcp open  %-14s %s\n", pr[i].port, svc_name(pr[i].port), banner);
                close(pr[i].fd);
            }
        }
    }
    printf("done: %d open, %d closed, %d filtered/no answer\n", nopen, nclosed, nfilt);
    free(pr);
    return 0;
usage:
    fprintf(stderr, "usage: scan [-p PORTS] [-t MS] [-b] HOST     TCP connect scan (PORTS: top | 22,80 | 1-1024)\n"
                    "       scan -s CIDR                          host sweep, e.g. scan -s 10.0.2.0/24\n"
                    "  -b grabs service banners. Only scan systems you own or are authorised to test.\n");
    return 2;
}

// ---- sniff --------------------------------------------------------------------------------------------
static volatile sig_atomic_t stop;
static void on_int(int s) { (void)s; stop = 1; }

static void dns_name(const unsigned char *d, int n, char *out, int on) {
    int o = 0, p = 12;
    while (p < n && d[p] && o < on - 2) {
        int l = d[p++];
        if (l > 63 || p + l > n) break;
        if (o) out[o++] = '.';
        for (int i = 0; i < l && o < on - 1; i++) out[o++] = d[p + i];
        p += l;
    }
    out[o] = 0;
}

static int cmd_sniff(int argc, char **argv) {
    const char *iface = 0, *wfile = 0;
    int count = 0, opt, verbose = 0;
    optind = 1;
    while ((opt = getopt(argc, argv, "i:c:w:v")) != -1) {
        if (opt == 'i') iface = optarg;
        else if (opt == 'c') count = atoi(optarg);
        else if (opt == 'w') wfile = optarg;
        else if (opt == 'v') verbose = 1;
        else { fprintf(stderr, "usage: sniff [-i IFACE] [-c COUNT] [-w FILE.pcap] [-v]\n  Ctrl+C to stop. Capturing needs root (the Terminal runs as root).\n"); return 2; }
    }
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) { perror("sniff: socket"); return 1; }
    if (iface) {
        struct sockaddr_ll sl = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = (int)if_nametoindex(iface) };
        if (!sl.sll_ifindex || bind(fd, (struct sockaddr *)&sl, sizeof sl)) { fprintf(stderr, "sniff: no such interface %s\n", iface); return 1; }
    }
    FILE *pc = 0;
    if (wfile) {
        pc = fopen(wfile, "wb");
        if (!pc) { perror("sniff: open"); return 1; }
        unsigned char gh[24] = { 0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0 };
        fwrite(gh, 1, 24, pc);
    }
    struct sigaction sa = { .sa_handler = on_int };
    sigaction(SIGINT, &sa, 0);
    sigaction(SIGTERM, &sa, 0);
    unsigned char buf[65536];
    int n = 0;
    struct timespec t0;
    clock_gettime(CLOCK_REALTIME, &t0);
    while (!stop && (!count || n < count)) {
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r < 14) continue;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        n++;
        if (pc) {
            unsigned h[4] = { (unsigned)ts.tv_sec, (unsigned)(ts.tv_nsec / 1000), (unsigned)r, (unsigned)r };
            fwrite(h, 4, 4, pc);
            fwrite(buf, 1, r, pc);
            fflush(pc);
        }
        double rel = (ts.tv_sec - t0.tv_sec) + (ts.tv_nsec - t0.tv_nsec) / 1e9;
        int et = buf[12] << 8 | buf[13];
        char line[300];
        if (et == 0x0806 && r >= 42) {
            char a[20], b[20];
            snprintf(a, sizeof a, "%d.%d.%d.%d", buf[38], buf[39], buf[40], buf[41]);
            snprintf(b, sizeof b, "%d.%d.%d.%d", buf[28], buf[29], buf[30], buf[31]);
            snprintf(line, sizeof line, "ARP  %s %s tell %s", buf[21] == 1 ? "who-has" : "is-at", a, b);
        } else if (et == 0x0800 && r >= 34) {
            const unsigned char *ip = buf + 14;
            int ihl = (ip[0] & 15) * 4, proto = ip[9];
            char s[20], d[20];
            snprintf(s, sizeof s, "%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]);
            snprintf(d, sizeof d, "%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19]);
            const unsigned char *l4 = ip + ihl;
            int l4n = (int)r - 14 - ihl;
            if (proto == 6 && l4n >= 20) {
                int sp = l4[0] << 8 | l4[1], dp = l4[2] << 8 | l4[3], fl = l4[13], off = (l4[12] >> 4) * 4;
                char fs[8] = "";
                if (fl & 2) strcat(fs, "S");
                if (fl & 16) strcat(fs, "A");
                if (fl & 1) strcat(fs, "F");
                if (fl & 4) strcat(fs, "R");
                if (fl & 8) strcat(fs, "P");
                int o = snprintf(line, sizeof line, "TCP  %s:%d > %s:%d [%s] len %d", s, sp, d, dp, fs, l4n - off);
                if (l4n > off + 4 && (sp == 80 || dp == 80 || sp == 8080 || dp == 8080)) {
                    const char *pl = (const char *)l4 + off;
                    if (!strncmp(pl, "GET ", 4) || !strncmp(pl, "POST ", 5) || !strncmp(pl, "HEAD ", 5) || !strncmp(pl, "HTTP/", 5)) {
                        int e = 0;
                        while (e < l4n - off && e < 80 && pl[e] != '\r' && pl[e] != '\n') e++;
                        snprintf(line + o, sizeof line - o, "  \"%.*s\"", e, pl);
                    }
                }
            } else if (proto == 17 && l4n >= 8) {
                int sp = l4[0] << 8 | l4[1], dp = l4[2] << 8 | l4[3];
                int o = snprintf(line, sizeof line, "UDP  %s:%d > %s:%d len %d", s, sp, d, dp, l4n - 8);
                if ((dp == 53 || sp == 53) && l4n > 20) {
                    char nm[128];
                    dns_name(l4 + 8, l4n - 8, nm, sizeof nm);
                    snprintf(line + o, sizeof line - o, "  DNS %s %s", (l4[10] & 0x80) ? "answer" : "query", nm);
                }
            } else if (proto == 1) snprintf(line, sizeof line, "ICMP %s > %s type %d", s, d, l4n > 0 ? l4[0] : -1);
            else snprintf(line, sizeof line, "IP   %s > %s proto %d", s, d, proto);
        } else snprintf(line, sizeof line, "ETH  type 0x%04x len %zd", et, r);
        printf("%9.3f %s\n", rel, line);
        if (verbose) {
            for (int i = 0; i < r && i < 96; i += 16) {
                printf("          %04x ", i);
                for (int k = 0; k < 16 && i + k < r; k++) printf("%02x ", buf[i + k]);
                printf("\n");
            }
        }
        fflush(stdout);
    }
    if (pc) fclose(pc);
    fprintf(stderr, "\n%d packets captured%s%s\n", n, wfile ? " -> " : "", wfile ? wfile : "");
    close(fd);
    return 0;
}

// ---- fetch ------------------------------------------------------------------------------------------------
static int cmd_fetch(int argc, char **argv) {
    const char *out = 0;
    int opt, quiet = 0;
    optind = 1;
    while ((opt = getopt(argc, argv, "o:q")) != -1) {
        if (opt == 'o') out = optarg;
        else if (opt == 'q') quiet = 1;
        else goto usage;
    }
    if (optind >= argc) goto usage;
    FILE *rc = fopen("/etc/resolv.conf", "r");        // follow the DNS the phone is using
    if (rc) {
        char l[200];
        while (fgets(l, sizeof l, rc)) {
            char ns[40];
            if (sscanf(l, "nameserver %39s", ns) == 1) { snprintf(dns_server, sizeof dns_server, "%s", ns); break; }
        }
        fclose(rc);
    }
    HttpResp *r = http_get(argv[optind]);
    if (!quiet) fprintf(stderr, "HTTP %d, %zu bytes, %.0f ms%s%s\n", r->status, r->len, r->ms, r->err[0] ? "  " : "", r->err);
    int code = r->status >= 200 && r->status < 400 ? 0 : 1;
    if (r->body) {
        FILE *o = out ? fopen(out, "wb") : stdout;
        if (!o) { perror("fetch: open"); http_free(r); return 1; }
        fwrite(r->body, 1, r->len, o);
        if (out) fclose(o);
    }
    http_free(r);
    return code;
usage:
    fprintf(stderr, "usage: fetch [-q] [-o FILE] URL     HTTPS GET with Lumen's own TLS stack (busybox wget is http-only)\n");
    return 2;
}

// ---- dispatch ---------------------------------------------------------------------------------------------
// returns the exit code if argv[0] names one of our tools, -1 otherwise (then main() boots the phone)
int tool_dispatch(int argc, char **argv) {
    char *tmp = strdup(argv[0]);
    const char *n = basename(tmp);
    int rc = -1;
    if (!strcmp(n, "apkinfo")) rc = cmd_apkinfo(argc, argv);
    else if (!strcmp(n, "pm")) rc = cmd_pm(argc, argv);
    else if (!strcmp(n, "scan")) rc = cmd_scan(argc, argv);
    else if (!strcmp(n, "sniff")) rc = cmd_sniff(argc, argv);
    else if (!strcmp(n, "fetch")) rc = cmd_fetch(argc, argv);
    free(tmp);
    return rc;
}
