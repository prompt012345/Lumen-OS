// apkcore: everything Lumen knows about .apk files, with no UI attached.
// ZIP reader, Android binary XML (AndroidManifest) parser, signing-block and
// PKCS#7 certificate reader, static analysis (permissions, flags, trackers,
// secrets, cleartext endpoints) and a tiny package store under /data/app.
//
// Used by the Packages app (apps/pkg.c) and by the CLI tools `apkinfo` / `pm`
// (tools.c). Pure libc + BearSSL (SHA-256) + net/inflate.c: no other deps.
#pragma once
#include <stddef.h>
#include <stdint.h>

enum { SEV_INFO, SEV_LOW, SEV_MED, SEV_HIGH };

typedef struct { char *name; int level; } ApkPerm;                 // level: 0 normal, 1 dangerous, 2 high-risk/special
typedef struct { char *name; char kind; int exported; int filter; char *perm; } ApkComp;   // kind: a s r p (activity, service, receiver, provider)
typedef struct { int sev; char *text; } ApkFinding;

typedef struct {
    char path[512];
    uint64_t size;
    char sha256[65];
    char package[160], vname[64], label[128], launcher[200];
    uint32_t vcode;
    int min_sdk, target_sdk;
    int debuggable, allow_backup, cleartext, test_only, netsec;    // -1 absent, 0 false, 1 true
    ApkPerm *perms; int nperms;
    ApkComp *comps; int ncomps;
    char **trackers; int ntrackers;       // known tracker / ad SDKs found by string match in classes*.dex
    char **urls; int nurls;               // distinct cleartext http:// endpoints found in classes*.dex
    ApkFinding *finds; int nfinds;
    char signer_sha256[65], signer_subject[256], signer_from[16], signer_to[16];
    int sig_v1, sig_v2, sig_v3, debug_cert;
    char abis[96];
    int ndex, nentries;
    int risk;                              // 0..100
} ApkInfo;

// 0 on success. On failure err describes the problem (ApkInfo is still safe to free).
int apk_analyze(const char *path, ApkInfo *ai, char *err, size_t errn);
void apk_info_free(ApkInfo *ai);
const char *apk_risk_label(int risk);      // LOW / MEDIUM / HIGH / CRITICAL
char *apk_report(const ApkInfo *ai);       // malloc'd plain-text report (for the terminal)
int apk_perm_level(const char *name);

// ---- package store (root is normally /data/app, one directory per package) --------------
typedef void (*ApkProgress)(void *ctx, int pct);
// copies the apk to <root>/<package>/base.apk, extracts native libs for the best ABI and
// writes info.txt. If a package with the same name is installed and was signed by a
// different key the install is refused (returns -2) unless force is set.
int apk_install(const char *path, const char *root, const ApkInfo *ai, int force, ApkProgress prog, void *ctx, char *err, size_t errn);
int apk_uninstall(const char *root, const char *package);

typedef struct { char pkg[160], label[128], version[64], sha256[65], signer[65]; int risk; long when; uint64_t size; } ApkInstalled;
int apk_installed_list(const char *root, ApkInstalled **out);    // returns count, caller frees *out
int apk_installed_get(const char *root, const char *pkg, ApkInstalled *out);   // 0 if installed
int apk_valid_package_name(const char *s);
