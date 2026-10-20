// shield: Lumen's privacy layer. DNS tracker blocking, private DNS, MAC randomisation,
// HTTPS-only, lock-screen PIN. Settings are cached in memory so network threads can
// read them without touching the store.
#pragma once
#include <stdbool.h>

void shield_init(void);                  // after store_init()
bool shield_trackers_on(void);
bool shield_mac_random(void);
bool shield_https_only(void);
bool shield_weather_on(void);
int shield_dns_choice(void);             // 0 network (DHCP), 1 Quad9, 2 Cloudflare, 3 Mullvad
const char *shield_dns_name(int choice);
const char *shield_dns_override(void);   // NULL when following DHCP
void shield_set(const char *what, int val);   // "trackers" "mac" "https" "weather" "dns"

// blocklist: built-in list + /data/shield/custom.txt (domains or hosts-file lines)
bool shield_blocked_host(const char *host);   // thread-safe; counts and logs hits
long shield_block_count(void);
int shield_blocklist_size(void);
int shield_recent_blocked(char out[][64], int max);
void shield_reload(void);
char *shield_upgrade_url(const char *url);    // http:// -> https:// when HTTPS-only is on (malloc'd) else NULL

// lock-screen PIN (salted, iterated SHA-256). This gates the UI only: data on disk is not encrypted.
bool shield_pin_enabled(void);
int shield_pin_check(const char *pin);   // 0 ok, 1 wrong, 2 locked out
int shield_pin_lock_left(void);          // seconds of lockout remaining
bool shield_pin_set(const char *pin);    // 4..12 digits; "" removes the PIN
