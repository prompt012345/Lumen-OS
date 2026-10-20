#!/bin/sh
# Runs inside the lumen-toolchain container.
#   /src   = repo (bind mount)      /kbuild = persistent docker volume (fast disk)
# Produces /src/build/Image and /src/build/initramfs.cpio
set -eu
KVER=6.12.113
K=/kbuild/linux-$KVER
OUT=/src/build
GEN=/kbuild/gen
JOBS=$(nproc)
mkdir -p "$OUT" "$GEN"

# ---- kernel -------------------------------------------------------------
if [ ! -d "$K" ]; then
  echo "[build] downloading linux-$KVER"
  curl -sSfL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz" | tar xJ -C /kbuild
fi
FRAG_SUM=$(md5sum /src/kernel/lumen.config | cut -d' ' -f1)
if [ "$(cat $K/.lumen-frag 2>/dev/null)" != "$FRAG_SUM" ]; then
  echo "[build] configuring kernel"
  make -C "$K" ARCH=arm64 allnoconfig >/dev/null
  (cd "$K" && ARCH=arm64 scripts/kconfig/merge_config.sh -m .config /src/kernel/lumen.config >/dev/null)
  make -C "$K" ARCH=arm64 olddefconfig >/dev/null
  # report fragment options that did not stick
  grep -E '^CONFIG_.*=y' /src/kernel/lumen.config | while read -r l; do
    grep -qx "$l" "$K/.config" || echo "[build] WARNING: $l not set"
  done
  echo "$FRAG_SUM" > "$K/.lumen-frag"
fi
make -C "$K" ARCH=arm64 -j"$JOBS" Image >/kbuild/kernel-build.log 2>&1 || { tail -40 /kbuild/kernel-build.log; exit 1; }
cp "$K/arch/arm64/boot/Image" "$OUT/Image"
# kernel UAPI headers (drm, input, sound, netlink) straight from this kernel
[ -f "$K/usr/include/drm/drm.h" ] || make -C "$K" ARCH=arm64 headers >/dev/null

# ---- BearSSL (the one TLS library) --------------------------------------
if [ ! -f /kbuild/bearssl/build/libbearssl.a ]; then
  echo "[build] building BearSSL"
  rm -rf /kbuild/bearssl && cp -r /src/third_party/bearssl /kbuild/bearssl
  make -C /kbuild/bearssl -j"$JOBS" lib tools >/dev/null
fi

# ---- CA bundle -> BearSSL trust anchors ----------------------------------
CA_SUM=$(md5sum /src/third_party/cacert.pem | cut -d' ' -f1)
if [ "$(cat $GEN/.ca 2>/dev/null)" != "$CA_SUM" ]; then
  echo "[build] converting Mozilla CA bundle"
  { echo '#include "bearssl.h"'; /kbuild/bearssl/build/brssl ta -q /src/third_party/cacert.pem;
    echo 'const br_x509_trust_anchor *lumen_tas = TAs; const size_t lumen_tas_num = TAs_NUM;'; } > "$GEN/ta.c"
  echo "$CA_SUM" > "$GEN/.ca"
fi

# ---- fonts: instance the variable font to static weights ------------------
if [ ! -f "$GEN/fonts/B800.ttf" ]; then
  echo "[build] instancing Bricolage Grotesque"
  mkdir -p "$GEN/fonts"
  VF=/src/third_party/fonts/BricolageGrotesque-VF.ttf
  fonttools varLib.instancer -q "$VF" wght=400 opsz=14 wdth=100 -o "$GEN/fonts/B400.ttf"
  fonttools varLib.instancer -q "$VF" wght=600 opsz=14 wdth=100 -o "$GEN/fonts/B600.ttf"
  fonttools varLib.instancer -q "$VF" wght=800 opsz=96 wdth=100 -o "$GEN/fonts/B800.ttf"
fi

# ---- Lab userland: busybox (static) + monospace font ----------------------
# (older toolchain images lack these packages, so install on demand)
if [ ! -x /bin/busybox.static ] || [ ! -f /usr/share/fonts/dejavu/DejaVuSansMono.ttf ]; then
  echo "[build] installing busybox-static + font-dejavu"
  apk add --no-cache busybox-static font-dejavu >/dev/null
fi
mkdir -p "$GEN/fonts"
cp /usr/share/fonts/dejavu/DejaVuSansMono.ttf "$GEN/fonts/Mono.ttf"

# ---- userland: one static binary ----------------------------------------
echo "[build] compiling lumen"
mkdir -p /kbuild/obj
CFLAGS="-O2 -g0 -std=gnu11 -Wall -Wno-unused-function -Wno-misleading-indentation -idirafter /kbuild/linux-$KVER/usr/include -I/src/src -I/src/third_party -I/kbuild/bearssl/inc -I$GEN -pthread"
OBJS=""
for f in $(cd /src/src && find . -name '*.c' | sort) ; do
  o=/kbuild/obj/$(echo "$f" | sed 's|^\./||; s|/|_|g; s|\.c$|.o|')
  if [ ! -f "$o" ] || [ "/src/src/$f" -nt "$o" ] || [ -n "$(find /src/src -name '*.h' -newer "$o" | head -1)" ]; then
    echo "  cc $f"
    gcc $CFLAGS -c "/src/src/$f" -o "$o" &
  fi
  OBJS="$OBJS $o"
  # cap parallelism
  while [ "$(jobs -p | wc -l)" -ge "$JOBS" ]; do sleep 0.05; done
done
wait
for o in $OBJS; do [ -f "$o" ] || { echo "compile failed"; exit 1; }; done
if [ ! -f /kbuild/obj/ta.o ] || [ "$GEN/ta.c" -nt /kbuild/obj/ta.o ]; then
  gcc -O2 -I/kbuild/bearssl/inc -c "$GEN/ta.c" -o /kbuild/obj/ta.o
fi
gcc -static -pthread -o /kbuild/lumen $OBJS /kbuild/obj/ta.o /kbuild/bearssl/build/libbearssl.a -lm
strip /kbuild/lumen

# ---- initramfs ------------------------------------------------------------
[ -x /kbuild/gen_init_cpio ] || gcc -O2 -o /kbuild/gen_init_cpio "$K/usr/gen_init_cpio.c"
BB=/bin/busybox.static
ETC=/kbuild/etc
rm -rf "$ETC"; mkdir -p "$ETC"
cat > "$ETC/profile" <<'EOP'
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/data/bin
export LUMEN_APPS=/data/app
export PS1='\[\e[38;5;190m\]lumen\[\e[0m\]:\[\e[38;5;117m\]\w\[\e[0m\]\$ '
alias ls='ls --color=auto'
alias ll='ls -lAh'
alias la='ls -A'
alias ..='cd ..'
cd "$HOME" 2>/dev/null
cat <<'EOB'
 Lumen Lab shell (busybox ash, root). Files in /data persist.
   pm install|list|info FILE.apk     apkinfo FILE.apk     fetch URL -o FILE
   scan -b HOST | scan -s CIDR       sniff -w cap.pcap    vi, nc, ping, wget, ip ...
   tracker blocklist: /data/shield/custom.txt   APK inbox: /data/Download
EOB
EOP
printf 'root:x:0:0:root:/data/home:/bin/sh\n' > "$ETC/passwd"
printf 'root:x:0:\n' > "$ETC/group"
printf '/bin/sh\n' > "$ETC/shells"
printf '127.0.0.1 localhost\n' > "$ETC/hosts"
printf 'nameserver 10.0.2.3\n' > "$ETC/resolv.conf"
cat > /kbuild/initramfs.list <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /tmp 1777 0 0
dir /data 0755 0 0
dir /root 0700 0 0
dir /fonts 0755 0 0
dir /bin 0755 0 0
dir /sbin 0755 0 0
dir /usr 0755 0 0
dir /usr/bin 0755 0 0
dir /usr/sbin 0755 0 0
dir /etc 0755 0 0
file /init /kbuild/lumen 0755 0 0
file /fonts/B400.ttf $GEN/fonts/B400.ttf 0644 0 0
file /fonts/B600.ttf $GEN/fonts/B600.ttf 0644 0 0
file /fonts/B800.ttf $GEN/fonts/B800.ttf 0644 0 0
file /fonts/Mono.ttf $GEN/fonts/Mono.ttf 0644 0 0
file /bin/busybox $BB 0755 0 0
file /etc/profile $ETC/profile 0644 0 0
file /etc/passwd $ETC/passwd 0644 0 0
file /etc/group $ETC/group 0644 0 0
file /etc/shells $ETC/shells 0644 0 0
file /etc/hosts $ETC/hosts 0644 0 0
file /etc/resolv.conf $ETC/resolv.conf 0644 0 0
EOF
# busybox applets -> symlinks (skip the ones that would fight our own PID 1)
$BB --list-full | while read -r p; do
  case "$p" in bin/busybox|*/init|linuxrc|*/halt|*/poweroff|*/reboot|*/getty|*/login|*/sulogin) continue;; esac
  echo "slink /$p /bin/busybox 0777 0 0"
done >> /kbuild/initramfs.list
# our own tools live inside /init and dispatch on argv[0]
for t in apkinfo pm scan sniff fetch; do echo "slink /bin/$t /init 0777 0 0" >> /kbuild/initramfs.list; done
/kbuild/gen_init_cpio /kbuild/initramfs.list > "$OUT/initramfs.cpio"
echo "[build] done: $(ls -la $OUT/Image $OUT/initramfs.cpio | awk '{print $5, $9}' | tr '\n' ' ')"
