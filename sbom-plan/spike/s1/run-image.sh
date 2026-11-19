#!/usr/bin/env bash
# Spike driver: run all measurements for one image. Usage: run-image.sh <image-ref> <outdir>
set -euo pipefail
IMG=${1:?image ref}; OUT=${2:?outdir}
CRANE=/root/go/bin/crane; B=/root/s1/bin; T=/root/s1/tools
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
step() { # step <name> <cmd...> : print, time, run (failures are logged and do not stop the run)
  local n=$1; shift
  echo "=== [$n] $*"; local s=$SECONDS
  "$@" || echo "!!! [$n] failed rc=$?"
  echo "=== [$n] took $((SECONDS - s))s" | tee -a "$OUT/timings.txt"
}
sh_step() { local n=$1; shift; step "$n" bash -o pipefail -c "$*"; }

sh_step digest "$CRANE digest --platform linux/amd64 '$IMG' > '$OUT/digest.txt'"
sh_step syft "$B/syft registry:'$IMG' --platform linux/amd64 -o syft-json='$OUT/syft-image.json' -o cyclonedx-json='$OUT/syft-image.cdx.json'"
# no -no_task / -no_wait handling needed beyond what scanner.go accepts; verify flags there if this fails
rm -rf "$OUT/linkdir" "$OUT/nv-raw.json" /var/neuvector/scan_result.json  # no stale results
sh_step nv-scan "S1_RAW_OUT='$OUT/nv-raw.json' S1_LINKDIR='$OUT/linkdir' $B/scanner-mod -license on_demand -d /root/s1/db/ -image '$IMG' -no_task -no_wait > '$OUT/nv-scan.log' 2>&1"
[ -f /var/neuvector/scan_result.json ] && cp /var/neuvector/scan_result.json "$OUT/" || true
sh_step probe-linkdir "$B/sbomprobe '$OUT/linkdir' > '$OUT/sbomprobe-linkdir.cdx.json'"
# rootfs + `syft dir:` is NOT used: Syft directorysource follows absolute symlinks to host files (see S1-RESULTS)
sh_step symlinks "{ echo image_symlinks=\$($CRANE export --platform linux/amd64 '$IMG' - | tar -tv | grep -c '^l'); echo linkdir_symlinks=\$(find '$OUT/linkdir' -type l | wc -l); } | tee '$OUT/symlinks.txt'"
P="python3 -I $T/s1purl.py"
sh_step cmp-nv-syft "$P compare '$OUT/nv-raw.json' '$OUT/syft-image.json' --json '$OUT/cmp-nv-syft.json' > '$OUT/cmp-nv-syft.txt'"
sh_step cmp-linkdir-image "$P compare '$OUT/sbomprobe-linkdir.cdx.json' '$OUT/syft-image.cdx.json' --json '$OUT/cmp-linkdir-image.json' > '$OUT/cmp-linkdir-image.txt'"
# same linkdir, but with Syft's image catalogers (what S6 must select; dir default = declared/lock-file catalogers)
sh_step syft-linkdir-imagecat "$B/syft dir:'$OUT/linkdir' --override-default-catalogers image -q -o syft-json='$OUT/syft-linkdir-imagecat.json'"
sh_step cmp-linkdir-imagecat "$P compare '$OUT/syft-linkdir-imagecat.json' '$OUT/syft-image.json' --json '$OUT/cmp-linkdir-imagecat.json' > '$OUT/cmp-linkdir-imagecat.txt'"
sh_step augment "$P augment '$OUT/nv-raw.json' '$OUT/syft-image.json' '$OUT/nv-augmented.json'"
sh_step size "$B/s1size '$OUT/nv-augmented.json' | tee '$OUT/size.txt'"
[ "${KEEP:-0}" = 1 ] || rm -rf "$OUT/linkdir"
