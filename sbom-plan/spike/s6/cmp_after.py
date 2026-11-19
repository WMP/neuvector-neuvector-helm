"""Agreement of a scanner ScanResult (with Purl, Origin=syft) vs `syft registry:` JSON.
Usage: python3 -I cmp_after.py <nv-raw.json> <syft-image.json>
Key = merge_key(purl) from s1purl.py. Agreement = |A n B| / |A u B|."""
import json, os, sys, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "s1"))
import s1purl

nv, sy = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
A, nopurl = set(), 0
for m in nv.get("Modules") or []:
    p = m.get("Purl")
    if not p:
        nopurl += 1
        continue
    A.add(s1purl.merge_key(p))
# NV folds apk binaries into the origin module; the merge maps them there (cvetools/syft.go)
origin = {}
for m in nv.get("Modules") or []:
    if m.get("Purl", "").startswith("pkg:apk/") and not m.get("Origin"):
        ns = s1purl.merge_key(m["Purl"]).split("/")[1]
        origin["apk/%s/%s@%s" % (ns, m["Name"].lower(), m["Version"])] = s1purl.merge_key(m["Purl"])
B = set()
for a in sy["artifacts"]:
    if not a.get("purl"):
        continue
    k = s1purl.merge_key(a["purl"])
    o = (a.get("metadata") or {}).get("originPackage")
    if k not in A and a.get("type") == "apk" and o:
        k = origin.get("apk/%s/%s@%s" % (k.split("/")[1], o.lower(), a.get("version")), k)
    B.add(k)
I, U = A & B, A | B
cnt = collections.Counter(s1purl.merge_key(m["Purl"]) for m in nv.get("Modules") or [] if m.get("Purl"))
out = {"modules": len(nv.get("Modules") or []),
       "syft_only_modules": sum(1 for m in nv.get("Modules") or [] if m.get("Origin") == "syft"),
       "with_licenses": sum(1 for m in nv.get("Modules") or [] if m.get("Licenses")),
       "no_purl": nopurl, "A": len(A), "B": len(B), "both": len(I),
       "agreement": round(100.0 * len(I) / len(U), 1) if U else 0, "B_covered": round(100.0 * len(I) / len(B), 1) if B else 0,
       "dup_keys": sum(1 for v in cnt.values() if v > 1), "A_only": sorted(A - B)[:40], "B_only": sorted(B - A)[:40]}
print(json.dumps(out, indent=1))
