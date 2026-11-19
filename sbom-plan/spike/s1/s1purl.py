#!/usr/bin/env -S python3 -I
"""Spike tool: NeuVector module -> purl mapping, purl build/parse, SBOM comparison and augmentation."""
import collections, glob, json, os, re, sys
from urllib.parse import quote, unquote

SPECS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "specs", "purl")

# ---------- purl build / parse ----------
_DEFS = {}
for _f in glob.glob(SPECS + "/types/*-definition.json"):
    _d = json.load(open(_f))
    _DEFS[_d["type"]] = _d
if not _DEFS:
    sys.exit("no purl type definitions in " + SPECS)


def _lower(t, part):  # part: "namespace_definition" or "name_definition"
    d = _DEFS.get(t, {}).get(part, {})
    return d.get("case_sensitive") is False or "shall be lowercased" in d.get("note", "")


def _enc(s):  # ECMA-427: keep unreserved chars and ':'
    return quote(s, safe=":")


def build_purl(type, namespace, name, version=None, qualifiers=None, subpath=None):
    t = type.lower()
    if not name:
        raise ValueError("name required")
    if namespace and _lower(t, "namespace_definition"):
        namespace = namespace.lower()
    if _lower(t, "name_definition"):
        name = name.lower()
    if t == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
    s = "pkg:" + t + "/"
    if namespace:
        s += "/".join(_enc(p) for p in namespace.strip("/").split("/")) + "/"
    s += _enc(name)
    if version:
        s += "@" + _enc(version)
    q = {k.lower(): v for k, v in (qualifiers or {}).items() if v not in (None, "")}
    if q:
        s += "?" + "&".join(k + "=" + _enc(q[k]) for k in sorted(q))
    if subpath:
        s += "#" + "/".join(_enc(p) for p in subpath.strip("/").split("/") if p not in ("", ".", ".."))
    return s


def parse_purl(p):
    """-> dict(type, namespace, name, version, qualifiers, subpath), percent-decoded, not normalized."""
    if not p.startswith("pkg:"):
        raise ValueError("no pkg: scheme")
    p = p[4:].lstrip("/")
    p, _, sub = p.partition("#")
    p, _, qs = p.partition("?")
    parts = p.split("/")
    if len(parts) < 2:
        raise ValueError("type/name required")
    parts[-1], _, ver = parts[-1].partition("@")  # version only after the last segment's '@' (scope may be unencoded)
    q = {}
    for kv in filter(None, qs.split("&")):
        k, _, v = kv.partition("=")
        q[k.lower()] = unquote(v)
    t, ns, n = parts[0].lower(), unquote("/".join(parts[1:-1])), unquote(parts[-1])
    if ns and _lower(t, "namespace_definition"):
        ns = ns.lower()
    if _lower(t, "name_definition"):
        n = n.lower()
    if t == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return {"type": t, "namespace": ns or None, "name": n, "version": unquote(ver) or None,
            "qualifiers": q or None, "subpath": unquote(sub).strip("/") or None}


def merge_key(purl):
    """type/namespace/name@version without qualifiers/subpath; case folded per type definition."""
    c = parse_purl(purl)
    t, ns, n, v = c["type"], c["namespace"] or "", c["name"], c["version"] or ""
    if t == "golang" and v.startswith("v"):
        v = v[1:]
    return t + "/" + (ns + "/" if ns else "") + n + "@" + v


def selftest():
    bad = 0
    for t in "deb apk rpm maven npm pypi golang gem nuget composer cran generic".split():
        tests = json.load(open("%s/tests/%s-test.json" % (SPECS, t)))["tests"]
        c = collections.Counter()
        for x in tests:
            if x["expected_failure"]:
                c["skip"] += 1
                print("  SKIPPED %s: %s (expected_failure vector; no validation rules implemented)" % (t, x["description"]))
                continue
            i, e, tt = x["input"], x["expected_output"], x["test_type"]
            for d in (i, e):  # test data bug: a description sentence sits in the subpath field; treat as no subpath
                if isinstance(d, dict) and (d.get("subpath") or "").startswith("Applied normalization"):
                    d["subpath"] = None
            try:
                if tt == "build":
                    ok = build_purl(i["type"], i["namespace"], i["name"], i["version"], i["qualifiers"], i["subpath"]) == e
                elif tt == "parse":
                    got = parse_purl(i)
                    ok = all(got[k] == e[k] for k in e)
                else:  # validate: roundtrip through parse + build
                    g = parse_purl(i)
                    ok = build_purl(g["type"], g["namespace"], g["name"], g["version"], g["qualifiers"], g["subpath"]) == e
            except Exception as ex:
                ok = False
            c[tt + (":pass" if ok else ":FAIL")] += 1
            if not ok:
                print("  FAIL %s/%s: %s" % (t, tt, x["description"]))
                bad += tt == "build"
        print("%-9s %s" % (t, dict(c)))
    print("build failures:", bad)
    return 1 if bad else 0


# ---------- NeuVector -> purl ----------
OS_MAP = {
    "debian": ("deb", "debian"), "ubuntu": ("deb", "ubuntu"), "alpine": ("apk", "alpine"),
    "wolfi": ("apk", "wolfi"), "chainguard": ("apk", "chainguard"), "rhel": ("rpm", "redhat"),
    "centos": ("rpm", "centos"), "fedora": ("rpm", "fedora"), "amzn": ("rpm", "amzn"), "ol": ("rpm", "ol"),
    "rocky": ("rpm", "rocky"), "almalinux": ("rpm", "almalinux"), "mariner": ("rpm", "mariner"),
    "azurelinux": ("rpm", "azurelinux"), "photon": ("rpm", "photon"), "sles": ("rpm", "sles"),
    "opensuse-leap": ("rpm", "opensuse"), "opensuse-tumbleweed": ("rpm", "opensuse"),
    "rhcos": ("rpm", "rhcos"), "suse-liberty": ("rpm", "suse-liberty"), "sl-micro": ("rpm", "sl-micro"),
    "sle-micro": ("rpm", "sle-micro"), "busybox": ("generic", ""),
}
OS_UNCERTAIN = {"rhcos", "suse-liberty", "sl-micro", "sle-micro"}


def _pre(name, prefix):
    return name[len(prefix):] if name.startswith(prefix) else name


def nv2purl(m, ns_source=""):
    """NeuVector module dict -> (purl or None, status, reason)."""
    try:
        return _nv2purl(m, ns_source)
    except ValueError as e:  # e.g. empty name after prefix strip
        return None, "impossible", str(e)


def _nv2purl(m, ns_source):
    name, ver, src, file = m.get("Name", ""), m.get("Version", ""), m.get("Source", ""), m.get("File", "")
    src = src or ns_source or ""
    g = lambda n: build_purl("generic", None, n, ver)
    if ":" in src or src == "":  # OS package: Source is "ID:VERSION"
        osid, _, osver = src.partition(":")
        if osid == "busybox":
            return g(name), "exact", ""
        if osid not in OS_MAP:
            return None, "impossible", "unknown package format for distro '%s'" % osid
        t, ns = OS_MAP[osid]
        st, why = ("uncertain", "distro namespace in Syft unverified") if osid in OS_UNCERTAIN else ("exact", "")
        q = {"distro": osid + "-" + osver} if osver else {}
        if name == "opensslxx":
            name, st, why = "openssl", "uncertain", "name 'opensslxx' rewritten to openssl"
        if t == "deb":
            if "/" in name:
                q["upstream"], name = name.split("/", 1)
        elif t == "apk":
            st, why = "uncertain", "; ".join(filter(None, [why, "origin name, binary names collapsed"]))
        elif t == "rpm" and ":" in ver:
            q["epoch"], ver = ver.split(":", 1)
        return build_purl(t, ns, name, ver, q), st, why
    if src == "jar":
        g_, _, a = name.partition(":")
        if not a:
            return None, "impossible", "no groupId in name"
        if g_ == "jar":
            return None, "impossible", "no groupId (manifest without vendor id)"
        if " " in a:  # MANIFEST Implementation-Title, not a maven artifactId
            return None, "impossible", "artifactId '%s' is a MANIFEST title" % a
        if "." not in g_:
            return build_purl("maven", g_, a, ver), "uncertain", "groupId '%s' has no dot, may be a MANIFEST vendor id" % g_
        return build_purl("maven", g_, a, ver), "exact", ""
    if src == "npm":
        ns, _, n = name.rpartition("/")
        return build_purl("npm", ns or None, n, ver), "exact", ""
    if src == "python":
        return build_purl("pypi", None, _pre(name, "python:"), ver), "exact", ""
    if src == "ruby":
        return build_purl("gem", None, _pre(name, "ruby:"), ver), "exact", ""
    if src == "golang":
        n = _pre(name, "go:")
        if n == "stdlib":
            return build_purl("golang", None, "stdlib", ver), "exact", ""
        ns, _, last = n.rpartition("/")
        v = "v" + ver if ver else ""
        st, why = ("uncertain", "synthetic module, version from image tag") if file == "kubernetes" else ("exact", "")
        return build_purl("golang", ns or None, last, v), st, why
    if src == ".NET":
        return build_purl("nuget", None, _pre(name, ".NET:"), ver), "exact", ""
    if src == "php":
        if name in ("php:", "php"):
            return g("php"), "uncertain", "PHP runtime mapped to generic"
        return None, "impossible", "composer vendor (namespace) dropped by NeuVector"
    if src == "r":
        n = _pre(name, "r:")
        n = n.split("-", 1)[1] if "-" in n else n
        return build_purl("cran", None, n, ver), "uncertain", "case lost (name lowercased), cran names are case-sensitive"
    if src == "Wordpress":
        return g("wordpress"), "uncertain", "wordpress as generic"
    if src in ("nginx", "openssl"):
        return g(src), "uncertain", "duplicate of OS module added only for CVE matching"
    if src == "busybox":
        return g("busybox"), "exact", ""
    return build_purl("bitnami", None, name, ver), "uncertain", "bitnami purl type not in specs; revision '-N' stripped by NeuVector"


def nvtest():
    P = lambda **k: nv2purl(k, k.get("ns", ""))
    r = nv2purl({"Name": "glibc/libc6", "Version": "2.36-9", "Source": "debian:12"})
    assert r == ("pkg:deb/debian/libc6@2.36-9?distro=debian-12&upstream=glibc", "exact", ""), r
    r = nv2purl({"Name": "bash", "Version": "1:5.2", "Source": "rhel:9.4"})
    assert r[0] == "pkg:rpm/redhat/bash@5.2?distro=rhel-9.4&epoch=1" and r[1] == "exact", r
    r = nv2purl({"Name": "musl", "Version": "1.2.5-r0", "Source": "alpine:3.20.3"})
    assert r[0].startswith("pkg:apk/alpine/musl@1.2.5-r0") and r[1] == "uncertain", r
    assert nv2purl({"Name": "x", "Version": "1", "Source": "foo:1"})[1] == "impossible"
    assert nv2purl({"Name": "busybox", "Version": "1.36.1", "Source": "busybox:1.36.1"})[0] == "pkg:generic/busybox@1.36.1"
    assert nv2purl({"Name": "opensslxx", "Version": "3.0", "Source": "debian:12"})[1] == "uncertain"
    assert nv2purl({"Name": "@angular/core", "Version": "1.0", "Source": "npm"})[0] == "pkg:npm/%40angular/core@1.0"
    assert nv2purl({"Name": "python:My_Pkg.X", "Version": "2", "Source": "python"})[0] == "pkg:pypi/my-pkg-x@2"
    assert nv2purl({"Name": "ruby:rack", "Version": "3", "Source": "ruby"})[0] == "pkg:gem/rack@3"
    assert nv2purl({"Name": "go:github.com/a/b", "Version": "1.2.3", "Source": "golang"})[0] == "pkg:golang/github.com/a/b@v1.2.3"
    assert nv2purl({"Name": "go:stdlib", "Version": "1.22.1", "Source": "golang"})[0] == "pkg:golang/stdlib@1.22.1"
    assert nv2purl({"Name": "go:k8s.io/ingress-nginx", "Version": "1.9", "Source": "golang", "File": "kubernetes"})[1] == "uncertain"
    assert nv2purl({"Name": "org.apache:commons", "Version": "1", "Source": "jar"})[1] == "exact"
    assert nv2purl({"Name": "jar:foo", "Version": "1", "Source": "jar"})[1] == "impossible"
    assert nv2purl({"Name": "spring-boot:foo", "Version": "1", "Source": "jar"})[1] == "uncertain"
    assert nv2purl({"Name": "org.apache.logging.log4j:Apache Log4j Core", "Version": "1", "Source": "jar"})[1] == "impossible"
    assert nv2purl({"Name": "NLog", "Version": "4", "Source": ".NET"}) [0] == "pkg:nuget/NLog@4"
    assert nv2purl({"Name": "php:", "Version": "8", "Source": "php"})[0] == "pkg:generic/php@8"
    assert nv2purl({"Name": "php:monolog", "Version": "8", "Source": "php"})[1] == "impossible"
    r = nv2purl({"Name": "cran-ggplot2", "Version": "3.0", "Source": "r"})
    assert r[0] == "pkg:cran/ggplot2@3.0" and r[1] == "uncertain", r
    assert nv2purl({"Name": "redis", "Version": "7.2.4", "Source": "redis"})[0] == "pkg:bitnami/redis@7.2.4"
    assert merge_key("pkg:golang/github.com/A/b@v1.0") == merge_key("pkg:golang/github.com/a/b@1.0")
    print("nvtest ok")


# ---------- loading / comparison ----------
def load(path):
    """-> (kind, entries[(purl|None, label, extra)], nv_statuses)"""
    d = json.load(open(path))
    if "Modules" in d or "ImageID" in d or "Namespace" in d or "Error" in d:
        out, st = [], []
        for m in d.get("Modules") or []:
            if m.get("Origin"):
                continue
            p, s, why = nv2purl(m, d.get("Namespace", ""))
            st.append((s, why, m))
            out.append((p, "%s %s [%s]" % (m.get("Name"), m.get("Version"), m.get("Source")), None))
        return "neuvector", out, st
    if "artifacts" in d:
        return "syft", [(a.get("purl") or None, "%s %s (%s)" % (a.get("name"), a.get("version"), a.get("type")), a) for a in d["artifacts"]], []
    if d.get("bomFormat") == "CycloneDX":
        out = []
        def walk(cs):
            for c in cs or []:
                if c.get("type") in ("file", "operating-system"):  # not packages
                    continue
                out.append((c.get("purl") or None, "%s %s" % (c.get("name"), c.get("version")), c))
                walk(c.get("components"))
        walk(d.get("components"))
        return "cyclonedx", out, []
    raise ValueError("unknown format: " + path)


def keyset(entries):
    keys, nop = {}, []
    for p, label, _ in entries:
        if p is None:
            nop.append(label)
        else:
            keys.setdefault(merge_key(p), []).append(label)
    return keys, nop


def compare(a, b, jout=None):
    ka, ia, sa = load(a)
    kb, ib, sb = load(b)
    A, nopa = keyset(ia)
    B, nopb = keyset(ib)
    I, U = set(A) & set(B), set(A) | set(B)
    pct = lambda x, y: "%.1f%%" % (100.0 * x / y if y else 0)
    out = {"a": a, "b": b, "A": len(A), "B": len(B), "intersection": len(I), "A_only": len(set(A) - set(B)),
           "B_only": len(set(B) - set(A)), "agreement": pct(len(I), len(U)), "I/A": pct(len(I), len(A)), "I/B": pct(len(I), len(B))}
    typ = lambda k: k.split("/", 1)[0]
    out["per_type"] = {}
    for t in sorted({typ(k) for k in U}):
        ta, tb = {k for k in A if typ(k) == t}, {k for k in B if typ(k) == t}
        out["per_type"][t] = {"A": len(ta), "B": len(tb), "both": len(ta & tb), "agreement": pct(len(ta & tb), len(ta | tb))}
    ao, bo = sorted(set(A) - set(B)), sorted(set(B) - set(A))
    nov = lambda k: k.rsplit("@", 1)[0]
    bmap = collections.defaultdict(list)
    for k in bo:
        bmap[nov(k)].append(k)
    out["A_only_keys"], out["B_only_keys"] = ao, bo
    out["version_diff"] = [[k, v] for k in ao for v in bmap.get(nov(k), [])]
    out["no_purl_A"], out["no_purl_B"] = nopa, nopb
    out["nv_status"] = {}
    for side, st in (("A", sa), ("B", sb)):
        if st:
            out["nv_status"][side] = dict(collections.Counter(s for s, _, _ in st))
            out["nv_status_items"] = out.get("nv_status_items", []) + [
                {"side": side, "status": s, "reason": w, "name": m.get("Name"), "version": m.get("Version"), "source": m.get("Source")}
                for s, w, m in st if s != "exact"]
    print("A=%s (%s)  B=%s (%s)" % (a, ka, b, kb))
    for k in ("A", "B", "intersection", "A_only", "B_only", "agreement", "I/A", "I/B"):
        print("%-13s %s" % (k, out[k]))
    print("\nper type:")
    for t, v in out["per_type"].items():
        print("  %-10s %s" % (t, v))
    for side, n in (("A", nopa), ("B", nopb)):
        print("\nno purl in %s: %d" % (side, len(n)))
        for x in n:
            print("  " + x)
    if out["nv_status"]:
        print("\nnv2purl status:", out["nv_status"])
        for it in out["nv_status_items"]:
            print("  %s %s %s@%s [%s]: %s" % (it["side"], it["status"], it["name"], it["version"], it["source"], it["reason"]))
    print("\nA-only (%d):" % len(ao)); [print("  " + k) for k in ao]
    print("\nB-only (%d):" % len(bo)); [print("  " + k) for k in bo]
    print("\nsame type/namespace/name, different version (%d):" % len(out["version_diff"]))
    for k, v in out["version_diff"]:
        print("  A %s  <->  B %s" % (k, v))
    if jout:
        json.dump(out, open(jout, "w"), indent=1)


def augment(nvp, syp, outp):
    nv = json.load(open(nvp))
    sy = json.load(open(syp))
    lic, pk = {}, {}
    for a in sy["artifacts"]:
        if not a.get("purl"):
            continue
        k = merge_key(a["purl"])
        ls = [l.get("spdxExpression") or l.get("value") for l in a.get("licenses") or []]
        lic.setdefault(k, [])
        lic[k] += [x for x in ls if x and x not in lic[k]]
        pk.setdefault(k, a)
    nvk, withlic, nopurl = set(), 0, 0
    for m in nv.get("Modules") or []:
        p, _, _ = nv2purl(m, nv.get("Namespace", ""))
        m["Purl"] = p or ""
        if p:
            k = merge_key(p)
            nvk.add(k)
            if lic.get(k):
                m["Licenses"] = lic[k]
                withlic += 1
        else:
            nopurl += 1
    added = 0
    for k, a in pk.items():
        if k not in nvk:
            nv.setdefault("Modules", []).append({"Name": a["name"], "Version": a.get("version", ""), "Purl": a["purl"],
                                                 "Licenses": lic[k], "Origin": "syft"})
            added += 1
    json.dump(nv, open(outp, "w"))
    print("nv modules=%d (no purl=%d, with licenses=%d) syft packages=%d (no purl skipped=%d) added=%d"
          % (len(nv.get("Modules") or []) - added, nopurl, withlic, len(pk), len(sy["artifacts"]) - sum(1 for a in sy["artifacts"] if a.get("purl")), added))


def osmap():
    print("| NeuVector distro ID | purl type | purl namespace |\n|---|---|---|")
    for k, (t, ns) in OS_MAP.items():
        print("| %s | %s | %s%s |" % (k, t, ns or "(none)", " (uncertain)" if k in OS_UNCERTAIN else ""))
    print("| any other ID | - | impossible (unknown package format) |")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["selftest"]:
        r = selftest()
        nvtest()
        sys.exit(r)
    elif a[:1] == ["nvtest"]:
        nvtest()
    elif a[:1] == ["compare"] and len(a) >= 3:
        compare(a[1], a[2], a[a.index("--json") + 1] if "--json" in a else None)
    elif a[:1] == ["augment"] and len(a) == 4:
        augment(*a[1:])
    elif a[:1] == ["osmap"]:
        osmap()
    else:
        sys.exit("usage: s1purl.py selftest|nvtest|compare A B [--json out]|augment nv syft out|osmap")
