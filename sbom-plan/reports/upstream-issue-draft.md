# Projekt issue do `neuvector/neuvector` (do zatwierdzenia przez użytkownika)

Wymóg `CONTRIBUTING.md` dla dużych zmian: najpierw issue z opisem zmiany i powodu. Nic nie zostało wysłane. Przed wysłaniem: sprawdź treść, usuń decyzje, których nie chcesz ogłaszać, i zdecyduj o sprawach z `HANDOFF.md` §11.

---

**Title:** Feature proposal: SBOM export (CycloneDX/SPDX), component search, version-range admission rule and optional Dependency-Track / S3 integration

**Problem**

NeuVector already collects a full package inventory for images, running containers and nodes (`ScanResult.Modules`), but users cannot:
- download it as a standard SBOM (CycloneDX 1.6 / SPDX 2.3),
- find every pod that runs a given library version when no CVE exists yet (for example a newly reported RCE),
- block deployment of an image that contains a library in a version range,
- send SBOMs to Dependency-Track.

**Proposal** (split into separate PRs, one topic each; vendor and generated code in separate commits)

1. **Inventory fields** – `ScanModule` gets `Purl`, `Licenses`, `Origin` (proto fields 7–9). A shared purl builder in `share/scan` (ECMA-427, tested with the official purl-spec vectors). The controller computes a purl on the fly for old reports. A guard keeps registry reports below the 512 KiB KV limit.
2. **SBOM export + RBAC** – `GET /v1/scan/{workload|image|host}/:id/sbom` and `GET /v1/scan/registry/:name/image/:id/sbom`, `format=cyclonedx|spdx` (`cyclonedx-go` v0.12.0, `spdx/tools-golang` v0.5.7; no existing dependency is bumped). New permission `sbom` with namespace scope. Packages found only at runtime are marked with a property.
3. **Component search + admission** – `GET /v1/scan/component?name=&purl=&version=` (version ranges, RBAC-filtered). The `modules` admission criterion accepts ranges such as `group:artifact>=2.0.0<2.17.1`; existing rules behave as before.
4. **Dependency-Track (optional, off by default)** – leader-only upload after scans, project name/version/tag templates from cluster, namespace, owner and labels, inactive marking with leader/sync/grace-period guards.
5. **Scanner: Syft for images** – Syft v1.42.4 runs on the already extracted layers (no second image pull), adds licenses and packages NeuVector does not detect (`Origin=syft`, no effect on CVE matching or existing admission rules). Can be disabled. Needs two minor dependency bumps (`hashicorp/go-version` 1.8.0, `mattn/go-runewidth` 0.0.19).
6. **Optional S3 storage of full SBOMs** – off by default; registry scans only; uses `aws-sdk-go` v1 `service/s3` from the module already vendored.
7. **Manager UI** – SBOM tab, Components view, Dependency-Track and S3 settings, `sbom` permission in the role editor.

**Measurements** (5 public images): Syft agreement after merge 99.1 %; largest KV report 77 KB gzip (15 % of the limit); scan time +0–3 s (one large npm image +15 s); scanner memory +230–570 MB.

**Questions for maintainers**
- Is this split acceptable, and should Syft be on or off by default?
- Should the S3 / Dependency-Track configuration need the `sbom` write permission (current proposal) or `config`?
- Is `aws-sdk-go` v1 acceptable for S3, or do you require v2?
- Version-range admission rules in federation with older managed clusters: require a minimum version or block ranges in fed rules?
