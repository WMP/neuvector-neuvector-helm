# Komentarz do neuvector/neuvector#930 (do zatwierdzenia i wysłania przez użytkownika)

Issue #930 „List Software Bill of Materials (SBOM) for containers” (otwarte od 2023-07-26, bez odpowiedzi opiekunów, prośby o CycloneDX i SPDX w komentarzach). Ten tekst zastępuje `upstream-issue-draft.md` jako pierwszy krok z `SESSIONS.md` („Kolejność PR do upstream”). Nic nie zostało wysłane.

Przed wysłaniem:
- Zdecyduj, czy podać linki do forków `WMP/*` (gałęzie są niżej tylko z nazwy).
- Rozstrzygnij sprawy z `HANDOFF.md` §11, które pojawiają się w pytaniach (D22, uprawnienie `sbom` vs `config`, aws-sdk-go v1, federacja).
- Liczby pochodzą z testów na publicznych obrazach, a nie z klastra produkcyjnego.

---

Hi, we would like to contribute this feature and we have a working prototype. Following `CONTRIBUTING.md`, we want to agree on the design here before we open PRs.

**What already exists in NeuVector:** every scan (image, running container, node) already keeps the full package inventory in `ScanResult.Modules`, not only the vulnerable packages. The prototype builds the SBOM from this data, so it needs no second scan and no second image pull.

**Proposed scope** (one topic per PR; `vendor/` and generated code in separate commits; no existing dependency bumped in `neuvector`):

1. **Inventory fields:** `ScanModule` gets `Purl`, `Licenses` and `Origin` (proto fields 7–9). A small purl builder in `share/scan` (ECMA-427, tested with the official purl-spec test vectors). For old reports the controller computes the purl on the fly. A guard keeps registry reports below the 512 KiB KV limit.
2. **SBOM download + RBAC:** `GET /v1/scan/{workload|image|host}/:id/sbom` and `GET /v1/scan/registry/:name/image/:id/sbom` with `format=cyclonedx|spdx` (CycloneDX 1.6 JSON via `cyclonedx-go` v0.12.0, SPDX 2.3 JSON via `spdx/tools-golang` v0.5.7). New permission `sbom` with namespace scope. Packages that exist only in the running container (not in the image) get a `runtime` property.
3. **Component search + admission:** `GET /v1/scan/component?name=&purl=&version=` answers "which pods, nodes and images contain library X in version range Y", also when no CVE exists yet. Results are filtered by the user's RBAC scope. The `modules` admission criterion accepts version ranges, for example `org.apache.logging.log4j:log4j-core>=2.0.0<2.17.1`. Existing rules work as before.
4. **Scanner: Syft for images (optional):** Syft v1.42.4 runs as a library on the layers the scanner has already extracted. It adds licenses and packages NeuVector does not detect. Syft-only packages are marked `Origin=syft` and do not change CVE matching or existing admission rules. It can be turned off (`SCANNER_DISABLE_SYFT`). It needs 2 minor bumps in the scanner (`hashicorp/go-version` 1.8.0, `mattn/go-runewidth` 0.0.19).
5. **Dependency-Track upload (optional, off by default):** the leader uploads after each scan. Projects are nested cluster → Rancher project (`field.cattle.io/projectId`) → namespace → owner (ReplicaSet etc.) → container, with name, version and tag templates (for example a tag from a pod label). Projects of removed workloads are marked inactive after a grace period, only by the leader and only after a full cache sync. Needs Dependency-Track 4.12.7 or later.
6. **S3 storage of full SBOM documents (optional, off by default):** for registry scans only. It uses `aws-sdk-go` v1 `service/s3` from the module that is already vendored (no new module). It works with MinIO and IRSA.
7. **Manager UI:** SBOM tab (component list, CycloneDX/SPDX download), "Components" search view, Dependency-Track and S3 settings, and the `sbom` permission in the role editor.

**Measurements** (5 public images: `debian:12`, a Spring Boot app with log4j 2.14.1 on Alpine, `prometheus/node-exporter`, `apache/druid:30.0.1`, `n8nio/n8n:1.64.0`):
- Agreement with `syft registry:<image>` after the merge: 99.1 % of packages (purl-based key).
- Largest scan report in KV: 77 KB gzip, 15 % of the 512 KiB limit.
- `ScanImage` time: +0–3 s; one large npm image +15 s.
- Scanner memory: +230–570 MB with Syft enabled.
- Component search over 2 000 workloads × 500 packages: 3–5 s.
- Generated documents pass the official CycloneDX 1.6 and SPDX 2.3 JSON schemas.

**Test images:** the prototype is already built. The images are public on GitHub Container Registry (no login needed). They are test builds from our forks, not official releases, linux/amd64 only.

| Component | Image |
|---|---|
| controller | `ghcr.io/wmp/neuvector-controller:claude-sbom-integration-3137103` |
| enforcer | `ghcr.io/wmp/neuvector-enforcer:claude-sbom-integration-3137103` |
| scanner | `ghcr.io/wmp/neuvector-scanner:claude-sbom-s8-scanner-c27f6fe` |
| manager | `ghcr.io/wmp/neuvector-manager:claude-sbom-s7-ui-8ae5183` |

To try them, install NeuVector with the Helm chart and override the image repositories and tags. The scanner needs more memory with Syft enabled (we use a 3 Gi limit).

**Questions for the maintainers:**
1. Is this split into PRs acceptable? Do you want the optional parts (Syft, Dependency-Track, S3) in this repository at all?
2. Should Syft in the scanner be on or off by default?
3. Should the Dependency-Track and S3 settings need the `sbom` write permission (current prototype) or the `config` permission?
4. Is `aws-sdk-go` v1 acceptable for S3, or do you require v2 (new modules)?
5. Version-range admission rules in a federation: older managed clusters would read a range with the old parser and the rule would never match. Should we require a minimum version, or block ranges in federated rules?

If the direction is acceptable, we will start with PR 1 (inventory fields and purl), because the other parts depend on it.
