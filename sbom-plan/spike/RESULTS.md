# Wyniki testów kompilacji (2026-11-19)

Wszystkie testy na kopiach repozytoriów (`git archive HEAD`), z `GOFLAGS=-mod=mod`. Toolchain Go wybierany automatycznie według dyrektywy `go` w `go.mod`: `neuvector-scanner` i `neuvector` budowane na go1.27.4 (`go version` w katalogu repozytorium), polecenia w `anchore-syft` na go1.26.8.

## Syft w `neuvector-scanner` (commit `a3c5110`)

| Wersja Syft | Podniesienia istniejących zależności | Kompilacja |
|---|---|---|
| v1.37.0 – v1.40.x | 0 w `go.mod` | **NIE**: `containerd` v1.7.x (też v1.7.36) nie kompiluje się z `runtime-spec` v1.3.0 (`oci/spec_opts.go`: `int64` vs `*int64`) |
| **v1.41.0 – v1.42.4** | **2**: `hashicorp/go-version` 1.7.0→1.8.0, `mattn/go-runewidth` 0.0.16→0.0.19 | **TAK** |
| v1.43.0 – v1.44.0 | 3 (+ `containerd/platforms`) | nie testowano |
| v1.45.0+ | 13–39, w tym `containerd/v2` | nie testowano |

Szczegóły dla v1.42.4:
- `go get github.com/anchore/syft@v1.42.4`: 180 nowych modułów, 2 podniesienia (jak wyżej). `containerd/v2` bez zmian (Syft wymaga v2.2.1, skaner ma v2.2.9).
- `go build ./...` OK. `go test ./cvetools/... ./detectors/...` OK.
- Binarka `cmd/scanner`: 97 812 464 B → 157 299 248 B (Syft wkompilowany).
- Program `sbomprobe/main.go` na katalogu z `/var/lib/dpkg/status` i `/etc/os-release`: CycloneDX 1.6, purl `pkg:deb/debian/bash@5.2-1?arch=amd64&distro=debian-12`.
- Bez importu `_ "modernc.org/sqlite"` Syft zwraca błąd: `sqlite driver is required for cataloging newer RPM databases`. Moduł `modernc.org/sqlite` już jest w `go.mod` skanera.

Daty wydania (proxy.golang.org): v1.37.0: 2025-11-03, v1.42.4: 2026-04-08, v1.44.0: 2026-04-29.

## Biblioteki formatów w `neuvector` (commit `c982a5e`)

- `go get github.com/CycloneDX/cyclonedx-go@v0.12.0 github.com/spdx/tools-golang@v0.5.7`.
- Podniesienia istniejących zależności: **0**. Nowe moduły: `cyclonedx-go`, `spdx/tools-golang`, `anchore/go-struct-converter`.
- `fmtprobe/main.go` kompiluje się.
- Dla porównania: enkodery formatów z Syft (`syft/format/cyclonedxjson`, `spdxjson`) dodają 153 moduły. Odrzucone.

## Rozmiar SBOM (duży przypadek)

`sbomprobe` na katalogu z 15 172 komponentami (cache modułów Go):

| Wariant | Rozmiar | gzip |
|---|---|---|
| Pełny CycloneDX z Syft | 18 190 665 B | 1 209 332 B |
| w tym `properties` Syft | ~11 MB | – |
| Odchudzony CycloneDX dla DT (`bom-ref`, `type`, `name`, `version`, `purl`, `licenses`) | 3 669 081 B (base64: 4 892 108 B) | 301 887 B |
| Inwentarz do KV (nazwa, wersja, purl, licencje) | 1 743 337 B | 90 364 B |

Wniosek: inwentarz mieści się w limicie KV 512 KB. Pełny dokument wymaga innego magazynu (S3, sesja S8).

## Jak powtórzyć

```bash
cd <kopia neuvector-scanner>
mkdir -p cmd/sbomprobe && cp spike/sbomprobe/main.go cmd/sbomprobe/
GOFLAGS=-mod=mod go get github.com/anchore/syft@v1.42.4
GOFLAGS=-mod=mod go build -o sbomprobe ./cmd/sbomprobe
./sbomprobe <katalog z systemem plików obrazu>
```
