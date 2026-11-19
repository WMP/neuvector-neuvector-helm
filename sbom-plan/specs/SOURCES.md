# Specyfikacje SBOM – źródła

Pobrane 2026-11-19. Odtworzenie: `cd specs && ./fetch-specs.sh` (wersje przypięte w skrypcie).

| Katalog | Co | Źródło | Wersja | Licencja |
|---|---|---|---|---|
| `cyclonedx-1.6/` | Schemat JSON CycloneDX 1.6 + schematy, do których się odwołuje (`spdx.schema.json`, `jsf-0.82.schema.json`) | `github.com/CycloneDX/specification` | tag `1.6` | Apache-2.0 |
| `spdx-2.3/` | Schemat JSON SPDX 2.3 | `github.com/spdx/spdx-spec` | tag `v2.3` | CC-BY-3.0 |
| `purl/specification/` | Specyfikacja purl (ECMA-427): budowanie, parsowanie, kwalifikatory, gramatyka | `github.com/package-url/purl-spec` | commit `5e4dd947` | MIT |
| `purl/types/` | Definicje typów purl (JSON) dla ekosystemów NV: deb, rpm, apk, maven, npm, pypi, golang, gem, nuget, composer, generic, cran | jw. | jw. | MIT |
| `purl/type-docs/` | Opisy tych typów (Markdown) | jw. | jw. | MIT |
| `purl/tests/` | Oficjalne wektory testowe purl (ogólne + dla każdego typu) | jw. | jw. | MIT |

Pełna specyfikacja tekstowa (HTML) do czytania:
- CycloneDX 1.6: https://cyclonedx.org/docs/1.6/json/
- SPDX 2.3: https://spdx.github.io/spdx-spec/v2.3/
- purl: `purl/specification/standard/Clause-5-Package-URL-Specification.md` (w pakiecie)

Specyfikacja API Dependency-Track: pobierz z własnej instancji DT (OpenAPI), bo zależy od wersji DT. **[weryfikacja]** Ścieżka do pliku OpenAPI w Twojej wersji DT.

## Walidacja

```bash
pip install jsonschema
python3 -I validate.py cyclonedx <sbom.cdx.json>
python3 -I validate.py spdx <sbom.spdx.json>
```

Skrypt działa offline: odwołania między schematami są rozwiązywane z plików lokalnych. Sprawdzony 2026-11-19: CycloneDX 1.6 z Syft (VALID), CycloneDX z błędnym `version` (INVALID, 1 błąd), minimalny SPDX 2.3 (VALID).

## Mapowanie ekosystemów NV → typ purl (punkt startowy dla S1)

| `Source` / `AppName` w NV | Typ purl |
|---|---|
| `debian:*`, `ubuntu:*` | `deb` |
| `centos:*`, `rhel:*`, `oracle:*`, `amzn:*`, `suse*`, `mariner:*` | `rpm` |
| `alpine:*` | `apk` |
| `jar` | `maven` |
| `npm` | `npm` |
| `python` | `pypi` |
| `golang` | `golang` |
| `ruby` | `gem` |
| `.NET` | `nuget` |
| `php` | `composer` |
| `r` | `cran` |
| `nginx`, `openssl`, `Wordpress`, inne | `generic` |

Nazwy przestrzeni nazw dystrybucji podane z pamięci. S1 sprawdza pełną listę w `neuvector-scanner/detectors/namespace.go`.
