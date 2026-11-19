# Pakiet startowy: SBOM w NeuVector

Pakiet dla sesji organizatora pracy. Sesja organizatora dzieli pracę na sesje wykonawcze według `SESSIONS.md`.

## Kolejność czytania

1. `HANDOFF.md`: cel, decyzje, ustalenia z kodu (pliki i linie).
2. `SESSIONS.md`: sesje wykonawcze, zależności, kryteria odbioru.
3. `TEST-RUNBOOK.md`: instrukcja dla agenta testowego w sieci wewnętrznej.
4. `spike/`: wyniki testów kompilacji i programy próbne.
5. `specs/`: specyfikacje formatów (CycloneDX 1.6, SPDX 2.3, purl) i skrypt walidacji. Źródła: `specs/SOURCES.md`.

## Repozytoria

Nazwa klonu i forka: `OWNER-REPO`.

| Upstream | Fork WMP | Katalog klonu | Status |
|---|---|---|---|
| `neuvector/neuvector` | `WMP/neuvector-neuvector` | `neuvector-neuvector` | jest |
| `neuvector/scanner` | `WMP/neuvector-scanner` | `neuvector-scanner` | jest |
| `anchore/syft` | `WMP/anchore-syft` | `anchore-syft` | jest, tylko do czytania |
| `neuvector/manager` | `WMP/neuvector-manager` | `neuvector-manager` | jest |
| `neuvector/neuvector-helm` | `WMP/neuvector-neuvector-helm` | `neuvector-neuvector-helm` | jest. Gałąź `claude/nifty-fermi-4ust84` przechowuje ten pakiet (`sbom-plan/`) |

Uwaga (korekta nadzorcy, 2026-11-19): fork głównego repozytorium nazywa się `WMP/neuvector-neuvector`. W `replace` w skanerze (S6) użyj `github.com/WMP/neuvector-neuvector`.

## Zasady pracy

- Kod tylko w tej sesji i w sesjach wykonawczych. Testy na żywym klastrze robi osobny agent w sieci wewnętrznej (`TEST-RUNBOOK.md`).
- Docelowo PR do repozytoriów upstream. Zasady upstream (`neuvector/CONTRIBUTING.md`):
  - Duża funkcja: najpierw issue z opisem zmiany i powodu.
  - Jeden PR = jedna sprawa.
  - Zmiany w `vendor/` i w kodzie generowanym w osobnym commicie.
  - Styl commitów: `feat:`, `fix:`, `chore:`, `deps(go):`.
- Bez podnoszenia wersji istniejących zależności. Wyjątek zatwierdzony przez użytkownika: Syft v1.42.4 w skanerze (2 drobne podniesienia, patrz `spike/RESULTS.md`).
- Bez danych klientów. Do testów tylko publiczne obrazy testowe.
