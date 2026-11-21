# Instrukcja dla agenta testowego (sieć wewnętrzna)

Agent testowy nie zmienia kodu. Agent wdraża obrazy z `ghcr.io`, wykonuje testy i zapisuje raport.

## Zasady
- Tylko klaster testowy. Nigdy klaster klienta.
- Tylko publiczne obrazy testowe (lista niżej). Bez danych klientów.
- W raporcie nie umieszczaj adresów wewnętrznych, kluczy API ani nazw hostów. Zastąp je symbolami, np. `<DT_URL>`.

## Specyfikacje
Pakiet zawiera katalog `specs/` (CycloneDX 1.6, SPDX 2.3, purl, skrypt `validate.py`). Skopiuj go na maszynę testową. Źródła i wersje: `specs/SOURCES.md`. Aktualizacja: `specs/fetch-specs.sh`.

## Dane wejściowe od organizatora
- Tagi obrazów: `controller`, `enforcer`, `scanner`, `manager` (format `<branch>-<sha>`).
- Numer sesji (S1–S8) do sprawdzenia.

## Obrazy NV do testów (stan 2026-11-19, 23:30 UTC)
Wszystkie pakiety ghcr są publiczne (bez logowania).

| Komponent | Obraz | Zawartość |
|---|---|---|
| controller | `ghcr.io/wmp/neuvector-controller:claude-sbom-integration-0148fe3` | S2 + S3 + S4 + S5 + S8a (gałąź `claude/sbom-integration`) |
| enforcer | `ghcr.io/wmp/neuvector-enforcer:claude-sbom-integration-0148fe3` | jak wyżej |
| scanner | `ghcr.io/wmp/neuvector-scanner:claude-sbom-s6-syft-99ae74f` | S6 (Syft, purl, licencje). **Bez S8b** (pełny SBOM do S3) – push S8b czeka na zgodę użytkownika. Po push: `ghcr.io/wmp/neuvector-scanner:claude-sbom-s8-scanner-c27f6fe` |
| manager | `ghcr.io/wmp/neuvector-manager:claude-sbom-s7-ui-e5c3238` | S7 A + B1 + B2 + C |

Uwagi:
- Skaner z S6 i kontroler z integracji są zgodne (pole flagi z S8a skaner S6 ignoruje). Testy S8 z pełnym SBOM w S3 wymagają skanera z S8b; bez niego S3 dostaje tylko konfigurację i listę (pustą).
- Syft zwiększa pamięć skanera o 230–570 MB – ustaw limit pamięci poda skanera z zapasem (np. 3 Gi) albo sprawdź OOM.
- Wyłączenie Syft: zmienna `SCANNER_DISABLE_SYFT=true` w podzie skanera.
- DT: minimalna wersja **4.12.7**; klucz API z BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO, PORTFOLIO_MANAGEMENT (bez PORTFOLIO_MANAGEMENT projekty są płaskie); ingress DT z `proxy-body-size: "100m"`.
- S4 admission: reguła musi mieć pełną nazwę NV, np. `org.apache.logging.log4j:log4j-core>=2.0.0<2.17.1` (kryterium `modules`).
- Szczegóły API: `HANDOFF.md` §10.

## Obrazy testowe
| Cel | Przykład (do wyboru przez organizatora) |
|---|---|
| Debian | `debian:12` |
| Alpine + Java | obraz z JRE na Alpine i aplikacją z biblioteką log4j-core |
| Go | obraz z binarką Go |
| Duży obraz | obraz z wieloma plikami jar (pomiar limitu 512 KB) |
| Runtime | pod, w którym po starcie wykonasz `pip install <pakiet>` |

## Wdrożenie
1. Zainstaluj NV z chart helm i nadpisz obrazy tagami z ghcr.
2. Wdroż obrazy testowe jako Deployment w 2 namespace, z etykietą `PRODUKT=<wartość testowa>`.
3. Poczekaj na zakończenie skanów (REST `GET /v1/scan/status`).

## Testy według sesji

### S1 (spike)
- Uruchom skaner standalone i `syft` na obrazach testowych. Zapisz zgodność list i rozmiar raportu.

### S3
- `GET /v1/scan/workload/<id>/sbom?format=cyclonedx` i `?format=spdx` dla każdego obrazu testowego.
- Walidacja według specyfikacji z pakietu: `python3 -I specs/validate.py cyclonedx <plik>` i `python3 -I specs/validate.py spdx <plik>` (wymaga `pip install jsonschema`, działa offline). Purl w wynikach sprawdź według `specs/purl/types/<typ>-definition.json`.
- RBAC: użytkownik bez `sbom` dostaje 403. Użytkownik z dostępem do jednego namespace nie widzi drugiego.
- Pod z `pip install`: pakiet ma property „runtime”.

### S4
- Zapytanie o `log4j-core` z zakresem wersji zwraca dokładnie oczekiwane pody. Zmierz czas.
- Reguła admission z zakresem wersji blokuje wdrożenie obrazu Alpine + Java. Istniejąca reguła `modules` bez zakresu działa jak przed zmianą.

### S5
- Włącz DT. Sprawdź nazwy projektów według szablonu `{cluster}/{namespace}/{replicaset}/{container}` i tag `PRODUKT`.
- Skaluj Deployment do 5 replik: liczba projektów się nie zmienia.
- Rollout nowej wersji: nowy projekt, stary dostaje oznaczenie „inactive”.
- Wyłącz DT na czas skanu: skan kończy się, wysyłka wraca po ponowieniu.
- **Hierarchia (D28):** w DT drzewo `<klaster>` → `<klaster>/<projekt Rancher>` → `.../<ns>` → `.../<rs>` → `.../<kontener>` (wersja = digest tylko na liściu). Namespace bez projektu Rancher: poziom Rancher pominięty. Istniejący płaski projekt z poprzedniej wersji dostaje rodzica. Podgląd w UI pokazuje rodziców.
- Usuń wszystkie pody z rs: po karencji liść, potem rs, ns, projekt Rancher i klaster (gdy nie mają aktywnych dzieci) dostają „inactive”. Restart kontrolera przed końcem karencji: nic nie dostaje „inactive”.

### S6
- Raport obrazu ma licencje i purl. Porównaj z `syft` na tym samym obrazie (cel ≥ 98%).
- Zmierz czas skanu i rozmiar raportu przed i po zmianie. Duży obraz: raport < 512 KB po gzip, brak błędu `errSizeTooBig` w logach kontrolera.
- Skaner z `-maxrec` > 0: skan działa, SBOM z Syft jest pominięty bez błędu.

### S8
- Uruchom MinIO w klastrze testowym. Włącz S3 w NV (endpoint MinIO, path-style).
- Po skanie obrazu: obiekt `<prefix>/<cluster>/images/<digest>.cdx.json.gz` istnieje i przechodzi `specs/validate.py` po rozpakowaniu. Raport w KV nie zawiera pełnego SBOM.
- S3 wyłączony: skaner nie wysyła pełnego SBOM (sprawdź rozmiar wiadomości gRPC w logach albo metrykach).
- `delete_unused=false`: po usunięciu Deploymentu obiekt zostaje.
- `delete_unused=true`, krótka karencja testowa: obiekt znika po upływie karencji. Restart wszystkich kontrolerów przed upływem karencji: nic nie znika.
- Użytkownik bez dostępu do namespace nie pobiera SBOM z S3 (403).

### S7
- Ścieżka: widok Components → komponent → lista podów → szczegóły poda.
- Pobranie CycloneDX i SPDX z UI.
- Użytkownik bez `sbom` nie widzi zakładki SBOM.

## Format raportu
```
Sesja: S<n>
Obrazy: controller=<tag> enforcer=<tag> scanner=<tag> manager=<tag>
Wynik: PASS | FAIL
Testy:
- <nazwa testu>: PASS/FAIL, <liczby, czasy>
Błędy: <log bez danych wewnętrznych>
```
