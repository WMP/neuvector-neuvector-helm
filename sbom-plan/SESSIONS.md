# Sesje wykonawcze

Każda sesja: jedno repozytorium (wyjątki opisane), jeden logiczny PR, testy jednostkowe, aktualizacja `HANDOFF.md` na końcu. Po każdej sesji agent testowy wykonuje odpowiednią sekcję `TEST-RUNBOOK.md`.

## Zasady wspólne (każda sesja)

1. **Start:** uruchom `/ponytail:ponytail` (D18). Przeczytaj `HANDOFF.md` §8 (istniejące helpery) i kod, który zmieniasz.
2. **Bez powtarzania kodu:** zanim napiszesz helper, sprawdź §8 i `grep` w repozytorium. Nowy helper używany w więcej niż jednym miejscu dopisz do §8.
3. **Zgodność ze specyfikacją (D16):** kod formatu i purl sprawdzaj według `specs/` (patrz `specs/SOURCES.md`). Testy purl używają oficjalnych wektorów testowych z `specs/purl/tests/`.
4. **Przegląd na końcu (D17):**
   - `/code-review` → popraw znalezione problemy → `/code-review` → popraw → `/code-review` → popraw. Razem 3 przebiegi.
   - `/security-review` → popraw znalezione problemy.
   - Po każdej poprawce uruchom testy. Wyniki przeglądów (liczba problemów, co poprawiono, co pominięto i dlaczego) zapisz w `HANDOFF.md` w sekcji sesji.
5. **Koniec:** testy przechodzą, przeglądy wykonane, `HANDOFF.md` zaktualizowany.

## Graf zależności

```
S0 (CI ghcr) ─> S1 (spike) ─> S2 (proto + purl) ─┬─> S3 (eksport SBOM + RBAC) ─┬─> S4 (wyszukiwanie + admission)
                                                   │                              ├─> S5 (Dependency-Track)
                                                   │                              └─> S7 (UI manager)
                                                   └─> S6 (Syft w skanerze) ──┐
                                                              S3 + S6 ────────┴─> S8 (magazyn S3)
```
S4, S5, S6 i S7 mogą działać równolegle po S3 (S6 tylko po S2). S8 po S3 i S6. S7 dostaje widok plików z S3 po S8.

---

## S0: CI do ghcr.io
**Repozytoria:** `neuvector`, `neuvector-scanner`, później `neuvector-manager`.
- Nowy workflow (nie zmieniaj `release.yml` upstream): build obrazów `controller`, `enforcer` (`neuvector/package/Dockerfile.*`), `scanner` (`neuvector-scanner/package/Dockerfile`), `manager`.
- Tag obrazu: nazwa gałęzi + krótki SHA, np. `ghcr.io/wmp/neuvector-controller:<branch>-<sha>`.
- Skaner: `data/cvedb` to Git LFS. Jeśli fork nie ma obiektu, skopiuj bazę z oficjalnego obrazu skanera w etapie budowania.
- Workflow nie może trafić do PR upstream: trzymaj go w osobnym commicie albo na osobnej gałęzi.

**Kryterium:** push na gałąź buduje obrazy, a `docker pull` z ghcr działa.

## S1: Spike – mapowanie purl i porównanie z Syft
**Repozytoria:** `neuvector-scanner` (tylko odczyt i skrypty), `neuvector`.
- Tabela mapowania `Source` + `Name` → purl dla każdego ekosystemu, z wyjątkami z `HANDOFF.md` §4.
- Skaner w trybie standalone (`-image`, `cmd/scanner/scanner.go:228`) i `syft` na 3 publicznych obrazach: Debian, Alpine z Javą, obraz z binarką Go. Porównanie list (nazwa + wersja).
- Test katalogu z twardymi dowiązaniami (`spike/sbomprobe`) na prawdziwym obrazie: wpływ braku symlinków.
- Pomiar rozmiaru prawdziwego raportu: `ScanResult` z polami `Purl`, `Licenses`, `Origin`, w tej samej serializacji co zapis do KV, po gzip, dla dużego obrazu kontenera. Porównanie z limitem 512 KB (`HANDOFF.md` §3 to tylko hipoteza).

**Kryterium:** dokument z tabelą purl, procentem zgodności z Syft i pomiarem rozmiaru. Decyzja: czy limit 512 KB wymaga skracania danych.

## S2: Proto i purl
**Repozytorium:** `neuvector`.
- `share/scan.proto`: w `ScanModule` dodaj pola `Purl`, `Licenses`, `Origin` (zakres pól według wyniku S1). Wygeneruj kod.
- Funkcja purl w `share/scan` (pakiet współdzielony, skaner go vendoruje), według tabeli z S1. Testy tabelaryczne dla każdego ekosystemu i każdego wyjątku oraz test z oficjalnymi wektorami `specs/purl/tests/*-test.json` (przypadki budowania purl).
- Kontroler: gdy `Purl` jest puste (stare raporty), oblicz purl w locie.

**Kryterium:** testy jednostkowe purl przechodzą. Stare raporty bez nowych pól działają.

## S3: Eksport SBOM i RBAC
**Repozytorium:** `neuvector` (kontroler).
- Zależności: `github.com/CycloneDX/cyclonedx-go` v0.12.0, `github.com/spdx/tools-golang` v0.5.7. `vendor/` w osobnym commicie. Zero podniesień (sprawdzone, `spike/RESULTS.md`).
- REST: `GET /v1/scan/{workload|image|host}/:id/sbom?format=cyclonedx|spdx` oraz odpowiednik dla obrazu z rejestru.
- Metadane: źródło („running container” / „image”), klaster, digest. Pakiety tylko z runtime: property „runtime”.
- Nowe uprawnienie `sbom` z zakresem namespace (`HANDOFF.md` §6). Testy: użytkownik bez uprawnienia dostaje 403, użytkownik z innym namespace nie widzi obiektu.
- Dokumentacja w `controller/api/apis.yaml`.

**Kryterium:** pliki z testów (golden files) przechodzą `python3 -I specs/validate.py cyclonedx|spdx <plik>`. Testy RBAC przechodzą.

## S4: Wyszukiwanie komponentów i admission
**Repozytorium:** `neuvector` (kontroler).
- REST: `GET /v1/scan/component?name=&version=` (zakres wersji, np. `<2.17.1`) oraz wyszukiwanie po purl. Wynik: pody, węzły, obrazy (z rejestru i z działających podów).
- Obrazy: wyszukiwanie w cache w pamięci. Workloady: przejście po blobach w SQLite. Tabela indeksu tylko wtedy, gdy pomiar pokaże, że to za wolno (cel: < 1 min dla klastra testowego).
- Admission: zakres wersji w istniejącym kryterium `modules` (`controller/cache/admission.go:1319`). Najpierw przeczytaj `isComplexMapCriterionMet`, aby zachować zgodność obecnych reguł.
- RBAC: wyniki filtrowane według zakresu użytkownika.

**Kryterium:** zapytanie o bibliotekę bez CVE zwraca wszystkie pody z tą wersją. Reguła admission blokuje wdrożenie obrazu z zakresem wersji. Stare reguły działają bez zmian.

## S5: Dependency-Track (opcjonalne)
**Repozytorium:** `neuvector` (kontroler).
- Konfiguracja według `HANDOFF.md` §5, domyślnie wyłączona. Klucz API zaszyfrowany w KV.
- Szablony: `strings.NewReplacer` i parser symboli `{pod.metadata.labels.KEY}`, `{namespace.metadata.labels.KEY}`. Walidacja przy zapisie.
- Wysyłka po zakończeniu skanu, kolejka z ponowieniami. Brak DT nie blokuje skanowania. Wysyła tylko lider klastra (wzór: inne integracje w kontrolerze).
- Oznaczenie projektu „inactive”, gdy żaden pod nie daje już tego klucza. Ochrona: tylko lider, po pełnej synchronizacji cache, po okresie karencji (`HANDOFF.md` §3a). Test: restart kontrolera nie oznacza projektów jako „inactive”.
- Pusty symbol w nazwie lub wersji projektu: zastępstwo albo pominięcie wysyłki (`HANDOFF.md` §5). Test: dwa pody bez właściciela w jednym namespace dają dwa różne projekty.
- Testy: renderowanie szablonów (puste etykiety, nieznany symbol), deduplikacja, ponowienia (serwer testowy `httptest`).

**Kryterium:** testy jednostkowe z serwerem `httptest`. Test na żywym DT robi agent testowy.

## S6: Syft w skanerze
**Repozytorium:** `neuvector-scanner`.
- `go get github.com/anchore/syft@v1.42.4`. Akceptowane podniesienia: tylko `hashicorp/go-version` i `mattn/go-runewidth`. Sprawdź diff `go.mod`: każde inne podniesienie = stop i pytanie do użytkownika.
- `replace github.com/neuvector/neuvector => github.com/WMP/neuvector-neuvector <commit z S2>`. `vendor/` w osobnym commicie.
- Katalog z twardymi dowiązaniami z mapy obrazu (`cvesearch.go:493-503`), tylko gdy `bFromRawData`. `directorysource` + katalogery z tagiem `image`, bez katalogerów plików. Import `_ "modernc.org/sqlite"`.
- **Purl w skanerze (D19):** w `feature2Module()` (`cvesearch.go:1574`) ustaw `Purl` funkcją z S2. Dla dokładnego purl dodaj w parserach (`detectors/features.go`, `share/scan/apps.go` przez vendor albo lokalnie) dane tylko dla purl: wersja binarna deb, nazwa binarna apk, źródło jar (pom/MANIFEST: bez purl maven z MANIFEST, gdy jest moduł z pom dla tego samego pliku), vendor composer. Nie zmieniaj `Name`/`Version` używanych do CVE. Szczegóły: `spike/S1-RESULTS.md` §6–7.
- Katalogery Syft z tagiem `image`. Bez absolutnych symlinków w katalogu skanu (`spike/S1-RESULTS.md` §3 pkt 5).
- Scalanie według klucza z `HANDOFF.md` §4 (znormalizowany purl). Moduł NV wygrywa. Syft dodaje `Licenses`. Pakiety tylko z Syft: nowe moduły z `Origin=syft`, bez `Vuls`. Nie zmieniaj dopasowania CVE.
- Testy: brak duplikatów dla jar (`groupId:artifactId` kontra Maven z Syft), python, go. Regresja: istniejąca reguła admission `modules` daje ten sam wynik przed i po S6 (moduły `Origin=syft` są pominięte w kontrolerze, `controller/cache/admission.go:1319`; ta jedna linia filtra należy do S6).
- Flaga do wyłączenia Syft (domyślna wartość do decyzji organizatora). Limit czasu dla Syft.
- Pomiar: czas skanu i rozmiar raportu przed i po zmianie.

**Kryterium:** testy `cvetools` i `detectors` przechodzą. Raport dla obrazu testowego ma licencje i purl. Rozmiar raportu < 512 KB po gzip dla obrazów z S1.

## S8: Magazyn S3 (decyzja D13)
**Repozytoria:** `neuvector` (kontroler, proto), `neuvector-scanner` (wysyłka pełnego SBOM). Zależy od S3 i S6. Kolejność: najpierw proto w `neuvector`, potem nowy `replace`/bump w skanerze.
- `share/scan.proto`: w `ScanResult` dodaj pole z pełnym SBOM (gzip), a w żądaniu skanu flagę „dołącz pełny SBOM”. Kontroler ustawia flagę tylko przy włączonym S3. Skaner wypełnia pole tylko przy ustawionej fladze.
- Kontroler: konfiguracja S3 (endpoint, region, bucket, prefix, path-style, opcjonalne dane logowania zaszyfrowane w KV; puste = domyślny łańcuch poświadczeń SDK, np. IRSA), domyślnie wyłączona. Zapis po odebraniu wyniku, potem usunięcie pola przed zapisem do KV. Błąd S3 nie blokuje skanu. Opcja `s3.delete_unused` (D15, domyślnie wyłączona): gdy jest włączona, kontroler usuwa obiekt, jeśli obraz o danym digest znika z klastra i rejestrów. Ochrona: tylko lider, po pełnej synchronizacji cache, po okresie `s3.delete_grace_period` (domyślnie 24 h). Testy: oba ustawienia `delete_unused`, restart kontrolera nic nie usuwa.
- `aws-sdk-go/service/s3` z już używanego modułu v1.55.7. Zmiany w `vendor/` w osobnym commicie. Zero nowych modułów.
- REST: endpointy z S3 zwracają pełny dokument z S3, gdy obiekt istnieje. W innym przypadku zwracają dokument generowany z inwentarza. Lista SBOM w S3 dla obiektów, do których użytkownik ma dostęp (RBAC).
- Testy: serwer S3 w teście (`httptest` z minimalnym API PUT/GET albo MinIO w runbooku).

**Kryterium:** po skanie obrazu obiekt jest w S3 pod kluczem z digest. Raport w KV nie zawiera pełnego SBOM. Pobranie z REST zwraca dokument z S3.

## S7: UI
**Repozytorium:** `neuvector-manager` (fork do utworzenia).
- Zakładka SBOM w szczegółach workloadu, obrazu i węzła: lista komponentów, filtry, pobieranie CycloneDX/SPDX.
- Widok „Components” z wyszukiwarką z S4.
- Ustawienia DT z podglądem wyniku szablonu.
- Edytor ról: nowe uprawnienie `sbom`.

**Kryterium:** użytkownik przechodzi od komponentu do listy podów. Użytkownik bez uprawnienia `sbom` nie widzi zakładki.

## Kolejność PR do upstream
1. Issue w `neuvector/neuvector` z opisem całej funkcji (wymóg `CONTRIBUTING.md` dla dużych zmian). Treść issue zatwierdza użytkownik.
2. PR `neuvector`: S2 → S3 → S4 → S5 (osobne PR).
3. PR `scanner`: S6, po scaleniu S2 w upstream (zamień `replace` na wersję upstream).
4. PR `neuvector`: S8 (proto + kontroler). Potem PR `scanner`: S8 (bump `neuvector` do wersji ze scalonym S8).
5. PR `manager`: S7.
