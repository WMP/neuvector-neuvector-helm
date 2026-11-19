# S1: mapowanie purl, porównanie z Syft, twarde dowiązania, rozmiar raportu

Stan na 2026-11-19. Sesja S1 (`session_01Y1996zbWayQibUKXwwFQ9A`, tylko odczyt, bez commitów). Kod: `neuvector-scanner` `a3c5110`, `neuvector` (`WMP/neuvector-neuvector`) `c982a5e`, Syft v1.42.4. Plik przeniesiony do pakietu przez nadzorcę bez zmian treści.

## 0. Środowisko i dane wejściowe

| Element | Wartość |
|---|---|
| Skaner | `go build ./cmd/scanner` z `a3c5110` + łatka pomiarowa `scanner-instrument.patch` (tylko lokalnie) |
| Baza CVE | `ghcr.io/neuvector/vul/cvedb:4.329` = `sha256:d6b8dc48…d0ab`. Podpis sprawdzony: `cosign` v3.1.4 (`cosign verify`, tożsamość `…/neuvector/release/.github/workflows/build-vuldbgen.yaml@refs/heads/master`): OK. SHA-256 pliku = adnotacja `sh.neuvector.db.sha256` (`b1b86276…7953`). `scanner -v`: `CVE database version: 4.329` |
| Syft | `go install github.com/anchore/syft/cmd/syft@v1.42.4` (go1.26.11) |
| Docker | brak demona w kontenerze. Skaner i Syft pobierają obrazy z rejestru |

Obrazy (linux/amd64, digest z `crane digest`):

| Skrót | Obraz | Digest | Uwagi |
|---|---|---|---|
| debian12 | `debian:12` | `sha256:366a6da5…14f3` | Debian |
| log4shell | `ghcr.io/christophetd/log4shell-vulnerable-app:latest` | `sha256:6f884306…9929` | Alpine 3.8 + OpenJDK 8 + Spring Boot fat jar z `log4j-core` 2.14.1 |
| nodeexp | `quay.io/prometheus/node-exporter:v1.8.2` | `sha256:065914c0…9396` | busybox + binarka Go |
| druid | `apache/druid:30.0.1` | `sha256:ec80de69…6e6d` | duży obraz z wieloma jar (pomiar rozmiaru) |
| n8n | `n8nio/n8n:1.64.0` | `sha256:06ee93c4…b8b1` | dodatkowy: duży obraz npm (przypadek skrajny dla rozmiaru) |

## 1. Tabela purl

Funkcja referencyjna: `nv2purl()` w `s1purl.py`. Budowanie purl sprawdzone oficjalnymi wektorami z `specs/purl/tests/` (12 typów): **0 błędów** (`python3 -I s1purl.py selftest`; build/parse/validate, np. maven 17/17/27, deb 6/6/7). 5 wektorów `expected_failure: true` pominiętych jawnie (brak reguł walidacji). Reguły NV: 22 asercje (`nvtest`).

Status: **dokładny** = purl wynika jednoznacznie z modułu. **Niepewny** = purl jest możliwy, ale może być inny niż w rzeczywistości. **Niemożliwy** = moduł nie ma danych na poprawny purl.

### 1a. Pakiety OS (`Source` = `ID:VERSION` z `os-release`, `cvesearch.go:1578`)

`Source` to przestrzeń nazw **przed** `os2DB()` (np. `rhel:9.4`, nie `centos:9`). Typ purl zależy od ID dystrybucji. Namespace purl = taki sam jak w Syft v1.42.4 (`syft/pkg/cataloger/{debian,alpine,redhat}/package.go`), żeby klucze scalania z S6 były równe.

| ID w `Source` | Typ | Namespace purl | Status |
|---|---|---|---|
| `debian`, `ubuntu` | `deb` | `debian`, `ubuntu` | dokładny (nazwa); wersja patrz niżej |
| `alpine`, `wolfi`, `chainguard` | `apk` | `alpine`, `wolfi`, `chainguard` | **niepewny** (nazwa źródłowa) |
| `rhel` | `rpm` | `redhat` (tak robi Syft) | dokładny |
| `centos`, `fedora`, `amzn`, `ol`, `rocky`, `almalinux`, `mariner`, `azurelinux`, `photon`, `sles` | `rpm` | = ID | dokładny (tylko kod; obrazów rpm nie mierzono) |
| `opensuse-leap`, `opensuse-tumbleweed` | `rpm` | `opensuse` (tak robi Syft) | dokładny (tylko kod) |
| `rhcos`, `suse-liberty`, `sl-micro`, `sle-micro` | `rpm` | = ID | niepewny (nie sprawdzono, co daje Syft) |
| `busybox` (NV ustawia, gdy brak OS i jest busybox, `cvesearch.go:1105`) | `generic` | – | dokładny: `pkg:generic/busybox@<ver>` |
| inne ID, `Source` pusty | – | – | **niemożliwy** (nieznany format pakietów) |

Reguły nazwy i wersji (z kodu `detectors/features.go`):
- **deb:** `Name` = `źródło/binarny`, gdy dpkg ma linię `Source:` (`features.go:162-176`). purl: `name` = pakiet binarny, kwalifikator `upstream=<źródło>`. **Wersja:** gdy linia `Source:` ma wersję, NV bierze wersję **źródłową** (`features.go:210-218`), a nie wersję binarną. Wtedy purl NV ≠ purl Syft (pomiar: 13 z 88 w debian12, 1 z 23 w druid; np. `bash 5.2.15-2` vs `5.2.15-2+b13`, `bsdutils 2.38.1-5+deb12u3` vs `1:2.38.1-5+deb12u3`). Z samego modułu nie da się tego wykryć.
- **apk:** `Name` = pakiet **origin** (linia `o:` nadpisuje `P:`, `features.go:110-118`), pakiety binarne z tym samym origin i wersją łączą się w 1 moduł. Przykład: NV `libressl` ↔ Syft `libressl2.7-libcrypto`, `-libssl`, `-libtls`. purl `pkg:apk/alpine/<origin>` często nazywa pakiet, którego nie ma w obrazie.
- **rpm:** `Version` = `E:V-R` → wersja purl `V-R`, kwalifikator `epoch=E` (jak Syft). Brak architektury (`arch`) w NV.
- **`opensslxx`:** nie trafia do `Modules`. Zmiana nazwy działa tylko przy `namespace == nil` (`cvesearch.go:1098-1103`), a wtedy `feature2Module("", nil, apps)` pomija wszystkie pakiety OS (`cvesearch.go:207`, `:660`). W `Modules` jest tylko aplikacja `openssl`.
- Kwalifikator `distro=<id>-<version>` dodajemy jak Syft. Nie jest częścią klucza scalania.

### 1b. Aplikacje (`Source` = `AppName`, `share/scan/apps.go`, `cvetools/bitnami.go`)

| `Source` | `Name` w NV | purl | Status |
|---|---|---|---|
| `jar` (z `pom.properties`) | `groupId:artifactId` | `pkg:maven/<g>/<a>@<v>` | dokładny |
| `jar` (z `MANIFEST.MF`) | `<Implementation-Vendor-Id / Bundle-Vendor / Automatic-Module-Name / "jar">:<Implementation-Title>` (`apps.go:440-465`) | brak poprawnego | **niemożliwy** albo **niepewny** (patrz niżej) |
| `npm` | `name` albo `@scope/name` | `pkg:npm/%40scope/name@<v>` | dokładny |
| `python` | `python:<nazwa z katalogu dist-info/egg-info>` | `pkg:pypi/<znormalizowana>@<v>` | dokładny (tylko kod) |
| `ruby` | `ruby:<nazwa z pliku .gemspec>` | `pkg:gem/<n>@<v>` | dokładny (tylko kod) |
| `golang` | `go:<ścieżka modułu>` (NV usuwa `v`) | `pkg:golang/<ścieżka>@v<v>` (dodaj `v`) | dokładny |
| `golang` | `go:stdlib` | `pkg:golang/stdlib@<v>` (jak Syft) | dokładny |
| `golang`, `File=kubernetes` | `go:k8s.io/ingress-nginx` (jedyny wpis w `matchKubenetesModeules`, `cvesearch.go:107`) | `pkg:golang/k8s.io/ingress-nginx@v<tag>` | niepewny (moduł sztuczny, wersja z tagu obrazu). Ścieżka modułu jest prawdziwa |
| `.NET` | `.NET:<n>` | `pkg:nuget/<n>@<v>` | dokładny (tylko kod) |
| `php` | `php:` (runtime z `php_version.h`) | `pkg:generic/php@<v>` | niepewny |
| `php` | `php:<pakiet>` (composer, **NV usuwa vendor**, `apps.go:657-662`) | brak | **niemożliwy** (namespace composer jest wymagany) |
| `r` | `<repo>-<nazwa>` małymi literami (`apps.go:880-889`) | `pkg:cran/<nazwa>@<v>` (usuń `<repo>-`; nazwy R nie mają `-`) | niepewny (wielkość liter utracona; cran rozróżnia wielkość liter) |
| `Wordpress` | `Wordpress` | `pkg:generic/wordpress@<v>` | niepewny |
| `nginx`, `openssl` | kopia pakietu OS tylko do dopasowania CVE (`cvesearch.go:1092-1103`) | nie twórz osobnego komponentu (duplikat). Ewentualnie `pkg:generic/<n>` | niepewny |
| `busybox` | kopia funkcji busybox | `pkg:generic/busybox@<v>` | dokładny |
| inne (bitnami: `Source == Name`, np. `redis`) | `<n>`, wersja bez `-N` (`bitnami.go:51-54`) | `pkg:bitnami/<n>@<v>` | niepewny (typ `bitnami` nie jest w `specs/purl`; Syft ma wersję z rewizją) |

**Jar – wynik pomiaru.** NV tworzy dla jednego pliku jar zwykle **2 moduły**: z `pom.properties` i z `MANIFEST.MF` (kolejność zależy od kolejności wpisów w zip). Przykład (log4shell, ten sam plik `BOOT-INF/lib/log4j-core-2.14.1.jar`): `org.apache.logging.log4j:log4j-core` i `org.apache.logging.log4j:Apache Log4j Core`. Moduł nie zapisuje, z którego pliku metadanych (pom czy MANIFEST) pochodzi. Moduły z MANIFEST mają tytuły ze spacjami, `groupId` = nazwa firmy (`Google, Inc.`, `SLF4J.ORG`) albo `spring.aop`. W druid: 198 modułów z tytułem ze spacją i 147 z `jar:` (razem 345 bez purl), 57 z `groupId` bez kropki.

**Przypadki bez purl albo z niepewnym purl (podsumowanie):** apk (origin), deb (wersja źródłowa), jar z MANIFEST, composer (brak vendor), R (wielkość liter), bitnami, `nginx`/`openssl` (duplikaty), moduł k8s (wersja z tagu), dystrybucje spoza tabeli.

## 2. Porównanie NV z Syft (`syft registry:<obraz>`)

Klucz porównania: purl bez kwalifikatorów i subpath, `type/namespace/name@version`, małe litery według `specs/purl/types`, wersja golang bez `v`. Zgodność = |NV ∩ Syft| / |NV ∪ Syft|. Moduły NV bez purl (status „niemożliwy”) nie są w zbiorze NV.

| Obraz | NV (klucze) | Syft | Wspólne | Zgodność | Wspólne/NV | Wspólne/Syft | NV bez purl |
|---|---|---|---|---|---|---|---|
| debian12 | 88 | 88 | 75 | **74,3%** | 85,2% | 85,2% | 0 |
| log4shell | 76 | 102 | 50 | **39,1%** | 65,8% | 49,0% | 17 |
| nodeexp | 45 | 47 | 45 | **95,7%** | 100% | 95,7% | 0 |
| druid | 765 | 787 | 648 | **71,7%** | 84,7% | 82,3% | 345 |
| n8n | 1466 | 1489 | 1456 | **97,1%** | 99,3% | 97,8% | 0 |
| **Razem** | 2440 | 2513 | 2274 | **84,9%** | 93,2% | 90,5% | 362 |

Według typu (wspólne / suma zbiorów): deb 97/125 = 77,6% (różnice to tylko wersje), apk 40/83 = 48,2%, maven 642/943 = 68,1% (log4shell 24,6%, druid 71,3%), golang 45/46 = 97,8%, npm 1450/1477 = 98,2%, generic 0/5.

Różnice i przyczyny (sprawdzone na danych):

| Przyczyna | Gdzie | Liczba |
|---|---|---|
| NV ma wersję pakietu źródłowego deb, Syft wersję binarną (`+bN`, epoka) | debian12, druid | 13 + 1 |
| NV apk = origin, Syft = pakiety binarne | log4shell, n8n | NV-only 10 + 4, Syft-only 19 + 10 |
| Jar z MANIFEST: inny `groupId` przy tym samym `artifactId@version` (`Google, Inc./guice` vs `com.google.inject/guice`, `spring.aop/spring-aop` vs `org.springframework/spring-aop`) | log4shell, druid | 9 + 14 |
| Jar: inna wersja (`zstd-jni 1.5.2.3` vs `1.5.2-3`, wersja `task ':json-path:jar' property 'archiveVersion'` w MANIFEST) | druid | 5 |
| Jar bez odpowiednika w drugim narzędziu (nazwy z MANIFEST, jar JDK, które Syft nazywa `charsets/charsets@` bez wersji) | log4shell, druid | NV 7 + 97, Syft 24 + 115 |
| Syft dodaje moduł główny Go (`github.com/prometheus/node_exporter@0.0.0-…`). NV raportuje tylko zależności i stdlib (`apps.go:286-308`) | nodeexp | 1 |
| Syft wykrywa binarki (`generic/busybox`, `generic/bash`, `generic/jq`, `generic/node`). NV ich nie ma | nodeexp, druid, n8n | 1 + 2 + 2 |
| NV nie widzi `busybox` w nodeexp: `bin/busybox` to twarde dowiązanie w tar, `ExtractAllArchive` go nie rozpakowuje (patrz §3). NV `Namespace` = brak | nodeexp | 1 |
| npm: NV-only `parse5*`, `shell-escape`; Syft-only m.in. pakiety bez wersji (`baz@`, `false_main@` z plików testowych) | n8n | 6 / 21. Przyczyny nie analizowano |

Polecenie: `python3 -I s1purl.py compare <out>/nv-raw.json <out>/syft-image.json --json <out>/cmp-nv-syft.json`.

## 3. Twarde dowiązania (katalog z mapy obrazu + Syft)

Łatka `s1LinkTree()` po zbudowaniu `fileMap` (`cvetools/cvesearch.go:493-503`) tworzy katalog z `os.Link` dla każdego pliku. Dla każdego obrazu: `sbomprobe` (domyślna konfiguracja Syft, źródło katalog) i `syft dir:<linkdir> --override-default-catalogers image`. Wzorzec: `syft registry:<obraz>`.

| Obraz | Symlinki w obrazie | W linkdir | Pakiety Syft obraz | `sbomprobe` (katalogery dir): brak / nadmiar | Katalogery `image`: brak / nadmiar |
|---|---|---|---|---|---|
| debian12 | 642 | 0 | 88 | 0 / 2 | 0 / 2 (`generic/bash`, `generic/gzip`) |
| log4shell | 712 | 0 | 102 | 0 / 0 | 0 / 0 |
| nodeexp | 364 (+403 twarde dowiązania tar) | 0 | 47 | 1 / 0 (`busybox`) | 1 / 0 (`busybox`) |
| druid | 918 | 0 | 787 | 0 / 0 | – (nie uruchomiono) |
| n8n | 1039 | 0 | 1489 | **1471** / 0 | **0 / 0** |

Wnioski:
1. **Brak symlinków daje mało strat.** Przy katalogerach `image` straty: 1 pakiet na 2513 (nodeexp `busybox`). Nadmiar: 2 (debian12).
2. **Katalogery dla katalogu są inne niż dla obrazu.** `directorysource` domyślnie wybiera katalogery „declared” (pliki lock). Dla n8n zgubił 1471 z 1489 pakietów npm (zainstalowane `package.json` bez lock). Z `--override-default-catalogers image`: 100%. S6 musi wybrać katalogery `image`.
3. **Twarde dowiązania w tar też są gubione.** `ExtractAllArchive` obsługuje tylko `TypeDir` i `TypeReg` (`neuvector/share/utils/extract.go:160-177`). Gubi `TypeSymlink` i `TypeLink`. W nodeexp `bin/busybox` (link do `bin/[`) nie istnieje w warstwie, więc NV i Syft nie widzą busybox. To błąd istniejący w NV, nie tylko w Syft.
4. **Nadmiar w debian12:** binarki `bash`, `gzip` są w `/usr/bin`, a lista plików dpkg ma `/bin/bash`. Bez symlinka `/bin → usr/bin` Syft nie łączy binarki z pakietem dpkg i dodaje `pkg:generic/bash`. Przyczyna: brak symlinków (usrmerge).
5. **Bezpieczeństwo (ważne dla S6):** Syft v1.42.4 `directorysource` idzie za **absolutnym** symlinkiem poza skanowany katalog i czyta plik z hosta. Test: katalog z jednym symlinkiem `x -> /usr/bin/runc` → `sbomprobe` zwraca 25 pakietów Go z `runc` hosta. Na rozpakowanym `debian:12` z symlinkami (`crane export | tar -x`) Syft zwrócił 358 pakietów Go z `/usr/bin/dockerd`, `containerd` itd. **tego kontenera**. Obecny katalog z twardymi dowiązaniami nie ma symlinków, więc jest bezpieczny. Gdy S6 doda symlinki, musi je przepisać na względne w obrębie katalogu albo nie może używać `directorysource`.

## 4. Rozmiar raportu w KV

Serializacja jak w kontrolerze: `gob` z `share.CLUSScanReport{ScannedAt, ScanResult}` + `utils.GzipBytes` (`controller/kv/helper.go:2378-2388` dla obrazów z rejestru, `controller/cache/scan.go:969-993` dla workload/host). Pola `Purl` (7), `Licenses` (8), `Origin` (9) dodane lokalnie w `vendor/.../share/scan.pb.go`. Licencje z Syft (`spdxExpression`, inaczej `value`). Moduły tylko z Syft dodane z `Origin=syft`. Polecenie: `s1size <out>/nv-augmented.json`.

| Obraz | Moduły (NV + Syft) | Vuls | Dziś (gzip) | + Purl + Licenses | Pełny (+ moduły Syft) | % z 512 KiB |
|---|---|---|---|---|---|---|
| debian12 | 88 + 13 | 210 | 7 259 | 9 682 | 10 105 | 1,9% |
| log4shell | 93 + 52 | 178 | 8 704 | 9 728 | 10 819 | 2,1% |
| nodeexp | 45 + 2 | 111 | 4 771 | 5 196 | 5 270 | 1,0% |
| druid | 1266 + 139 | 650 | 45 572 | 58 588 | **61 899** | **11,8%** |
| n8n | 1952 + 33 | 753 | 60 320 | 76 183 | **76 936** | **14,7%** |

- Koszt nowych pól: +28% (n8n) do +36% (druid) w stosunku do dzisiejszego raportu.
- Koszt na moduł w wariancie pełnym: 38,8 B (n8n) i 44,1 B (druid) po gzip. **Szacunek** (liniowy, niezmierzony): limit przy około 11 900–13 500 modułach.
- `CPEs` nie zmieniają rozmiaru (obrazy deb/apk nie mają CPE w module). `Vuls` to około 30% rozmiaru (wariant `full-novuls`).
- Gob bez gzip dla n8n: 517 387 B (powyżej 512 KiB), ale KV zapisuje dane po gzip.
- gzip różni się między przebiegami o kilka bajtów (znacznik czasu `ScannedAt`). Gob jest stały.
- gRPC: limit 64 MB, bez problemu.

**Stan obecny w kodzie (ważne dla decyzji):**
- Workload/host/platforma: `putGZipKVChunks` dzieli gzip na części < 512 KiB (`controller/cache/scan.go:898-937`). Limit nie dotyczy tych raportów.
- Obraz z rejestru: `PutRegistryImageSummaryAndReport` → `txn.PutBinary` (`share/cluster/intfs.go:756-767`). Przy ≥ 512 KiB wpis jest **pomijany po cichu** (tylko log), a transakcja zapisuje sam `summary`. Raport obrazu znika bez błędu. To problem istniejący, nie nowy.

## 5. Decyzja: limit 512 KB

**Skracanie danych nie jest potrzebne** dla zmierzonych obrazów (maksimum 14,7% limitu). Zalecam **zabezpieczenie zamiast skracania**:
1. S2: przed `txn.PutBinary` dla raportu rejestru sprawdź rozmiar po gzip. Gdy ≥ 512 KiB, usuwaj w tej kolejności: moduły `Origin=syft`, potem `Licenses`, potem `Purl` (da się je odtworzyć funkcją z S2). Moduły NV i `Vuls` zostają (CVE i admission). Zapisz ostrzeżenie w logu.
2. Alternatywa (większa zmiana): użyj `putGZipKVChunks` także dla raportów rejestru. Wymaga zmiany odczytu (`GetScanReport`) i kasowania części.
3. Bez `Hashes` w KV: ich nie mierzono, a ich koszt na moduł (SHA-256 = 64 znaki, prawie bez kompresji) jest większy niż koszt purl.

## 6. Zalecenia dla S2

1. **Licz purl w skanerze, nie w kontrolerze.** Skaner wie więcej niż moduł: wersję binarną deb, nazwę binarną apk, epokę rpm, źródło jar (pom vs MANIFEST). Funkcja w `feature2Module()` (`cvesearch.go:1574`) obejmuje obrazy i działające pody (`ScanRunning`). Moduły od agenta (bez tych danych) dostają purl z tej samej funkcji, z niższą dokładnością.
2. **Pola proto `ScanModule`:** `Purl` (string), `Licenses` (repeated string, ID SPDX albo nazwa), `Origin` (string). Bez `Hashes` w KV.
3. **Wyjątki purl** do zakodowania i testów: tabela §1 (`nvtest` w `s1purl.py` = 22 przypadki do przeniesienia do testów Go) + oficjalne wektory z `specs/purl/tests/`.
4. **Zmiany w parserach (osobna decyzja, wpływ na CVE):** deb – zapisz wersję binarną dla purl (nie zmieniaj `Version` używanego do CVE). apk – zapisz nazwę binarną dla purl (dziś `o:` nadpisuje `P:`; 1 moduł NV = kilka pakietów). jar – zapisz, czy moduł pochodzi z `pom.properties`; dla MANIFEST nie twórz purl maven, gdy jest moduł z pom dla tego samego pliku. composer – zachowaj vendor.
5. `nginx`/`openssl`/`busybox` jako aplikacje: nie twórz osobnych komponentów SBOM (duplikaty pakietów OS).
6. Dodaj do `specs/` definicję typu `bitnami` (brak w pakiecie) **[weryfikacja]**.

## 7. Zalecenia dla S6

1. **Katalogery:** `syft.DefaultCreateSBOMConfig().WithCatalogerSelection(...)` z domyślnym tagiem `image` (odpowiednik `--override-default-catalogers image`). Bez tego `directorysource` gubi pakiety zainstalowane (n8n: 1471 z 1489). Nazwę API sprawdź w Syft v1.42.4 **[weryfikacja]**.
2. **Symlinki:** katalog z twardymi dowiązaniami (bez symlinków) jest bezpieczny i daje 1 stratę na 2513 pakietów. **Nie** odtwarzaj absolutnych symlinków: Syft idzie za nimi do plików skanera (§3 pkt 5). Jeśli trzeba symlinków (usrmerge, `/bin → usr/bin`), przepisz je na względne w obrębie katalogu i sprawdź test z `x -> /usr/bin/runc`.
3. **Twarde dowiązania tar (`TypeLink`):** `ExtractAllArchive` ich nie rozpakowuje. Poprawka w `neuvector/share/utils/extract.go` (np. `os.Link` do już rozpakowanego celu) naprawi też wykrywanie w NV (busybox). Osobna sprawa, osobny PR.
4. Scalanie: moduły tylko z Syft (`Origin=syft`) to w zmierzonych obrazach 2–139 modułów na obraz. Klucz scalania z S2 musi używać wersji binarnej deb i nazwy binarnej apk, inaczej deb/apk dają duplikaty (debian12: 13 par).
5. Czas: Syft na obrazie z rejestru 5 s (debian12). Skan NV 43–44 s (debian12, druid). Czasu Syft w skanerze nie mierzono.

## 8. Inne odkrycia (poza zakresem S1)

1. **Bezpieczeństwo, `scripts/ghcr-vulndb-artifact.sh` (upstream, używany w S0):** sprawdzenie podpisu jest **fail-open**. `digest_ref=$(resolve_and_verify …)`: w bash bez `shopt -s inherit_errexit` błąd `cosign verify` w `$(...)` nie zatrzymuje funkcji. Dowód: tożsamość `https://github.com/attacker/x/.github/workflows/evil.yaml@refs/heads/master` → `cosign` zwraca błąd „no matching CertificateIdentity”, a skrypt kończy się kodem 0 i zapisuje bazę. Poprawka: `cosign verify … >&2 || return 1` w `resolve_and_verify` oraz `digest_ref=$(…) || exit 1` (albo `shopt -s inherit_errexit`). Zalecam zgłoszenie do upstream (security). Nadzorca potwierdził mechanizm testem bash (`set -euo pipefail; f(){ false; echo after; }; x=$(f)` kończy się kodem 0).
2. `cosign` v2.4.1 nie znajduje podpisu (`no signatures found`). Działa v3.1.4 (wersja z `.github/actions/install-cosign`).

## 9. Polecenia do powtórzenia

```bash
# narzędzia
GOBIN=/root/go/bin go install github.com/google/go-containerregistry/cmd/crane@v0.20.2
GOBIN=/root/s1/bin go install github.com/anchore/syft/cmd/syft@v1.42.4
curl -fsSL https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 -o /root/s1/bin/cosign
echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  /root/s1/bin/cosign" | sha256sum -c && chmod +x /root/s1/bin/cosign
# baza CVE (z ręcznym sprawdzeniem podpisu, bo skrypt jest fail-open)
cd neuvector-scanner
PATH=/root/s1/bin:/root/go/bin:$PATH GITHUB_REPOSITORY_OWNER=neuvector \
  COSIGN_CERTIFICATE_IDENTITY=https://github.com/neuvector/release/.github/workflows/build-vuldbgen.yaml@refs/heads/master \
  bash scripts/ghcr-vulndb-artifact.sh download cvedb cvedb.regular /root/s1/db/cvedb 4.329 /nonexistent.ref
/root/s1/bin/cosign verify --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/neuvector/release/.github/workflows/build-vuldbgen.yaml@refs/heads/master \
  ghcr.io/neuvector/vul/cvedb@$(crane digest ghcr.io/neuvector/vul/cvedb:4.329)
# skaner z łatką pomiarową (worktree, bez commita)
git worktree add --detach /root/s1/scanner-mod HEAD && cd /root/s1/scanner-mod && git apply /root/s1/tools/scanner-instrument.patch
mkdir -p cmd/s1size && cp <pakiet>/spike/s1/s1size/*.go cmd/s1size/
go build -o /root/s1/bin/scanner-mod ./cmd/scanner && go build -o /root/s1/bin/s1size ./cmd/s1size && go test ./cmd/s1size/
# sbomprobe (osobny moduł)
mkdir -p /root/s1/tools/sbomprobe && cp <pakiet>/spike/sbomprobe/main.go /root/s1/tools/sbomprobe/ && cd /root/s1/tools/sbomprobe
go mod init sbomprobe && go get github.com/anchore/syft@v1.42.4 && go mod tidy && go build -o /root/s1/bin/sbomprobe .
# testy skryptu purl
python3 -I s1purl.py selftest
# pomiar jednego obrazu (wyniki: cmp-*.txt/json, size.txt, symlinks.txt, timings.txt)
bash run-image.sh debian:12 /root/s1/out/debian12
# test symlinka absolutnego (Syft czyta plik hosta)
mkdir -p /tmp/t && ln -s /usr/bin/runc /tmp/t/x && /root/s1/bin/sbomprobe /tmp/t | grep -c pkg:golang
```

Ścieżki w skryptach są stałe (`/root/s1/...`, `SPECS` w `s1purl.py`). Przy innym układzie katalogów zmień je.
