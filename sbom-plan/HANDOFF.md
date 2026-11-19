# SBOM w NeuVector – kontekst i decyzje

Stan na 2026-11-19. Ustalenia pochodzą z kodu: neuvector `c982a5e`, neuvector-scanner `a3c5110`, anchore-syft `1a72047`. Rzeczy podane z pamięci mają oznaczenie **[weryfikacja]**.

## 1. Cel

NeuVector daje pełny inwentarz komponentów (SBOM) dla obrazów, działających podów i węzłów:
- pobieranie SBOM w formatach CycloneDX 1.6 JSON i SPDX 2.3 JSON,
- wyszukiwanie komponentów w całym klastrze („RCE bez CVE”: które pody mają bibliotekę X w wersji < Y),
- blokada w admission control według nazwy i zakresu wersji komponentu,
- opcjonalna wysyłka do Dependency-Track (DT).

**DT nie jest wymagany.** Wszystkie funkcje oprócz wysyłki do DT działają bez DT.

## 2. Decyzje użytkownika

| # | Temat | Decyzja |
|---|---|---|
| D1 | Zależności | Nie podnoś wersji istniejących zależności. Mała liczba zmian. |
| D2 | Syft | Biblioteka Syft **v1.42.4** w skanerze. Akceptowane podniesienia: `hashicorp/go-version` 1.7.0→1.8.0, `mattn/go-runewidth` 0.0.16→0.0.19. |
| D3 | Gdzie Syft | Tylko skaner, tylko obrazy. Nie w enforcerze. Bez drugiego pobierania obrazu. |
| D4 | Formaty | CycloneDX 1.6 JSON **i** SPDX 2.3 JSON, oba od razu. |
| D5 | DT – nazwa projektu | Domyślny szablon: `{cluster}/{namespace}/{replicaset}/{container}`. Szablon można zmienić. |
| D6 | DT – tagi | Tagi z etykiet obiektów k8s, np. `.metadata.labels.PRODUKT` → tag `PRODUKT`. |
| D7 | DT | Opcjonalny, domyślnie wyłączony. |
| D8 | RBAC | Pełny RBAC: nowe uprawnienie dla SBOM, z zakresem namespace. |
| D9 | Bez Trivy, bez PostgreSQL | NV nie obsługuje zewnętrznej bazy. Nie dodajemy jej. |
| D10 | Testy | Kod powstaje w chmurze. Testy na żywym klastrze robi inny agent w sieci wewnętrznej. |
| D11 | Obrazy testowe | GitHub Actions w forkach buduje obrazy do `ghcr.io`. |
| D12 | Cel PR | Docelowo PR do upstream. |
| D13 | S3 | Pełne SBOM w S3 (sesja S8). Zaakceptowane. |
| D14 | Stan | NV pokazuje **stan obecny**. Bez historii wersji kontenerów w NV. |
| D15 | Usuwanie z S3 | Opcjonalne i konfigurowalne (`s3.delete_unused`, domyślnie wyłączone). |
| D16 | Specyfikacje | Kod jest sprawdzany według pobranych specyfikacji w `specs/` (CycloneDX 1.6, SPDX 2.3, purl). |
| D17 | Przegląd | Każda sesja kończy się 3 przebiegami `/code-review` i przebiegiem `/security-review` (`SESSIONS.md`, „Zasady wspólne”). |
| D18 | Ponytail | Każda sesja działa ze skillem `/ponytail:ponytail`. Najpierw użyj istniejących helperów (§8), nie powtarzaj kodu. |
| D19 | Zakres S2/S6 (2026-11-19, po S1) | S2 (`neuvector`): proto, funkcja purl w `share/scan`, zabezpieczenie limitu 512 KB. Zmiany w parserach skanera dla purl (wersja binarna deb, nazwa binarna apk, źródło jar pom/MANIFEST, vendor composer) idą do S6. Pole `Version` używane do CVE bez zmian. |
| D20 | Zgłoszenie fail-open cosign | Użytkownik zlecił zgłoszenie. Kanał upstream to e-mail (`security-neuvector@suse.com`). Tekst: `reports/upstream-security-cosign-failopen.md`. Wysyła człowiek. |
| D21 | Praca nocna | Użytkownik: „nie pytaj o więcej”. Nadzorca prowadzi sesje według grafu bez pytań. Decyzje wymagające człowieka (zgoda na podniesienie zależności spoza D2, PR do upstream, wysyłka na zewnątrz) czekają w §11. |

## 3. Gdzie NV trzyma dane (odpowiedź na pytanie o miejsce na pliki SBOM)

Stan w kodzie:
- **Consul KV** (wbudowany w kontrolery, replikowany Raft). Raporty skanów są tam jako gzip: `share/clus_apis.go:372-380` (`scan/data/report/...`), rejestr: `share/clus_apis.go:450`. **Limit 512 KB na wartość**: `share/cluster/intfs.go:403`, większy zapis zwraca błąd (`intfs.go:578`).
- **SQLite** w kontrolerze: `/tmp/vulasset.db` (`db/models.go:187`). Plik jest **usuwany przy starcie kontrolera** (`db/models.go:235`) i odbudowywany. To nie jest trwały magazyn.
- Brak PVC/object storage dla danych skanów.

**Decyzja projektowa (zalecana, do potwierdzenia przez organizatora):** NV **nie przechowuje plików SBOM**. NV przechowuje wzbogacony inwentarz w istniejącym `ScanModule` i generuje CycloneDX/SPDX **na żądanie**.
- Nowe pola w `ScanModule` (`share/scan.proto:92`): `Purl`, `Licenses`, `Origin` (puste = NV, `syft` = tylko Syft). Pola dodatkowe opcjonalnie, jeśli zmieszczą się w limicie: `Hashes`.
- Dane idą istniejącą ścieżką: raport w KV (gzip) i blob modułów w SQLite. Bez nowego magazynu i bez migracji infrastruktury.
- **Pomiar** (`spike/RESULTS.md`, 15 172 komponenty): pełny SBOM z Syft = 18 MB (1,2 MB gzip), z czego 11 MB to `properties` Syft. Sam inwentarz (nazwa, wersja, purl, licencje) = **90 KB gzip**, czyli około 6 B na komponent. To jest **hipoteza**: pomiar użył krótkich kluczy (`n/v/p/l`) na cache modułów Go, a raport w KV ma pełne nazwy pól `ScanModule` (plus `cpes`, `file`) i `Vuls`. S1 mierzy prawdziwy `ScanResult` z nowymi polami, w tej samej serializacji co KV, na dużym obrazie kontenera. Pełny dokument na pewno się nie mieści.
- Licencje zapisuj jako ID SPDX albo nazwę, bez tekstu licencji.

### 3a. S3 jako magazyn pełnych SBOM (decyzja D13)
- NV ma już `github.com/aws/aws-sdk-go` v1.55.7 w `vendor/` (używane dla ECR: `controller/scan/aws_auth.go`). Pakiet `service/s3` pochodzi z tego samego modułu: **bez nowego modułu i bez zmiany wersji**, tylko nowe pakiety w `vendor/`.
- **[weryfikacja]** aws-sdk-go v1 jest wycofany przez AWS (koniec wsparcia w 2025). Upstream może wymagać v2, a to oznacza nowe moduły.
- Przepływ: kontroler ustawia w żądaniu skanu flagę „dołącz pełny SBOM” **tylko wtedy, gdy S3 jest włączony**. Wtedy skaner wysyła pełny SBOM z Syft (gzip) w nowym polu `ScanResult` (gRPC limit 64 MB). Kontroler, który odebrał wynik, zapisuje go do S3 i **usuwa to pole przed zapisem do KV** (wzór: `report.Modules = nil` w `controller/cache/scan.go:578` i `controller/scan/registry.go:584`). Dane logowania S3 są tylko w kontrolerze (zaszyfrowane w KV). Klucze są opcjonalne: gdy są puste, kontroler używa domyślnego łańcucha poświadczeń SDK (rola IAM, IRSA, profil instancji).
- Klucz obiektu: `<prefix>/<cluster>/images/<digest>.cdx.json.gz` (+ `.spdx.json.gz`). Deduplikacja po digest. Usuwanie (D15): opcja konfiguracji `s3.delete_unused` (domyślnie wyłączona). Gdy jest włączona, kontroler usuwa obiekt, jeśli w klastrze i w rejestrach nie ma już obrazu o tym digest (ten sam wyzwalacz co oznaczenie „inactive” w DT). **Ochrona przed błędnym usunięciem** (dotyczy też „inactive” w DT): porządkowanie wykonuje tylko lider, dopiero po pełnej synchronizacji cache po starcie albo zmianie lidera, a digest musi być nieobecny dłużej niż okres karencji (`s3.delete_grace_period`, domyślnie 24 h). Gdy jest wyłączona, obiekty zostają, a retencję ustawia administrator regułami lifecycle S3.
- Pobieranie: REST NV czyta obiekt z S3 i przesyła go strumieniem po sprawdzeniu RBAC. Nie zwraca przeglądarce linków presigned.
- Endpoint S3 można zmienić, a styl ścieżek ustawić na path-style, więc działa też MinIO i Ceph RGW.
- Bez S3: pobieranie SBOM generowane na żądanie z inwentarza (bez dodatkowych danych Syft).

## 4. Ustalenia z kodu

### Inwentarz `Modules`
- `Modules` zawiera **wszystkie** pakiety, nie tylko podatne: `neuvector-scanner/cvetools/cvesearch.go:1574` (`feature2Module`).
- `Source` dla OS = przestrzeń nazw dystrybucji, np. `debian:12` (`cvesearch.go:1578`).
- `Source` dla aplikacji: `jar`, `npm`, `python`, `ruby`, `golang`, `.NET`, `php`, `r`, `Wordpress`, `nginx`, `openssl` (`neuvector/share/scan/apps.go:30-64`).
- Przedrostki w `Name`: `python:`, `go:`, `ruby:`, `.NET:`, `php:`. Dla jar: `groupId:artifactId`.
- Wyjątki do purl: `opensslxx` (`cvesearch.go:1103`), nginx/openssl dodane drugi raz jako aplikacje (`cvesearch.go:1094`), sztuczny moduł `go:k8s.io/<name>` z tagu obrazu (`cvesearch.go:178`).
- Skaner tworzy `Modules` także dla działających podów (`ScanRunning`), więc purl liczony w jednym miejscu obejmuje wszystkie źródła.
- **Scalanie NV + Syft (S6):** klucz = purl znormalizowany do `type/namespace/name@version`, bez kwalifikatorów. Purl modułu NV pochodzi z funkcji z S2. Gdy klucze są równe: moduł NV zostaje (nazwa, wersja, `Vuls`), Syft dodaje tylko `Licenses` (i `Purl`, gdy moduł NV go nie ma). Gdy moduł jest tylko w Syft: nowy moduł z polem `Origin=syft`.
- **Zgodność wsteczna:** moduły z `Origin=syft` **nie** wchodzą do istniejącego kryterium admission `modules` ani do dopasowania CVE. Obecne reguły działają jak przed zmianą. Moduły z Syft są widoczne w SBOM, wyszukiwaniu (S4) i DT.

### Agent (działające pody)
- Agent sam parsuje aplikacje i wysyła JSON, nie surowe pliki: `neuvector/share/scan/scan_utils.go:259`. RPM sparsowany (n, e, v, r; bez architektury i licencji).
- Syft nie może pracować na danych z poda. SBOM poda = `Modules` poda. Jeśli istnieje skan obrazu o tym samym digest, dodaj licencje z obrazu. Pakiety, których nie ma w obrazie, oznacz jako „runtime” (property w CycloneDX).

### Kontroler
- Moduły w SQLite jako skompresowany blob: `db/assetvuls.go:915`. SQL ich nie przeszuka.
- Moduły obrazów są w pamięci cache: `controller/scan/interface.go:243`.
- Wyniki z rejestru: `controller/scan/registry.go:570`.
- Admission ma kryterium `modules` (nazwa → wersja): `share/criteria.go:54`, `controller/cache/admission.go:1319`. Brakuje zakresu wersji.
- REST API: dokumentacja w `controller/api/apis.yaml`. gRPC limit: 64 MB (`share/cluster/grpc.go:31`).

### Dane do szablonów DT
- Pod z API k8s: `controller/resource/types.go:125-140`: `Name`, `Domain`, `OwnerName`, `OwnerType`, `Labels`.
- Namespace: `controller/resource/types.go:99-103`: `Labels`.
- Workload: `share/clus_apis.go:1164-1196`: `Name`, `Image`, `ImageDigest`, `Service`, `Domain`, `Labels`.
- Nazwa klastra: `ClusterName` w konfiguracji systemu (`share/clus_apis.go:820`).
- `Service` = nazwa właściciela bez hasha RS (`share/orchestration/kubernetes.go:354`).

### Zależności między repozytoriami
- Skaner importuje `github.com/neuvector/neuvector` (`neuvector-scanner/go.mod:12`, `vendor/`).
- Zmiana `share/scan.proto` najpierw w `neuvector`. W forku skaner używa `replace` na commit z `WMP/neuvector`. Przy PR do upstream: najpierw PR `neuvector`, potem bump w skanerze.
- Oba repozytoria mają `vendor/`. Zmiany w `vendor/` idą do osobnego commita.

### Syft (szczegóły w `spike/RESULTS.md`)
- Licencja Apache-2.0. Fork `WMP/anchore-syft` = upstream bez zmian. Fork nie jest potrzebny w `go.mod`.
- v1.42.4 kompiluje się w skanerze. Testy `cvetools` i `detectors` przechodzą. Wymaga importu `_ "modernc.org/sqlite"`.
- Binarka skanera: 98 MB → 157 MB.
- W kontrolerze **nie** używaj enkoderów Syft (+153 moduły). Używaj `cyclonedx-go` v0.12.0 i `spdx/tools-golang` v0.5.7: zero podniesień, 3 nowe moduły (sprawdzone).

### Jeden katalog dla Syft bez drugiego pobierania
- Skaner rozpakowuje każdą warstwę do osobnego katalogu: `cvetools/image.go:641`.
- Skaner buduje mapę obrazu (ścieżka → plik w warstwie) z obsługą whiteoutów: `cvetools/cvesearch.go:493-503`, `cvetools/tools.go:37`.
- Z mapy utwórz jeden katalog z twardymi dowiązaniami (`os.Link`, ten sam system plików), uruchom `directorysource` Syft, potem usuń katalog.
- Ograniczenia:
  - Przy cache warstw (`-maxrec` > 0) pliki warstw z cache nie są na dysku (gałąź „records” w `cvesearch.go:505`). Wtedy pomiń Syft. Domyślnie `-maxrec` = 0.
  - `ExtractAllArchive` nie rozpakowuje symlinków (`neuvector/share/utils/extract.go:162,177`). Spike mierzy wpływ.

## 5. Szablony DT (D5, D6)

Symbole w nazwie, wersji i tagach projektu:

| Symbol | Źródło |
|---|---|
| `{cluster}` | `ClusterName` |
| `{namespace}` | `Pod.Domain` |
| `{replicaset}` | `Pod.OwnerName` (`controller/resource/kubernetes_resource.go:917-921`), gdy `OwnerType` = ReplicaSet. Dla innych właścicieli (StatefulSet, DaemonSet, Job): nazwa właściciela. Pod bez właściciela: `{pod}` |
| `{service}` | `Workload.Service` |
| `{pod}` | `Pod.Name` |
| `{container}` | etykieta `io.kubernetes.container.name` |
| `{image}`, `{digest}` | `Workload.Image`, `Workload.ImageDigest` |
| `{pod.metadata.labels.KEY}` | `Pod.Labels[KEY]` |
| `{namespace.metadata.labels.KEY}` | `Namespace.Labels[KEY]` |

Przykład konfiguracji:
```yaml
dependency_track:
  enabled: false
  url: https://dt.example.internal
  api_key: <zaszyfrowany w KV>
  project_name: "{cluster}/{namespace}/{replicaset}/{container}"
  project_version: "{digest}"
  tags:
    - "PRODUKT={pod.metadata.labels.PRODUKT}"
    - "cluster={cluster}"
```
- Wysyłka: `POST /api/v1/bom` jako `multipart/form-data` (`autoCreate`, `projectName`, `projectVersion`, opcjonalnie `parentName`). Nie używaj `PUT` z base64, bo base64 zwiększa rozmiar o 33% (źródło: dokumentacja DT, strona CI/CD).
- Do DT wysyłaj **odchudzony** CycloneDX (`bom-ref`, `type`, `name`, `version`, `purl`, `licenses`, opcjonalnie `cpe` i `hashes`), bez `properties` Syft. Pomiar dla 15 172 komponentów: 3,7 MB (pełny dokument: 18 MB).
- DT nie ma w dokumentacji własnego limitu rozmiaru BOM. Typowy limit to ingress nginx (domyślnie 1 MB → błąd 413). DT FAQ zaleca adnotację `nginx.ingress.kubernetes.io/proxy-body-size: "100m"`. NV musi zapisać błąd 413 w logu z jasnym opisem.
- Tag, w którym symbol jest pusty, jest pomijany.
- Pusty symbol w **nazwie albo wersji** projektu: najpierw zastępstwo z tabeli (np. `{replicaset}` → `{pod}`). Gdy symbol nadal jest pusty, NV nie wysyła BOM i zapisuje ostrzeżenie w logu. Dzięki temu różne pody nie trafiają do jednego projektu.
- Nieznany symbol: błąd przy zapisie konfiguracji.
- Deduplikacja: klucz = wynik szablonu nazwy i wersji.
- Etykiety innych obiektów (Deployment itp.) nie są dziś w cache kontrolera. Dodaj je tylko na życzenie.
- **[weryfikacja]** Format tagów w DT (czy tag może mieć postać `klucz=wartość`), `PUT /api/v1/bom` z `autoCreate`, flaga `active`, projekty nadrzędne.

## 6. RBAC (D8)

- Nowe uprawnienie `sbom` (odczyt: pobieranie SBOM, wyszukiwanie komponentów; zapis: konfiguracja DT).
- Zakres namespace: użytkownik widzi tylko SBOM i wyniki wyszukiwania dla obiektów, do których ma dostęp (wzór: obecne `acc.Authorize` w endpointach skanów).
- Klucz API DT: zaszyfrowany w KV, tak jak inne sekrety. Nigdy w odpowiedzi REST.

## 7. Do weryfikacji

- **[weryfikacja]** API DT (patrz sekcja 5).
- Projekt SUSE `sbomscanner` (nazwa w `controller/opa/regoConversion_test.go:31`). Oceń przed startem, czy nie dubluje pracy.
- `data/cvedb` w skanerze to plik Git LFS. Fork może nie mieć obiektu LFS. Obraz testowy skanera może wymagać kopii bazy z oficjalnego obrazu `neuvector/scanner`.
- Workflow `release.yml` w upstream używa sekretów Vault SUSE i nie zadziała w forkach. Potrzebny osobny workflow do `ghcr.io`.

## 8. Istniejące helpery (użyj, nie pisz od nowa)

Sesja, która dodaje nowy helper używany w więcej niż jednym miejscu, dopisuje go do tej tabeli.

| Potrzeba | Helper | Miejsce |
|---|---|---|
| gzip / gunzip | `utils.GzipBytes`, `utils.GunzipBytes` | `neuvector/share/utils/utils.go:142,199` |
| Szyfrowanie sekretów (klucz DT, S3) | `utils.EncryptSensitive` i odpowiednik do odszyfrowania | `neuvector/share/utils/utils.go:1075` |
| Zapis do KV z limitem rozmiaru | `cluster.PutBinary` | `neuvector/share/cluster/intfs.go:576` |
| Kompresja modułów w SQLite | `encodeAndCompress`, `UnzipModules` | `neuvector/db/assetvuls.go:915`, `neuvector/db/models.go:548` |
| Moduł → REST | `scanUtils.ScanModule2REST` | `neuvector/share/scan/scan_report.go:158` |
| Porównanie wersji pakietów (deb-like) | `utils.NewVersion`, `Version.Compare` | `neuvector/share/utils/version.go:39,138` |
| Porównanie wersji semver | `hashicorp/go-version` (już używany) | `neuvector/share/scan/compliance.go` |
| Porównanie wersji aplikacji (skaner) | `compareAppVersion` | `neuvector-scanner/cvetools/apps.go:161` |
| Kryterium mapy w admission | `isComplexMapCriterionMet` | `neuvector/controller/cache/admission.go:1034` |
| Sesja AWS (wzór dla S3) | `GetAwsEcrAuthToken` / `session.Session` | `neuvector/controller/scan/aws_auth.go:85-110` |
| Mapa obrazu z whiteoutami | `collectImageFileMap` | `neuvector-scanner/cvetools/tools.go:37` |
| Nazwa właściciela z etykiet poda | `GetServiceFromPodLabels` | `neuvector/share/orchestration/kubernetes.go:354` |
| Lista workloadów z RBAC | `CacheMethod.GetAllWorkloads` | `neuvector/controller/cache/cache.go:1213` |
| Walidacja SBOM według schematu | `specs/validate.py` | ten pakiet |
| purl modułu (z obliczaniem w locie dla starych raportów) | `scanUtils.ModulePurl(m, namespace)` | `neuvector/share/scan/purl.go` (S2) |
| budowanie purl (ECMA-427) | `scanUtils.BuildPurl` | `neuvector/share/scan/purl.go` (S2) |
| klucz scalania NV + Syft | `scanUtils.PurlMergeKey` | `neuvector/share/scan/purl.go` (S2) |
| zapis raportu rejestru w limicie KV | `encodeScanReport` (niepubliczny) | `neuvector/controller/kv/helper.go` (S2) |
| generowanie `*.pb.go` | protoc 3.5.1 + protoc-gen-go v1.0.0, `make -C share` | `neuvector/share/Makefile` |

## 9. Bezpieczeństwo

- SBOM klastra to mapa oprogramowania i ułatwia atak. RBAC na wszystkich nowych endpointach.
- Testy tylko na publicznych obrazach testowych. Bez danych i klastrów klientów.
- Wyniki z sesji wykonawczych i testów weryfikuje człowiek przed PR do upstream.

## 10. Wyniki sesji

### S0: CI do ghcr.io – wynik (sesja `session_01Y1996xaFsjiC8zWeDi42Ye`, przegląd nadzorcy: OK)
**Co zrobiono:** nowy workflow `.github/workflows/fork-images.yml` na gałęzi `claude/sbom-s0-ci-ghcr` w `neuvector-neuvector` (`46ecedf`, macierz controller + enforcer), `neuvector-manager` (`6c516f4`) i `neuvector-scanner` (`46945e0`). Uruchamia się przy push na każdą gałąź oprócz `main`/`master` i przez `workflow_dispatch`. Obraz: `ghcr.io/wmp/neuvector-<komponent>:<gałąź oczyszczona>-<7 znaków SHA>`. Workflow jest w osobnym commicie: **usuń ten commit przed PR do upstream**. Każda następna sesja bazuje na `claude/sbom-s0-ci-ghcr` (albo cherry-pick tego commita), żeby push budował obrazy.
**Obrazy (publiczne, `docker pull` bez logowania):**
- `ghcr.io/wmp/neuvector-controller:claude-sbom-s0-ci-ghcr-46ecedf`
- `ghcr.io/wmp/neuvector-enforcer:claude-sbom-s0-ci-ghcr-46ecedf`
- `ghcr.io/wmp/neuvector-manager:claude-sbom-s0-ci-ghcr-6c516f4`
- `ghcr.io/wmp/neuvector-scanner:claude-sbom-s0-ci-ghcr-46945e0`
**Decyzje:**
- Tylko `actions/checkout` (przypięty SHA). `docker login` z `GITHUB_TOKEN` przez `--password-stdin`. `permissions: {}` na poziomie workflow, job: `contents: read`, `packages: write`. Warunek `github.repository_owner != 'neuvector'`.
- Tylko linux/amd64. Bez cache GHA. `concurrency` z `cancel-in-progress`, `timeout-minutes: 120`.
- neuvector: `VERSION=interim/<tag>`. Bez prefiksu `interim/` kontroler traktuje obraz jako wydanie (`controller/controller.go:932`, `controller/kv/upgrade.go:981`).
- Skaner, baza CVE: bez Git LFS. Skrypt upstream `scripts/ghcr-vulndb-artifact.sh` pobiera podpisany (cosign) artefakt `ghcr.io/neuvector/vul/cvedb:<VULNDB_VERSION z Dockerfile>` jako `data/cvedb.regular`. Dockerfile bez zmian.
**Sprawdzenie:** actionlint i zizmor: 0 nowych uwag (skaner: uwagi takie same jak w `release.yml` upstream). Lokalny `docker build`: scanner, controller, enforcer OK. GitHub Actions: neuvector, manager i scanner – sukces. Actions włączone we wszystkich 3 forkach.
**Przeglądy (D17):** /code-review 1: 6 nit, poprawiono 2. /code-review 2: 5 uwag, poprawiono 1 (tag zaczynał się od `-`). /code-review 3: 4 uwagi, poprawiono 2 (prefiks `interim/`, `timeout-minutes`). /security-review: 0.
**Otwarte sprawy:** stare tagi w ghcr nie są usuwane automatycznie.
**Wnioski dla nadzorcy:** sesje potomne nie dostają przydzielonej gałęzi, a `add_repo` z dostępem push może zostać odrzucony przez tryb auto (w S0 dostęp do skanera dodał użytkownik). Repozytorium, do którego sesja ma pisać, podawaj jako `source_url`.
**Nowe helpery:** brak.

### S1: Spike purl, Syft, dowiązania, rozmiar – wynik (sesja `session_01Y1996zbWayQibUKXwwFQ9A`, przegląd nadzorcy: OK)
**Co zrobiono:** tabela `Source`+`Name` → purl dla wszystkich ekosystemów NV, sprawdzona oficjalnymi wektorami `specs/purl/tests/` (0 błędów; nadzorca powtórzył `python3 -I spike/s1/s1purl.py selftest`). Skaner standalone z lokalną łatką pomiarową i `syft` v1.42.4 na 5 publicznych obrazach (`debian:12`, `ghcr.io/christophetd/log4shell-vulnerable-app` (Alpine + Java + log4j-core 2.14.1), `quay.io/prometheus/node-exporter:v1.8.2` (Go), `apache/druid:30.0.1` (jar), `n8nio/n8n:1.64.0` (npm)). Test katalogu z twardymi dowiązaniami. Pomiar `ScanResult` z polami `Purl`, `Licenses`, `Origin` w serializacji KV (gob + gzip). Szczegóły i polecenia: `spike/S1-RESULTS.md`. Skrypty: `spike/s1/`.
**Wyniki:**
- Zgodność NV z Syft (klucz purl bez kwalifikatorów): razem **84,9%** (2274 wspólne z 2679). Obrazy: debian12 74,3%, log4shell 39,1%, node-exporter 95,7%, druid 71,7%, n8n 97,1%. Typy: npm 98,2%, golang 97,8%, deb 77,6%, maven 68,1%, apk 48,2%.
- Przyczyny różnic: deb – NV ma wersję pakietu źródłowego (`+bN`, epoka); apk – NV ma nazwę origin zamiast nazwy binarnej; jar – NV tworzy 2 moduły na plik (z `pom.properties` i z `MANIFEST.MF`), moduły z MANIFEST nie są współrzędnymi maven; Syft dodaje moduł główny Go i binarki (`generic`).
- Katalog z twardymi dowiązaniami: przy katalogerach `image` Syft gubi 1 pakiet na 2513 (busybox – twarde dowiązanie w tar). Z domyślnymi katalogerami katalogu gubi 1471 z 1489 pakietów npm (n8n).
- Rozmiar w KV (gzip): maksimum **76 936 B = 14,7% z 512 KiB** (n8n, 1985 modułów, 753 CVE). druid: 61 899 B (11,8%). Nowe pola: +28–36%. Szacunek (liniowy): limit przy około 12 000–13 500 modułach.
**Decyzje (zalecenia S1; zakres S2/S6 czeka na decyzję użytkownika):**
- Limit 512 KB **nie wymaga skracania** danych. Dodać zabezpieczenie: przed zapisem raportu rejestru (`txn.PutBinary` pomija za duży wpis po cichu, `share/cluster/intfs.go:756-767`, sprawdzone przez nadzorcę) usuwać kolejno moduły `Origin=syft`, `Licenses`, `Purl`. Bez `Hashes` w KV.
- purl liczony w skanerze (`feature2Module`), bo tylko skaner zna wersję binarną deb, nazwę binarną apk i źródło jar.
- S6: katalogery Syft z tagiem `image`. Katalog z twardymi dowiązaniami bez symlinków.
**Otwarte sprawy:**
- **Bezpieczeństwo:** `scripts/ghcr-vulndb-artifact.sh` (upstream, używany w S0) sprawdza podpis w trybie fail-open (`$(...)` bez `inherit_errexit`). Nadzorca potwierdził mechanizm testem bash. Dowód w `S1-RESULTS.md` §8. Zgłoszenie do upstream: decyzja użytkownika.
- **Bezpieczeństwo:** Syft `directorysource` idzie za absolutnym symlinkiem do plików hosta. S6 nie może dodawać absolutnych symlinków do katalogu skanu.
- `ExtractAllArchive` nie rozpakowuje `TypeLink` (twarde dowiązania tar) ani `TypeSymlink` (`share/utils/extract.go:160-177`, sprawdzone przez nadzorcę). NV nie widzi przez to np. busybox. Osobny PR.
- Nie zmierzono na danych: rpm, python, ruby, .NET, php, R, bitnami, moduł k8s (`ingress-nginx`). Namespace Syft dla `rhcos`, `suse-liberty`, `sl-micro` **[weryfikacja]**. Typ purl `bitnami` brak w `specs/` **[weryfikacja]**.
- Nazwa API Syft do wyboru katalogerów `image` w bibliotece **[weryfikacja]** (w CLI: `--override-default-catalogers image`).
**Przegląd:** 1× `/code-review` skryptów pomiarowych (S1 nie wysyła kodu do repozytorium): 6 uwag ważnych, 4 drobne. Poprawiono 7 (brak `Modules`, wyjątki w `nv2purl`, brak specyfikacji, stare pliki wyniku, `pipefail`, powód `opensslxx`, shebang). 1 bez zmiany: brak symlinków w katalogu to zamierzony przedmiot pomiaru. Pominięto 2 drobne (cudzysłowy w nazwie obrazu, `--json` bez wartości): skrypty dostają tylko stałe argumenty.
**Nowe helpery:** brak w repozytoriach. Narzędzia pomiarowe w pakiecie: `spike/s1/s1purl.py` (`nv2purl`, `build_purl`, `merge_key`, test wektorów purl – wzór dla testów Go w S2; `SPECS` = ścieżka względna do pakietu), `spike/s1/run-image.sh`, `spike/s1/s1size/`, `spike/s1/scanner-instrument.patch`.

### S2: Proto i purl – wynik (sesja `session_01Y1996yiCeBjitPLdze85mz`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s2-proto-purl` w `neuvector-neuvector` (od `claude/sbom-s0-ci-ghcr`, 8 commitów, ostatni `3a8b879`).
- `share/scan.proto`, `ScanModule`: `Purl` (7), `Licenses` (8), `Origin` (9). `scan.pb.go` w osobnym commicie (`ad85a7a`): protoc 3.5.1 + protoc-gen-go v1.0.0. `vendor/` i `go.mod` bez zmian.
- `share/scan/purl.go`: `BuildPurl`, `ModulePurl`, `PurlMergeKey` (port `s1purl.py`, bez nowych modułów Go). Wektory purl-spec i LICENSE (MIT) w `share/scan/testdata/purl/`.
- Kontroler: `ModulePurl(m, namespace)` to jedno miejsce odczytu purl. Zwraca `m.Purl` albo liczy purl w locie. REST API bez zmian. Eksport SBOM w S3 używa tej funkcji.
- Limit 512 KiB: `encodeScanReport` w `controller/kv/helper.go` (`PutRegistryImageSummaryAndReport`). Gdy gzip ≥ `cluster.KVValueSizeMax`, usuwa na kopii raportu kolejno: moduły `Origin=syft`, `Licenses`, `Purl`. Ostrzeżenie w logu.
- Dopasowanie CVE i admission bez zmian.
**API (`share/scan`, alias `scanUtils` w kontrolerze):**
```go
func BuildPurl(typ, namespace, name, version string, qualifiers map[string]string, subpath string) string // "" gdy typ lub name puste
func ModulePurl(m *share.ScanModule, namespace string) string // m.Purl albo purl z Source/Name/Version; "" = brak poprawnego purl
func PurlMergeKey(purl string) string // "type/namespace/name@version"; "" gdy purl niepoprawny
```
**Obrazy:** `ghcr.io/wmp/neuvector-controller:claude-sbom-s2-proto-purl-3a8b879`, `ghcr.io/wmp/neuvector-enforcer:claude-sbom-s2-proto-purl-3a8b879`. CI (unitest, golangci-lint, openapi-lint) run 44586186222: sukces. Fork test images run 44586186138: sukces.
**Testy:** `go test ./share/... ./controller/...` OK. Nadzorca powtórzył `go test -count=1 ./share/scan/ ./controller/kv/`: OK (lokalnie wymaga `libpcre3-dev`). TestPurlModule (30 przypadków), TestPurlMergeKey, TestPurlOfficialVectors (12 typów), TestPurlOldGobCompat, TestPurlOldProtoCompat, TestEncodeScanReport.
**Decyzje:** status „niepewny” nie jest zwracany, „niemożliwy” = pusty string. Odstępstwa od `s1purl.py`: R – nazwa po ostatnim `-`; jar – brak purl, gdy nazwa ma spację (też vendor); golang – brak purl dla ścieżek lokalnych, wersja stdlib obcięta przed spacją (`X:boringcrypto`); `kubernetes`/`openshift` → `pkg:generic/<źródło>`; `PurlMergeKey` zmienia nazwę cran na małe litery. `nginx`/`openssl` jako aplikacje dają `pkg:generic/...`: usuwanie duplikatów w SBOM należy do S3. Raport nadal za duży po 3 krokach: zachowanie jak przed zmianą.
**Przeglądy (D17):** /code-review 1: 9 uwag, poprawiono 3. /code-review 2: 7 uwag, poprawiono 3. /code-review 3: 7 uwag, poprawiono 3. Pominięte: problemy istniejące (raport za duży po 3 krokach, limit transakcji Consul), zakres S6 (parsery, filtr admission), zgodność z planem (klucz bez epoki rpm, typ bitnami). /security-review: 0. **Uwaga dla S3:** segmenty `..` w namespace purl zostają w napisie; nie używaj purl jako ścieżki pliku ani URL.
**Otwarte sprawy:** limit transakcji Consul (`txn_max_req_len` po base64) **[weryfikacja na klastrze]**; raport za duży po 3 krokach ginie bez błędu (problem istniejący, osobny PR: `putGZipKVChunks` dla rejestru); dokładność purl deb/apk/jar/composer/R – S6 (D19); typ `bitnami` **[weryfikacja]**.

## 11. Decyzje czekające na człowieka

- Wysłanie zgłoszenia `reports/upstream-security-cosign-failopen.md` e-mailem (D20).
