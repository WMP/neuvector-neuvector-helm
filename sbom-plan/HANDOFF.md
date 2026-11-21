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
| D22 | Syft w skanerze – domyślnie (decyzja nadzorcy) | Syft domyślnie **włączony**. Flaga/zmienna do wyłączenia. Limit czasu 300 s. Błąd albo przekroczenie czasu: skan kończy się bez danych Syft, ostrzeżenie w logu. Do potwierdzenia przez użytkownika przed PR upstream (upstream może woleć domyślnie wyłączony). |
| D23 | Filtr `Origin=syft` w admission (decyzja nadzorcy) | Przeniesiony z S6 do S4. Linia filtra jest w repozytorium `neuvector` (`controller/cache/admission.go`), a S6 zmienia tylko skaner. S4 i tak zmienia admission. Do czasu S4 moduły Syft w obrazach z gałęzi S6 mogą wejść do istniejącego kryterium `modules` – testy admission na klastrze dopiero po S4. |
| D24 | Podniesienia z bumpa neuvector w skanerze (decyzja nadzorcy, S6) | Zaakceptowane: `hashicorp/go-rootcerts` 1.0.2→1.1.0, `go.yaml.in/yaml/v3` 3.0.5→3.0.6. Źródło: `go.mod` upstream neuvector `c982a5e` (skaner miał neuvector `230e5ebe`, 8 commitów wcześniej). Każdy bump neuvector w skanerze je przyniesie, niezależnie od SBOM. |
| D25 | Podgląd szablonu DT (decyzja nadzorcy, S5) | `POST /v1/sbom/dependency_track/preview` wymaga globalnego `sbom` do **zapisu**. Podgląd renderuje etykiety dowolnego poda i namespace, a potrzebuje go tylko osoba edytująca konfigurację DT. |
| D26 | Format pełnego SBOM w S3 (decyzja nadzorcy, S8) | Skaner wysyła tylko CycloneDX JSON (pełny dokument Syft, gzip). Obiekt `<prefix>/<cluster>/images/<digest>.cdx.json.gz`. SPDX nie jest przechowywany w S3: endpoint SPDX zawsze generuje dokument z inwentarza. |
| D27 | Podniesienie w skanerze przez S8a (decyzja nadzorcy, S8b) | Zaakceptowane: `github.com/CycloneDX/cyclonedx-go` 0.10.0 → 0.12.0 (indirect przez Syft). Źródło: `go.mod` neuvector od S3 (bezpośrednia zależność 0.12.0, wybrana w spike). Warunek: testy skanera przechodzą. |
| D28 | Hierarchia projektów DT (użytkownik, 2026-11-21, po teście) | Projekty zagnieżdżone: klaster → projekt Rancher → namespace → replicaset → kontener (wcześniej płaskie: S5 nie używała `parentName`). Nazwy = pełna ścieżka (`klaster`, `klaster/p-abc12`, `klaster/p-abc12/ns`, …), bo DT wymaga unikalnej pary nazwa + wersja. Poziomy = segmenty szablonu nazwy rozdzielone `/` (poza `{...}`). Projekt Rancher = etykieta namespace `field.cattle.io/projectId` (ID, np. `p-abc12`; nazwy wyświetlanej nie ma w klastrze podrzędnym), symbol `{rancher.project}`; pusty segment = poziom pominięty (namespace bez projektu Rancher). „Inactive” kaskadowo w górę, gdy rodzic nie ma aktywnych dzieci (te same zabezpieczenia). |

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
| SBOM z modułów (CycloneDX 1.6 / SPDX 2.3) | `sbom.Components`, `sbom.Write`, `sbom.ContentType` | `neuvector/controller/sbom/sbom.go` (S3) |
| Moduły i baseOS skanu workloadu/hosta (bez kontroli dostępu) | `cacher.GetScanModules` | `neuvector/controller/cache/scan.go` (S3) |
| Moduły obrazu z rejestru z RBAC (także `all`) | `scanner.GetRegistryImageModules` | `neuvector/controller/scan/interface.go` (S3) |
| Kontrola dostępu do rejestru i obrazu | `resolveRegistry`, `authorizeRegistryImage` (niepubliczne) | `neuvector/controller/scan/interface.go` (S3) |
| Klasyfikacja licencji SPDX | `classifyLicense` (niepubliczne) | `neuvector/controller/sbom/license.go` (S3) |
| Wspólne kroki handlerów SBOM (RBAC, format, odpowiedź) | `sbomPrepare`, `sbomRespond`, `sbomRespErr` | `neuvector/controller/rest/sbom.go` (S3) |
| UI: panel SBOM (lista komponentów, filtr, pobieranie) | `SbomPanelModule` / `app-sbom-panel` (wejścia `url`, `params`, `name`, `tableHeight`), `cdxToRows`, `sbomFileName` | `neuvector-manager/admin/webapp/websrc/app/routes/components/sbom-panel/` (S7) |
| UI: proxy SBOM do kontrolera | `PolicyService.getSbom(tokenId, segments, format)` | `neuvector-manager/admin/src/main/scala/com/neu/service/policy/PolicyService.scala` (S7) |
| Zapytanie o wersję (dokładna albo zakres, dpkg/semver według typu purl) | `sbom.ParseVersionQuery`, `VersionQuery.Match` | `neuvector/controller/sbom/version.go` (S4) |
| Moduły z SQLite bez podatności | `db.GetModules` | `neuvector/db/models.go` (S4) |
| Walidacja wpisu kryterium `modules` (zakres) | `cache.ValidateModulesCriterionValue` | `neuvector/controller/cache/admission.go` (S4) |
| Szablony projektu DT (walidacja, renderowanie) | `dtrack.ValidateTemplates`, `dtrack.Render`, `dtrack.WithDefaults` | `neuvector/controller/sbom/dtrack/` (S5) |
| Klient i kolejka DT | `dtrack.Client`, `dtrack.NewUploader` | `neuvector/controller/sbom/dtrack/` (S5) |
| Moduły obrazu z rejestru bez RBAC (tylko wewnętrznie) | `scan.RegistryImageModules(imageID)` | `neuvector/controller/scan/interface.go` (S5) |
| Syft na obrazie bez drugiego pobierania (katalog dowiązań, limit czasu) | `startSyft`, `waitSyft`, `runSyft`, `buildSyftTree` | `neuvector-scanner/cvetools/syft.go` (S6) |
| Scalanie NV + Syft | `mergeSyftModules` | `neuvector-scanner/cvetools/syft.go` (S6) |
| Porównanie raportu skanera z `syft registry:` | `spike/s6/cmp_after.py` | ten pakiet (S6) |
| Magazyn pełnych SBOM w S3 (klucz, walidacja, właściciel, Put/Open/Owned/List/Delete) | `s3store.New`, `s3store.Validate`, `s3store.ValidDigest`, `s3store.Configure`, `s3store.Current` | `neuvector/controller/sbom/s3store/s3store.go` (S8a) |
| Fałszywy serwer S3 do testów | `s3fake.New` | `neuvector/controller/sbom/s3store/s3fake` (S8a) |
| Digesty obrazów wszystkich rejestrów bez RBAC (tylko wewnętrznie) | `scan.RegistryImageDigests` | `neuvector/controller/scan/sbom_s3.go` (S8a) |
| Obrazy rejestrów o danych digest z RBAC | `scanner.GetRegistryImagesByDigest` | `neuvector/controller/scan/sbom_s3_rest.go` (S8a) |

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

### S3: Eksport SBOM i RBAC – wynik (sesja `session_01Y19972WPZSna5MfP2XVLqi`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s3-export-rbac` w `neuvector-neuvector` (od `claude/sbom-s2-proto-purl`, 8 commitów, ostatni `da8cf49`).
- `deps(go)` (`3bded4f`): `cyclonedx-go` v0.12.0, `spdx/tools-golang` v0.5.7, `anchore/go-struct-converter` v0.1.0 (indirect). 0 podniesień (nadzorca sprawdził diff `go.mod`).
- Pakiet `controller/sbom`: CycloneDX 1.6 i SPDX 2.3 JSON z `Modules`; purl z `scanUtils.ModulePurl`. Lista ID licencji SPDX: `controller/sbom/spdx.schema.json` (`go:embed`).
- REST (GET, `format=cyclonedx|spdx`, domyślnie cyclonedx, inny = 400): `/v1/scan/workload/:id/sbom` (źródło „running container”, property `neuvector:runtime=true` dla pakietów spoza skanu obrazu z rejestru o tym samym image ID, licencje ze skanu obrazu), `/v1/scan/image/:id/sbom` (skan z rejestru, gdy dostępny; inaczej skan runtime workloadu), `/v1/scan/host/:id/sbom`, `/v1/scan/registry/:name/image/:id/sbom` (także `all`). `Content-Disposition` ze stałą nazwą pliku. Dokumentacja: `controller/api/apis.yaml`.
- Kody: brak `sbom` w żadnej domenie = 403; obiekt w niedostępnym namespace/rejestrze = 403 (wzór istniejących raportów skanu); brak obiektu/skanu/skan z błędem = 404; inny błąd = 500 bez tekstu błędu.
- Uprawnienie `sbom`: `PERM_SBOM = 0x00200000`, zakres global + namespace, odczyt i zapis (`CONST_API_SBOM`). admin/fedAdmin: odczyt + zapis; reader/fedReader: odczyt; ciops/none: brak. Admin/reader w namespace: też `sbom`. Istniejące role własne nie dostają `sbom` (wyjątek niżej). Rancher SSO: zasób `sbom`. `sbom` wystarcza bez rt_scan/reg_scan (D8).
**API generatora (`controller/sbom`):**
```go
const FormatCycloneDX = "cyclonedx"; FormatSPDX = "spdx"
const SourceContainer = "running container"; SourceImage = "image"; SourceHost = "host"
type Meta struct { Source, Name, ID, Domain, Cluster, Digest string; Created time.Time; Serial string }
type Component struct { Name, Version, Purl string; Licenses []string; Runtime bool }
func ContentType(format string) (ct string, ok bool)
func Components(modules []*share.ScanModule, namespace string, image []*share.ScanModule) []Component
func Write(w io.Writer, format string, meta Meta, comps []Component) error
// controller/cache: func (m CacheMethod) GetScanModules(id string) ([]*share.ScanModule, string, error) – bez kontroli dostępu
// controller/scan: func (m *scanMethod) GetRegistryImageModules(name, id string, acc *access.AccessControl) ([]*share.ScanModule, *share.CLUSRegistryImageSummary, error)
```
**Obrazy:** `ghcr.io/wmp/neuvector-controller:claude-sbom-s3-export-rbac-da8cf49`, `ghcr.io/wmp/neuvector-enforcer:claude-sbom-s3-export-rbac-da8cf49`. CI run 44596216304 i Fork test images run 44596216395: sukces.
**Testy:** `go test ./share/... ./controller/...` OK (nadzorca powtórzył dla `sbom`, `rest`, `access`, `scan`, `cache`, `share/...`: OK). golangci-lint v2.15.0: 0. openapi-lint: OK. 6 plików wzorcowych `controller/sbom/testdata/`: `validate.py` VALID (nadzorca powtórzył: VALID). Testy RBAC: brak `sbom` → 403 na 4 endpointach; admin/reader → 200; użytkownik ns1 → ns2 = 403, host = 403, rejestr ns2 = 403; `sbom` w ns2 + rt_scan w ns1 → workload ns1 = 403.
**Decyzje:**
- Duplikaty: aplikacja `nginx`/`openssl`/`busybox` usuwana tylko, gdy istnieje pakiet OS o tej samej nazwie. Duplikaty Source+Name+Version łączone (suma licencji, pierwszy niepusty purl).
- Nazwa komponentu: OS – nazwa binarna; aplikacje – bez przedrostków `python:`, `go:` itd. (jar: `groupId:artifactId`).
- Runtime: klucz Source+Name+Version, skan obrazu = skan z rejestru o tym samym image ID (nie digest manifestu), tylko z rejestrów dostępnych dla użytkownika.
- Licencje: ID SPDX → `license.id`; wyrażenie → `expression`; tekst → `license.name` / `LicenseRef-<tekst>`.
- `documentNamespace` SPDX = `https://neuvector.com/spdx/<UUID>`. Purl tylko w polu `purl`/`externalRefs`.
- Nazwa klastra przez `NewReaderAccessControl` (użytkownik namespace widzi ją w dokumencie).
- **Rola własna z wszystkimi uprawnieniami odczytu oprócz `sbom`** (zapisana przed S3) nadal dostaje pełny `PERMS_CLUSTER_READ`, a więc też `sbom`. Bez tego stare role tracą dostęp do federacji, systemu itd. Uzasadnienie: taka rola i tak czyta raporty skanów z modułami. Do potwierdzenia przed PR (§11).
**Przeglądy (D17):** /code-review 1: 7 uwag, poprawiono 5 (+2 w przeglądzie 2). /code-review 2: 8 uwag, poprawiono 8. /code-review 3: 9 uwag, poprawiono 7; pominięto 2 (zapis `sbom` bez API – S5; `sbom` bez rt_scan – D8). /security-review: 0 HIGH/MEDIUM; regresja `PERMS_CLUSTER_READ` dla starych ról poprawiona (`da8cf49`); LOW (OpenShift: nazwa repo:tag z innego projektu w nazwie dokumentu rejestru, tak samo jak istniejące endpointy) pominięta.
**Uzupełnienie po S6** (commity `4b68a02`, `013cca5`, `0f61914`; CI run 44614902235: sukces; obrazy `...:claude-sbom-s3-export-rbac-0f61914`): łączenie komponentów po purl. Klucz `purlKey` = `PurlMergeKey` + `?epoch=` dla rpm; `pkg:generic/...` nie łączy. Nazwa jar z pom (`groupId:artifactId`) wygrywa z MANIFEST. Runtime tylko, gdy żaden łączony moduł nie jest w skanie obrazu. Różne wersje przy tym samym purl = mniejsza wartość. Ten sam klucz dopasowuje moduły ze skanu obrazu. 6/6 plików wzorcowych VALID (nadzorca sprawdził). **Uwaga:** gałęzie S4 i S5 bazują na starszym `da8cf49` (bez tego uzupełnienia).
**Otwarte sprawy:**
- `GetScanModules`/`GetRegistryImageModules` dla skanów z błędem sprawdzone tylko przeglądem kodu. Do sprawdzenia na klastrze (TEST-RUNBOOK S3).
- Moduły `Origin=syft` nie trafiają do SBOM workloadu (agent nie uruchamia Syft). SBOM obrazu je zawiera.
- DT (S5) potrzebuje odchudzonego CycloneDX: dziś `Write` daje pełny dokument.
- Lokalny golangci-lint: zbuduj Go 1.27 (`GOTOOLCHAIN=go1.27.4 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0`).

### S7 (część A): UI – zakładka SBOM i uprawnienie – wynik (sesja `session_01Y199724PNuPQ5sBeo1XLqV`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s7-ui` w `neuvector-manager` (od `claude/sbom-s0-ci-ghcr`, 4 commity, ostatni `25b0950`).
- Proxy Scala (`PolicyApi.scala`, `PolicyService.getSbom`): `GET scan/workload/sbom?id&format`, `scan/host/sbom?id&format`, `scan/registry/image/sbom?name&imageId&format` → `/v1/scan/.../sbom`. Każda wartość kodowana (`URLEncoder`, `+`→`%20`). Odpowiedź kontrolera bez zmian. Nadzorca sprawdził: ścieżka z `..` trafia do kontrolera z tokenem tego samego użytkownika (RBAC w kontrolerze), bez eskalacji.
- Komponent `components/sbom-panel`: CycloneDX jako tekst, ag-grid (nazwa, wersja, purl, licencje, runtime z `neuvector:runtime=true`), filtr (`QuickFilterService`), pobieranie CycloneDX (ten sam tekst) i SPDX (drugie żądanie), `file-saver`. 404 → „Brak wyniku skanu”, inny błąd → „Nie udało się pobrać SBOM”.
- Zakładka „SBOM” (ostatnia) w szczegółach workloadu, węzła i w dialogu obrazu z rejestru (także `all`).
- RBAC w UI: `PERMISSION_MAP.sbom = ['sbom_r','sbom_w']`, `authUtils.getDisplayFlag('sbom')`. Bez `sbom` zakładka ukryta. Edytor ról: `sbom` w `permission.service.ts`, tłumaczenia en i zh_cn.
**Obraz:** `ghcr.io/wmp/neuvector-manager:claude-sbom-s7-ui-25b0950`. Fork test images run 44604311861: sukces (build obejmuje kompilację Scala).
**Decyzje:** manager nie ma widoku szczegółów obrazu runtime, więc `/v1/scan/image/:id/sbom` nie ma zakładki; SBOM obrazu jest w dialogu rejestru. Lista komponentów z dokumentu CycloneDX, bez nowego endpointu.
**Testy:** `ng build --configuration production`, `ng lint`, Prettier: OK. Karma (ChromeHeadless): 5/5 testów SBOM (pełny zestaw spec projektu nie kompiluje się – problem istniejący). Scala lokalnie bez sbt; kompilację potwierdza CI.
**Przeglądy (D17):** /code-review 1: 6 uwag, poprawiono 4. /code-review 2: 5 uwag, poprawiono 3. /code-review 3: 4 uwagi, poprawiono 2. Pominięte: wysokość gridu (jak istniejące), kodowanie ścieżki (httprouter dekoduje), kontener zakończony (otwarta sprawa). /security-review: 0 HIGH/MEDIUM.
**Otwarte sprawy:** kontener zakończony – zakładka pokazuje „Brak wyniku skanu” (do decyzji: ukryć albo inny komunikat). Brak sprawdzenia w przeglądarce z prawdziwym kontrolerem (TEST-RUNBOOK S7). Panel czyta tylko `components` pierwszego poziomu. Część B (Components z S4, ustawienia DT z S5) – po S4 i S5.

### S4: Wyszukiwanie komponentów i admission – wynik (sesja `session_01Y19972PmCiLenoPh37oTcJ`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s4-search-admission` w `neuvector-neuvector` (od `claude/sbom-s3-export-rbac`, 5 commitów, ostatni `1c0f139`).
- REST `GET /v1/scan/component?name=&purl=&version=` (`controller/rest/component.go`), uprawnienie `sbom`, wyniki według `acc`. `name` (≤256, bez wielkości liter) pasuje do nazwy komponentu SBOM albo nazwy w purl; `purl` (≤512) przez `PurlMergeKey`, bez wersji = wszystkie wersje; `version` (≤128, ≤8 ograniczeń): `2.17.1`, `<2.17.1`, `>=1.0, <2.0` (operatory `=`, `==`, `<`, `<=`, `>`, `>=`). `name` + `purl` = AND. Kody: 400 (parametry), 403 (brak `sbom`), 429 (inne wyszukiwanie trwa).
- Odpowiedź `RESTComponentSearchData`: `workloads` (id, name, container, domain, image, image_id, components), `hosts` (tylko globalny `sbom`), `images` (rejestry: registry, image_id, digest, images, domain, components; tagi z niedostępnych namespace ukryte), `running_images` (image_id, image, workloads, components). Listy posortowane, zawsze `[]`.
- Porównanie wersji (`controller/sbom/version.go`): deb/rpm/apk/alpm i komponenty bez purl – dpkg (`utils.NewVersion`); inne typy – `hashicorp/go-version`, zapas dpkg; bez parsowania – `=` jako napis.
- Admission (`controller/cache/admission.go`): D23 – moduły `Origin=syft` pominięte w `modules`. Nowy zakres `nazwa>=a<b` (≥2 granice, bez przecinka, bo przecinek dzieli wpisy, porównanie dpkg). Stare formaty bez zmian. Walidacja przy zapisie (REST 400, CRD) tylko dla wpisów z ≥2 `<`/`>`.
- Nowy `db.GetModules` (tylko kolumna modułów); używają go też endpointy SBOM z S3. Odczyt SQLite poza `scanMutex`/`stateMux`.
- DoS: jedno wyszukiwanie naraz (`TryLock`, 429), limity parametrów, przerwanie po rozłączeniu klienta.
**Obrazy:** `ghcr.io/wmp/neuvector-controller:claude-sbom-s4-search-admission-1c0f139`, `ghcr.io/wmp/neuvector-enforcer:claude-sbom-s4-search-admission-1c0f139`. CI run 44605869875 i Fork test images run 44605870046: sukces.
**Testy:** `go test ./controller/... ./db/... ./share/...` OK (nadzorca powtórzył dla `cache`, `sbom`, `rest`, `access`, `scan`, `db`: OK). golangci-lint 0, openapi-lint OK. RBAC: ns1 nie widzi ns2, hostów, rejestru ns2, tagów innych namespace; brak `sbom` = 403. Regresja D23: wynik reguł `modules` taki sam z modułami Syft i bez nich. Pomiar: 2000 workloadów × 500 modułów w SQLite = 3,2–5,2 s (cel < 1 min, bez tabeli indeksu).
**Przeglądy (D17):** /code-review 1: 7 uwag, poprawiono 4. /code-review 2: 6 uwag, poprawiono 4. /code-review 3: 7 uwag, poprawiono 5. Pominięte: stare wartości w formacie zakresu zaczną działać (cel S4), `vim=<1.0` bez walidacji (jak przed zmianą), różne komparatory w wyszukiwaniu i admission (zgodność wsteczna), zły zakres w CRD = błąd (jak zły regex), `baseOS` z innego skanu przy jednoczesnym skanie (rzadkie, wpływa tylko na `distro`). /security-review: 0 HIGH/MEDIUM.
**Otwarte sprawy:**
- **Federacja z różnymi wersjami:** starszy klaster zarządzany czyta zakres starym parserem i reguła nigdy nie pasuje (bez błędu). Przed PR upstream: wymaganie wersji albo blokada zakresu w regułach fed (§11).
- Reguły zapisane przed S4 w formacie zakresu zaczną działać – opisać w informacji o wydaniu.
- Różne komparatory: `2.0.0-beta1 < 2.0.0` w wyszukiwaniu, ale nie w admission.
- Czas wyszukiwania dla wielu obrazów w rejestrach niezmierzony.
- Admission wymaga pełnej nazwy NV (jar: `org.apache.logging.log4j:log4j-core>=2.0.0<2.17.1`). Samo `log4j-core` działa tylko w wyszukiwaniu.

### S5: Dependency-Track – wynik (sesja `session_01Y19971rN5EokWvWw9am8Lz`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s5-dependency-track` w `neuvector-neuvector` (od `claude/sbom-s3-export-rbac`, 10 commitów, ostatni `f5144ec` – D25; obrazy `ghcr.io/wmp/neuvector-{controller,enforcer}:claude-sbom-s5-dependency-track-f5144ec`, CI run 44613205380: sukces). Bez nowych modułów Go.
- Konfiguracja: `CLUSSystemConfig.DependencyTrack` (`share.CLUSDependencyTrack`): `enabled`, `url`, `api_key` (tag `cloak`), `project_name`, `project_version`, `tags`, `inactive_grace_period` (min, domyślnie 1440). Domyślnie wyłączona.
- REST: `GET /v1/sbom/dependency_track` (globalny `sbom` odczyt; zwraca `api_key_set`, nigdy klucza) i `PATCH` (globalny `sbom` zapis; pola opcjonalne; `api_key: ""` usuwa klucz). 400: zły URL (tylko http/https, bez userinfo/query/fragmentu), `enabled` bez URL/klucza, **nowy URL bez nowego `api_key`** (ochrona klucza), zły szablon (nieznany symbol, nawiasy, znaki sterujące, >1024), tagi (przecinek, puste, >50).
- Pakiet `controller/sbom/dtrack`: szablony (`strings.NewReplacer`, jeden przebieg), klient (multipart `POST /api/v1/bom`, lookup, `PATCH active`, bez przekierowań), `Uploader` (1 worker, deduplikacja, backoff 30 s → 30 min, 8 prób; 413 i 4xx bez ponowień).
- Podgląd: `POST /v1/sbom/dependency_track/preview`, body `{"project_name"?, "project_version"?, "tags"?, "workload_id"}` (pominięte pole = zapisana konfiguracja), odpowiedź `{"project_name","project_version","tags":[],"skipped_reason"?}` (`skipped_reason`: pusty symbol, `pod not known yet`, `workload is not running`, `workload is not a scanned container`). 400/403/404/500. Wspólny kod z wysyłką (`dtrackVars` + `dtrack.Render`), bez wysyłki i bez klucza. Uprawnienie: globalny `sbom` zapis (D25). `CacheInterface.DtrackPreview(id, cfg)`. Commity `e3bc8d4`, `0f3a48a`; CI run 44611756382: sukces.
- `controller/cache/dtrack.go`: wysyłka po `scanDone` kontenera, przegląd co 5 min, mapa podów z eventów k8s, tylko lider, reset kolejki po utracie lidera. SBOM = `sbom.Write` (CycloneDX z S3) po `json.Compact`.
**Obrazy:** `ghcr.io/wmp/neuvector-controller:claude-sbom-s5-dependency-track-830ee31`, `ghcr.io/wmp/neuvector-enforcer:claude-sbom-s5-dependency-track-830ee31`. CI run 44607140970 i Fork test images run 44607140894: sukces.
**Testy:** 34 testy + test szyfrowania (`dtrack`, szablony, cache z `httptest` jako DT, REST). `-race` OK. Testy logów: klucz API nie występuje w logach ani błędach. Nadzorca powtórzył `go test` dla `sbom/...`, `cache`, `rest`, `common`, `scan`: OK.
**Ustalenia z DT (zamknięcie [weryfikacja] z §5; źródła: kod DT master i docs.dependencytrack.org):**
- `POST /api/v1/bom` multipart: `project`, `autoCreate`, `projectName`, `projectVersion`, `projectTags`, `parentName`, `parentVersion`, `parentUUID`, `isLatest`, `bom` (czysty JSON). Uprawnienia klucza: BOM_UPLOAD + PROJECT_CREATION_UPLOAD (albo PORTFOLIO_MANAGEMENT); dla „inactive”: VIEW_PORTFOLIO + PORTFOLIO_MANAGEMENT. Nagłówek `X-Api-Key`.
- `projectTags`: jeden napis, przecinki; od DT 4.12.0 (poprawka dla istniejących projektów 4.12.7). Tag `klucz=wartość` jest poprawny; DT zmienia nazwę tagu na małe litery (`PRODUKT=x` → `produkt=x`).
- `active`: `PATCH /api/v1/project/{uuid}` `{"active":false}` (200/304/409), UUID z `GET /api/v1/project/lookup?name=&version=`. Pole od 4.12.0. Wysyłka do nieaktywnego projektu nie aktywuje go, więc NV ustawia active=true przed pierwszą wysyłką **[weryfikacja na żywym DT]**.
- DT nie ma własnego limitu rozmiaru BOM; 413 pochodzi z proxy (FAQ: `nginx.ingress.kubernetes.io/proxy-body-size: "100m"`). Limity Jetty/Alpine **[weryfikacja]**.
- **Minimalna wersja DT: 4.12.0** (tagi i `active`), zalecana ≥ 4.12.7.
**Decyzje:** klucz przez tag `cloak` (wzór sekretów NV w KV: DEK, migracja, eksport), nie `EncryptSensitive`; `Format` ukrywa klucz w `%v`. Odchudzony CycloneDX niepotrzebny (kontroler nie ma `properties` Syft). Deduplikacja: klucz nazwa+wersja, pamiętany digest (5 replik = 1 wysyłka). Zastępstwo `{replicaset}` → `{pod}` w nazwie, wersji i tagach. Pod bez eventu k8s pominięty do przeglądu. „Inactive”: lider + `syncInitDone` + grace od wyboru lidera, od startu uploadera i od ostatniego widzenia projektu; stan w pamięci lidera, więc restart niczego nie oznacza. Poza Kubernetes: ostrzeżenie, bez wysyłki. `resolveRegistry` ma ochronę przed nil registry (`67f1cf2`).
**Przeglądy (D17):** /code-review 1: 10 uwag, poprawiono 7 (m.in. kradzież klucza przez zmianę URL). /code-review 2: 9 uwag, poprawiono 7. /code-review 3: 8 uwag, poprawiono 5. Pominięte: wyścig na `syncInitDone` (wzór `isLeader()`), osierocone projekty i odświeżanie SBOM (otwarte sprawy, komentarze `shortcut:`), nil-check w innych miejscach `repoScanRegistry` (istniejący). /security-review: 0 HIGH/MEDIUM; LOW (kolizja projektów przy szablonie tylko z etykiet poda) pominięta.
**Otwarte sprawy:** projekty wysłane przed restartem/zmianą lidera/zmianą konfiguracji nigdy nie dostają „inactive” (bezpieczne, ale zostają; rozwiązanie: klucze w KV). SBOM w DT odświeżany tylko po zmianie digest albo restarcie (rozwiązanie: hash modułów). Etykiety Deployment niedostępne (§5). Konfiguracja tylko przez REST (bez helm).

### S7 (część B1): UI – widok „Components” – wynik (sesja `session_01Y199724PNuPQ5sBeo1XLqV`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s7-ui` w `neuvector-manager`, 4 commity, ostatni `ad2c981`. Obraz: `ghcr.io/wmp/neuvector-manager:claude-sbom-s7-ui-ad2c981`. Fork test images run 44612022488: sukces.
- Proxy Scala `GET scan/component?name&purl&version` → `/v1/scan/component` (`PolicyService.searchComponents`, wspólne `enc`).
- Strona `routes/sbom-components` (trasa `/components`, menu „Security Risks > Components”, ukryte bez `sbom`). Formularz: nazwa (≤256), purl (≤512), wersja/zakres (≤128). 4 tabele: pody, węzły, obrazy z rejestru, obrazy działających podów. 429 → „spróbuj ponownie”.
- Przejścia: pod → `/workloads?container=<id>` (szczegóły z zakładką SBOM), węzeł → `/hosts?node=<id>` (nowy link głęboki), obraz z rejestru → `/regScan?registry&image&tag` (dialog z zakładką SBOM). Kryterium S7 (komponent → pody → szczegóły poda) spełnione w kodzie.
**Testy:** `ng build --configuration production`, `ng lint`: OK. Karma 11/11. Scala: CI.
**Przeglądy (D17):** /code-review 1: 10 uwag, poprawiono 5. /code-review 2: 7, poprawiono 2. /code-review 3: 8, poprawiono 2. Pominięte m.in.: digest w `images` (S4 zwraca tylko `repo[:tag]`), strażnik trasy (kontroler zwraca 403), tylko pierwszy tag obrazu. /security-review: 0 HIGH/MEDIUM.
**Otwarte sprawy:** wiersz obrazu z kilkoma tagami otwiera pierwszy tag; brak strażnika trasy `/components`; menu nie jest filtrowane ponownie po przełączeniu na klaster zdalny; obrazy działających podów bez linku (brak widoku obrazu runtime); brak testu w przeglądarce (TEST-RUNBOOK S7).

### S7 (część B2): UI – ustawienia Dependency-Track – wynik (sesja `session_01Y199724PNuPQ5sBeo1XLqV`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s7-ui` w `neuvector-manager`, 4 commity, ostatni `fd677fe`. Obraz: `ghcr.io/wmp/neuvector-manager:claude-sbom-s7-ui-fd677fe`. Fork test images run 44617301541: sukces.
- Proxy Scala: `GET`/`PATCH sbom/dependency_track`, `POST sbom/dependency_track/preview`. Logi tylko ze stałym tekstem (nadzorca sprawdził), treść JSON bez zmian (wzór istniejących tras).
- Strona `routes/settings/dependency-track`, kafelek w ustawieniach (nieaktywny bez globalnego `sbom`). `PERMISSION_MAP.sbom_global_read`, `write_sbom`. Bez zapisu: tylko odczyt, bez „Save” i podglądu.
- Klucz API: `type=password`, nigdy nie jest wypełniany; `api_key_set` → „API key saved”, „Remove key” (`api_key: ""`), „Keep the key”. Po zmianie URL klucz wymagany, gdy jest zapisany (reguła S5).
- Podgląd: lista kontenerów (`AssetsHttpService.getContainers()`), wynik nazwa/wersja/tagi albo `skipped_reason`. Pomoc: symbole, tagi małymi literami, uprawnienia klucza DT, DT ≥ 4.12.0. Tłumaczenia en i zh_cn.
**Testy:** `ng build --configuration production`, `ng lint`: OK. Karma 21/21 (A, B1, B2).
**Przeglądy (D17):** /code-review 1: 8 uwag, poprawiono 7. /code-review 2: 8, poprawiono 5. /code-review 3: 9, poprawiono 3. /security-review: 0 HIGH/MEDIUM (klucz nie jest logowany i nie wraca do przeglądarki).
**Otwarte sprawy:** `skipped_reason` tylko po angielsku; lista kontenerów w podglądzie bez stronicowania; brak strażnika trasy (kontroler 403); tłumaczenia zh_cn do przeglądu przez osobę znającą język; brak testu w przeglądarce i z żywym DT.

### S7 (część C): UI – magazyn SBOM w S3 – wynik (sesja `session_01Y199724PNuPQ5sBeo1XLqV`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s7-ui` w `neuvector-manager`, 4 commity, ostatni `e5c3238`. **Ostatni obraz UI: `ghcr.io/wmp/neuvector-manager:claude-sbom-s7-ui-e5c3238`.** Fork test images run 44631895960: sukces. S7 łącznie: 16 commitów (A, B1, B2, C).
- Proxy Scala: `GET`/`PATCH sbom/s3`, `GET sbom/s3/images` (logi ze stałym tekstem – nadzorca sprawdził).
- Strona `routes/settings/sbom-storage`: konfiguracja (tylko z globalnym `sbom` odczyt, edycja z zapisem), pola jak w API, sekret jak klucz DT w B2 (password, `secret_key_set`, Remove/Keep, wymagany po zmianie endpointu). `delete_unused`: ostrzeżenie i dialog potwierdzenia. Lista zapisanych SBOM (ag-grid) z pobieraniem przez endpoint SBOM obrazu z rejestru. Pomoc: MinIO, IRSA, unikalny prefiks. Tłumaczenia en i zh_cn.
**Testy:** `ng build --configuration production`, `ng lint`: OK. Karma 33/33 (cała S7).
**Przeglądy (D17):** /code-review 1: 6 uwag, poprawiono 1. /code-review 2: 6, poprawiono 2. /code-review 3: 6, poprawiono 2. /security-review: 0 HIGH/MEDIUM.
**Otwarte sprawy:** **logowanie sekretów w managerze zależy od biblioteki**: `ClientSslConfig.sendReceiver` loguje `request.toString` (INFO); pekko-http 1.0.1 wypisuje tylko rozmiar treści, ale po podniesieniu pekko-http trzeba to sprawdzić albo jawnie maskować treść dla `sbom/s3` i `sbom/dependency_track` (ten sam mechanizm dotyczy istniejących sekretów managera). SBOM obrazu usuniętego z rejestru zostaje na liście (karencja), ale pobranie zwraca 404 (rozwiązanie: endpoint pobrania z S3 po digest). Brak strażników tras (kontroler 403). Brak testu w przeglądarce i z MinIO.

### S5 – hierarchia projektów DT (D28) – wynik (sesja `session_01Y19971rN5EokWvWw9am8Lz`, przegląd nadzorcy: OK)
**Co zrobiono:** commity `d424937`, `0769d07`, `1014305`, `f55a66e` na `claude/sbom-s5-dependency-track`. Obrazy `ghcr.io/wmp/neuvector-{controller,enforcer}:claude-sbom-s5-dependency-track-f55a66e`. CI run 44878698107 i Fork test images run 44878698117: sukces. Nadzorca powtórzył testy `sbom/...`, `cache`, `rest`, `access`: OK.
- Poziomy = segmenty `project_name` rozdzielone `/` poza `{...}` (`splitLevels`). Nazwa poziomu = pełna ścieżka. Rodzice bez wersji; wersja i tagi tylko na liściu.
- `{rancher.project}` = etykieta namespace `field.cattle.io/projectId`; pusty poziom nadrzędny pominięty; pusty liść = brak wysyłki. Domyślny szablon: `{cluster}/{rancher.project}/{namespace}/{replicaset}/{container}`. Pusty poziom w szablonie (`a//b`) = 400.
- Lider tworzy/aktywuje rodziców od korzenia (`PUT /api/v1/project`, `PATCH`), pamięta UUID. Istniejący płaski liść dostaje rodzica przez `PATCH`. Wysyłka `POST /api/v1/bom` z `parentUUID`. Workload czeka na dane namespace w cache.
- „Inactive” kaskadowo: liście, potem rodzice bez żywych liści, od najgłębszego; 409 bez pętli; restart nic nie dezaktywuje.
- Podgląd: nowe pole `parents` (od korzenia).
**Ustalenia z DT (kod master, changelog):** rodzic bez wersji działa (lookup bez parametru `version` = `version == null`); `PUT /api/v1/project` z nieznanym UUID rodzica tworzy projekt bez rodzica (NV poprawia przez PATCH); `POST /api/v1/bom` ustawia rodzica tylko przy autoCreate, rodzic musi istnieć; `PATCH` zwraca 409 dla nieaktywnego rodzica i dla dezaktywacji rodzica z aktywnymi dziećmi. **Minimalna wersja DT: 4.12.7. Klucz: BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO, PORTFOLIO_MANAGEMENT** (bez PORTFOLIO_MANAGEMENT wysyłka płaska).
**Przeglądy (D17):** /code-review 1: 8 uwag, poprawiono 6. /code-review 2: 8, poprawiono 5. /code-review 3: 7, poprawiono 3. /security-review: 0 (nazwa rodzica to zawsze prefiks ścieżki dziecka, więc właściciel namespace nie przeniesie projektu innego zespołu).
**Otwarte sprawy:**
- **Nowy domyślny szablon zmienia nazwy projektów w namespace z projektem Rancher.** Stare płaskie projekty `klaster/ns/rs/kontener` zostają aktywne w DT (NV ich nie zna) – usuń je ręcznie albo zapisz stary szablon przed aktualizacją. W namespace bez Rancher nazwy są takie same, a stare projekty dostają rodzica.
- Powrót do płaskiego szablonu nie przenosi projektów do korzenia (`shortcut:`).
- **[weryfikacja na żywym DT]:** lookup bez wersji (null w DataNucleus), BOM pod nieaktywnym rodzicem (prawdopodobnie 500), kody 409.
- Rodzice sprzed restartu/zmiany lidera nie dostają „inactive” (ten sam skrót co dla liści).

### S7 – zmiana D28 (sesja `session_01Y199724PNuPQ5sBeo1XLqV`)
Commity `06ad42a`, `8ae5183` na `claude/sbom-s7-ui`. **Obraz `ghcr.io/wmp/neuvector-manager:claude-sbom-s7-ui-8ae5183`** (Fork test images run 44880219648: sukces). Podgląd DT pokazuje hierarchię (`parents` + liść, z wcięciem; helper `projectPath`). Pomoc: `{rancher.project}`, zasada poziomów, nowy domyślny szablon, ostrzeżenie o zmianie nazw, uprawnienia klucza z PORTFOLIO_MANAGEMENT, DT ≥ 4.12.7. Karma 34/34, lint, build: OK. /code-review: 5 uwag, poprawiono 1.

### S6: Syft w skanerze – wynik (sesja `session_01Y19971RUMrz1fHKj5EopAB`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s6-syft` w `neuvector-scanner` (od `claude/sbom-s0-ci-ghcr`, 6 commitów, ostatni `99ae74f`). Obraz: `ghcr.io/wmp/neuvector-scanner:claude-sbom-s6-syft-99ae74f`. Workflow: sukces (uwaga: workflow unitest upstream nie uruchamia `go test`, bo `uname -p` = `unknown` na runnerze – problem istniejący).
- `deps(go)` (`b62bae2`): Syft v1.42.4, `replace github.com/neuvector/neuvector => github.com/WMP/neuvector-neuvector v0.0.0-20261119181710-3a8b8792ee72` (S2). Podniesienia (nadzorca sprawdził `go.mod`): `go-version` 1.8.0, `go-runewidth` 0.0.19 (D2), `go-rootcerts` 1.1.0, `yaml/v3` 3.0.6 (D24). 182 nowe moduły.
- purl (D19): `feature2Module` ustawia `Purl` przez `scan.ModulePurl` dla każdego modułu. dpkg: wersja binarna (`Version:`), apk: nazwa binarna (`P:`) – tylko dla purl (`FeatureVersion.PurlName`, `PurlVersion`). `Name`/`Version` do CVE bez zmian (nadzorca sprawdził diff parserów).
- Syft (`cvetools/syft.go`): tylko skan obrazu z warstwami na dysku (`bFromRawData`), pominięty przy `-maxrec` > 0. Katalog `imgPath/syft-*`: tylko katalogi i twarde dowiązania do zwykłych plików (`Lstat`), nigdy symlinki. `directorysource` (`Base = root`), katalogery z tagiem `image`. Równolegle ze skanem CVE.
- Scalanie (`mergeSyftModules`, `PurlMergeKey`): moduł NV wygrywa, Syft dodaje `Licenses`. apk z Syft scalany z modułem origin. Jar NV dostaje purl z Syft przy dopasowaniu po pliku i wersji (1 pakiet Syft w pliku). Pakiety tylko z Syft: `Origin=syft`, `Source` = typ Syft, bez `Vuls`. Dopasowanie CVE bez zmian.
- Wyłączenie: zmienna `SCANNER_DISABLE_SYFT` (`strconv.ParseBool`), domyślnie Syft włączony (D22). Limit 300 s (katalog + Syft), twardy termin czekania 310 s; błąd/timeout/panic = skan bez danych Syft. Bez importu `_ "modernc.org/sqlite"` (sterownik rejestruje już `glebarez/go-sqlite`; drugi import = panic).
**Pomiar** (standalone, 4 vCPU, baza CVE 4.329 z ręcznym `cosign verify`):

| Obraz | ScanImage przed / po [s] | Syft [s] | gzip przed → po [B] | % z 512 KiB | Zgodność z `syft registry:` | Max RSS przed → po [MB] |
|---|---|---|---|---|---|---|
| debian:12 | 7,0 / 7,3 | 1,6 | 7 232 → 9 805 | 1,9% | 97,8% | ~1320 → ~1575 |
| log4shell | 5,8 / 5,6 | 1,6 | 8 721 → 10 179 | 1,9% | 98,9% | ~1250 → ~1510 |
| node-exporter v1.8.2 | 2,8 / 3,0 | 1,1 | 4 773 → 5 247 | 1,0% | 97,9% | ~1085 → ~1335 |
| druid 30.0.1 | 17,3 / 19,9 | 5,7 | 46 390 → 61 354 | 11,7% | 98,4% | ~1610 → ~2005 |
| n8n 1.64.0 | 26,1 / 41,3 | 7,3 | 60 400 → 76 780 | 14,6% | 99,6% | ~1325 → ~1895 |
| **Razem** | | | | **maks. 14,6%** | **99,1%** (2497/2520), pokrycie Syft 99,96% | |

Kryteria S6 spełnione (< 512 KiB, ≥ 98% łącznie). Poniżej 98%: debian12 (`generic/bash`, `gzip` – brak symlinka usrmerge), node-exporter (busybox – `TypeLink` w tar). Licencje: debian12 86/90, log4shell 80/106, druid 964/1345, n8n 1937/1975 modułów.
**Testy:** `go test ./...` OK (nadzorca powtórzył `cvetools`, `detectors`, `common`: OK). Testy m.in.: katalog bez symlinków (także `-> /etc/passwd`), `..` nie wychodzi poza katalog, katalogery `image` (npm bez lockfile), limit czasu, brak duplikatów jar/python/go/deb/apk, jar shaded, licencje SPDX.
**Przeglądy (D17):** /code-review 1: 10 uwag, poprawiono 6 (+1 własna). /code-review 2: 8 uwag, poprawiono 8 (+2 własne). /code-review 3: 5 uwag, poprawiono 4. Pominięte: `replace` na fork (plan), D22, `Source` = typ Syft, problemy istniejące (apk bez pustej linii, dpkg `hold`). /security-review: 0 podatności.
**Otwarte sprawy:**
- Panic w goroutine katalogera Syft może zakończyć proces skanera (DoS; `recover` łapie tylko goroutine wywołującą). Po terminie goroutine Syft działa do końca i sama usuwa katalog.
- **Pamięć skanera +230–570 MB RSS**, n8n +15 s – sprawdzić limity pamięci poda skanera w helm (TEST-RUNBOOK S6).
- Ten sam purl w kilku modułach (pom + MANIFEST, wiele lokalizacji) – deduplikacja po purl w `sbom.Components` zlecona S3 (uzupełnienie).
- Potrzebne zmiany w `share/scan` (osobna sesja/PR): źródło metadanych jar (pom/MANIFEST), jar zagnieżdżony 2+ poziomy, vendor composer, `TypeLink`/`TypeSymlink` w `ExtractAllArchive` (busybox).
- Problemy istniejące (osobne PR skanera): dpkg `hold ok installed` pomijany; workflow unitest (`uname -p` → `uname -m`).
- Dla S8: `runSyft` zwraca tylko `[]pkg.Package`; pełny SBOM wymaga `*sbom.SBOM`.

### S8a: Magazyn S3 – kontroler – wynik (sesja `session_01Y19972i6GRVGCT7x7PS6jQ`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-s8-s3-storage` w `neuvector-neuvector` (od `claude/sbom-s3-export-rbac` `0f61914`, 11 commitów, ostatni `84ebcea`). Obrazy `ghcr.io/wmp/neuvector-{controller,enforcer}:claude-sbom-s8-s3-storage-84ebcea`. CI run 44625822533 i Fork test images run 44625822639: sukces. `go.mod` bez zmian (nadzorca sprawdził); `vendor/` tylko pakiety `service/s3` z `aws-sdk-go` v1.55.7 (`9554983`).
- **Proto (dla S8b):** `ScanImageRequest.IncludeFullSBOM` (13), `ScanResult.FullSBOM` (29, gzip), `ScanResult.FullSBOMFormat` (30, `share.FullSBOMFormatCycloneDX` = `cyclonedx-json`). Kod generowany: `c19e089`. Skaner: `replace github.com/neuvector/neuvector => github.com/WMP/neuvector-neuvector v0.0.0-20261119220907-84ebcea44eb3`.
- **Kontrakt skanera:** flaga tylko przy włączonym S3, tylko w skanach rejestru i przy niepustym digest. Przy fladze: pełny CycloneDX JSON z Syft, gzip, ≤ 32 MiB (`s3store.MaxObjectSize`), cała wiadomość < 64 MiB gRPC. Za duży/błąd/brak Syft: pole puste, skan bez błędu. `result.Digest` musi być równy digest z listy rejestru.
- **Konfiguracja** `CLUSSystemConfig.SBOMStorage` (`sbom_s3`): `enabled`, `endpoint`, `region`, `bucket`, `prefix`, `path_style`, `access_key`, `secret_key` (`cloak`), `delete_unused` (false), `delete_grace_period` (min, 0 = 1440). Puste klucze = łańcuch AWS SDK (IRSA). REST `GET/PATCH /v1/sbom/s3` (globalny `sbom`, PATCH = zapis; zmiana endpointu wymaga nowego `secret_key`; walidacja endpointu, regionu, bucket, prefiksu). Sekret nie wraca w REST ani w logach.
- **Pakiet `controller/sbom/s3store`:** klucz `<prefix>/<cluster>/images/<digest>.cdx.json.gz` (digest `sha256:`/`sha512:` hex). Właściciel obiektu w `x-amz-meta-nv-owner` (rejestr + ID obrazu). Klient bez przekierowań.
- **Zapis:** upload w tle po zapisie wyniku, maks. 4 naraz, timeout 2 min, nadpisanie. Pole usuwane przed zapisem do KV (i w `encodeScanReport`). Błąd S3 = ostrzeżenie.
- **Usuwanie (D15)** `controller/cache/sbom_s3.go`: co 10 min, tylko lider, po `syncInitDone`, `delete_unused=true`; obecne digesty = rejestry + `ImageDigest`/`ImageRepoDigests` workloadów; pusty zbiór = brak usuwania; karencja od pierwszego przeglądu lidera i od `leaderElectedAt` (nadzorca sprawdził warunki). Restart i zmiana lidera niczego nie usuwają przed pełną karencją.
- **REST:** `GET /v1/sbom/s3/images` (RBAC; `{"images":[{registry,image_id,digest,images[],size,last_modified}]}`). `format=cyclonedx` dla obrazu rejestru i `/v1/scan/image/:id/sbom` zwraca dokument z S3 po tej samej kontroli RBAC (sprawdzenie CRC, ≤ 32 MiB gzip, ≤ 256 MiB JSON, maks. 4 pobrania, 30 s); inaczej inwentarz. Workload, host i SPDX: zawsze inwentarz (D26).
**Testy:** `go test ./controller/... ./share/...` OK, `-race` OK, golangci-lint 0, Redocly OK. Nadzorca powtórzył 8 pakietów: OK. Testy m.in.: oba `delete_unused`, karencja, restart, brak lidera, brak synchronizacji, pusty zbiór, cudze obiekty, digest wraca; błąd S3 nie blokuje skanu; pole nie trafia do KV; sekret nie w logach; 403 bez zapytania do S3.
**Przeglądy (D17):** /code-review 1: 9 uwag, poprawiono 6. /code-review 2: 10 uwag, poprawiono 6 (m.in. **PATCH był w mapie uprawnień DELETE**). /code-review 3: 8 uwag, poprawiono 6. /security-review: **1 HIGH poprawiony** (`84ebcea`): rejestr dodany przez użytkownika namespace mógł podać cudzy digest i nadpisać SBOM innego tenanta – teraz właściciel obiektu w metadanych.
**Otwarte sprawy:**
- Zmiana nazwy klastra zostawia stare obiekty (rozwiązanie: stały ID klastra w kluczu). Klastry z tą samą nazwą i prefiksem we wspólnym bucket kolidują – wymagany unikalny prefiks (dokumentacja).
- Multi-arch: digest indeksu (workload) i manifestu (rejestr) mogą się różnić – przy `delete_unused=true` obiekt może zniknąć, choć pod działa.
- Proxy rejestru używane też dla S3 (bez no_proxy dla wewnętrznego MinIO).
- Zapis konfiguracji S3 wymaga tylko globalnego zapisu `sbom` (SSRF przez endpoint dla tej roli) – §11.
- `Docker-Content-Digest` nie jest sprawdzany z treścią manifestu (problem istniejący, osobny PR).
- aws-sdk-go v1 wycofany przez AWS; upstream może chcieć v2.
- Lista `/v1/sbom/s3/images` czyta cały prefiks klastra (+ HEAD) przy każdym wywołaniu.
- Uwaga procesowa sesji: jeden błędny `git reset --hard` w trakcie pracy; zmiany odtworzone, commity kompletne.

### S8b: Pełny SBOM w skanerze – wynik (sesja `session_01Y19971ctDDmFyJiRU9pnCP`, przegląd nadzorcy: OK po push 2026-11-21)
**Co zrobiono:** gałąź `claude/sbom-s8-scanner` w `neuvector-scanner` (od `claude/sbom-s6-syft` `99ae74f`, 5 commitów lokalnie: `0c05eec` deps(go), `46a0f04` feat, `92111d5`, `c7c25f3`, `c27f6fe` fix). Push 2026-11-21 po zgodzie użytkownika. **Obraz `ghcr.io/wmp/neuvector-scanner:claude-sbom-s8-scanner-c27f6fe`.** Fork test images run 44927169271: sukces. Nadzorca sprawdził diff (`go.mod`: tylko `replace` i D27) i powtórzył testy `cvetools`, `detectors`, `common`: OK.
- `deps(go)`: `replace` → `WMP/neuvector-neuvector v0.0.0-20261119220907-84ebcea44eb3` (S8a). Podniesienie `cyclonedx-go` 0.10.0 → 0.12.0 (D27). 0 nowych modułów.
- `ScanImage` (tylko ścieżka z Syft): przy `req.IncludeFullSBOM` pełny dokument Syft → CycloneDX 1.6 JSON → gzip → `result.FullSBOM`, `FullSBOMFormat = share.FullSBOMFormatCycloneDX`. Kodowanie zaraz po Syft. `metadata.component`: `container`, nazwa `<host rejestru>/<repozytorium>`, wersja = digest; ścieżka tymczasowa nie trafia do dokumentu.
- Limity: gzip > 32 MiB, `proto.Size(result)` > min(limit gRPC, 64 MiB) − 1 MiB, błąd albo panic = pole puste, WARN, skan bez błędu. `result.Digest` bez zmian. Inne ścieżki skanu bez zmian.
**Pomiar:** debian:12 15 421 B gzip (165 KB JSON, 15 ms), druid 139 590 B (2,0 MB, 64 ms), n8n 226 280 B (3,0 MB, 123 ms). Maks. 0,7% limitu 32 MiB. Pamięć w granicach szumu.
**Testy (według sesji):** `go test ./...` OK; `TestFullSBOM` (flaga, bez flagi, brak Syft, limit 32 MiB, limit gRPC, limit 64 MiB). Walidacja `specs/validate.py`: druid i n8n VALID; **debian:12 INVALID** – ID licencji `Artistic-dist`, `SMAIL-GPL` nie ma w `spdx.schema.json` z tagu CycloneDX 1.6 w `specs/` (nowsza lista SPDX w Syft). Dotyczy tylko dokumentu z S3 (dokument z kontrolera S3 klasyfikuje nieznane ID jako `license.name`).
**Przeglądy (D17, według sesji):** /code-review 1: 7 uwag, poprawiono 5. /code-review 2: 5, poprawiono 2. /code-review 3: 7, poprawiono 4. /security-review: 0.
**Otwarte sprawy:** nieznane ID licencji SPDX w dokumencie Syft (aktualizacja `specs/` albo zamiana nieznanych `id` na `name` w skanerze); ten sam limit gRPC wymagany w kontrolerze i skanerze; pominięcie SBOM widać tylko w logu skanera.

### S9: Integracja neuvector – wynik (sesja `session_01Y1996xnte5eBWXJgPh7W8v`, przegląd nadzorcy: OK)
**Co zrobiono:** gałąź `claude/sbom-integration` w `neuvector-neuvector` (od `claude/sbom-s8-s3-storage`) = S0 CI + S2 + S3 (z łączeniem po purl) + S8a + merge S4 (`5b2f0a4`) + merge S5 (`e8ddf2e`) + 2 poprawki: `d3dfeb3` (brak pustego SBOM dla obrazu usuniętego z rejestru w trakcie odczytu z bazy), `0148fe3` (test mapowania URI dla S4 i S5). **Tylko do testów – nie do PR upstream.**
**Konflikty** (rozwiązane przez zachowanie obu stron): `apis.yaml`; `access.go` (listy `CONST_API_SBOM`: S8a + S5); `share/clus_apis.go` (`SBOMStorage` i `DependencyTrack` w `CLUSSystemConfig`); `controller/api/apis.go`; `cache.go` (utrata lidera: `s3SweepReset` i `dtrackLeaderLost`); `config.go` (`s3store.Configure` i `dtrackConfigUpdate`); `marshal_test.go`.
**Sprawdzenie nadzorcy:** brak znaczników konfliktów; `go.mod`/`go.sum`/`vendor/` jak w bazie; `go build ./...` OK; `go test ./controller/... ./share/... ./db/...` – wszystko OK. CI run 44629462228 i Fork test images run 44629462426: sukces.
**Obrazy:** `ghcr.io/wmp/neuvector-controller:claude-sbom-integration-0148fe3`, `ghcr.io/wmp/neuvector-enforcer:claude-sbom-integration-0148fe3`.
**Uwaga:** sesja nie wysłała raportu (zakończyła turę po przeglądzie); dane z commitów merge i z przeglądu nadzorcy.
**Uzupełnienie D28:** merge `6290d14` (S5 `f55a66e`, bez konfliktów) i `fix` `3137103` (`GetScanModules` sprawdza `scanMap` po odczycie z SQLite, jak `d3dfeb3` dla rejestru). CI run 44880204849 i Fork test images run 44880204893: sukces. **Obrazy `ghcr.io/wmp/neuvector-{controller,enforcer}:claude-sbom-integration-3137103`.** Nadzorca powtórzył testy `cache`, `sbom/...`, `rest`: OK. /code-review: 2 uwagi, poprawiono 1 (pominięty test wyścigu – brak punktu wstrzyknięcia).
**Przed PR upstream:** poprawki `d3dfeb3` i `3137103` są tylko na gałęzi integracyjnej, a błąd pochodzi z S4 (odczyt SQLite poza blokadą). Przenieś je (cherry-pick) na `claude/sbom-s4-search-admission`. Problem istniejący: usunięcie obrazu z jednego rejestru kasuje wspólny wiersz SQLite dla tego samego ID w innych rejestrach.

## 11. Decyzje czekające na człowieka

- Wysłanie zgłoszenia `reports/upstream-security-cosign-failopen.md` e-mailem (D20).
- S3: rola własna z wszystkimi uprawnieniami odczytu (zapisana przed S3) automatycznie dostaje `sbom` (decyzja S3, `controller/access/access.go`, `getRolePermitValues`). Potwierdź przed PR upstream.
- D22: Syft domyślnie włączony. Potwierdź przed PR upstream.
- D24, D27: 3 podniesienia w skanerze wynikające z `go.mod` neuvector (go-rootcerts, yaml/v3, cyclonedx-go). Potwierdź przed PR upstream.
- S4: reguły admission z zakresem w federacji z klastrami starszych wersji nigdy nie pasują (bez błędu). Zdecyduj przed PR: wymaganie wersji albo blokada zakresu w regułach fed.
- S6: Syft zwiększa pamięć skanera o 230–570 MB. Sprawdź limity pamięci poda skanera w helm przed wdrożeniem.
- S8a: konfiguracja S3 (endpoint) wymaga tylko globalnego zapisu `sbom`, a nie `config` – rola z tym uprawnieniem może kierować żądania kontrolera na dowolny endpoint (SSRF, odpowiedzi nie wracają do wywołującego). Ten sam model co DT (S5). Potwierdź przed PR.
- S8a: aws-sdk-go v1 jest wycofany. Upstream może wymagać v2 (nowe moduły).
