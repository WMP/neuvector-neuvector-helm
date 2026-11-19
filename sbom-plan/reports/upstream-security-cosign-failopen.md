# Zgłoszenie bezpieczeństwa do upstream: fail-open w `ghcr-vulndb-artifact.sh`

**Kanał:** e-mail `security-neuvector@suse.com` (`neuvector/scanner/SECURITY.md`). Nie twórz publicznego issue.
**Status:** tekst gotowy do wysłania. Sesja Claude nie ma narzędzia do wysyłki e-mail. Wysyła człowiek.
**Do sprawdzenia przed wysłaniem:** treść, nadawca, czy `master` upstream ma ten sam kod (sprawdzono na `a3c5110`).

---

**Subject:** [neuvector/scanner] Signature verification in scripts/ghcr-vulndb-artifact.sh fails open

Hello NeuVector security team,

We found that the cosign signature check in `scripts/ghcr-vulndb-artifact.sh` (neuvector/scanner, checked at commit a3c5110, "chore: bump VULNDB_VERSION to 4.329") does not stop the script when verification fails. The script then downloads and writes the unverified CVE database. The release workflow (`.github/workflows/release.yml`, step that runs `ghcr-vulndb-artifact.sh download cvedb ...`) uses this script to put `data/cvedb.regular` into the official scanner image.

## Root cause

`download_artifact` and `verify_artifact` call:

    digest_ref=$(resolve_and_verify "$artifact_name" "$tag_ref")

`resolve_and_verify` runs `cosign verify ... >&2` and then `printf '%s\n' "$digest_ref"`. The function runs in a command substitution subshell. Bash does not apply `set -e` inside a command substitution unless `shopt -s inherit_errexit` is set. So a failed `cosign verify` does not stop the function, `printf` returns 0, the assignment returns 0, and the script continues with `crane export`. The code comment says "TOCTOU-safe, fail closed", but the behavior is fail open. The same applies to `crane digest` in `resolve_and_verify`.

## Impact

The signature check is the control that binds the database to the trusted signing workflow (`neuvector/release/.github/workflows/build-vuldbgen.yaml@refs/heads/master`). With this bug, anyone who can push or retag an artifact in the OCI repository (`ghcr.io/neuvector/vul/cvedb`, or the repository named by `OCI_REPOSITORY_PREFIX` / `GITHUB_REPOSITORY_OWNER`) can get an unsigned or wrongly signed database into a scanner release build. The cosign error appears only in the log and the job stays green. A tampered CVE database can hide vulnerabilities from all users of that scanner image.

Precondition: write access to the OCI repository (for example a leaked token or a compromised publisher). The bug removes the defense-in-depth layer for exactly this case.

## Reproduction (offline, stub binaries)

    mkdir -p poc/bin && cd poc
    cat > bin/cosign <<'X'
    #!/bin/sh
    echo "Error: no matching signatures" >&2; exit 1
    X
    cat > bin/crane <<'X'
    #!/bin/sh
    case "$1" in
     digest) echo sha256:0000000000000000000000000000000000000000000000000000000000000000;;
     export) d=$(mktemp -d); mkdir -p $d/db; echo UNSIGNED-PAYLOAD > $d/db/cvedb.regular; tar -cf "$3" -C $d db;;
    esac
    X
    chmod +x bin/*
    PATH=$PWD/bin:$PATH OCI_REPOSITORY_PREFIX=ghcr.io/example/vul \
      COSIGN_CERTIFICATE_IDENTITY=https://github.com/neuvector/release/.github/workflows/build-vuldbgen.yaml@refs/heads/master \
      bash <scanner>/scripts/ghcr-vulndb-artifact.sh download cvedb cvedb.regular out/cvedb.regular 4.329 /nonexistent.ref
    echo "exit=$?"; cat out/cvedb.regular

Result (GNU bash 5.2.21):

    Error: no matching signatures
    exit=0
    UNSIGNED-PAYLOAD

We also confirmed this with the real `cosign` v3.1.4 and the real artifact `ghcr.io/neuvector/vul/cvedb:4.329`, with a wrong `COSIGN_CERTIFICATE_IDENTITY`: cosign reports "no matching CertificateIdentity", and the script exits 0 and writes the database.

## Suggested fix

Tested with the stubs above: with a failing `cosign` the script exits 1 and writes no file. With a passing `cosign` the result is the same as before.

```diff
@@ resolve_and_verify
-  digest=$(crane digest "$tag_ref")
+  digest=$(crane digest "$tag_ref") || return 1
@@
-    "$digest_ref" >&2
+    "$digest_ref" >&2 || return 1
@@ verify_artifact
-  digest_ref=$(resolve_and_verify "$artifact_name" "$tag_ref")
+  digest_ref=$(resolve_and_verify "$artifact_name" "$tag_ref") || exit 1
@@ download_artifact
-  digest_ref=$(resolve_and_verify "$artifact_name" "$tag_ref")
+  digest_ref=$(resolve_and_verify "$artifact_name" "$tag_ref") || exit 1
```

An alternative is `shopt -s inherit_errexit` after `set -euo pipefail`, but the explicit `|| return 1` / `|| exit 1` also works if somebody calls the functions in another context. We suggest checking other scripts in the NeuVector repositories that call verification functions inside `$(...)`.

Thank you.
