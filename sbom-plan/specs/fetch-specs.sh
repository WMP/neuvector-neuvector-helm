#!/usr/bin/env bash
# Pobiera specyfikacje SBOM w przypiętych wersjach. Uruchom z katalogu specs/.
set -euo pipefail
CDX_REF=1.6          # CycloneDX/specification (tag)
SPDX_REF=v2.3        # spdx/spdx-spec (tag)
PURL_REF=5e4dd947d9f535616124f1f870ef9c04f5846227   # package-url/purl-spec (commit)
TYPES="deb rpm apk maven npm pypi golang gem nuget composer generic cran"

get() { mkdir -p "$(dirname "$2")"; curl -sSfL --retry 3 -o "$2" "$1"; echo "OK $2"; }

raw=https://raw.githubusercontent.com
get $raw/CycloneDX/specification/$CDX_REF/schema/bom-1.6.schema.json cyclonedx-1.6/bom-1.6.schema.json
get $raw/CycloneDX/specification/$CDX_REF/schema/spdx.schema.json    cyclonedx-1.6/spdx.schema.json
get $raw/CycloneDX/specification/$CDX_REF/schema/jsf-0.82.schema.json cyclonedx-1.6/jsf-0.82.schema.json
get $raw/CycloneDX/specification/$CDX_REF/LICENSE                     cyclonedx-1.6/LICENSE
get $raw/spdx/spdx-spec/$SPDX_REF/schemas/spdx-schema.json            spdx-2.3/spdx-schema.json
get $raw/spdx/spdx-spec/$SPDX_REF/LICENSE                             spdx-2.3/LICENSE

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git clone -q https://github.com/package-url/purl-spec "$tmp/purl-spec"
git -C "$tmp/purl-spec" checkout -q "$PURL_REF"
rm -rf purl && mkdir -p purl/types purl/type-docs purl/tests
cp -r "$tmp/purl-spec/docs/specification" purl/
cp "$tmp/purl-spec/LICENSE" purl/
cp "$tmp/purl-spec/tests/spec/specification-test.json" purl/tests/
for t in $TYPES; do
  cp "$tmp/purl-spec/types/$t-definition.json" purl/types/
  cp "$tmp/purl-spec/docs/types/definitions/$t-definition.md" purl/type-docs/
  cp "$tmp/purl-spec/tests/types/$t-test.json" purl/tests/
done
echo "OK purl @ $PURL_REF"
