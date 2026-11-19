#!/usr/bin/env python3
"""Validate an SBOM file against the local copies of the official schemas.

Usage: python3 -I validate.py cyclonedx|spdx <file.json>
Needs: pip install jsonschema (pulls in 'referencing'). Works offline.
"""
import json
import pathlib
import sys

import jsonschema
from referencing import Registry, Resource

HERE = pathlib.Path(__file__).resolve().parent
SCHEMAS = {
    "cyclonedx": HERE / "cyclonedx-1.6" / "bom-1.6.schema.json",
    "spdx": HERE / "spdx-2.3" / "spdx-schema.json",
}


def registry(schema_dir):
    # resolve relative $ref (spdx.schema.json, jsf-0.82.schema.json) from local files only
    res = []
    for p in schema_dir.glob("*.json"):
        r = Resource.from_contents(json.loads(p.read_text()))
        res.append((p.name, r))
        if r.id():
            res.append((r.id(), r))
    return Registry().with_resources(res)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in SCHEMAS:
        sys.exit(__doc__)
    schema_path = SCHEMAS[sys.argv[1]]
    schema = json.loads(schema_path.read_text())
    doc = json.loads(pathlib.Path(sys.argv[2]).read_text())
    cls = jsonschema.validators.validator_for(schema)
    v = cls(schema, registry=registry(schema_path.parent), format_checker=cls.FORMAT_CHECKER)
    errors = sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))
    for e in errors[:50]:
        print(f"ERROR {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message[:300]}")
    print(f"{sys.argv[2]}: {'INVALID' if errors else 'VALID'} ({len(errors)} errors)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
