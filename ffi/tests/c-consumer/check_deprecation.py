#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Compile every legacy declaration to check the CBOR-only deprecation boundary."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile


LEGACY = {
    "from_bytes", "to_bytes", "kind", "int", "simple", "bytes", "text", "tag",
    "tagged_payload", "len", "array_at", "map_at_int", "map_at_text", "map_at",
    "map_has_int_key", "map_has_text_key", "map_has_key", "map_entry_at",
    "map_key_at", "map_value_at", "free",
}
SUPPORTED = {
    "tav_validate_cose_sign1",
    "tav_verify_cose_sign1_embedded",
    "tav_verify_cose_sign1_detached",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True)
    parser.add_argument("--cxx", required=True)
    args = parser.parse_args()
    include = Path(__file__).resolve().parents[2] / "include"
    header = (include / "tav/cose.h").read_text()
    legacy = {"tav_cbor_value_" + suffix for suffix in LEGACY}
    declared = re.findall(r"\b(tav_\w+)\s*\([^;]*\);", header)
    assert len(declared) == len(set(declared)), "duplicate function declaration"
    assert set(declared) == legacy | SUPPORTED, "update the explicit ABI coverage"

    with tempfile.TemporaryDirectory(prefix="tav-deprecation-") as temporary:
        for compiler, extension, standard in (
            (args.cc, "c", "c11"), (args.cxx, "cpp", "c++17")
        ):
            source = Path(temporary) / ("consumer." + extension)
            for symbol in sorted(legacy | SUPPORTED):
                source.write_text(
                    '#include <tav/cbor.h>\n#include <tav/cose.h>\n'
                    f"void check(void) {{ (void)&{symbol}; }}\n"
                )
                result = subprocess.run(
                    [compiler, f"-std={standard}", "-Werror", "-Wdeprecated-declarations",
                     "-fsyntax-only", "-I", str(include), str(source)],
                    capture_output=True, text=True, check=False,
                )
                if symbol in legacy:
                    assert result.returncode != 0, f"{symbol} must be deprecated in {extension}"
                    assert "deprecated" in result.stderr and "Use tav/cbor.h" in result.stderr, result.stderr
                else:
                    assert result.returncode == 0, result.stderr
    print("All 21 legacy CBOR functions deprecated; COSE functions supported in C and C++.")


if __name__ == "__main__":
    main()
