# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Check that the C++ error enum maps every C error code exactly once."""

import re
from pathlib import Path


def enum_members(source, declaration):
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)
    match = re.search(declaration + r"\s*\{([^{}]*)\}", source)
    if match is None:
        raise ValueError(f"Enum declaration not found: {declaration}")
    members = {}
    for entry in match.group(1).split(","):
        if not entry.strip():
            continue
        member = re.fullmatch(r"\s*(\w+)\s*=\s*(\w+)\s*", entry)
        if member is None:
            raise ValueError(f"Unsupported enum entry: {entry.strip()}")
        name, value = member.groups()
        if name in members:
            raise ValueError(f"Duplicate enum member: {name}")
        members[name] = value
    if not members:
        raise ValueError("Error enum is empty")
    return members


def check_error_codes(c_source, cpp_source):
    c_members = enum_members(c_source, r"typedef\s+enum\s+TavErrorCode")
    cpp_members = enum_members(cpp_source, r"enum\s+class\s+ErrorCode\s*:\s*int")
    prefix = "TAV_ERROR_"
    if any(not name.startswith(prefix) for name in c_members):
        raise ValueError("C error code name does not start with TAV_ERROR_")
    expected = {name.removeprefix(prefix): name for name in c_members}
    missing = expected.keys() - cpp_members.keys()
    extra = cpp_members.keys() - expected.keys()
    incorrect = {
        name for name in expected.keys() & cpp_members.keys()
        if cpp_members[name] != expected[name]
    }
    if missing or extra or incorrect:
        raise ValueError(
            f"C++ ErrorCode mismatch: missing={sorted(missing)}, "
            f"extra={sorted(extra)}, incorrectly mapped={sorted(incorrect)}"
        )


if __name__ == "__main__":
    include = Path(__file__).resolve().parents[2] / "include" / "tav"
    check_error_codes(
        (include / "utils.h").read_text(),
        (include / "utils.hpp").read_text(),
    )
