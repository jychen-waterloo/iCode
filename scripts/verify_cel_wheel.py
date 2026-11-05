#!/usr/bin/env python3
"""Inspect a repaired CEL wheel; refuse re-tagged newer-glibc native objects.

Use alongside auditwheel show, which owns the manylinux external-library
policy. readelf inspects each bundled ELF, not just the importable main module.
"""
from __future__ import annotations

import argparse
import email
import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

LIMITS = {"GLIBC": (2, 17), "GLIBCXX": (3, 4, 19), "CXXABI": (1, 3, 7)}
NEEDED = re.compile(r"Shared library: \[(.*?)\]")
VERSION = re.compile(r"\b(GLIBC|GLIBCXX|CXXABI)_(\d+(?:\.\d+)+)\b")


def check_wheel(wheel: Path, arch: str) -> dict[str, object]:
    expected = "cel_expr_python-0.1.3-cp314-cp314-"
    if not wheel.name.startswith(expected) or not wheel.name.endswith(".whl"):
        raise ValueError(f"Wrong package, version or Python ABI: {wheel.name}")
    if not any(
        tag in wheel.name
        for tag in (f"manylinux2014_{arch}", f"manylinux_2_17_{arch}")
    ):
        raise ValueError(f"Wheel does not have manylinux2014 {arch} tag: {wheel.name}")
    native: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadatas = [x for x in names if x.endswith(".dist-info/METADATA")]
        if len(metadatas) != 1:
            raise ValueError("Expected exactly one wheel METADATA")
        metadata = email.message_from_bytes(archive.read(metadatas[0]))
        if metadata["Name"].lower().replace("_", "-") != "cel-expr-python":
            raise ValueError(f"Unexpected project in metadata: {metadata['Name']}")
        if metadata["Version"] != "0.1.3":
            raise ValueError(f"Wrong metadata version: {metadata['Version']}")
        for name in names:
            blob = archive.read(name)
            if not blob.startswith(b"\x7fELF"):
                continue
            target = Path(tmp) / f"elf-{len(native)}"
            target.write_bytes(blob)
            header = subprocess.check_output(["readelf", "-W", "-h", str(target)], text=True)
            expected_machine = "X86-64" if arch == "x86_64" else "AARCH64"
            machine = re.search(r"Machine:\s+([^\n]+)", header)
            if machine is None or expected_machine not in machine.group(1).upper():
                raise ValueError(f"{name}: ELF machine does not match {arch}: {machine}")
            if "ELF64" not in header:
                raise ValueError(f"{name}: expected 64-bit ELF")
            symbols = subprocess.check_output(["readelf", "-W", "--version-info", str(target)], text=True)
            dynamic = subprocess.check_output(["readelf", "-W", "-d", str(target)], text=True)
            maxima: dict[str, tuple[int, ...]] = {}
            for kind, version in VERSION.findall(symbols):
                v = tuple(int(piece) for piece in version.split("."))
                maxima[kind] = max(maxima.get(kind, ()), v)
                if v > LIMITS[kind]:
                    raise ValueError(f"{name}: requires {kind}_{version}, exceeds {LIMITS[kind]}")
            for line in dynamic.splitlines():
                if "(RPATH)" not in line and "(RUNPATH)" not in line:
                    continue
                match = re.search(r"Library (?:rpath|runpath): \[(.*?)\]", line)
                if match is None:
                    raise ValueError(f"{name}: unrecognized RPATH/RUNPATH: {line}")
                # auditwheel may legitimately install bundled libs under
                # $ORIGIN/.libs; an absolute or non-origin path is not portable.
                if any(not path.startswith("$ORIGIN/") and path != "$ORIGIN"
                       for path in match.group(1).split(":")):
                    raise ValueError(f"{name}: non-relocatable RPATH/RUNPATH: {line}")
            native.append({
                "path": name,
                "max_versions": {k: ".".join(map(str, v)) for k, v in maxima.items()},
                "needed": NEEDED.findall(dynamic),
            })
    if len(native) < 7:
        raise ValueError(f"Expected seven CEL native extension modules; found {len(native)}")
    return {"wheel": wheel.name, "arch": arch, "native_objects": native}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("wheel", type=Path)
    ap.add_argument("--arch", choices=("x86_64", "aarch64"), required=True)
    args = ap.parse_args()
    print(json.dumps(check_wheel(args.wheel, args.arch), indent=2))


if __name__ == "__main__":
    main()
