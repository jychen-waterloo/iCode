#!/usr/bin/env python3
"""Stage the immutable CEL 0.1.3 source for an unprivileged manylinux build.

No source is fetched here. The calling workflow must checkout the pinned commit
and independently SHA256-check the Bazel executable it supplies.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

CEL_COMMIT = "3e369fe3dfd29ef2fcb3d8a63997e58f50e592ae"
CEL_VERSION = "0.1.3"
BAZEL_VERSION = "8.5.1"


def replace_once(value: str, original: str, replacement: str) -> str:
    if value.count(original) != 1:
        raise ValueError(f"Upstream CEL build recipe changed: {original!r}")
    return value.replace(original, replacement)


def stage(source: Path, target: Path, bazel_binary: Path, smoke: Path, prejudge: Path, integration_smoke: Path) -> None:
    sha = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True, stdin=subprocess.DEVNULL
    ).strip()
    if sha != CEL_COMMIT:
        raise ValueError(f"Expected CEL v{CEL_VERSION} at {CEL_COMMIT}; got {sha}")
    bazel_version = (source / ".bazelversion").read_text(encoding="utf-8").strip()
    if bazel_version != BAZEL_VERSION:
        raise ValueError(f"Unexpected upstream Bazel version {bazel_version!r}")
    if target.exists():
        raise FileExistsError(f"Staging directory already exists: {target}")
    shutil.copytree(
        source, target, symlinks=False,
        ignore=shutil.ignore_patterns(".git", "bazel-*", "wheelhouse", "build_area", "__pycache__"),
    )
    release = source / "release"
    for name in ("setup.py", "cel_basic_test.py"):
        shutil.copy2(release / name, target / name)
    shutil.copy2(smoke, target / "icode_cel_smoke.py")
    shutil.copy2(prejudge, target / "prejudge_under_test.py")
    shutil.copy2(integration_smoke, target / "icode_prejudge_smoke.py")
    shutil.copy2(bazel_binary, target / "bazel-pinned")
    (target / "bazel-pinned").chmod(0o755)

    config = (release / "pyproject.toml").read_text(encoding="utf-8")
    config = replace_once(config, 'version = "$VERSION"', f'version = "{CEL_VERSION}"')
    config = replace_once(
        config, 'build = "cp311-* cp312-* cp313-* cp314-*"', 'build = "cp314-*"'
    )
    config = replace_once(config, 'manylinux-x86_64-image = "manylinux_2_28"', 'manylinux-x86_64-image = "manylinux2014"')
    config = replace_once(config, 'manylinux-aarch64-image = "manylinux_2_28"', 'manylinux-aarch64-image = "manylinux2014"')
    config = replace_once(
        config,
        'before-build = "pip install --no-index --find-links={project}/build_deps setuptools wheel virtualenv"',
        'before-build = "python -m pip install setuptools==83.0.0 wheel==0.45.1 virtualenv==20.35.4"',
    )
    beginning = 'before-all = "git config --global http.sslVerify false && echo '
    candidates = [line for line in config.splitlines() if line.startswith(beginning)]
    if len(candidates) != 1:
        raise ValueError("CEL release before-all changed; check its TLS and Bazel logic")
    config = replace_once(
        config, candidates[0],
        'before-all = "install -m 0755 {project}/bazel-pinned /usr/local/bin/bazel && bazel --version"',
    )
    config = replace_once(
        config, 'test-command = "python {project}/cel_basic_test.py"',
        'test-command = "python {project}/cel_basic_test.py && python {project}/icode_cel_smoke.py && python {project}/icode_prejudge_smoke.py"',
    )
    config = replace_once(
        config,
        'build-verbosity = 1',
        'test-requires = ["PyYAML==6.0.3", "tree-sitter==0.25.1", "tree-sitter-bash==0.25.1"]\nbuild-verbosity = 1',
    )
    (target / "pyproject.toml").write_text(config, encoding="utf-8")

    # Upstream setup.py updates python.defaults(3.11) at build time, but the
    # hermetic toolchain declaration is independently pinned to 3.11.
    # Both must target cp314; check exact upstream syntax before editing.
    module = (target / "MODULE.bazel").read_text(encoding="utf-8")
    module = replace_once(
        module, 'python.defaults(python_version = "3.11")',
        'python.defaults(python_version = "3.14")',
    )
    module = replace_once(
        module, 'python.toolchain(python_version = "3.11")',
        'python.toolchain(python_version = "3.14")',
    )
    (target / "MODULE.bazel").write_text(module, encoding="utf-8")
    if "http.sslVerify false" in config:
        raise ValueError("Unsafe Git TLS setting survived staging")
    print(f"Staged cel-expr-python {CEL_VERSION} @ {CEL_COMMIT} (Bazel {BAZEL_VERSION}) to {target}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bazel", type=Path, required=True)
    parser.add_argument("--smoke", type=Path, required=True)
    parser.add_argument("--prejudge", type=Path, required=True)
    parser.add_argument("--integration-smoke", type=Path, required=True)
    opts = parser.parse_args()
    stage(
        opts.source.resolve(), opts.output.resolve(), opts.bazel.resolve(),
        opts.smoke.resolve(), opts.prejudge.resolve(), opts.integration_smoke.resolve(),
    )


if __name__ == "__main__":
    main()
