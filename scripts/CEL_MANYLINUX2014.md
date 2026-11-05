# CEL 0.1.3 manylinux2014 rebuild — implementation checkpoint

This file describes the **build implementation, not a successful build**.
At this commit no CEL binary has been compiled or published by this PR.
Do not add a CEL row to scripts/offline_wheel_overrides.txt without the real
published wheel, its SHA256SUMS and an offline-bundle verification.

## What is being built

- The existing iCode import is from cel_expr_python import cel, **not**
  cel-go, the CEL policy repository or a new evaluator.
- Source: https://github.com/cel-expr/cel-python, signed/unsigned tag name
  v0.1.3 (annotated tag ac3706aaf0df40682c4bbf46fcad464d35cd18b3),
  dereferenced immutable source commit
  3e369fe3dfd29ef2fcb3d8a63997e58f50e592ae.
- Package version: cel-expr-python==0.1.3; native modules:
  cel_expr_python.cel, ext_bindings, ext_encoders, ext_math, ext_optional,
  ext_proto, ext_strings (seven in total).
- iCode .python-version is 3.14.8. Wheel must be cp314-cp314 and must
  not have a cp314t/free-threaded ABI.
- Bazel 8.5.1, as pinned upstream in .bazelversion. Upstream's
  MODULE.bazel pins cel-cpp by commit
  76ae0b3c1768d93a10270f904101de338867bdb1, with BCR module
  version declarations for the remaining dependencies.
- manylinux2014 images are pinned by digest in the workflow; the two Bazel
  release executables are independently checked against the SHA256
  digests advertised by their upstream GitHub release before use.
- The upstream release/build_wheel.sh is intentionally NOT invoked: it
  uses VERSION=0.0.1, interactive read, a separate staging tree and Google
  CI assumptions. scripts/stage_cel_wheel.py copies from the pinned source,
  sets version 0.1.3, adjusts the cp314 and manylinux2014 targets, fixes the
  separately pinned hermetic Python toolchain, and replaces the unsafe
  git http.sslVerify=false setup with a checked Bazel executable.

The candidate build uses the native x86_64 and aarch64 GitHub runners, not
cross-architecture source objects from a newer host. The C++ compilation and
Bazel dependency resolution happen in the pinned manylinux2014 image.
No Google credentials, remote executor or remote cache are required.
Normal TLS verification is retained. Pip build dependencies are version-pinned,
but the upstream BCR module repository does not ship MODULE.bazel.lock, and
the public registries/tool archives are still network inputs. This is NOT
bit-for-bit reproducibility. The ELF/auditwheel checks must catch a compiler,
Bazel toolchain or native dependency that raises glibc/libstdc++ requirements.

## Wheel build and tests

Workflow: .github/workflows/cel-manylinux2014.yml

For a trusted checkout with Docker and GitHub Actions available, explicitly
dispatch with build=1, publish=false. Publication is gated to a separately
authorized zshufan/iCode default-branch run; never publish to openJiuwen-ai.
Choose a new rebuild number for any subsequent release. Artifacts from a
build run are NOT downloadable at release URLs until that specific tag is
actually published.

Build validation includes:
1. Native cel_expr_python.cel import; version and extension location;
   PR's actual cel.Type.List(cel.Type.STRING) variable declaration;
   CEL Boolean compilation and evaluation, including invalid-type cases.
2. Real tree-sitter and tree-sitter-bash pinned versions and the copied
   iCode Pre-Judge module, with ALLOW/BLOCK/DEFER regression cases.
   These smoke tests run in cibuildwheel's target image and do not execute
   the sample commands.
3. auditwheel show, readelf symbol versions (GLIBC <= 2.17,
   GLIBCXX <= 3.4.19, CXXABI <= 1.3.7), all seven ELF modules, architecture,
   DT_NEEDED and origin-relative RPATH/RUNPATH.
4. SHA256SUMS for the finished wheel and validation logs as Actions artifacts.

A build that fails one of these checks is not a valid compatible wheel.
A release must publish the exact checked artifact bytes; no retagging of
a newer binary, no bundling of glibc and no ignored/removed native extensions.

## iCode dependency and offline release — NOT YET INTEGRATED

The normal install must retain the optional, lazy feature. The intended
project extra is:

    [project.optional-dependencies]
    prejudge = [
      "cel-expr-python==0.1.3",
      "tree-sitter==0.25.1",
      "tree-sitter-bash==0.25.1",
    ]

This is **not yet written into pyproject.toml**, because the matching uv.lock
must be produced using uv lock on an index-connected runtime and checked with
uv lock --check in the same change. The current working container has no
network route to the package index and has neither Python 3.14 nor a container
engine. Hand-writing new lock hashes would violate the supply-chain contract.
The upstream tags for tree-sitter and tree-sitter-bash already provide
manylinux2014 cp314 (or cp310-abi3) wheels for both architectures, but the
actual resolved dependency closure and clean install still need testing.

scripts/build_offline_dist.sh exports DEFAULT locked production dependencies,
so an extra must be explicitly selected for Linux in uv export --locked.
The actual CEL wheel must then replace the locked PyPI hashes using the existing
scripts/offline_wheel_overrides.txt mechanism for EACH architecture. Its
download row must use the actual release in zshufan/iCode, version 0.1.3,
the published wheel's real SHA256 and matching cp314/machine tag. A row with
an uncreated release URL, a fabricated hash, or a wheel from another
repository is forbidden. Linux offline builds must fail when this wheel is
missing or its hash mismatches, rather than downloading the newer PyPI wheel.
MacOS and Windows default installation paths must remain unchanged.

Do not enable the extra in the release matrix until:
- both native builds and manylinux2014 CEL/Pre-Judge tests pass;
- uv.lock and pyproject.toml agree, and the actual released wheel URLs exist;
- the offline script is updated to include the extra on Linux and validates
  override hashes/versions for both architectures;
- a real x86_64 offline bundle is built and exercised with the network
  disabled on glibc 2.17; aarch64 bundle keeps its existing 2.18 floor;
- repository Smart Test, Ruff, Ty, wheel checks and relevant release tests pass.

Package license is Apache-2.0 (cel-expr-python/CEL-C++); Tree-sitter and
tree-sitter-bash are MIT. Update NOTICE/third-party records when binaries
become included in the distribution, not on the strength of an unrun recipe.

## Actual verification status

Verified from immutable upstream files: tag -> commit, Bazel 8.5.1,
native extension names, build script limitations, and staging substitutions.
The current environment contains Python 3.13 only, no Bazel/Docker, and cannot
clone GitHub or install the CEL dependencies. A PR-branch push trigger was
attempted; GitHub Actions returned no associated run. No wheel/SHA256SUMS,
auditwheel/ELF report, native smoke output, or offline bundle exists yet.
Do not describe any of those as passed.
