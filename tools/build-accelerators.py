#!/usr/bin/env python3
"""Build the optional Cython ingestion extension in place."""

import hashlib
import os
from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup

ROOT = Path(__file__).resolve().parent.parent
KERNEL = Path("zircolite") / "flatten_kernel.py"
STAGING = Path("build") / "cython"


def main():
    os.chdir(ROOT)
    source = KERNEL.read_bytes()
    # The extension records which kernel it was compiled from, so a checkout that
    # edits flatten_kernel.py without rebuilding falls back to Python instead of
    # running stale flattening rules. The copy sits in a package directory of
    # its own so the kernel's relative imports resolve against `zircolite`.
    staged = STAGING / "zircolite" / "_flatten_native.py"
    staged.parent.mkdir(parents=True, exist_ok=True)
    (staged.parent / "__init__.py").touch()
    digest = hashlib.sha256(source).hexdigest()
    staged.write_bytes(source + f'\n\nSOURCE_SHA256 = "{digest}"\n'.encode())
    setup(
        name="zircolite-accelerators",
        packages=[],
        py_modules=[],
        ext_modules=cythonize(
            [Extension("zircolite._flatten_native", [str(staged)])],
            build_dir=str(STAGING / "c"),
            compiler_directives={"language_level": 3, "annotation_typing": False},
        ),
        script_args=["build_ext", "--inplace"],
    )


if __name__ == "__main__":
    main()
