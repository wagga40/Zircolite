"""Compile the flattening kernel while the project is installed.

Everything else about the project lives in pyproject.toml; this file exists only
because an extension built from a staged copy of a source file cannot be declared
there.
"""

import hashlib
import os
import sys
from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup

ROOT = Path(__file__).resolve().parent
KERNEL = Path("zircolite") / "flatten_kernel.py"
STAGING = Path("build") / "cython"


def native_kernel() -> list[Extension]:
    os.chdir(ROOT)
    source = KERNEL.read_bytes()
    # The extension records which kernel it was compiled from, so a checkout that
    # edits flatten_kernel.py without reinstalling falls back to Python instead of
    # running stale flattening rules. The copy sits in a package directory of
    # its own so the kernel's relative imports resolve against `zircolite`.
    staged = STAGING / "zircolite" / "_flatten_native.py"
    staged.parent.mkdir(parents=True, exist_ok=True)
    (staged.parent / "__init__.py").touch()
    digest = hashlib.sha256(source).hexdigest()
    staged.write_bytes(source + f'\n\nSOURCE_SHA256 = "{digest}"\n'.encode())
    extensions = cythonize(
        [Extension("zircolite._flatten_native", [str(staged)])],
        build_dir=str(STAGING / "c"),
        compiler_directives={"language_level": 3, "annotation_typing": False},
    )
    # Without a C compiler the install still succeeds and Zircolite runs the same
    # code as Python. CI, the Docker image and the release binaries set
    # ZIRCOLITE_REQUIRE_NATIVE=1 so a missing kernel fails the build instead.
    # cythonize() rebuilds the Extension objects, so this is set on its output.
    required = os.environ.get("ZIRCOLITE_REQUIRE_NATIVE") == "1"
    for extension in extensions:
        extension.optional = not required
    return extensions


# A PEP 517 backend always passes a command. Poetry does not go through the backend
# for its editable install: it runs this file bare as its build script, and there
# the kernel has to land beside flatten_kernel.py, as an editable install puts it.
setup(
    ext_modules=native_kernel(),
    script_args=None if len(sys.argv) > 1 else ["build_ext", "--inplace"],
)
