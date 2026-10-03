#!/usr/bin/env python3
"""
Zircolite Transform Tester
===========================

Standalone tool for developing and testing RestrictedPython transforms
outside of Zircolite. Uses the exact same sandbox environment as
Zircolite's transform engine.

Usage:
    # Test a transform file with a sample value
    python transform_tester.py my_transform.py "C:\\Windows\\System32\\cmd.exe"

    # Test with value from stdin (useful for multiline input)
    echo "test value" | python transform_tester.py my_transform.py -

    # Interactive mode: enter values one per line
    python transform_tester.py my_transform.py --interactive

    # Show available builtins and modules
    python transform_tester.py --list-builtins

    # Run with verbose output (show compilation details)
    python transform_tester.py my_transform.py "test" --verbose

Transform File Format:
    A transform file must define a single function:

        def transform(param):
            # param is always a string (the field value)
            # return a string (the transformed value)
            return param.upper()

Available in transforms:
    - re, base64, math, chardet: read-only stand-ins exposing their public
      functions only; `import re` (etc.) returns the same stand-in
    - dict/list/set writes: d[key] = value
    - augmented assignments: x += 1, s += "text"
    - all safe Python builtins (len, str, int, range, sorted, etc.)
    - NOT available: file I/O, other imports, exec, eval, os, sys, subprocess
"""

import argparse
import sys
import time
from pathlib import Path

# Test against the engine of the checkout this file ships with rather than a
# copy of it, so the two sandboxes cannot drift apart.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from RestrictedPython import compile_restricted

    from zircolite.streaming import _RESTRICTED_BUILTINS as BUILTINS
    from zircolite.streaming import _exec_transform
except ImportError as exc:
    print(f"[!] {exc}. Run this from the project environment (pdm install, uv sync or poetry install)", file=sys.stderr)
    sys.exit(1)


def compile_transform(source: str, filename: str = "<transform>"):
    """Compile transform source code with RestrictedPython.

    Returns the transform function or raises on error.
    """
    byte_code = compile_restricted(source, filename=filename, mode='exec')

    # Check for compilation errors (RestrictedPython stores them in the code)
    if byte_code is None:
        raise SyntaxError("RestrictedPython compilation returned None")

    func = _exec_transform(byte_code, BUILTINS)
    if func is None:
        raise ValueError(
            "No 'transform' function found. "
            "Your file must define: def transform(param): ..."
        )
    return func


def run_transform(func, value: str, verbose: bool = False):
    """Execute a transform function and return (result, elapsed_ms)."""
    start = time.perf_counter()
    result = func(value)
    elapsed = (time.perf_counter() - start) * 1000
    return result, elapsed


def list_builtins():
    """Print available builtins and modules."""
    print("=== Available Modules (public functions only, no submodules) ===")
    print("  base64    - Base64 encoding/decoding")
    print("  re        - Regular expressions")
    print("  chardet   - Character encoding detection")
    print("  math      - Mathematical functions (log2, sqrt, etc.)")
    print()
    print("=== Available Builtins ===")
    available = sorted(k for k in BUILTINS if not k.startswith('_') and isinstance(k, str))
    for name in available:
        obj = BUILTINS[name]
        kind = type(obj).__name__
        print(f"  {name:30s}  ({kind})")
    print()
    print("=== Supported Operations ===")
    print("  dict[key] = value          (container writes)")
    print("  x += 1, s += 'text'        (augmented assignments)")
    print("  for x in iterable:         (iteration)")
    print("  [x for x in ...]           (comprehensions)")
    print()
    print("=== NOT Available ===")
    print("  import (arbitrary)          - only re, base64, math, chardet")
    print("  open, file I/O              - no filesystem access")
    print("  exec, eval, compile         - no dynamic code execution")
    print("  os, sys, subprocess         - no system access")
    print("  object attribute writes     - only dict/list/set writes")


def main():
    parser = argparse.ArgumentParser(
        description="Zircolite Transform Tester - develop and test transforms locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s transforms/image_exename.py "C:\\\\Windows\\\\System32\\\\cmd.exe"
  %(prog)s my_transform.py --interactive
  %(prog)s --list-builtins
  echo "dGVzdA==" | %(prog)s transforms/commandline_b64decoded.py -
""",
    )
    parser.add_argument("transform_file", nargs="?", help="Path to transform .py file")
    parser.add_argument("value", nargs="?", help='Input value to transform (use "-" for stdin)')
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode: enter values line by line")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show compilation details")
    parser.add_argument("--list-builtins", action="store_true", help="List available builtins and modules")

    args = parser.parse_args()

    if args.list_builtins:
        list_builtins()
        return

    if not args.transform_file:
        parser.error("transform_file is required (unless using --list-builtins)")

    # Read transform source
    transform_path = Path(args.transform_file)
    if not transform_path.exists():
        print(f"[!] File not found: {transform_path}", file=sys.stderr)
        sys.exit(1)

    source = transform_path.read_text(encoding="utf-8")
    if args.verbose:
        print(f"[*] Loaded transform: {transform_path} ({len(source)} bytes)")
        print("[*] Compiling with RestrictedPython...")

    # Compile
    try:
        func = compile_transform(source, filename=str(transform_path))
    except Exception as e:
        print(f"[!] Compilation error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print("[*] Compilation successful")

    # Interactive mode
    if args.interactive:
        print("[*] Interactive mode — enter values (Ctrl+D / Ctrl+C to quit):")
        print(f"[*] Transform: {transform_path.name}")
        print("-" * 60)
        try:
            while True:
                try:
                    value = input("input > ")
                except EOFError:
                    break
                result, elapsed = run_transform(func, value, args.verbose)
                print(f"  => {result!r}  ({elapsed:.2f}ms)")
        except KeyboardInterrupt:
            print()
        return

    # Single value mode
    if args.value is None:
        parser.error("value is required (use --interactive for interactive mode, or '-' for stdin)")

    value = sys.stdin.read().strip() if args.value == "-" else args.value

    if args.verbose:
        print(f"[*] Input: {value!r}")

    try:
        result, elapsed = run_transform(func, value, args.verbose)
    except Exception as e:
        print(f"[!] Runtime error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"{result!r}")
    if args.verbose:
        print(f"[*] Elapsed: {elapsed:.2f}ms")
        print(f"[*] Return type: {type(result).__name__}")


if __name__ == "__main__":
    main()
