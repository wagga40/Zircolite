#!/usr/bin/env python3
"""Turn the frames record.py captured into a looping animated WebP.

Usage:
  uv run --no-project --with pillow python encode.py --work <work dir> --out tour.webp \
      [--fps 12] [--mode lossy|lossless|mixed] [--q 70] [--review <dir>]

Waits record.py marked as loading are shortened to their cap, frames closer together than
1/fps are merged (the later state wins), identical neighbours are merged, and img2webp
encodes the result with per-frame durations. --review writes the frame shown at each beat,
decoded back from the WebP, as PNG files.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image


def warp_function(marks: list[list[float]]):
    """Maps wall time to tour time, running each loading stretch at the speed that fits its cap."""
    spans = sorted((a, b, cap) for a, b, cap in marks if b - a > cap)
    merged: list[list[float]] = []
    for a, b, cap in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
            merged[-1][2] = max(merged[-1][2], cap)
        else:
            merged.append([a, b, cap])

    def warp(t: float) -> float:
        removed = 0.0
        for a, b, cap in merged:
            if t <= a:
                break
            if t >= b:
                removed += (b - a) - cap
            else:
                removed += (t - a) * (1 - cap / (b - a))
                break
        return t - removed

    return warp


def plan(work: Path, fps: float) -> tuple[list[tuple[Path, int]], list[dict], float]:
    meta = json.loads((work / 'frames.json').read_text())
    warp = warp_function(meta['compress'])
    origin = warp(meta['start'])
    frames = [(warp(f['t']) - origin, work / 'frames' / f['file']) for f in meta['frames']]
    frames.sort(key=lambda f: f[0])
    end = warp(meta['end']) - origin
    beats = [{'name': b['name'], 'v': warp(b['t']) - origin, 'hold': b.get('hold', 1.5)} for b in meta['beats']]

    # Scrolls and the like keep fewer frames: each is nearly a whole new picture.
    coarse = [(warp(a) - origin, warp(b) - origin, rate) for a, b, rate in meta.get('coarse', [])]

    def slot_at(v: float) -> float:
        for a, b, rate in coarse:
            if a <= v <= b:
                return 1 / min(rate, fps)
        return 1 / fps

    # Merge frames inside one slot: the slot keeps its start, the latest picture wins.
    kept: list[list] = []
    for v, path in frames:
        if kept and v - kept[-1][0] < slot_at(kept[-1][0]):
            kept[-1][1] = path
        else:
            kept.append([max(v, 0.0), path])

    # Identical neighbours become one longer frame.
    out: list[list] = []
    last_digest = None
    for v, path in kept:
        digest = hashlib.blake2b(Image.open(path).convert('RGB').tobytes(), digest_size=16).digest()
        if digest == last_digest:
            continue
        out.append([v, path])
        last_digest = digest

    # Whole milliseconds that still add up to the real length.
    timed: list[tuple[Path, int]] = []
    clock = 0
    for i, (_, path) in enumerate(out):
        until = out[i + 1][0] if i + 1 < len(out) else end
        ms = max(20, round(until * 1000) - clock)
        clock += ms
        timed.append((path, ms))
    return timed, beats, end


def encode(timed: list[tuple[Path, int]], out: Path, mode: str, q: float, method: int) -> int:
    args = ['-loop', '0']
    if mode == 'mixed':
        args.append('-mixed')
    frame_opts = ['-lossy', '-q', str(q), '-m', str(method)] if mode in ('lossy', 'mixed') else ['-lossless', '-q', str(q), '-m', str(method)]
    for i, (path, ms) in enumerate(timed):
        args += (frame_opts if i == 0 else []) + ['-d', str(ms), str(path)]
    args += ['-o', str(out)]
    # Hundreds of frames overflow a command line, and img2webp splits its argument file on spaces.
    if any(any(c.isspace() for c in str(a)) for a in args):
        sys.exit('img2webp cannot read a path with a space: use a work directory and an output path without one')
    argfile = out.with_suffix('.args')
    argfile.write_text(' '.join(args))
    subprocess.run(['img2webp', str(argfile)], check=True, capture_output=True)  # noqa: S603, S607 -- img2webp from PATH, our own frame files
    argfile.unlink()
    return out.stat().st_size


def review(webp: Path, timed: list[tuple[Path, int]], beats: list[dict], directory: Path) -> None:
    """Decodes the WebP back and saves the frame on screen just before each beat ends."""
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    starts = []
    clock = 0
    for _, ms in timed:
        starts.append(clock)
        clock += ms
    image = Image.open(webp)
    for i, beat in enumerate(beats):
        # Late in the hold, when the page has long settled.
        until = beats[i + 1]['v'] if i + 1 < len(beats) else clock / 1000
        at = min(beat['v'] + 0.7 * beat['hold'], until - 0.05) * 1000
        index = max(j for j, s in enumerate(starts) if s <= at)
        image.seek(index)
        image.convert('RGB').save(directory / f'{i + 1:02d}-{beat["name"]}.png')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--fps', type=float, default=12)
    parser.add_argument('--mode', choices=('lossy', 'lossless', 'mixed'), default='lossy')
    parser.add_argument('--q', type=float, default=70)
    parser.add_argument('--method', type=int, default=6)
    parser.add_argument('--review', type=Path)
    parser.add_argument('--budget', type=int, default=2_500_000, help='bytes; above it, a warning')
    parser.add_argument('--cap', type=int, default=3_000_000, help='bytes; above it, exit 1')
    args = parser.parse_args()
    if not shutil.which('img2webp'):
        sys.exit('img2webp is not on the PATH (brew install webp)')
    timed, beats, _ = plan(args.work, args.fps)
    size = encode(timed, args.out, args.mode, args.q, args.method)
    total = sum(ms for _, ms in timed) / 1000
    print(f'{args.out}: {size:,} bytes, {len(timed)} frames, {total:.1f} s, {args.mode} q{args.q:g} at most {args.fps:g} fps')
    if args.review:
        review(args.out, timed, beats, args.review)
        print(f'review frames in {args.review}')
    if size > args.cap:
        sys.exit(f'{size:,} bytes is over the {args.cap:,} byte cap: lower --fps, --q or the holds')
    if size > args.budget:
        print(f'warning: {size:,} bytes is over the {args.budget:,} byte budget')


if __name__ == '__main__':
    main()
