#!/bin/sh
# Records the Zircolite Viewer tour and encodes it as a looping animated WebP.
#
#   make-tour.sh <unpacked package dir | package .zip> <viewer build dir> [output.webp]
#
# The viewer build directory holds app.js, app.css and index.html (gui/viewer); they are copied
# over a copy of the package, which itself is never changed. The output defaults to the README's
# docs/pics/viewer-tour.webp. Settings: TOUR_WORK (work directory, default a new temporary one),
# TOUR_FPS (15), TOUR_MODE (lossless | lossy | mixed), TOUR_Q (100), TOUR_METHOD (6).
set -eu
if [ $# -lt 2 ]; then
  sed -n '2,10p' "$0"
  exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
package=$1
viewer=$2
out=${3:-$here/../../docs/pics/viewer-tour.webp}
work=${TOUR_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/viewer-tour.XXXXXX")}
mkdir -p "$work"
case $package in
  *.zip)
    rm -rf "$work/package"
    mkdir "$work/package"
    unzip -q "$package" -d "$work/package"
    package=$work/package
    ;;
esac
uv run --no-project --with playwright==1.62.0 python -I "$here/record.py" \
  --package "$package" --viewer "$viewer" --out "$work"
uv run --no-project --with pillow python -I "$here/encode.py" --work "$work" --out "$out" \
  --fps "${TOUR_FPS:-15}" --mode "${TOUR_MODE:-lossless}" --q "${TOUR_Q:-100}" --method "${TOUR_METHOD:-6}" \
  --review "$work/review"
webpmux -info "$out" | sed -n '1,4p'
