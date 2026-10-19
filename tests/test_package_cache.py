"""Cached viewer bytes must never replace or contaminate a run's data."""

import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.package_fixtures import read_package
from tests.test_package_build import build, fake_viewer, part
from zircolite import package
from zircolite.package_spool import PackageSpool


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    monkeypatch.delenv("ZIRCOLITE_NO_CACHE", raising=False)
    directory = fake_viewer(tmp_path)
    viewer = package.Viewer(directory, "0.0.1", ("index.html", "app.js"), ("engine.wasm.gz",))
    spool = PackageSpool(directory=str(tmp_path / "spool"), time_field="SystemTime", rule_keys={})
    spool_path = tmp_path / "spool"
    spool_path.mkdir()
    data = build(spool, [part(spool, 0, [{"Computer": "one"}])])
    cache = tmp_path / "cache"

    def write(label, *, cached=True):
        work = tmp_path / label
        work.mkdir()
        return package.write_package(viewer, data, work, work, cache_directory=cache if cached else None)

    return viewer, data, cache, write


def members(path):
    with zipfile.ZipFile(path) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist()))
        return {name: archive.read(name) for name in archive.namelist()}


def test_cold_warm_and_disabled_are_identical_without_recompressing_static_files(bundle, monkeypatch):
    from zircolite import package_cache

    _, data, cache, write = bundle
    cold = members(write("cold"))
    (template,) = (cache / "package-assets").glob("*.zip")
    assert all(not name.startswith("data/") for name in members(template))
    uncached = members(write("disabled", cached=False))
    assert cold == uncached

    def unexpected(*args, **kwargs):
        pytest.fail("warm cache recompressed the static viewer")

    monkeypatch.setattr(package_cache, "_write_static", unexpected)
    data.manifest["test_run"] = "fresh"
    warm_path = write("warm")
    warm = members(warm_path)
    assert warm.pop("data/manifest.js") != cold.pop("data/manifest.js")
    assert warm == cold
    assert read_package(warm_path)[0]["test_run"] == "fresh"


@pytest.mark.parametrize("damage", ["truncated", "changed", "extra", "missing", "duplicate"])
def test_damaged_or_foreign_cache_is_rebuilt(bundle, damage):
    _, _, cache, write = bundle
    expected = members(write("first"))
    (template,) = (cache / "package-assets").glob("*.zip")
    contents = members(template)
    if damage == "truncated":
        template.write_bytes(b"PK broken")
    else:
        if damage == "changed":
            contents["index.html"] = b"x" * len(contents["index.html"])
        elif damage == "extra":
            contents["data/stale.js"] = b"previous run data"
        elif damage == "missing":
            del contents["index.html"]
        with zipfile.ZipFile(template, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in contents.items():
                archive.writestr(name, payload)
            if damage == "duplicate":
                with pytest.warns(UserWarning, match="Duplicate"):
                    archive.writestr("index.html", b"duplicate")
    assert members(write("recovered")) == expected


@pytest.mark.parametrize("changed", ["app.js", "engine.wasm.gz", "viewer.json", "chunk_size", "readme"])
def test_asset_changes_invalidate_the_cache(bundle, changed, monkeypatch):
    viewer, _, cache, write = bundle
    write("first")
    first = set((cache / "package-assets").glob("*.zip"))
    if changed == "chunk_size":
        monkeypatch.setattr(package, "CHUNK_BYTES", 6)
    elif changed == "readme":
        monkeypatch.setattr(package, "README_TEXT", "updated documentation")
    else:
        target = viewer.directory / changed
        target.write_bytes(target.read_bytes() + b" ")
    assert members(write("changed")) == members(write("uncached", cached=False))
    assert len(set((cache / "package-assets").glob("*.zip")) - first) == 1


def test_cache_keeps_two_versions(bundle):
    viewer, _, cache, write = bundle
    for number in range(4):
        (viewer.directory / "app.js").write_text(str(number))
        write(str(number))
    assert len(list((cache / "package-assets").glob("*.zip"))) == 2


def test_warm_cache_always_wraps_current_run_data(bundle):
    _, data, _, write = bundle
    _, original = read_package(write("first"))
    # The ZIP writer treats table bytes as opaque; use a distinct payload to
    # prove no table can accidentally be supplied by the static cache.
    data.tables["events"].write_bytes(b"new run payload")
    _, fresh = read_package(write("next"))
    assert fresh["events.parquet"] == b"new run payload"
    assert fresh["events.parquet"] != original["events.parquet"]


def test_no_cache_environment_and_library_default_leave_no_cache(bundle, monkeypatch):
    _, _, cache, write = bundle
    monkeypatch.setenv("ZIRCOLITE_CACHE_DIR", str(cache))
    write("library", cached=False)
    assert not cache.exists()
    monkeypatch.setenv("ZIRCOLITE_NO_CACHE", "1")
    write("disabled")
    assert not cache.exists()


def test_unwritable_cache_does_not_prevent_export(bundle):
    _, _, cache, write = bundle
    cache.write_bytes(b"a file cannot contain a cache directory")
    assert members(write("unwritable")) == members(write("uncached", cached=False))


def test_concurrent_cache_publication_produces_complete_packages(bundle):
    _, _, cache, write = bundle
    with ThreadPoolExecutor(max_workers=2) as executor:
        outputs = list(executor.map(write, ("a", "b")))
    assert members(outputs[0]) == members(outputs[1])
    assert len(list((cache / "package-assets").glob("*.zip"))) == 1
    assert len(list((cache / "package-assets").iterdir())) == 1
