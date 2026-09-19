# Forgejo Actions

These workflows are a pre-flight mirror of `.github/workflows/`, used to run CI
on a self-hosted Forgejo instance before pushing to GitHub.

Forgejo reads `.forgejo/workflows/` and, when that directory exists, ignores
`.github/workflows/` completely. GitHub never looks at `.forgejo/`. The two sets
therefore never both run on the same forge, and neither needs conditionals to
stay out of the other's way.

## Coverage

One x86_64 Linux runner cannot reproduce a GitHub matrix spanning three
operating systems and two architectures. What the mirror does and does not cover:

| Workflow | GitHub | Forgejo |
|---|---|---|
| `lint_python` | ubuntu-latest | same |
| `tests` | {ubuntu, windows, macos} × {3.10, 3.14} | ubuntu × {3.10, 3.14} — 2 of 6 legs |
| `external_tests` | ubuntu-latest | same, on the host label |
| `build_pyinstaller` | linux x64/arm64, windows x64/arm64, macOS arm64; verify on clean runners and older distributions; release | linux x64 build, binary tests and package smoke in one job — 1 of 5 legs, no release |

Windows, macOS and arm64 remain GitHub-only. A green Forgejo run is a strong
signal, not a substitute for the GitHub matrix.

Tests and release builds compile the native flattening kernel while `pdm install`
installs the project, with `ZIRCOLITE_REQUIRE_NATIVE=1` so a failed compile fails the
job; the binary tests also check that the frozen binary selects it.

## Deliberate differences

**`pdm-project/setup-pdm` is replaced by `python -m pip install pdm`.** Bare
`uses:` references resolve through `data.forgejo.org`, which does not mirror
that action. pip yields the same toolchain without depending on the proxy.

**`tests` runs in `ghcr.io/catthehacker/ubuntu:act-24.04`.** `actions/setup-python`
publishes Linux builds for Ubuntu only, and the runner's `ubuntu-latest` label
is a Debian image (`node:22-bookworm`), where the action fails with *"version
not found for this operating system"*. An Ubuntu job container makes it behave
as it does on GitHub.

`build_pyinstaller` needs no such substitute: it runs in the
`quay.io/pypa/manylinux_2_28_x86_64` image GitHub builds linux-x64 in, at the same
dated tag. That image is what holds the binaries to glibc 2.28, so it is pinned
rather than documented: `tests/test_forgejo_workflows.py` fails if the two tags
differ.

**`external_tests` runs on the `self-hosted` (host) label, not in a container.**
See the comment at the top of `external_tests.yml` — the harness computes its
own bind-mount paths, so it only works where the Docker daemon and the job share
a filesystem.

**`build_pyinstaller` installs node before anything else.** The manylinux image
has none, and this runner, unlike GitHub's, does not mount its own into job
containers, so every JavaScript action would fail with `Cannot find: node in
PATH`. The first step runs `dnf -y module install nodejs:22/common`; the
`nodejs:22` stream has no default profile, and without `/common` dnf refuses.

**`build_pyinstaller` is one leg in one job, with no release.** GitHub builds five
targets, verifies each archive on a separate clean runner and releases on a tag.
Here the linux-x64 leg builds, runs the binary tests and packages exactly as
GitHub does, then runs GitHub's verify smoke from the extracted archive at the
end of the same job: `--version`, the golden detection over
`sample_bitsadmin.evtx` and `--package`. That job still has Python and pdm
installed, so it is not the clean machine GitHub's verify job is. Not mirrored:

- the runs in `rockylinux:8`, `debian:11` and `ubuntu:20.04`, since job
  containers here get no Docker socket. The binary tests' glibc floor check,
  which reads every shipped ELF, does run.
- the release job: no `SHA256SUMS`, no attestations and no draft release.
- the arm64, macOS and Windows legs.

A push touching what ends up in a package stands in for GitHub's linux-x64
canary, and `workflow_dispatch` for its full build: only a manual run sets
`ZIRCOLITE_TEST_NETWORK=1` and tests `-U`. There is no tag trigger, no schedule
and no `dry_run` input.

**Actions are referenced by version tag, not commit SHA.** GitHub's
`build_pyinstaller` pins every action by SHA. Here `uses:` resolves through
`data.forgejo.org`, as in the other mirrors.

**Artifacts are uploaded with `actions/upload-artifact@v3`, not `@v4`.** v4 and
the `@actions/artifact` v2 library it wraps refuse to talk to anything that is
not github.com, failing with `GHESNotSupportedError`. v3 uses the older upload
API, which Forgejo implements. It zips what it uploads, where GitHub's
`build_pyinstaller` uploads the archive as it is; the executable bit survives
either way, inside the tarball.

Every workflow also adds a `concurrency` group. The runner has capacity 1, so
without it each superseded push queues behind the last.

## Runner requirements

The `ubuntu-latest` jobs need nothing beyond a working Docker-backed runner
that can pull from `ghcr.io` and `quay.io`; `build_pyinstaller` also reaches the
AlmaLinux mirrors for node.
The `external_tests` job runs directly on the runner host and needs:

- `docker`, with a daemon able to **build** images (see below)
- `python3` with `venv`
- `git`
- `node` — `actions/checkout` and `actions/upload-artifact` are JavaScript
  actions and a host-mode job has no image to supply it

### Docker inside an LXC guest

If the runner host is an LXC guest, the Docker daemon cannot load the
`docker-default` AppArmor profile and every `RUN` step fails under both BuildKit
and the legacy builder:

```
unable to apply apparmor profile: apparmor failed to apply profile:
write .../attr/apparmor/exec: no such file or directory
```

`docker run --security-opt apparmor=unconfined` avoids it, but `docker build`
takes no equivalent flag and there is no daemon-level default. Unconfining the
guest (`lxc.apparmor.profile: unconfined`) does not help either — it removes the
host's confinement while dockerd carries on applying its own profile.

Docker enables AppArmor only when `/sys/kernel/security/apparmor` exists *and*
`/sys/module/apparmor/parameters/enabled` reads `Y`. Mask one of them in the
guest before Docker starts:

```
# /etc/systemd/system/docker.service.d/no-apparmor.conf
[Service]
ExecStartPre=-/bin/umount /sys/kernel/security
```

`docker info` should then no longer list `apparmor` under Security Options.
