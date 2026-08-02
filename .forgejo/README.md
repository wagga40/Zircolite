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
| `tests` | {ubuntu, windows, macos} × {3.10, 3.13} | ubuntu × {3.10, 3.13} — 2 of 6 legs |
| `external_tests` | ubuntu-latest | same, on the host label |
| `build_pyinstaller` | linux x64/arm64, windows x64/arm64 | linux x64 only — 1 of 4 legs |

Windows, macOS and arm64 remain GitHub-only. A green Forgejo run is a strong
signal, not a substitute for the GitHub matrix.

## Deliberate differences

**`pdm-project/setup-pdm` is replaced by `python -m pip install pdm`.** Bare
`uses:` references resolve through `data.forgejo.org`, which does not mirror
that action. pip yields the same toolchain without depending on the proxy.

**Jobs run in `ghcr.io/catthehacker/ubuntu:act-24.04`.** `actions/setup-python`
publishes Linux builds for Ubuntu only, and the runner's `ubuntu-latest` label
is a Debian image (`node:22-bookworm`), where the action fails with *"version
not found for this operating system"*. An Ubuntu job container makes it behave
as it does on GitHub.

**`external_tests` runs on the `self-hosted` (host) label, not in a container.**
See the comment at the top of `external_tests.yml` — the harness computes its
own bind-mount paths, so it only works where the Docker daemon and the job share
a filesystem.

**`build_pyinstaller` always runs on `workflow_dispatch`.** On GitHub it is
gated behind a commit or PR message containing `Release v`; here a release build
must be rehearsable before that commit exists.

**Artifacts are uploaded with `actions/upload-artifact@v3`, not `@v4`.** v4 and
the `@actions/artifact` v2 library it wraps refuse to talk to anything that is
not github.com, failing with `GHESNotSupportedError`. v3 uses the older upload
API, which Forgejo implements.

Every workflow also adds a `concurrency` group. The runner has capacity 1, so
without it each superseded push queues behind the last.

## Runner requirements

The `ubuntu-latest` jobs need nothing beyond a working Docker-backed runner.
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
