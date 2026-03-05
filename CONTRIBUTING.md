# Contributing to Zircolite

Thank you for your interest in contributing. This document gives a short overview of how to get started and submit changes.

## Getting started

1. Clone the repository and install dependencies with [PDM](https://pdm-project.org/):

   ```bash
   git clone https://github.com/wagga40/Zircolite.git
   cd Zircolite
   pdm install
   ```

2. Run the test suite to confirm everything works:

   ```bash
   pdm run pytest
   ```

## Development workflow

- **Linting and formatting**: This project uses [ruff](https://docs.astral.sh/ruff/). If you use [Task](https://taskfile.dev/) with the development taskfile: `task -t Taskfile.dev.yml lint`, `task -t Taskfile.dev.yml lint:fix`, and `task -t Taskfile.dev.yml format`. Otherwise: `pdm run ruff check zircolite/ zircolite.py` and `pdm run ruff format zircolite/ zircolite.py`.
- **Tests**: `pdm run pytest` (or `task -t Taskfile.dev.yml test`). Use `pdm run pytest -v` for verbose output and `pdm run pytest --cov=zircolite --cov-report=term-missing` for coverage.
- **Documentation**: Project structure, code style, and conventions are described in the [docs](docs/) directory, [.cursorrules](.cursorrules), and [CLAUDE.md](CLAUDE.md). Please follow existing patterns for type hints, logging, and configuration.

## Submitting changes

1. **Open an issue** for substantial changes or new features so we can align on approach before you invest time.
2. **Branch from `master`** and make your changes. Keep commits focused and messages clear.
3. **Run tests and lint** before opening a pull request: `pdm run pytest` and `pdm run ruff check zircolite/ zircolite.py`.
4. **Open a pull request** with a short description of what changed and why. Reference any related issue.

Code, comments, and documentation should read as if written by a human developer. Do not add AI-attribution text or optimization-tracking markers in the codebase.

## Code of conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (GNU Lesser General Public License v3.0 or later). See [LICENSE](LICENSE) and the [README](README.md#license) for details.
