"""
Single-direction resolution of CLI arguments and YAML configuration.

There is one pass, described by :data:`SETTINGS`: for every argparse
destination, the value is the first of **CLI argument**, **YAML key**, **built-in
default**. Options that would otherwise be ambiguous are declared with
``default=None`` in ``parse_arguments()`` so that "the user passed the default
explicitly" stays distinguishable from "the user passed nothing"; the real
default is applied here instead.

Merge semantics for the list-valued keys follow one rule:

    Additive knobs concatenate. Selective knobs replace.

``--add-index``, ``--remove-index`` and ``--transform-category`` name things to
*add to* a run, so the CLI extends the configuration file. A ruleset, a
pipeline, a template or a ``--select`` pattern names *which* things a run uses,
so the CLI replaces the configuration file — concatenating there would widen
the run rather than redirect it.

Resolution happens in two phases because the logger is built from ``debug``,
``nolog`` and ``logfile`` before the configuration file has been validated.
:data:`EARLY_DESTS` names those three; everything else is resolved afterwards.
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from .config_loader import (
    DEFAULT_AFTER,
    DEFAULT_BEFORE,
    DEFAULT_CSV_DELIMITER,
    DEFAULT_LIMIT,
    DEFAULT_LOG_FILE,
    DEFAULT_MEMORY_LIMIT_PERCENT,
    DEFAULT_OUTFILE,
    DEFAULT_PACKAGE_DIR,
    DEFAULT_TIME_FIELD,
)
from .formats import format_by_yaml, has_explicit_format

# Marks a YAML key that is absent, which `None` cannot do: `key:` with no value
# is a legitimate way to write null.
UNSET = object()


class Merge(Enum):
    """How a CLI value and a YAML value combine."""

    CLI_WINS = auto()  # scalars: CLI, else YAML, else default
    OR = auto()  # booleans: set when either source sets it
    CLI_REPLACES = auto()  # selective lists: a CLI value discards the YAML one
    CONCAT = auto()  # additive lists: YAML then CLI, order-preserving dedup


@dataclass(frozen=True)
class Setting:
    """One argparse destination and the YAML key that feeds it."""

    dest: str
    section: str | None
    key: str | None
    default: Any = None
    merge: Merge = Merge.CLI_WINS
    # YAML shape -> argparse shape, e.g. ["a"] -> [["a"]] for append/nargs opts
    from_yaml: Callable[[Any], Any] | None = None
    # YAML says `recursive: false` to mean the CLI's `--no-recursion`
    invert: bool = False


def as_list(value: Any) -> list:
    """A YAML value for a list-valued key, as a list.

    ``rulesets: rules/x.json`` reads naturally and is the obvious way to name a
    single one, but iterating that string yields one entry per character --
    silently replacing the ruleset with 32 one-character paths. A scalar means
    one item.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        return [value]
    return list(value)


def nest_each(values: Any) -> list[list[str]]:
    """``["a", "b"]`` -> ``[["a"], ["b"]]``, the shape append/nargs produces."""
    return [[v] for v in as_list(values)]


def flatten_groups(value: Any) -> list[str]:
    """Flatten an argparse append/nargs list of lists into a single list."""
    if not value:
        return []
    return [item for group in value for item in group]


def _default_outfile(args: Any) -> str:
    """CSV output gets a .csv name unless the user chose one."""
    return "detected_events.csv" if getattr(args, "csv", False) else DEFAULT_OUTFILE


SETTINGS: tuple[Setting, ...] = (
    # -- input ------------------------------------------------------------
    Setting("evtx", "input", "path"),
    Setting("no_recursion", "input", "recursive", False, Merge.OR, invert=True),
    Setting("file_pattern", "input", "file_pattern"),
    Setting("fileext", "input", "file_extension"),
    Setting("logs_encoding", "input", "encoding"),
    Setting("select", "input", "select", None, Merge.CLI_REPLACES, nest_each),
    Setting("avoid", "input", "avoid", None, Merge.CLI_REPLACES, nest_each),
    # -- rules ------------------------------------------------------------
    Setting("ruleset", "rules", "rulesets", None, Merge.CLI_REPLACES, nest_each),
    Setting("pipeline", "rules", "pipelines", None, Merge.CLI_REPLACES, nest_each),
    Setting("rulefilter", "rules", "filters", None, Merge.CLI_REPLACES, nest_each),
    Setting("save_ruleset", "rules", "save_ruleset", False, Merge.OR),
    # -- output -----------------------------------------------------------
    Setting("outfile", "output", "file", _default_outfile),
    Setting("csv_delimiter", "output", "csv_delimiter", DEFAULT_CSV_DELIMITER),
    Setting("template_append", "output", "template_append", False, Merge.OR),
    Setting("package", "output", "package", False, Merge.OR),
    Setting("package_dir", "output", "package_dir", DEFAULT_PACKAGE_DIR),
    Setting("keepflat", "output", "keep_flat", False, Merge.OR),
    Setting("dbfile", "output", "db_file"),
    Setting("logfile", "output", "log_file", DEFAULT_LOG_FILE),
    Setting("nolog", "output", "no_output", False, Merge.OR),
    # -- processing -------------------------------------------------------
    Setting("unified_db", "processing", "unified_db", False, Merge.OR),
    Setting("no_auto_mode", "processing", "auto_mode", False, Merge.OR, invert=True),
    Setting("hashes", "processing", "hashes", False, Merge.OR),
    Setting("limit", "processing", "limit", DEFAULT_LIMIT),
    Setting("timefield", "processing", "time_field", DEFAULT_TIME_FIELD),
    Setting("debug", "processing", "debug", False, Merge.OR),
    Setting("remove_events", "processing", "remove_events", False, Merge.OR),
    Setting("all_transforms", "processing", "all_transforms", False, Merge.OR),
    Setting(
        "transform_categories",
        "processing",
        "transform_categories",
        None,
        Merge.CONCAT,
    ),
    Setting("add_index", "processing", "add_index", None, Merge.CONCAT, nest_each),
    Setting(
        "remove_index", "processing", "remove_index", None, Merge.CONCAT, nest_each
    ),
    Setting("auto_index", "processing", "auto_index", 0),
    Setting(
        "no_event_filter",
        "processing",
        "event_filter_enabled",
        False,
        Merge.OR,
        invert=True,
    ),
    Setting("strict", "processing", "strict_evtx", False, Merge.OR),
    # -- time_filter ------------------------------------------------------
    Setting("after", "time_filter", "after", DEFAULT_AFTER),
    Setting("before", "time_filter", "before", DEFAULT_BEFORE),
    # -- parallel ---------------------------------------------------------
    Setting("no_parallel", "parallel", "enabled", False, Merge.OR, invert=True),
    Setting("parallel_workers", "parallel", "max_workers"),
    # These two are YAML-only -- no CLI flag of their own -- but are still
    # resolved so the namespace always carries a usable value.
    # --parallel-memory-limit below does have a flag.
    Setting("parallel_min_workers", "parallel", "min_workers", 1),
    Setting("parallel_adaptive", "parallel", "adaptive", True),
    Setting(
        "parallel_memory_limit",
        "parallel",
        "memory_limit_percent",
        DEFAULT_MEMORY_LIMIT_PERCENT,
    ),
)

# Defaults keyed by destination, so that `--help` and the resolver quote the
# same literal. Callables are resolved against the namespace.
DEFAULTS: dict[str, Any] = {s.dest: s.default for s in SETTINGS}

# Resolved before the logger exists; see the module docstring.
EARLY_DESTS: frozenset[str] = frozenset({"debug", "nolog", "logfile"})


def _dedup(values: list[Any]) -> list[Any]:
    """Order-preserving de-duplication."""
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _cli_given(setting: Setting, cli: Any) -> bool:
    """Whether the CLI actually supplied a value for *setting*.

    ``-R`` with ``nargs='*'`` and no operand yields ``[[]]``, which is truthy
    but names nothing; treating it as given would silently discard the
    configuration file's rule filters.
    """
    if cli is None:
        return False
    if setting.from_yaml is nest_each:
        return bool(flatten_groups(cli))
    if isinstance(cli, list):
        return bool(cli)
    return True


def _combine(setting: Setting, cli: Any, yaml_value: Any) -> Any:
    """Combine the CLI and YAML values for one setting, or return UNSET."""
    has_yaml = yaml_value is not UNSET and yaml_value is not None
    nested = setting.from_yaml is nest_each

    if setting.merge is Merge.OR:
        # YAML can only ever turn a store_true flag on. For an inverted key
        # (`recursive: false` meaning `--no-recursion`) that means reacting to
        # the false value, never to the true one.
        yaml_sets = has_yaml and (
            yaml_value is False if setting.invert else bool(yaml_value)
        )
        return bool(cli) or yaml_sets

    if setting.merge is Merge.CONCAT:
        yaml_items = as_list(yaml_value) if has_yaml else []
        cli_items = flatten_groups(cli) if nested else list(cli or [])
        merged = _dedup(yaml_items + cli_items)
        if not merged:
            return UNSET
        return [merged] if nested else merged

    if _cli_given(setting, cli):
        return cli
    if has_yaml and yaml_value != []:
        return setting.from_yaml(yaml_value) if setting.from_yaml else yaml_value
    return UNSET


def _apply_custom(args: Any, raw: Mapping[str, Any]) -> None:
    """Apply the three YAML keys that do not map 1:1 onto a destination."""
    inp = raw.get("input") or {}
    out = raw.get("output") or {}

    # input.format selects one of the mutually exclusive format flags, but only
    # when the CLI did not already choose one.
    fmt = inp.get("format")
    if fmt and not has_explicit_format(args):
        spec = format_by_yaml(fmt)
        if spec is not None and spec.has_cli_flag:
            setattr(args, spec.args_flag, True)

    if out.get("format") == "csv":
        args.csv = True
        # Read back when reporting the "CSV with multiple rulesets" error, so
        # the message names the configuration file rather than --csv.
        args._csv_from_yaml = True

    # output.templates carries a positionally paired (template, output) list;
    # the two destinations are replaced together or not at all.
    templates = out.get("templates")
    if templates and not getattr(args, "template", None):
        args.template = [[t["template"]] for t in templates]
        args.templateOutput = [[t["output"]] for t in templates]


def resolve(
    args: Any,
    raw: Mapping[str, Any] | None = None,
    *,
    only: frozenset[str] | None = None,
    skip: frozenset[str] | None = None,
) -> Any:
    """Resolve *raw* YAML onto *args* in place: CLI wins, YAML fills in, default last.

    Args:
        args: the argparse namespace, mutated in place
        raw: the parsed YAML document; an empty mapping resolves defaults only
        only: restrict resolution to these destinations
        skip: resolve everything except these destinations

    Returns:
        The same namespace, for convenience.
    """
    raw = raw or {}
    explicit = set(getattr(args, "_explicit", frozenset()))

    # Before the loop: `output.format: csv` decides the default output filename.
    if only is None:
        _apply_custom(args, raw)

    for setting in SETTINGS:
        if only is not None and setting.dest not in only:
            continue
        if skip is not None and setting.dest in skip:
            continue

        cli = getattr(args, setting.dest, None)
        if cli is not False and _cli_given(setting, cli):
            explicit.add(setting.dest)

        section = (raw.get(setting.section) or {}) if setting.section else {}
        yaml_value = section.get(setting.key, UNSET) if setting.key else UNSET

        # "The user set this", not "the CLI set this": a value pinned in the
        # configuration file is just as deliberate as one typed on the command
        # line, and callers use this to decide whether auto-detection may
        # override the value.
        if yaml_value is not UNSET and yaml_value is not None and yaml_value != []:
            explicit.add(setting.dest)

        value = _combine(setting, cli, yaml_value)
        if value is UNSET:
            default = setting.default
            value = default(args) if callable(default) else default
        setattr(args, setting.dest, value)

    args._explicit = frozenset(explicit)
    return args
