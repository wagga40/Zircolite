"""
Ruleset handling and updating for Zircolite.

This module contains:
- EventFilter: Filter events based on channel and eventID from rules
- RulesetHandler: Parse and convert Sigma rules to Zircolite format
- RulesUpdater: Download and update rulesets from repository
- UnknownPipelineError: A requested pySigma pipeline is not installed
"""

import hashlib
import logging
import os
import re
import shutil
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import orjson as json
import requests  # type: ignore[import-untyped]
import yaml

# Rich progress for downloads and conversion
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from sigma.backends.sqlite import sqlite
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule, SigmaExtendedCorrelationCondition
from sigma.exceptions import SigmaRuleLocation, SigmaRuleNotFoundError
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.resolver import ProcessingPipelineResolver

from .assets import bundled_dir
from .config import RULE_LEVELS, RulesetConfig

# Rich console for styled output
from .console import console, is_quiet, literal, make_file_link
from .correlations import is_correlation_plan_rule, plan_problem
from .sqlscan import channel_constraints, eventid_constraints
from .utils import random_suffix, safe_load_all

# Newest Zircolite ruleset format this version reads. Version 2 (pySigma's
# SQLite backend 2) adds required_fields, result_type and correlation plans;
# rulesets without a schema_version are version 1.
RULESET_SCHEMA_VERSION = 2


def _level_rank(rule: dict[str, Any]) -> int:
    level = str(rule.get("level") or "").lower()
    return RULE_LEVELS.index(level) if level in RULE_LEVELS else 0


def _referenced_names(rule: SigmaCorrelationRule) -> list[str]:
    """The rule names or ids a correlation refers to, as written."""
    if rule.rules is not None:
        return [reference.reference for reference in rule.rules]
    if isinstance(rule.condition, SigmaExtendedCorrelationCondition):
        return list(rule.condition.get_referenced_rules())
    return []


def _rule_path(rule: Any) -> str | None:
    """The file a Sigma rule was loaded from, if pySigma recorded it."""
    source = getattr(rule, "source", None)
    path = getattr(source, "path", None)
    return str(path) if path is not None else None


def ruleset_format_problem(rules: list[dict[str, Any]]) -> str | None:
    """Why this JSON ruleset cannot be run as written, or None if it can."""
    for rule in rules:
        title = rule.get("title", "untitled rule")
        version = rule.get("schema_version", 1)
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            return f"rule {title!r} has an invalid schema_version {version!r}"
        if version > RULESET_SCHEMA_VERSION:
            return (
                f"rule {title!r} uses ruleset schema version {version}, and this "
                f"Zircolite reads up to version {RULESET_SCHEMA_VERSION}: update Zircolite"
            )
        is_correlation = rule.get("correlation") or rule.get("result_type") == "correlation"
        if version >= 2 and is_correlation and not is_correlation_plan_rule(rule):
            # Run as plain SQL, its alert rows would be reported as events.
            return f"correlation rule {title!r} has no correlation_plan"
    return None


class EventFilter:
    """
    Filter events based on channel and eventID from loaded rules.

    This class extracts the channel and eventID values from a ruleset and
    provides fast lookup to determine if an event should be processed.

    EventID bounds come from each rule's SQL, never from its ``eventid``
    metadata. The backend collects that metadata from every detection group
    including negated ``filter`` blocks, so a rule that *excludes* an eventID
    arrives claiming to want it; bounding on that drops exactly the events the
    rule is looking for. Anything the SQL does not pin down -- a negated
    comparison, an OR branch free of EventID, a correlation subquery -- leaves
    the channel unbounded, because a filter that guesses wrong produces a rule
    that finds nothing and says nothing.

    EventIDs are bounded *per channel*. A rule naming a channel but no eventID
    matches any eventID on that channel, so it widens only its own channel
    rather than switching eventID filtering off everywhere. Judging a rule's
    events against unrelated rules' eventIDs would drop events it should have
    seen -- alert counts would then differ between a single-rule and a
    full-ruleset run (issue #117). Keying the bounds by channel keeps that
    guarantee while preserving the selectivity a global set throws away.

    An event is discarded when its Channel is claimed by no rule, or when that
    channel carries a finite eventID set the event's EventID is absent from.
    An event with no usable Channel, or no usable EventID on a bounded channel,
    is kept: too little information to discard it safely.

    A rule constraining eventIDs but *no* channel cannot be keyed by channel, so
    a ruleset containing one falls back to the two independent global axes,
    where each axis filters only when every rule constrains it.
    """

    __slots__ = (
        '_channel_filter',
        '_channel_map',
        '_eventid_bounded',
        '_eventid_filter',
        '_has_filter_data',
        '_rules_with_filter',
        '_rules_without_filter',
        'channels',
        'eventids',
        'logger'
    )

    def __init__(
        self,
        rulesets: list[dict[str, Any]],
        *,
        logger: logging.Logger | None = None,
    ):
        """
        Initialize EventFilter from a list of rules.

        Args:
            rulesets: List of rule dictionaries, each potentially containing
                      'channel' (list of strings) and 'eventid' (list of ints)
            logger: Logger instance (creates default if None)
        """
        self.logger = logger or logging.getLogger(__name__)

        # Storage for unique values across ALL rules (built as sets, converted to frozenset)
        self.channels: frozenset[str] = frozenset()
        self.eventids: frozenset[int] = frozenset()

        # Channel (lowercase, plus an original-case alias) -> frozenset of
        # eventIDs, or True when any eventID is allowed on that channel.
        self._channel_map: dict[str, frozenset[int] | bool] = {}

        # Stats
        self._rules_with_filter = 0
        self._rules_without_filter = 0

        # Flags
        self._has_filter_data = False
        self._channel_filter = False
        self._eventid_filter = False
        self._eventid_bounded = False

        # Extract filter data from rulesets
        self._extract_filter_data(rulesets)

    @staticmethod
    def _rule_channels(rule: dict[str, Any], queries: list[str]) -> list[str]:
        """The channels a rule can match, empty when it cannot be bounded.

        Read from the SQL, which is what actually runs, for the same reason
        ``_rule_eventids`` does. The ``channel`` metadata is a bag of raw
        SigmaStrings collected from every detection group, so two shapes make it
        name no channel the rule wants: ``Channel|contains`` contributes a
        wildcard pattern that matches no real channel, and a Channel named only
        under a negation is the one channel the rule *excludes*. Both are
        non-empty, so trusting them left the rule counted as bounded and starved
        it of its own events.

        Returning empty hands the decision to the caller, which disables the
        channel axis entirely -- the fail-open the eventID axis already uses.
        Rules carrying no SQL cannot run, and bounds only ever union, so their
        metadata can widen a channel but never narrow one.
        """
        if queries:
            return sorted(channel_constraints(queries) or [])
        return [channel for channel in (rule.get('channel') or []) if channel]

    def _rule_eventids(
        self, rule: dict[str, Any], queries: list[str]
    ) -> set[int] | None:
        """The eventIDs a rule can match, or None when it cannot be bounded.

        Read from the rule's SQL, which is what actually runs. The ``eventid``
        metadata cannot be trusted: ``pysigma-backend-sqlite`` harvests it from
        every detection group including negated ``filter`` blocks, so a rule
        that *excludes* EventID 4624 arrives claiming to want it. Bounding a
        channel on that drops precisely the events the rule is looking for.

        Correlation rules stay unbounded: their SQL wraps the base rule's
        detection in a subquery, and mistaking that shape would starve them.
        Rules carrying no SQL fall back to the metadata -- they cannot run, and
        bounds only ever union, so they can widen a channel but never narrow it.
        """
        if rule.get('correlation'):
            return None
        if queries:
            return eventid_constraints(queries)
        ids: set[int] = set()
        for eventid in rule.get('eventid') or []:
            if eventid is None:
                continue
            try:
                ids.add(int(eventid))
            except (ValueError, TypeError):
                self.logger.debug(
                    f"EventFilter: skipping non-numeric eventid '{eventid}'"
                )
        return ids or None

    def _extract_filter_data(self, rulesets: list[dict[str, Any]]) -> None:
        """Collect the channels, the eventIDs, and the per-channel bounds."""
        if any(is_correlation_plan_rule(rule) for rule in rulesets):
            # A correlation plan reads every row: the latest timestamp in the
            # input, matched or not, is the horizon its absence windows wait for,
            # and a pure-negative condition takes its groups from unmatched events.
            self.logger.debug("EventFilter: a correlation plan reads every event - filtering disabled")
            return
        rules_with_filter = 0
        rules_without_filter = 0
        rules_without_channel = 0
        rules_without_eventid = 0

        # Build as mutable sets first
        channels_set: set[str] = set()
        eventids_set: set[int] = set()
        # Lowercase channel -> mutable eventID set, or True for "any eventID"
        channel_bounds: dict[str, set[int] | bool] = {}

        for rule in rulesets:
            queries = rule.get('rule') or []
            channels = self._rule_channels(rule, queries)
            rule_ids = self._rule_eventids(rule, queries)
            eventids = rule_ids if rule_ids is not None else []

            # Check if this rule has filter metadata
            if channels or eventids:
                rules_with_filter += 1

                # Add all channels from this rule
                for channel in channels:
                    if channel:
                        channels_set.add(channel)

                eventids_set.update(eventids)
            else:
                rules_without_filter += 1

            if not channels:
                rules_without_channel += 1
            if not eventids:
                rules_without_eventid += 1

            # An empty eventID set means the rule matches any eventID on its
            # channels, so it must widen them, never narrow them. Merging with
            # setdefault/update rather than assigning keeps two rules that spell
            # the same channel differently from overwriting each other's bounds.
            for channel in channels:
                if not channel:
                    continue
                key = channel.lower()
                if not rule_ids:
                    channel_bounds[key] = True
                elif channel_bounds.get(key) is not True:
                    bound = channel_bounds.setdefault(key, set())
                    bound.update(rule_ids)  # type: ignore[union-attr]

        # Convert to immutable frozensets for faster lookups
        self.channels = frozenset(channels_set)
        self.eventids = frozenset(eventids_set)

        # Store stats
        self._rules_with_filter = rules_with_filter
        self._rules_without_filter = rules_without_filter

        # Per-channel bounds need every rule to name a channel; a rule with
        # eventIDs but no channel cannot be keyed by one. When that happens the
        # run falls back to the two independent global axes, where each axis
        # filters only when every rule constrains it (issue #117).
        self._channel_filter = bool(self.channels) and rules_without_channel == 0
        self._eventid_filter = bool(self.eventids) and rules_without_eventid == 0
        self._has_filter_data = self._channel_filter or self._eventid_filter

        if self._channel_filter:
            self._channel_map = self._freeze_channel_bounds(channel_bounds)
            self._eventid_bounded = any(
                value is not True for value in self._channel_map.values()
            )

        if not self._has_filter_data:
            self.logger.debug(
                "EventFilter: every rule leaves at least one of channel/eventid "
                "unconstrained (any log source) - filtering disabled"
            )
        elif not self._channel_filter:
            self.logger.debug(
                "EventFilter: filtering on eventID only; at least one rule "
                "names no channel"
            )

    def _freeze_channel_bounds(
        self, channel_bounds: dict[str, set[int] | bool]
    ) -> dict[str, frozenset[int] | bool]:
        """Freeze the per-channel bounds and add original-case aliases."""
        frozen: dict[str, frozenset[int] | bool] = {
            key: (True if value is True else frozenset(value))  # type: ignore[arg-type]
            for key, value in channel_bounds.items()
        }

        # Alias the original spelling so the common case costs one dict lookup
        for channel in self.channels:
            key = channel.lower()
            if channel != key and key in frozen:
                frozen[channel] = frozen[key]

        return frozen

    @property
    def is_enabled(self) -> bool:
        """Check if the filter has anything to filter on."""
        return self._has_filter_data

    def should_process_event(self, channel: str | None, eventid: int | None) -> bool:
        """
        Check if an event should be processed based on its channel and eventID.

        Filtering logic:
        - Channel claimed by no rule → discard
        - Channel bounded to a finite eventID set the event's EventID is absent
          from → discard

        An event with no usable Channel, or no usable EventID on a bounded
        channel, is kept: too little information to discard it safely. When the
        ruleset has a rule with eventIDs but no channel, the per-channel bounds
        cannot be built and the global eventID axis applies instead.

        Args:
            channel: The event's channel name (e.g., 'Microsoft-Windows-Sysmon/Operational')
            eventid: The event's EventID (int, str convertible to int, or None)

        Returns:
            True if the event should be processed, False if it can be skipped
        """
        # Fast path: nothing to filter on
        if not self._has_filter_data:
            return True

        if self._channel_map:
            if channel is None:
                return True
            allowed = self._channel_map.get(channel)
            if allowed is None:
                allowed = self._channel_map.get(channel.lower())
            if allowed is None:
                return False
            if not isinstance(allowed, frozenset):
                # True: this channel accepts any eventID
                return True
            if eventid is None:
                return True
            # Internal callers pass int, but the API accepts str
            if not isinstance(eventid, int):
                try:
                    eventid = int(eventid)
                except (ValueError, TypeError):
                    return True
            return eventid in allowed

        if self._eventid_filter and eventid is not None:
            # Internal callers pass int, but the API accepts str
            if not isinstance(eventid, int):
                try:
                    eventid = int(eventid)
                except (ValueError, TypeError):
                    return True
            if eventid not in self.eventids:
                return False

        return True

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the filter data."""
        # Original-case aliases always carry an uppercase letter, so the
        # all-lowercase keys are exactly the canonical entries
        canonical = {
            key: value
            for key, value in self._channel_map.items()
            if key == key.lower()
        }
        any_eventid_channels = sorted(
            channel for channel in self.channels
            if canonical.get(channel.lower()) is True
        )
        if self._channel_map:
            mode = 'per-channel'
        elif self._eventid_filter:
            mode = 'eventid-only'
        else:
            mode = 'disabled'

        return {
            'mode': mode,
            'channels_count': len(self.channels),
            'eventids_count': len(self.eventids),
            'bounded_channels_count': len(canonical) - len(any_eventid_channels),
            'any_eventid_channels': any_eventid_channels,
            'channel_eventid_pairs': sum(
                len(value)
                for value in canonical.values()
                if isinstance(value, frozenset)
            ),
            'is_enabled': self.is_enabled,
            'channel_filter': self._channel_filter,
            'eventid_filter': self._eventid_filter or self._eventid_bounded,
            'rules_with_filter': self._rules_with_filter,
            'rules_without_filter': self._rules_without_filter
        }


class RulesUpdateError(Exception):
    """The downloaded rules release cannot be installed as it stands."""


class RulesUpdater:
    """Install the rulesets published by the Zircolite-Rules-v2 repository.

    The repository publishes a release manifest naming every artifact with its
    SHA-256. The rulesets -- ``rules_*.json`` and ``experimental/*.json`` --
    the licence texts of their sources and the manifest itself are installed;
    reports, provenance and the repository's own tests are not. The manifest
    stays beside the rulesets because it names each one's source and licence,
    which a release built from ``rules/`` needs to credit them. Every file is
    checked against the manifest before any is installed, and one that fails
    leaves ``rules/`` as it was. The manifest arrives in the same archive, so
    this proves the download complete and consistent, not who published it.
    """

    url = "https://github.com/wagga40/Zircolite-Rules-v2/archive/refs/heads/main.zip"
    manifest_name = "release-manifest.json"
    manifest_version = 1

    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        rules_dir: Path | None = None,
    ):
        """
        Initialize RulesUpdater.

        Args:
            logger: Logger instance (creates default if None)
            rules_dir: Where to install rulesets (resolved from the install if None)
        """
        self.logger = logger or logging.getLogger(__name__)
        self.tempFile = f'tmp-rules-{random_suffix(4)}.zip'
        self.tmpDir = f'tmp-rules-{random_suffix(4)}'
        self.rules_dir = rules_dir if rules_dir is not None else self._install_rules_dir()
        self.updated_rulesets: list[str] = []

    def _install_rules_dir(self) -> Path:
        """The ``rules/`` directory a run would read, not the one the shell is in.

        A run resolves a relative ``rules/...`` against the install when the
        working directory has none, so rulesets written to the working directory
        would be invisible to the next run started from anywhere else.
        """
        destination = bundled_dir("rules")
        probe = destination if destination.is_dir() else destination.parent
        if probe.is_dir() and os.access(probe, os.W_OK):
            return destination
        self.logger.warning(
            f"[yellow]    [!] Cannot write to {destination}, "
            "installing rulesets into ./rules instead[/]"
        )
        return Path('rules')

    def download(self) -> None:
        resp = requests.get(self.url, stream=True, timeout=30)
        resp.raise_for_status()
        total = int(resp.headers.get('content-length', 0))

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
            disable=is_quiet(),
        )

        with progress:
            task_id = progress.add_task(f"Downloading {self.tempFile}", total=total)
            with open(self.tempFile, 'wb') as file:
                for data in resp.iter_content(chunk_size=1024):
                    size = file.write(data)
                    progress.update(task_id, advance=size)

    def unzip(self) -> None:
        shutil.unpack_archive(self.tempFile, self.tmpDir, "zip")

    def _release_root(self) -> Path:
        """The repository's top directory inside the unpacked archive.

        GitHub wraps a branch archive in one folder (``Zircolite-Rules-v2-main/``).
        """
        root = Path(self.tmpDir)
        entries = list(root.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            return entries[0]
        return root

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _read_manifest(self, root: Path) -> dict[str, Any] | None:
        path = root / self.manifest_name
        if not path.is_file():
            return None
        try:
            manifest = json.loads(path.read_bytes())
        except json.JSONDecodeError as e:
            raise RulesUpdateError(f"{self.manifest_name} is not valid JSON: {e}") from e
        version = manifest.get("schema_version") if isinstance(manifest, dict) else None
        if version != self.manifest_version:
            raise RulesUpdateError(
                f"{self.manifest_name} uses schema version {version!r}, which this "
                "Zircolite does not read: update Zircolite"
            )
        if not isinstance(manifest.get("sources"), dict):
            raise RulesUpdateError(f"{self.manifest_name} lists no sources")
        return manifest

    @staticmethod
    def _build_error(source: dict[str, Any]) -> str:
        """Why the rules build could not refresh *source*, without the URL.

        requests ends its HTTP errors with the URL fetched, which differs for
        every source and hides that they all failed for one reason.
        """
        return re.sub(r"\s+for url: \S+$", "", str(source.get("error") or "")).strip()

    @staticmethod
    def _built(timestamp: object, now: datetime | None = None) -> str:
        """When a ruleset was built: its age first, since that is what matters."""
        try:
            built = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except ValueError:
            return literal(timestamp) if timestamp else "at an unknown date"
        if built.tzinfo is None:
            built = built.replace(tzinfo=timezone.utc)
        built = built.astimezone(timezone.utc)
        seconds = max(0, int(((now or datetime.now(timezone.utc)) - built).total_seconds()))
        age = "less than a minute ago"
        for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
            if seconds >= size:
                count = seconds // size
                age = f"{count} {unit}{'s' if count != 1 else ''} ago"
                break
        return f"{age} ({built:%Y-%m-%d %H:%M} UTC)"

    def _report_sources(self, manifest: dict[str, Any]) -> None:
        """Explain sources whose rulesets are older than their upstream.

        The rules repository rebuilds each source on its own and keeps the last
        good rulesets of one it cannot rebuild, so a stale source says nothing
        about this update: what it installed is exactly what is published.
        """
        sources = {name: s for name, s in sorted(manifest["sources"].items()) if isinstance(s, dict)}
        stale = {name: s for name, s in sources.items() if s.get("status") == "stale"}
        if stale:
            errors = {self._build_error(s) for s in stale.values()}
            shared = errors.pop() if len(errors) == 1 else ""
            if len(sources) == 1:
                scope = "its only source"
            elif len(stale) == len(sources):
                scope = f"any of its {len(sources)} sources"
            else:
                scope = f"{len(stale)} of its {len(sources)} sources"
            reason = f" ({literal(shared)})" if shared else ""
            lines = [
                f"[yellow]    [!] Upstream, the latest rules build could not refresh {scope}{reason}[/]",
                "        Their previous rulesets are still published and work as before; "
                "a later -U fetches newer ones once a build succeeds:",
            ]
            width = max(len(name) for name in stale)
            for name, source in stale.items():
                revision = str(source.get("revision") or "unknown")[:12]
                line = (f"          {literal(name.ljust(width))}  {literal(revision.ljust(12))}  "
                        f"built {self._built(source.get('last_success'))}")
                if not shared and (error := self._build_error(source)):
                    line += f"  [dim]{literal(error)}[/]"
                lines.append(line)
            self.logger.warning("\n".join(lines))
        for name, source in sources.items():
            if source.get("status") == "unavailable":
                error = self._build_error(source)
                reason = f" ({literal(error)})" if error else ""
                self.logger.warning(
                    f"[yellow]    [!] Upstream, no {literal(name)} rulesets have been published yet{reason}[/]"
                )

    def _selection(self, root: Path, manifest: dict[str, Any] | None) -> list[tuple[str, str | None]]:
        """(relative path, expected SHA-256) of every file to install.

        Raises RulesUpdateError when the archive and its manifest disagree.
        """
        rulesets = [p.relative_to(root).as_posix() for p in sorted(root.glob("rules_*.json"))]
        if manifest is None:
            # A release made before the manifest existed: its rulesets only, unverified.
            return [(name, None) for name in rulesets]
        rulesets += [p.relative_to(root).as_posix() for p in sorted(root.glob("experimental/*.json"))]
        # Sources publish their own rulesets; aggregates combine several of
        # them (rules_windows_all.json).
        published: dict[str, str] = {}
        for entries in (manifest["sources"], manifest.get("aggregates") or {}):
            for entry in entries.values() if isinstance(entries, dict) else ():
                if isinstance(entry, dict) and isinstance(entry.get("artifacts"), dict):
                    published.update(entry["artifacts"])

        unlisted = [name for name in rulesets if name not in published]
        if unlisted:
            raise RulesUpdateError(f"rulesets missing from {self.manifest_name}: {', '.join(unlisted)}")
        wanted = [
            name for name in published
            if (name.startswith("rules_") and "/" not in name)
            or name.startswith(("experimental/", "licenses/"))
        ]
        absent = [name for name in wanted if not (root / name).is_file()]
        if absent:
            raise RulesUpdateError(f"files listed in {self.manifest_name} are missing: {', '.join(absent)}")
        mismatched = [name for name in wanted if self._sha256(root / name) != published[name]]
        if mismatched:
            raise RulesUpdateError(f"files do not match {self.manifest_name}: {', '.join(mismatched)}")
        return [(name, published[name]) for name in sorted(wanted)]

    def install(self) -> None:
        """Check the unpacked release, then install the files that changed."""
        root = self._release_root()
        manifest = self._read_manifest(root)
        if manifest is None:
            self.logger.warning(
                f"[yellow]    [!] The rules repository publishes no {self.manifest_name}: "
                "installing its top-level rulesets unverified[/]"
            )
        selection = self._selection(root, manifest)
        if not any(name.endswith(".json") for name, _ in selection):
            raise RulesUpdateError("the downloaded archive holds no rulesets")
        if manifest is not None:
            # Last, so an interrupted install never leaves a manifest that
            # describes files it did not get to.
            selection.append((self.manifest_name, None))

        rules_dir = Path(self.rules_dir)
        rules_dir.mkdir(parents=True, exist_ok=True)
        rulesets = 0
        for name, digest in selection:
            source = root / name
            destination = rules_dir.joinpath(*name.split("/"))
            if destination.is_file() and self._sha256(destination) == (digest or self._sha256(source)):
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(source, destination)
            self.updated_rulesets.append(str(destination))
            if name.endswith(".json") and name != self.manifest_name:
                rulesets += 1
                self.logger.info(f"    [>] Updated : {make_file_link(str(destination))}")
            else:
                self.logger.debug(f"    [>] Updated : {destination}")

        if rulesets:
            self.logger.info(f"[green]    [>] {rulesets} ruleset{'s' if rulesets != 1 else ''} updated[/]")
        else:
            self.logger.info("[green]    [>] No newer rulesets: yours already match the latest release[/]")
        if manifest is not None:
            self._report_sources(manifest)

    def clean(self) -> None:
        if Path(self.tempFile).exists():
            os.remove(self.tempFile)
        if Path(self.tmpDir).exists():
            shutil.rmtree(self.tmpDir)

    def run(self) -> bool:
        """Download, check and install; False when nothing could be installed."""
        try:
            self.download()
            self.unzip()
            self.install()
            return True
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"    [-] Network connection failed: {literal(e)}")
        except requests.exceptions.Timeout:
            self.logger.error(f"    [-] Download timed out after 30s: {self.url}")
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"    [-] Server returned an error: {literal(e)}")
        except RulesUpdateError as e:
            self.logger.error(f"    [-] Rulesets not updated: {literal(e)}")
        except Exception as e:
            self.logger.error(f"    [-] {literal(e)}")
        finally:
            self.clean()
        return False


def pipeline_install_hint() -> str:
    """How to get a pipeline that is not installed, for this kind of install."""
    # A binary bundles the pipelines it was built with; a package manager
    # cannot add one to it.
    if getattr(sys, "frozen", False):
        return ("This build bundles only the pipelines listed; "
                "any other needs a source install of Zircolite")
    return ("You can install pipelines with your Python package manager, "
            "e.g. pdm add pysigma-pipeline-sysmon")


class UnknownPipelineError(ValueError):
    """One or more requested pySigma pipelines are not installed.

    Raised rather than logged: a Sigma rule converts without its pipeline all
    the same, only without the conditions the pipeline adds (``EventID=1`` for
    sysmon process creation, for instance), so carrying on turns every rule
    into a broader one that matches events it should not.
    """

    def __init__(self, unknown: list[str], installed: list[str]):
        self.unknown = unknown
        self.installed = installed
        self.hint = pipeline_install_hint()
        super().__init__(
            f"Unknown pipeline(s): {', '.join(unknown)}. "
            f"Installed pipelines: {', '.join(installed) or 'none'}"
        )


class RulesetHandler:
    """Handle ruleset parsing and Sigma rule conversion."""

    def __init__(
        self,
        ruleset_config: RulesetConfig | None = None,
        *,
        logger: logging.Logger | None = None,
        list_pipelines_only: bool = False
    ):
        """
        Initialize RulesetHandler.

        Args:
            ruleset_config: Ruleset configuration (uses defaults if None)
            logger: Logger instance (creates default if None)
            list_pipelines_only: If True, only list available pipelines and return
        """
        cfg = ruleset_config or RulesetConfig()

        self.logger = logger or logging.getLogger(__name__)
        self.saveRuleset = cfg.save_ruleset
        self.rulesetPathList = cfg.ruleset
        self.time_field = cfg.time_field
        self.timestamp_format = cfg.timestamp_format
        self.min_level = cfg.min_level
        # The native Sigma paths converted in this run, if any
        self.yaml_paths: list[Path] = []
        self.pipelines = []
        self.event_filter: EventFilter | None = None  # Will be populated after loading

        # Init pipelines. Validators are never run, and loading them imports
        # pySigma's MITRE tag data, which unpickles a cache under ~/.cache/pysigma.
        plugins = InstalledSigmaPlugins.autodiscover(include_validators=False)
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_list = list(pipeline_resolver.pipelines.keys())

        if list_pipelines_only:
            self.logger.info("[+] Installed pipelines : "
                            + ", ".join(pipeline_list)
                            + f"\n    {pipeline_install_hint()}"
                            )
        elif cfg.pipeline:
            requested = [item for pipeline in cfg.pipeline for item in pipeline]
            unknown = [name for name in dict.fromkeys(requested) if name not in pipeline_list]
            if unknown:
                raise UnknownPipelineError(unknown, pipeline_list)
            self.pipelines = [plugins.pipelines[name]() for name in requested]

        # Parse & (if necessary) convert ruleset, final list is stored in self.rulesets
        # (--pipeline-list only prints the installed pipelines: skip loading entirely)
        if list_pipelines_only:
            self.rulesets = []
            return

        raw_rulesets = self.ruleset_parsing()
        # Flatten list of rulesets into a single list of rules
        self.rulesets = [
            item for sub_ruleset in raw_rulesets if sub_ruleset for item in sub_ruleset
        ]
        if self.min_level is not None:
            self.rulesets = self._at_or_above(self.rulesets, self.min_level)

        # Sort by level FIRST so that, among duplicates sharing the same SQL,
        # the surviving rule is the highest-severity one (stable sort keeps
        # file order within a level).
        level_order = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "informational": 5
        }
        self.rulesets = sorted(self.rulesets, key=lambda d: level_order.get(d.get('level', 'informational'), float('inf')))

        # Remove duplicates based on SQL query
        unique_rules = []
        seen_keys = set()
        for rule in self.rulesets:
            # Use the SQL query as the unique key
            rule_queries = rule.get('rule')
            rule_key = tuple(rule_queries) if rule_queries else None
            if rule_key and rule_key not in seen_keys:
                seen_keys.add(rule_key)
                unique_rules.append(rule)

        self.rulesets = unique_rules

        if not self.rulesets:
            self.logger.error("[red]    [-] No rules to execute ![/]")
        else:
            self.logger.info(f"[+] {len(self.rulesets)} rules loaded")
            self._report_unrunnable_plans()

            self.event_filter = EventFilter(self.rulesets, logger=self.logger)
            if any(is_correlation_plan_rule(rule) for rule in self.rulesets):
                self.logger.info(
                    "[+] Event filter disabled: correlation rules read every event "
                    "(the last one sets the end of the observation window)"
                )
            elif self.event_filter.is_enabled:
                stats = self.event_filter.get_stats()
                if stats['mode'] == 'per-channel':
                    summary = f"[cyan]{stats['channels_count']}[/] channels"
                    if stats['bounded_channels_count']:
                        summary += (
                            f", [cyan]{stats['bounded_channels_count']}[/] EventID-bounded "
                            f"([cyan]{stats['channel_eventid_pairs']}[/] channel/eventID pairs)"
                        )
                    self.logger.info(f"[+] Event filter enabled: {summary}")
                    if stats['any_eventid_channels']:
                        unbounded = ", ".join(stats['any_eventid_channels'])
                        self.logger.info(f"[+]   any EventID allowed on: [cyan]{unbounded}[/]")
                else:
                    self.logger.info(
                        f"[+] Event filter enabled: [cyan]{stats['eventids_count']}[/] eventIDs"
                    )

    def _at_or_above(self, rules: list[dict[str, Any]], level: str) -> list[dict[str, Any]]:
        """The rules at *level* or above; a rule without a known level counts as informational."""
        floor = RULE_LEVELS.index(level)
        kept = [rule for rule in rules if _level_rank(rule) >= floor]
        if len(kept) < len(rules):
            self.logger.info(f"[+] {len(rules) - len(kept)} rule(s) below level {level} left out")
        return kept

    def _report_unrunnable_plans(self) -> None:
        """Say once, at load time, which correlation plans cannot run here.

        They stay in the ruleset, so every run also records them as rules in
        error and reports a partial status rather than a clean one.
        """
        problems: dict[str, int] = {}
        for rule in self.rulesets:
            if is_correlation_plan_rule(rule):
                problem = plan_problem(rule["correlation_plan"])
                if problem is not None:
                    problems[problem] = problems.get(problem, 0) + 1
        for problem, count in problems.items():
            self.logger.error(f"[red]    [-] {count} correlation rule(s) cannot run: {literal(problem)}[/]")

    def is_yaml(self, filepath: Path) -> bool | None:
        """Test if the file is a YAML file (including multi-document streams)."""
        if filepath.suffix in (".yml", ".yaml"):
            with open(filepath, encoding="utf-8") as file:
                content = file.read()
                try:
                    for _ in safe_load_all(content):
                        pass
                    return True
                except yaml.YAMLError:
                    return False
        return None

    def is_json(self, filepath: Path) -> bool | None:
        """Test if the file is a JSON file."""
        if filepath.suffix == ".json":
            with open(filepath, encoding="utf-8") as file:
                content = file.read()
                try:
                    json.loads(content)
                    return True
                except json.JSONDecodeError:
                    return False
        return None

    def is_valid_sigma_rule(self, filepath: Path) -> bool:
        """Check if a YAML file contains at least one Sigma rule, correlation or filter."""
        try:
            with open(filepath, encoding="utf-8") as file:
                for doc in safe_load_all(file):
                    if not isinstance(doc, dict):
                        continue
                    has_standard = all(
                        f in doc for f in ("title", "logsource", "detection")
                    )
                    has_correlation = "title" in doc and "correlation" in doc
                    has_filter = all(f in doc for f in ("title", "logsource", "filter"))
                    if has_standard or has_correlation or has_filter:
                        return True
        except Exception:
            pass
        return False

    def rand_ruleset_name(self, sigma_rules: str) -> str:
        """Generate a random ruleset filename."""
        # Clean the ruleset name
        cleaned_name = ''.join(char if char.isalnum() else '-' for char in sigma_rules).strip('-')
        cleaned_name = re.sub(r'-+', '-', cleaned_name)
        return f"ruleset-{cleaned_name}-{random_suffix(8)}.json"

    @staticmethod
    def _merge_converted_queries(converted: list[dict[str, Any]]) -> dict[str, Any]:
        """Fold every query the backend produced into one Zircolite rule.

        A Sigma ``condition:`` may be a YAML list, and pySigma then returns one
        finalized rule per branch. Keeping only the first silently drops the
        others: nothing counts them, because the conversion tally is per rule,
        not per query. A Zircolite rule already carries a list of SELECTs that
        ``execute_rule`` ORs together, so the branches belong in one rule.
        """
        merged = converted[0]
        if len(converted) > 1:
            merged["rule"] = [
                query for entry in converted for query in entry.get("rule", [])
            ]
            if any("required_fields" in entry for entry in converted):
                merged["required_fields"] = sorted({
                    field for entry in converted for field in entry.get("required_fields", [])
                })
        return merged

    def convert_sigma_rules(self, backend: Any, rule: Any) -> dict[str, Any] | None:
        """Convert a single Sigma rule using the provided backend."""
        try:
            converted = backend.convert_rule(rule, "zircolite")
            if not converted:
                return None
            return self._merge_converted_queries(converted)
        except Exception as e:
            self.logger.debug(f"[red]    [-] Cannot convert rule '{rule!s}' : {e}[/]")
            return None

    def convert_correlation_rule(
        self, backend: Any, rule: SigmaCorrelationRule
    ) -> dict[str, Any] | None:
        """Convert a Sigma correlation rule using the provided backend."""
        try:
            converted = backend.convert_correlation_rule(rule, "zircolite")
            if not converted:
                return None
            result = self._merge_converted_queries(converted)
            result["correlation"] = True
            return result
        except Exception as e:
            title = getattr(rule, "title", str(rule))
            self.logger.debug(f"[red]    [-] Cannot convert correlation rule '{title}' : {e}[/]")
            return None

    def _sigma_backend(self, pipelines: list[Any]) -> Any:
        """The SQLite backend, with the pipelines applied in the order given."""
        pipeline_resolver = ProcessingPipelineResolver()
        # Preserve user order: pySigma's resolve() sorts by (priority, path).
        # When priorities are equal it uses pipeline name, so e.g. "Add Channel..."
        # runs before "Generic Log Sources..." and Channel is never set for Sysmon.
        # Temporarily set priority to index so user order is respected.
        original_priorities = [p.priority for p in pipelines]
        try:
            for i, pipeline in enumerate(pipelines):
                pipeline.priority = i
            for pipeline in pipelines:
                pipeline_resolver.add_pipeline_class(pipeline)
            # Resolve using pipeline names in user order (lower priority = earlier)
            combined_pipeline = pipeline_resolver.resolve([p.name for p in pipelines])
        finally:
            for pipeline, orig in zip(pipelines, original_priorities, strict=True):
                pipeline.priority = orig
        # row_id is the logs table's integer primary key: correlation evidence
        # names events by it.
        backend = sqlite.sqliteBackend(
            combined_pipeline, timestamp_field=self.time_field, event_id_field="row_id",
            timestamp_format=self.timestamp_format,
        )
        backend.init_processing_pipeline("zircolite")
        return backend

    def _resolve_references(self, merged: SigmaCollection) -> SigmaCollection:
        """Resolve correlation references, dropping only the correlations that cannot be.

        pySigma resolves a whole collection at once, and one correlation naming
        a rule nobody loaded fails it -- every rule of every path with it. A
        correlation that depends on a dropped one is dropped in turn.
        """
        rules: list[Any] = list(merged.rules)
        while True:
            # Filters were applied when the paths were merged; none are passed again.
            collection = SigmaCollection(init_rules=rules, resolve_references=False)
            broken: dict[int, tuple[Any, str]] = {}
            for rule in collection.rules:
                if not isinstance(rule, SigmaCorrelationRule):
                    continue
                for name in _referenced_names(rule):
                    try:
                        collection[name]
                    except SigmaRuleNotFoundError:
                        broken[id(rule)] = (rule, name)
                        break
            if not broken:
                break
            for rule, name in broken.values():
                self.logger.error(
                    f"[red]    [-] Correlation '{literal(rule.title)}' ({literal(_rule_path(rule) or 'unknown file')}) "
                    f"references '{literal(name)}', which no loaded rule defines: skipped[/]"
                )
            rules = [rule for rule in rules if id(rule) not in broken]
        collection.resolve_rule_references()
        return collection

    def sigma_rules_to_ruleset(
        self, sigma_rules_list: Sequence[Path | str], pipelines: list[Any]
    ) -> list[dict[str, Any]]:
        """Convert Sigma rules to Zircolite ruleset format.

        Every path goes into one collection, so a correlation can name a rule
        defined in another file or directory, and a Sigma filter applies to the
        rules of every path. Each path still gets its own conversion summary
        and, with --save-ruleset, its own saved ruleset.
        """
        paths = [Path(p) for p in sigma_rules_list]
        documents: list[SigmaCollection] = []
        # Resolved file -> index of the path it was loaded from
        origin: dict[Path, int] = {}
        invalid = [0] * len(paths)
        unloadable = [0] * len(paths)
        for index, path in enumerate(paths):
            files = sorted(path.rglob("*.yml")) + sorted(path.rglob("*.yaml")) if path.is_dir() else [path]
            valid = [f for f in files if self.is_valid_sigma_rule(f)]
            invalid[index] = len(files) - len(valid)
            if invalid[index]:
                self.logger.debug(f"[yellow]    [!] Skipped {invalid[index]} invalid Sigma rule(s)[/]")
            for file in valid:
                resolved = file.resolve()
                if resolved in origin:
                    continue
                try:
                    # As SigmaCollection.load_ruleset does: filters are collected per
                    # file and applied once, over every rule, when the files merge.
                    with open(file, encoding="utf-8") as handle:
                        documents.append(SigmaCollection.from_yaml(
                            handle, source=SigmaRuleLocation(file),
                            collect_filters=True, resolve_references=False,
                        ))
                except Exception as e:
                    self.logger.error(f"[red]    [-] Cannot load {literal(file)}: {literal(e)}[/]")
                    unloadable[index] += 1
                    continue
                origin[resolved] = index

        if not documents:
            return []

        sqlite_backend = self._sigma_backend(pipelines)
        rule_collection = self._resolve_references(
            SigmaCollection.merge(documents, resolve_references=False)
        )
        rulesets: list[list[dict[str, Any]]] = [[] for _ in paths]
        referenced_only = [0] * len(paths)
        failed = [0] * len(paths)

        # Process rules with Rich progress bar
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[cyan]{task.completed}/{task.total}[/]"),
            console=console,
            transient=True,
            disable=is_quiet(),
        )

        with progress:
            task_id = progress.add_task("Converting rules", total=len(rule_collection))
            for rule in rule_collection:
                rule_path = _rule_path(rule)
                index = origin.get(Path(rule_path).resolve(), 0) if rule_path else 0
                # A rule referenced by a correlation, and not generated on its own,
                # returns no standalone query; converting it still stores the
                # predicates the correlation is compiled from. References come
                # first in the collection, so they are ready when it is.
                if not rule._output:
                    try:
                        if isinstance(rule, SigmaCorrelationRule):
                            sqlite_backend.convert_correlation_rule(rule, "zircolite")
                        else:
                            sqlite_backend.convert_rule(rule, "zircolite")
                    except Exception as e:
                        self.logger.debug(
                            f"[red]    [-] Cannot convert rule '{rule!s}' : {e}[/]"
                        )
                    referenced_only[index] += 1
                    progress.update(task_id, advance=1)
                    continue
                if isinstance(rule, SigmaCorrelationRule):
                    converted_rule = self.convert_correlation_rule(
                        sqlite_backend, rule
                    )
                else:
                    converted_rule = self.convert_sigma_rules(sqlite_backend, rule)
                if converted_rule is None:
                    failed[index] += 1
                else:
                    rulesets[index].append(converted_rule)
                progress.update(task_id, advance=1)

        combined_ruleset: list[dict[str, Any]] = []
        for index, path in enumerate(paths):
            ruleset = sorted(rulesets[index], key=lambda d: d.get('level', 'informational'))
            summary_parts = [f"[green]\\[✓][/] Converted [cyan]{len(ruleset)}[/] rules"]
            if len(paths) > 1:
                summary_parts.append(f" from {literal(path)}")
            detail_parts = []
            if invalid[index]:
                detail_parts.append(f"{invalid[index]} invalid skipped")
            if unloadable[index] or failed[index]:
                detail_parts.append(f"{unloadable[index] + failed[index]} failed")
            if detail_parts:
                summary_parts.append(f" [dim]({', '.join(detail_parts)})[/]")
            self.logger.info("".join(summary_parts))

            if self.saveRuleset:
                temp_ruleset_name = self.rand_ruleset_name(str(path))
                with open(temp_ruleset_name, "w", encoding="utf-8") as outfile:
                    outfile.write(
                        json.dumps(ruleset, option=json.OPT_INDENT_2).decode("utf-8")
                    )
                self.logger.info(f"[+] Saved ruleset as : {make_file_link(temp_ruleset_name)}")

            combined_ruleset.extend(ruleset)

        return combined_ruleset

    def ruleset_parsing(self) -> list[list[dict[str, Any]]]:
        """Parse and convert rulesets from files or directories."""
        ruleset_list = []
        yaml_paths: list[Path] = []
        for ruleset in self.rulesetPathList:
            ruleset_path = Path(ruleset)
            if not ruleset_path.exists():
                self.logger.warning(f"[yellow]    [!] Ruleset path does not exist: {literal(ruleset_path)}[/]")
                continue
            if ruleset_path.is_file():
                if self.is_json(ruleset_path):  # JSON Ruleset
                    try:
                        with open(ruleset_path, encoding='utf-8') as f:
                            parsed = json.loads(f.read())
                        # A Zircolite ruleset is an array of rule objects. Well-formed
                        # JSON of any other shape reached the rule loop and died on a
                        # bare AttributeError naming neither the file nor the problem.
                        if not isinstance(parsed, list) or not all(
                            isinstance(rule, dict) for rule in parsed
                        ):
                            self.logger.error(
                                f"[red]    [-] {literal(ruleset_path)} is not a Zircolite "
                                "ruleset: expected a JSON array of rule objects[/]"
                            )
                            continue
                        problem = ruleset_format_problem(parsed)
                        if problem is not None:
                            self.logger.error(f"[red]    [-] Cannot load {literal(ruleset_path)}: {literal(problem)}[/]")
                            continue
                        ruleset_list.append(parsed)
                        self.logger.info(f"    [>] Loaded JSON/Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                    except Exception as e:
                        self.logger.error(f"[red]    [-] Cannot load {literal(ruleset_path)} {literal(e)}[/]")
                elif self.is_yaml(ruleset_path):  # YAML Ruleset
                    self.logger.info(f"    [>] Converting Native Sigma to Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                    yaml_paths.append(ruleset_path)
                else:
                    self.logger.warning(
                        f"[yellow]    [!] Skipping unrecognized ruleset file "
                        f"(not a valid JSON ruleset or Sigma YAML file): {literal(ruleset_path)}[/]"
                    )
            elif ruleset_path.is_dir():  # Directory
                self.logger.info(f"    [>] Converting Native Sigma to Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                yaml_paths.append(ruleset_path)
        self.yaml_paths = yaml_paths
        if yaml_paths:
            # One collection for every path, so correlations resolve across them
            try:
                ruleset_list.append(self.sigma_rules_to_ruleset(yaml_paths, self.pipelines))
            except Exception as e:
                names = ", ".join(str(path) for path in yaml_paths)
                self.logger.error(f"[red]    [-] Cannot convert {literal(names)} {literal(e)}[/]")
        return ruleset_list
