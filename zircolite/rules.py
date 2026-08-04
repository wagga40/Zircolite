"""
Ruleset handling and updating for Zircolite.

This module contains:
- EventFilter: Filter events based on channel and eventID from rules
- RulesetHandler: Parse and convert Sigma rules to Zircolite format
- RulesUpdater: Download and update rulesets from repository
"""

import hashlib
import logging
import os
import re
import shutil
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
from sigma.correlations import SigmaCorrelationRule
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.rule import SigmaRule

from .assets import bundled_dir
from .config import RulesetConfig

# Rich console for styled output
from .console import console, is_quiet, make_file_link
from .sqlscan import channel_constraints, eventid_constraints
from .utils import random_suffix


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


class RulesUpdater:
    """Download rulesets from the https://github.com/wagga40/Zircolite-Rules-v2 repository and update if necessary."""

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
        self.url = "https://github.com/wagga40/Zircolite-Rules-v2/archive/refs/heads/main.zip"
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

    def checkIfNewerAndMove(self) -> None:
        count = 0
        rules_dir = Path(self.rules_dir)
        rules_dir.mkdir(parents=True, exist_ok=True)

        for ruleset in Path(self.tmpDir).rglob("*.json"):
            with open(ruleset, 'rb') as f:
                hash_new = hashlib.md5(f.read(), usedforsecurity=False).hexdigest()

            # Preserve the archive's relative directory structure so same-named
            # rulesets in different subdirectories do not overwrite each other
            rel_path = ruleset.relative_to(Path(self.tmpDir))
            # Drop the archive's top-level folder (e.g. Zircolite-Rules-v2-main/)
            parts = rel_path.parts[1:] if len(rel_path.parts) > 1 else rel_path.parts
            dest_file = rules_dir.joinpath(*parts)
            hash_old = ""

            if dest_file.is_file():
                with open(dest_file, 'rb') as f:
                    hash_old = hashlib.md5(f.read(), usedforsecurity=False).hexdigest()

            if hash_new != hash_old:
                count += 1
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(ruleset, dest_file)
                self.updated_rulesets.append(str(dest_file))
                self.logger.info(f"    [>] Updated : {make_file_link(str(dest_file))}")

        if count == 0:
            self.logger.info("[cyan]    [>] No newer rulesets found")

    def clean(self) -> None:
        if Path(self.tempFile).exists():
            os.remove(self.tempFile)
        if Path(self.tmpDir).exists():
            shutil.rmtree(self.tmpDir)

    def run(self) -> None:
        try:
            self.download()
            self.unzip()
            self.checkIfNewerAndMove()
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"    [-] Network connection failed: {e}")
        except requests.exceptions.Timeout:
            self.logger.error(f"    [-] Download timed out after 30s: {self.url}")
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"    [-] Server returned an error: {e}")
        except Exception as e:
            self.logger.error(f"    [-] {e}")
        finally:
            self.clean()


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
        self.pipelines = []
        self.event_filter: EventFilter | None = None  # Will be populated after loading

        # Init pipelines
        plugins = InstalledSigmaPlugins.autodiscover()
        pipeline_resolver = plugins.get_pipeline_resolver()
        pipeline_list = list(pipeline_resolver.pipelines.keys())

        if list_pipelines_only:
            self.logger.info("[+] Installed pipelines : "
                            + ", ".join(pipeline_list)
                            + "\n    You can install pipelines with your Python package manager"
                            + "\n    e.g : pip install pysigma-pipeline-sysmon"
                            )
        else:
            # Resolving pipelines
            if cfg.pipeline:
                for pipelineName in [item for pipeline in cfg.pipeline for item in pipeline]: # Flatten the list of pipeline names list
                    if pipelineName in pipeline_list:
                        self.pipelines.append(plugins.pipelines[pipelineName]())
                    else:
                        self.logger.error(f"[red]    [-] {pipelineName} not found. You can list installed pipelines with '--pipeline-list'[/]")

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

            self.event_filter = EventFilter(self.rulesets, logger=self.logger)
            if self.event_filter.is_enabled:
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

    def is_yaml(self, filepath: Path) -> bool | None:
        """Test if the file is a YAML file (including multi-document streams)."""
        if filepath.suffix in (".yml", ".yaml"):
            with open(filepath, encoding="utf-8") as file:
                content = file.read()
                try:
                    for _ in yaml.safe_load_all(content):
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
        """Check if a YAML file contains at least one valid Sigma or correlation rule."""
        try:
            with open(filepath, encoding="utf-8") as file:
                for doc in yaml.safe_load_all(file):
                    if not isinstance(doc, dict):
                        continue
                    has_standard = all(
                        f in doc for f in ("title", "logsource", "detection")
                    )
                    has_correlation = "title" in doc and "correlation" in doc
                    if has_standard or has_correlation:
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

    def sigma_rules_to_ruleset(
        self, sigma_rules_list: list[Path | str], pipelines: list[Any]
    ) -> list[dict[str, Any]]:
        """Convert Sigma rules to Zircolite ruleset format."""
        combined_ruleset: list[dict[str, Any]] = []

        for sigma_rules in sigma_rules_list:
            # Create the pipeline resolver
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
            # Instantiate backend, using our resolved pipeline
            sqlite_backend = sqlite.sqliteBackend(combined_pipeline)
            sqlite_backend.timestamp_field = self.time_field
            sqlite_backend.init_processing_pipeline("zircolite")

            rules = Path(sigma_rules)
            if rules.is_dir():
                rule_list = list(rules.rglob("*.yml")) + list(rules.rglob("*.yaml"))
            else:
                rule_list = [rules]

            # Filter out invalid Sigma rules
            valid_rule_list = [r for r in rule_list if self.is_valid_sigma_rule(r)]
            skipped_count = len(rule_list) - len(valid_rule_list)
            if skipped_count > 0:
                self.logger.debug(f"[yellow]    [!] Skipped {skipped_count} invalid Sigma rule(s)[/]")

            if not valid_rule_list:
                continue

            rule_collection = SigmaCollection.load_ruleset(
                [str(p) for p in valid_rule_list]
            )
            ruleset: list[dict[str, Any]] = []

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
                skipped_referenced_only = 0
                for rule in rule_collection:
                    # Rules only referenced by correlation have _output False; pySigma does not
                    # return standalone queries for them, but convert_rule must still run so
                    # correlation conversion can embed the referenced detection SQL.
                    if isinstance(rule, SigmaRule) and not rule._output:
                        try:
                            sqlite_backend.convert_rule(rule, "zircolite")
                        except Exception as e:
                            self.logger.debug(
                                f"[red]    [-] Cannot convert rule '{rule!s}' : {e}[/]"
                            )
                        skipped_referenced_only += 1
                        progress.update(task_id, advance=1)
                        continue
                    if isinstance(rule, SigmaCorrelationRule):
                        converted_rule = self.convert_correlation_rule(
                            sqlite_backend, rule
                        )
                    else:
                        converted_rule = self.convert_sigma_rules(sqlite_backend, rule)
                    if converted_rule is not None:
                        ruleset.append(converted_rule)
                    progress.update(task_id, advance=1)

            # Print conversion summary
            conversion_errors = (
                len(rule_collection) - skipped_referenced_only - len(ruleset)
            )
            summary_parts = [f"[green]\\[✓][/] Converted [cyan]{len(ruleset)}[/] rules"]
            if skipped_count > 0 or conversion_errors > 0:
                detail_parts = []
                if skipped_count > 0:
                    detail_parts.append(f"{skipped_count} invalid skipped")
                if conversion_errors > 0:
                    detail_parts.append(f"{conversion_errors} failed")
                summary_parts.append(f" [dim]({', '.join(detail_parts)})[/]")
            self.logger.info("".join(summary_parts))

            ruleset = sorted(ruleset, key=lambda d: d.get('level', 'informational'))

            if self.saveRuleset:
                temp_ruleset_name = self.rand_ruleset_name(str(sigma_rules))
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
        for ruleset in self.rulesetPathList:
            ruleset_path = Path(ruleset)
            if not ruleset_path.exists():
                self.logger.warning(f"[yellow]    [!] Ruleset path does not exist: {ruleset_path!s}[/]")
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
                                f"[red]    [-] {ruleset_path!s} is not a Zircolite "
                                "ruleset: expected a JSON array of rule objects[/]"
                            )
                            continue
                        ruleset_list.append(parsed)
                        self.logger.info(f"    [>] Loaded JSON/Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                    except Exception as e:
                        self.logger.error(f"[red]    [-] Cannot load {ruleset_path!s} {e}[/]")
                elif self.is_yaml(ruleset_path):  # YAML Ruleset
                    try:
                        self.logger.info(f"    [>] Converting Native Sigma to Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                        ruleset_list.append(self.sigma_rules_to_ruleset([ruleset_path], self.pipelines))
                    except Exception as e:
                        self.logger.error(f"[red]    [-] Cannot convert {ruleset_path!s} {e}[/]")
                else:
                    self.logger.warning(
                        f"[yellow]    [!] Skipping unrecognized ruleset file "
                        f"(not a valid JSON ruleset or Sigma YAML file): {ruleset_path!s}[/]"
                    )
            elif ruleset_path.is_dir():  # Directory
                try:
                    self.logger.info(f"    [>] Converting Native Sigma to Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                    ruleset_list.append(self.sigma_rules_to_ruleset([ruleset_path], self.pipelines))
                except Exception as e:
                    self.logger.error(f"[red]    [-] Cannot convert {ruleset_path!s} {e}[/]")
        return ruleset_list
