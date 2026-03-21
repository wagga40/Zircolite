#!python3
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
from typing import Any, Dict, List, Optional, Set, FrozenSet, Union

import orjson as json
import requests  # type: ignore[import-untyped]
import yaml
# Rich console for styled output
from .console import console, is_quiet, make_file_link
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.backends.sqlite import sqlite
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.plugins import InstalledSigmaPlugins
# Rich progress for downloads and conversion
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn

from .config import RulesetConfig
from .utils import random_suffix


class EventFilter:
    """
    Filter events based on channel and eventID from loaded rules.
    
    This class extracts all unique channel and eventID values from a ruleset
    and provides fast lookup to determine if an event should be processed.
    
    Filtering is enabled only when:
    - There is at least one channel and one eventID across the ruleset, and
    - No rule has empty channel and eventid (i.e. "any" log source).
    
    If any rule has no channel/eventid constraints, filtering is disabled so
    that events needed by such rules are not dropped, keeping alert counts
    consistent whether you run a single rule or a full ruleset.
    
    When enabled, filtering logic:
    - If event's Channel is NOT in the set of all channels from rules → discard
    - If event's EventID is NOT in the set of all eventIDs from rules → discard
    
    Both checks are independent - an event must have BOTH a known channel AND
    a known eventID to be processed.
    """

    __slots__ = (
        'channels', 'eventids', '_has_filter_data', 'logger',
        '_channels_lower', '_rules_with_filter', '_rules_without_filter'
    )

    def __init__(
        self, 
        rulesets: List[Dict[str, Any]], 
        *, 
        logger: Optional[logging.Logger] = None
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
        self.channels: FrozenSet[str] = frozenset()
        self.eventids: FrozenSet[int] = frozenset()
        
        # Stats
        self._rules_with_filter = 0
        self._rules_without_filter = 0
        
        # Flags
        self._has_filter_data = False
        
        # Pre-computed lowercase channels for case-insensitive matching
        self._channels_lower: FrozenSet[str] = frozenset()
        
        # Extract filter data from rulesets
        self._extract_filter_data(rulesets)

    def _extract_filter_data(self, rulesets: List[Dict[str, Any]]) -> None:
        """Extract all unique channels and eventIDs from all rules."""
        rules_with_filter = 0
        rules_without_filter = 0
        
        # Build as mutable sets first
        channels_set: Set[str] = set()
        eventids_set: Set[int] = set()
        
        for rule in rulesets:
            channels = rule.get('channel', [])
            eventids = rule.get('eventid', [])
            
            # Check if this rule has filter metadata
            if channels or eventids:
                rules_with_filter += 1
                
                # Add all channels from this rule
                for channel in channels:
                    if channel:
                        channels_set.add(channel)
                
                # Add all eventids from this rule
                for eventid in eventids:
                    if eventid is not None:
                        eventids_set.add(int(eventid))
            else:
                rules_without_filter += 1
        
        # Convert to immutable frozensets for faster lookups
        self.channels = frozenset(channels_set)
        self.eventids = frozenset(eventids_set)
        
        # Pre-compute lowercase channels for case-insensitive matching
        self._channels_lower = frozenset(c.lower() for c in self.channels)
        
        # Store stats
        self._rules_with_filter = rules_with_filter
        self._rules_without_filter = rules_without_filter
        
        # Enable filtering only if we have BOTH channels AND eventIDs AND no rule
        # has "any" log source. Rules with empty channel/eventid match any event;
        # if we filtered by other rules' log sources we would drop events needed
        # by those rules and get inconsistent counts (see issue #117).
        self._has_filter_data = bool(
            self.channels and self.eventids and (rules_without_filter == 0)
        )
        
        if not self._has_filter_data:
            if rules_without_filter > 0:
                self.logger.debug(
                    "EventFilter: At least one rule has no channel/eventid (any log source) - filtering disabled"
                )
            else:
                self.logger.debug("EventFilter: Missing channels or eventIDs - filtering disabled")

    @property
    def is_enabled(self) -> bool:
        """Check if filtering is enabled (has both channels and eventIDs)."""
        return self._has_filter_data

    @property
    def has_filter_data(self) -> bool:
        """Check if filter data was extracted from rules."""
        return self._has_filter_data

    def should_process_event(self, channel: Optional[str], eventid: Optional[int]) -> bool:
        """
        Check if an event should be processed based on its channel and eventID.
        
        Filtering logic:
        - If event's Channel is NOT in the set of all channels → discard
        - If event's EventID is NOT in the set of all eventIDs → discard
        
        Both checks are independent. An event must have a known channel AND 
        a known eventID to be processed.
        
        Args:
            channel: The event's channel name (e.g., 'Microsoft-Windows-Sysmon/Operational')
            eventid: The event's EventID (int, str convertible to int, or None)
            
        Returns:
            True if the event should be processed, False if it can be skipped
        """
        # Fast path: if no filter data or incomplete event info, process everything
        if not self._has_filter_data or channel is None or eventid is None:
            return True
        
        # Convert eventid to int if needed (internal callers pass int, but API accepts str)
        # isinstance check is cheap; only convert when necessary for external callers
        if not isinstance(eventid, int):
            try:
                eventid = int(eventid)
            except (ValueError, TypeError):
                return True
        
        # Local bindings for faster attribute access in tight loop
        channels = self.channels
        channels_lower = self._channels_lower
        
        # Check 1: Is the channel in our known channels? (case-insensitive fallback)
        if channel not in channels and channel.lower() not in channels_lower:
            return False
        
        # Check 2: Is the eventID in our known eventIDs?
        return eventid in self.eventids

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the filter data."""
        return {
            'channels_count': len(self.channels),
            'eventids_count': len(self.eventids),
            'is_enabled': self.is_enabled,
            'rules_with_filter': self._rules_with_filter,
            'rules_without_filter': self._rules_without_filter
        }


class RulesUpdater:
    """Download rulesets from the https://github.com/wagga40/Zircolite-Rules-v2 repository and update if necessary."""

    def __init__(self, *, logger: Optional[logging.Logger] = None):
        """
        Initialize RulesUpdater.
        
        Args:
            logger: Logger instance (creates default if None)
        """
        self.url = "https://github.com/wagga40/Zircolite-Rules-v2/archive/refs/heads/main.zip"
        self.logger = logger or logging.getLogger(__name__)
        self.tempFile = f'tmp-rules-{random_suffix(4)}.zip'
        self.tmpDir = f'tmp-rules-{random_suffix(4)}'
        self.updated_rulesets: List[str] = []

    def download(self) -> None:
        resp = requests.get(self.url, stream=True, timeout=30)
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
        rules_dir = Path('rules/')
        
        if not rules_dir.exists():
            rules_dir.mkdir()
            
        for ruleset in Path(self.tmpDir).rglob("*.json"):
            with open(ruleset, 'rb') as f:
                hash_new = hashlib.md5(f.read()).hexdigest()
            
            dest_file = rules_dir / ruleset.name
            hash_old = ""
            
            if dest_file.is_file():
                with open(dest_file, 'rb') as f:
                    hash_old = hashlib.md5(f.read()).hexdigest()
            
            if hash_new != hash_old:
                count += 1
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
        ruleset_config: Optional[RulesetConfig] = None,
        *,
        logger: Optional[logging.Logger] = None,
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
        self.event_filter: Optional[EventFilter] = None  # Will be populated after loading

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
        raw_rulesets = self.ruleset_parsing()
        # Flatten list of rulesets into a single list of rules
        self.rulesets = [
            item for sub_ruleset in raw_rulesets if sub_ruleset for item in sub_ruleset
        ]
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

        level_order = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "informational": 5
        }
        self.rulesets = sorted(unique_rules, key=lambda d: level_order.get(d.get('level', 'informational'), float('inf'))) # Sorting by level
            
        if all(not sub_ruleset for sub_ruleset in self.rulesets):
            self.logger.error("[red]    [-] No rules to execute ![/]")
        else:
            self.logger.info(f"[+] {len(self.rulesets)} rules loaded")
            
            # Correlation rules carry no Channel/EventID for filtering; excluding them
            # avoids disabling EventFilter for the whole ruleset (see EventFilter docstring).
            non_correlation_rules = [r for r in self.rulesets if not r.get("correlation")]
            self.event_filter = EventFilter(non_correlation_rules, logger=self.logger)
            if self.event_filter.is_enabled:
                stats = self.event_filter.get_stats()
                self.logger.info(
                    f"[+] Event filter enabled: [cyan]{stats['channels_count']}[/] channels, "
                    f"[cyan]{stats['eventids_count']}[/] eventIDs"
                )

    def is_yaml(self, filepath: Path) -> Optional[bool]:
        """Test if the file is a YAML file (including multi-document streams)."""
        if filepath.suffix in (".yml", ".yaml"):
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()
                try:
                    for _ in yaml.safe_load_all(content):
                        pass
                    return True
                except yaml.YAMLError:
                    return False
        return None

    def is_json(self, filepath: Path) -> Optional[bool]:
        """Test if the file is a JSON file."""
        if filepath.suffix == ".json":
            with open(filepath, "r", encoding="utf-8") as file:
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
            with open(filepath, 'r', encoding="utf-8") as file:
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

    def convert_sigma_rules(self, backend: Any, rule: Any) -> Optional[Dict[str, Any]]:
        """Convert a single Sigma rule using the provided backend."""
        try:
            converted = backend.convert_rule(rule, "zircolite")
            if not converted:
                return None
            return converted[0]
        except Exception as e:
            self.logger.debug(f"[red]    [-] Cannot convert rule '{str(rule)}' : {e}[/]")
            return None

    def convert_correlation_rule(
        self, backend: Any, rule: SigmaCorrelationRule
    ) -> Optional[Dict[str, Any]]:
        """Convert a Sigma correlation rule using the provided backend."""
        try:
            converted = backend.convert_correlation_rule(rule, "zircolite")
            if not converted:
                return None
            result = converted[0]
            result["correlation"] = True
            return result
        except Exception as e:
            title = getattr(rule, "title", str(rule))
            self.logger.debug(f"[red]    [-] Cannot convert correlation rule '{title}' : {e}[/]")
            return None

    def sigma_rules_to_ruleset(
        self, sigma_rules_list: List[Union[Path, str]], pipelines: List[Any]
    ) -> List[Dict[str, Any]]:
        """Convert Sigma rules to Zircolite ruleset format."""
        combined_ruleset: List[Dict[str, Any]] = []

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
                for pipeline, orig in zip(pipelines, original_priorities):
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
            ruleset: List[Dict[str, Any]] = []

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
                                f"[red]    [-] Cannot convert rule '{str(rule)}' : {e}[/]"
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

    def ruleset_parsing(self) -> List[List[Dict[str, Any]]]:
        """Parse and convert rulesets from files or directories."""
        ruleset_list = []
        for ruleset in self.rulesetPathList:
            ruleset_path = Path(ruleset)
            if not ruleset_path.exists():
                self.logger.warning(f"[yellow]    [!] Ruleset path does not exist: {str(ruleset_path)}[/]")
                continue
            if ruleset_path.is_file():
                if self.is_json(ruleset_path):  # JSON Ruleset
                    try:
                        with open(ruleset_path, encoding='utf-8') as f:
                            ruleset_list.append(json.loads(f.read()))
                        self.logger.info(f"    [>] Loaded JSON/Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                    except Exception as e:
                        self.logger.error(f"[red]    [-] Cannot load {str(ruleset_path)} {e}[/]")
                elif self.is_yaml(ruleset_path):  # YAML Ruleset
                    try:
                        self.logger.info(f"    [>] Converting Native Sigma to Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                        ruleset_list.append(self.sigma_rules_to_ruleset([ruleset_path], self.pipelines))
                    except Exception as e:
                        self.logger.error(f"[red]    [-] Cannot convert {str(ruleset_path)} {e}[/]")
            elif ruleset_path.is_dir():  # Directory
                try:
                    self.logger.info(f"    [>] Converting Native Sigma to Zircolite ruleset : {make_file_link(str(ruleset_path))}")
                    ruleset_list.append(self.sigma_rules_to_ruleset([ruleset_path], self.pipelines))
                except Exception as e:
                    self.logger.error(f"[red]    [-] Cannot convert {str(ruleset_path)} {e}[/]")
        return ruleset_list
