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
import random
import re
import shutil
import string
from pathlib import Path
from typing import Optional, Set, FrozenSet, Tuple, List, Dict, Any

import orjson as json
import requests
import yaml
# Rich console for styled output
from .console import console
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqlite
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.plugins import InstalledSigmaPlugins
# Rich progress for downloads and conversion
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn

from .config import RulesetConfig


class EventFilter:
    """
    Filter events based on channel and eventID from loaded rules.
    
    This class extracts all unique channel and eventID values from a ruleset
    and provides fast lookup to determine if an event should be processed.
    
    Filtering logic:
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
        
        # Enable filtering if we have BOTH channels AND eventIDs
        self._has_filter_data = bool(self.channels and self.eventids)
        
        if not self._has_filter_data:
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
        self.tempFile = f'tmp-rules-{self._randString()}.zip'
        self.tmpDir = f'tmp-rules-{self._randString()}'
        self.updated_rulesets = []

    def _randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))

    def download(self):
        resp = requests.get(self.url, stream=True)
        total = int(resp.headers.get('content-length', 0))
        
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True
        )
        
        with progress:
            task_id = progress.add_task(f"Downloading {self.tempFile}", total=total)
            with open(self.tempFile, 'wb') as file:
                for data in resp.iter_content(chunk_size=1024):
                    size = file.write(data)
                    progress.update(task_id, advance=size)
    
    def unzip(self):
        shutil.unpack_archive(self.tempFile, self.tmpDir, "zip")
    
    def checkIfNewerAndMove(self):
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
                self.logger.info(f"[cyan]   [+] Updated : {dest_file}[/]")
                
        if count == 0: 
            self.logger.info("[cyan]   [+] No newer rulesets found")
    
    def clean(self):
        if Path(self.tempFile).exists():
            os.remove(self.tempFile)
        if Path(self.tmpDir).exists():
            shutil.rmtree(self.tmpDir)
    
    def run(self):
        try: 
            self.download()
            self.unzip()
            self.checkIfNewerAndMove()
        except Exception as e: 
            self.logger.error(f"   [-] {e}")
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
                        self.logger.error(f"[red]   [-] {pipelineName} not found. You can list installed pipelines with '--pipeline-list'[/]")

        # Parse & (if necessary) convert ruleset, final list is stored in self.rulesets
        self.rulesets = self.ruleset_parsing()

        # Combining rulesets 
        self.rulesets = [item for sub_ruleset in self.rulesets if sub_ruleset for item in sub_ruleset]
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
            self.logger.error("[red]   [-] No rules to execute ![/]")
        else:
            self.logger.info(f"[+] {len(self.rulesets)} rules loaded")
            
            # Create EventFilter from loaded rulesets for early event filtering
            self.event_filter = EventFilter(self.rulesets, logger=self.logger)
            if self.event_filter.is_enabled:
                stats = self.event_filter.get_stats()
                self.logger.info(
                    f"[+] Event filter enabled: [cyan]{stats['channels_count']}[/] channels, "
                    f"[cyan]{stats['eventids_count']}[/] eventIDs"
                )

    def is_yaml(self, filepath): 
        """Test if the file is a YAML file."""
        if (filepath.suffix == ".yml" or filepath.suffix == ".yaml"):
            with open(filepath, 'r', encoding="utf-8") as file:
                content = file.read()
                try:
                    yaml.safe_load(content)
                    return True
                except yaml.YAMLError:
                    return False

    def is_json(self, filepath): 
        """Test if the file is a JSON file."""
        if (filepath.suffix == ".json"):
            with open(filepath, 'r', encoding="utf-8") as file:
                content = file.read()
                try:
                    json.loads(content)
                    return True
                except json.JSONDecodeError:
                    return False

    def is_valid_sigma_rule(self, filepath):
        """Check if a YAML file is a valid Sigma rule (has required fields)."""
        try:
            with open(filepath, 'r', encoding="utf-8") as file:
                content = yaml.safe_load(file)
                if not isinstance(content, dict):
                    return False
                # A valid Sigma rule must have title, logsource and detection
                required_fields = ['title', 'logsource', 'detection']
                return all(field in content for field in required_fields)
        except Exception:
            return False

    def rand_ruleset_name(self, sigma_rules):
        """Generate a random ruleset filename."""
        # Clean the ruleset name
        cleaned_name = ''.join(char if char.isalnum() else '-' for char in sigma_rules).strip('-')
        cleaned_name = re.sub(r'-+', '-', cleaned_name)
        # Generate a random string 
        random_string = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
        return f"ruleset-{cleaned_name}-{random_string}.json"

    def convert_sigma_rules(self, backend, rule):
        """Convert a single Sigma rule using the provided backend."""
        try: 
            return backend.convert_rule(rule, "zircolite")[0]
        except Exception as e:
            self.logger.debug(f"[red]   [-] Cannot convert rule '{str(rule)}' : {e}[/]")

    def sigma_rules_to_ruleset(self, sigma_rules_list, pipelines):
        """Convert Sigma rules to Zircolite ruleset format."""
        for sigma_rules in sigma_rules_list:
            # Create the pipeline resolver
            pipeline_resolver = ProcessingPipelineResolver()
            # Add pipelines
            for pipeline in pipelines:
                pipeline_resolver.add_pipeline_class(pipeline)
            # Create a single sorted and prioritized pipeline
            combined_pipeline = pipeline_resolver.resolve(pipeline_resolver.pipelines)
            # Instantiate backend, using our resolved pipeline
            sqlite_backend = sqlite.sqliteBackend(combined_pipeline)

            rules = Path(sigma_rules)
            if rules.is_dir():
                rule_list = list(rules.rglob("*.yml")) + list(rules.rglob("*.yaml"))
            else:
                rule_list = [rules]
            
            # Filter out invalid Sigma rules
            valid_rule_list = [r for r in rule_list if self.is_valid_sigma_rule(r)]
            skipped_count = len(rule_list) - len(valid_rule_list)
            if skipped_count > 0:
                self.logger.debug(f"[yellow]   [!] Skipped {skipped_count} invalid Sigma rule(s)[/]")
            
            rule_collection = SigmaCollection.load_ruleset(valid_rule_list)
            ruleset = []

            # Process rules with Rich progress bar
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[cyan]{task.completed}/{task.total}[/]"),
                console=console,
                transient=True
            )
            
            with progress:
                task_id = progress.add_task("Converting rules", total=len(rule_collection))
                for rule in rule_collection:
                    converted_rule = self.convert_sigma_rules(sqlite_backend, rule)
                    if converted_rule is not None:
                        ruleset.append(converted_rule)
                    progress.update(task_id, advance=1)
            
            ruleset = sorted(ruleset, key=lambda d: d.get('level', 'informational'))  # Sorting by level

            if self.saveRuleset:
                temp_ruleset_name = self.rand_ruleset_name(str(sigma_rules))
                with open(temp_ruleset_name, 'w', encoding='utf-8') as outfile:
                    outfile.write(json.dumps(ruleset, option=json.OPT_INDENT_2).decode('utf-8'))
                    self.logger.info(f"[cyan]   [+] Saved ruleset as : {temp_ruleset_name}[/]")

        return ruleset
    
    def ruleset_parsing(self):
        """Parse and convert rulesets from files or directories."""
        ruleset_list = []
        for ruleset in self.rulesetPathList:
            ruleset_path = Path(ruleset)
            if ruleset_path.exists():
                if ruleset_path.is_file():
                    if self.is_json(ruleset_path):  # JSON Ruleset
                        try:
                            with open(ruleset_path, encoding='utf-8') as f:
                                ruleset_list.append(json.loads(f.read()))
                            self.logger.info(f"    [>] Loaded JSON/Zircolite ruleset : [cyan]{str(ruleset_path)}[/]")
                        except Exception as e:
                            self.logger.error(f"[red]    [-] Cannot load {str(ruleset_path)} {e}[/]")
                    elif self.is_yaml(ruleset_path):  # YAML Ruleset
                        try:
                            self.logger.info(f"[cyan]    [>] Converting Native Sigma to Zircolite ruleset : {str(ruleset_path)}[/]")
                            ruleset_list.append(self.sigma_rules_to_ruleset([ruleset_path], self.pipelines))
                        except Exception as e:
                            self.logger.error(f"[red]    [-] Cannot convert {str(ruleset_path)} {e}[/]")
                elif ruleset_path.is_dir():  # Directory
                    try:
                        self.logger.info(f"[cyan]    [>] Converting Native Sigma to Zircolite ruleset : {str(ruleset_path)}[/]")
                        ruleset_list.append(self.sigma_rules_to_ruleset([ruleset_path], self.pipelines))
                    except Exception as e:
                        self.logger.error(f"[red]    [-] Cannot convert {str(ruleset_path)} {e}[/]")
        return ruleset_list
