"""Early event filtering by the Channel and EventID values a ruleset can match.

Kept apart from the rest of ruleset handling so that a worker unpickling an
EventFilter never imports pySigma or requests.
"""

import logging
from typing import Any

from .correlations import is_correlation_plan_rule
from .sqlscan import channel_constraints, eventid_constraints


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

        self._rules_with_filter = 0
        self._rules_without_filter = 0

        self._has_filter_data = False
        self._channel_filter = False
        self._eventid_filter = False
        self._eventid_bounded = False

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

        channels_set: set[str] = set()
        eventids_set: set[int] = set()
        # Lowercase channel -> mutable eventID set, or True for "any eventID"
        channel_bounds: dict[str, set[int] | bool] = {}

        for rule in rulesets:
            queries = rule.get('rule') or []
            channels = self._rule_channels(rule, queries)
            rule_ids = self._rule_eventids(rule, queries)
            eventids = rule_ids if rule_ids is not None else []

            if channels or eventids:
                rules_with_filter += 1

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

        self.channels = frozenset(channels_set)
        self.eventids = frozenset(eventids_set)

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
