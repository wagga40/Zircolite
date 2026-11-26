"""Flattening kernel, also compiled as ``zircolite._flatten_native``.

The Python module is the reference implementation. Both builds use the same
scalar rules and keep transforms in the existing RestrictedPython sandbox.
"""

from typing import Any

from .utils import (
    _EXCLUDED_SENTINEL,
    _NON_ALNUM_RE,
    _normalize_scalar,
    is_oversized_integer,
    parse_timestamp,
)

# Path trie entries kept before starting over, as the lru_cache it replaced did.
_MAX_PATH_TRIE_ENTRIES = 10000


def flatten_event(self, event_dict: dict, filename: str) -> dict | None:
    """
    Flatten a single event dictionary and track discovered fields.
    Returns flattened dict or None if filtered out.
    """
    # Add metadata
    event_dict["OriginalLogfile"] = filename

    # Cache references for hot loop (local vars are faster than attribute access)
    useless_values = self.useless_values
    aliases_get = self.aliases.get
    field_split_list = self.field_split_list
    field_split_list_get = field_split_list.get
    transforms_get = self._transforms_baked.get
    transforms_enabled = self.transforms_enabled
    enabled_transforms_set = self.enabled_transforms_set
    chosen_input = self.chosen_input
    ignore_source_condition = self._ignore_source_condition
    discovered_fields = self.discovered_fields
    field_types = self.field_types
    transform_value = self._transform_value
    resolve_path = self._resolve_path
    if self._path_trie_entries > _MAX_PATH_TRIE_ENTRIES:
        self._path_trie.clear()
        self._path_trie_entries = 0
    trie = self._path_trie
    special_fields = self._special_fields
    seen_leaf_keys = self._seen_leaf_keys
    _sentinel = _EXCLUDED_SENTINEL

    # Result dict
    json_line: dict[str, Any] = {}
    # Pairs split out of a field value, merged once every real field is known
    split_fields: dict[str, str] = {}

    def process_leaf(cached: Any, last_part: str, obj: Any) -> None:
        if cached is _sentinel:
            return
        raw_field_name, mapped_key = cached
        value: Any
        if isinstance(obj, list):
            value = str(obj)
        elif obj is True or obj is False:
            # SQLite has no boolean type and Sigma rules compare against the
            # lowercase JSON spelling, so storing 1/0 makes them unmatchable.
            value = "true" if obj else "false"
        else:
            value = obj
        if value in useless_values:
            return
        key = mapped_key

        # Ultra-fast path: the vast majority of leaves have no alias, split
        # rule, or active transform. They only need a value assignment plus a
        # one-time column-type record, so they skip the lookups below.
        if key not in special_fields and raw_field_name not in special_fields:
            is_int = isinstance(value, int)
            if is_int and not -(1 << 63) <= value < (1 << 63):
                # Past SQLite's INTEGER range; stored as REAL, like orjson reads it
                self.rounded_integer_fields.add(key)
                value = float(value)
                is_int = False
            json_line[key] = value
            if key not in seen_leaf_keys:
                key_lower = key.lower()
                if key_lower not in discovered_fields:
                    discovered_fields[key_lower] = key
                    # NUMERIC keeps floats numeric without forcing later
                    # 64-bit integers through REAL's lossy float conversion.
                    field_types[key] = (
                        "INTEGER COLLATE NOCASE" if is_int else
                        "NUMERIC COLLATE NOCASE" if isinstance(value, float) else
                        "TEXT COLLATE NOCASE"
                    )
                seen_leaf_keys.add(key)
            return

        alias_key = aliases_get(key)
        alias_raw = aliases_get(raw_field_name)
        split_config = field_split_list_get(
            raw_field_name
        ) or field_split_list_get(key)
        keys = [key]
        if alias_key is not None:
            keys.append(alias_key)
        if alias_raw is not None:
            keys.append(alias_raw)
        transformed_keys: set | None = None
        transformed_values: dict[str, Any] = {}
        # An empty value has nothing to transform, and some transforms would
        # turn it into a score or a label that no event carried.
        if transforms_enabled and value != "":
            transform_fields = (key,) if key == raw_field_name else (key, raw_field_name)
            for field_name in transform_fields:
                field_transforms = transforms_get(field_name)
                if field_transforms:
                    for transform in field_transforms:
                        alias_name = transform.alias_name
                        if enabled_transforms_set is not None:
                            # Non-alias transforms have an empty alias_name;
                            # enabled_transforms and categories name them by field
                            if (alias_name or field_name) not in enabled_transforms_set:
                                continue
                        else:
                            if not transform.enabled:
                                continue
                        if (
                            not ignore_source_condition
                            and chosen_input not in transform.source_condition
                        ):
                            continue
                        transform_code = transform.code
                        if transform.alias:
                            keys.append(alias_name)
                            if transformed_keys is None:
                                transformed_keys = set()
                            transformed_keys.add(alias_name)
                            transformed_values[alias_name] = transform_value(
                                transform_code, value
                            )
                        else:
                            value = transform_value(transform_code, value)
        if split_config:
            try:
                separator = split_config["separator"]
                equal_sign = split_config["equal"]
                # One malformed pair must not cost the remaining ones: split
                # on the first separator only and skip pairs that have none.
                for split_field in value.split(separator):
                    k, found, v = split_field.partition(equal_sign)
                    if not found:
                        continue
                    # The pair names a column from log content, so it gets
                    # the same treatment as any other field name.
                    k = _NON_ALNUM_RE.sub("", k)
                    if k:
                        split_fields[k] = v
            except (KeyError, AttributeError) as exc:
                # A missing separator/equal key or a non-string value drops
                # every derived column, and every hash-based IOC rule then
                # matches nothing. Say so once per field rather than never.
                if last_part not in self._failed_splits:
                    self._failed_splits.add(last_part)
                    self.logger.warning(
                        f"[yellow]   [!] Cannot split field "
                        f"[cyan]{last_part}[/]: {exc}; no derived field "
                        f"will be created for it[/]"
                    )
        for k in keys:
            if transformed_keys is not None and k in transformed_keys:
                final_value = transformed_values[k]
            else:
                final_value = value
            if is_oversized_integer(final_value):
                self.rounded_integer_fields.add(k)
            final_value = _normalize_scalar(final_value)
            json_line[k] = final_value
            if k not in seen_leaf_keys:
                key_lower = k.lower()
                if key_lower not in discovered_fields:
                    discovered_fields[key_lower] = k
                    field_types[k] = (
                        "INTEGER COLLATE NOCASE" if isinstance(final_value, int) else
                        "NUMERIC COLLATE NOCASE" if isinstance(final_value, float) else
                        "TEXT COLLATE NOCASE"
                    )
                seen_leaf_keys.add(k)

    # Descend through the event tree beside the path trie. A trie node maps
    # each key to [dotted path, resolved leaf, nested node], filled the first
    # time the key is met there, so a field seen before costs dict lookups
    # rather than a new path string and a cache lookup keyed by it.
    # Only dicts are ever pushed, so every popped node is one.
    stack: list[tuple[dict[str, Any], dict, str]] = [(event_dict, trie, "")]
    while stack:
        obj, node, raw_path = stack.pop()
        for k, v in obj.items():
            entry = node.get(k)
            if entry is None:
                entry = [f"{raw_path}.{k}" if raw_path else k, None, None]
                node[k] = entry
                self._path_trie_entries += 1
            if isinstance(v, dict):
                child = entry[2]
                if child is None:
                    child = entry[2] = {}
                stack.append((v, child, entry[0]))
            else:
                cached = entry[1]
                if cached is None:
                    cached = entry[1] = resolve_path(entry[0], k)
                process_leaf(cached, k, v)

    if split_fields:
        # A pair inside a field value must not stand in for a field the event
        # really carries: a Hashes of "MD5=x,Image=benign.exe" would otherwise
        # replace Image. SQLite column names ignore case, so neither may a
        # different spelling of one.
        taken = {key.lower() for key in json_line}
        for k, v in split_fields.items():
            if k.lower() in taken:
                continue
            json_line[k] = v
            if k not in seen_leaf_keys:
                key_lower = k.lower()
                if key_lower not in discovered_fields:
                    discovered_fields[key_lower] = k
                    field_types[k] = "TEXT COLLATE NOCASE"
                seen_leaf_keys.add(k)

    # Time filtering (with pre-parsed bounds)
    if self._has_time_filter:
        # Use configured time_field or auto-detect
        effective_time_field = self.time_field

        # Auto-detect timestamp field if not found or not set
        if not effective_time_field or effective_time_field not in json_line:
            if effective_time_field and not self._timefield_warned:
                self._timefield_warned = True
                self.logger.warning(
                    f"[yellow]Configured time field '{effective_time_field}' not found in event; "
                    f"falling back to auto-detection. Time filters (--after/--before) "
                    f"may not apply as expected.[/]"
                )
            if self._detected_time_field and self._detected_time_field in json_line:
                effective_time_field = self._detected_time_field
            elif self._timestamp_auto_detect:
                detected = self._detect_timestamp_field(json_line)
                if detected is not None:
                    self._detected_time_field = detected
                    effective_time_field = detected
                    self.logger.debug(f"Auto-detected timestamp field: {detected}")

        if effective_time_field:
            ts_value = json_line.get(effective_time_field)
            if ts_value is not None:
                # Bounds are inclusive. An unparsable timestamp keeps the
                # event: dropping it would hide data behind a format quirk.
                moment = parse_timestamp(ts_value)
                if (
                    moment is not None
                    and self._time_after is not None
                    and self._time_before is not None
                    and not (self._time_after <= moment <= self._time_before)
                ):
                    self._events_time_filtered_count += 1
                    return None

    return json_line


def source_values(event: Any) -> str:
    """Keyword search text: every decoded scalar, keys in order, one per line.

    The backend's ``source-values-v1`` representation, built before mapping or
    flattening. Iterative, and indifferent to key names: what an event contains
    must never be a reason to drop it.
    """
    values: list[str] = []
    stack: list[Any] = [event]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node[key] for key in sorted(node, reverse=True))
        elif isinstance(node, (list, tuple)):
            stack.extend(reversed(node))
        elif isinstance(node, str):
            values.append(node)
        elif isinstance(node, bool):
            values.append("true" if node else "false")
        elif node is not None and isinstance(node, (int, float)):
            values.append(str(node))
    return "\n".join(values)


def event_filter_values(event_dict: Any, channel_plan: dict, channel_hint: Any,
                        eventid_plan: dict, eventid_hint: Any) -> tuple:
    """Channel and EventID of a raw event for the event filter, failing open.

    Returns ``(channel, channel_hint, eventid, eventid_hint)``: a non-empty
    string or None, an int or None, and for each the path that produced it
    (the hint passed in when none did). See ``_filter_value``.
    """
    if not isinstance(event_dict, dict):
        # A JSON line can hold any value; it is not this filter's to drop
        return None, channel_hint, None, eventid_hint
    channel, channel_hint = _filter_value(event_dict, channel_plan, channel_hint, False)
    eventid, eventid_hint = _filter_value(event_dict, eventid_plan, eventid_hint, True)
    return channel, channel_hint, eventid, eventid_hint


def _filter_value(event_dict: dict, field_plan: dict, hint: Any, eventid: bool) -> tuple:
    """A value read from every configured path, failing open.

    ``field_plan`` holds the configured paths grouped by top-level key. The
    filter runs before flattening, so it cannot read the column the rules
    query: when an event carries several of these paths, which one ends up in
    that column is decided by the flattener's traversal order and the field
    mappings, not by the configured order. So every path is read, and if two
    present paths disagree, or one holds an unusable value, the result is
    None and the filter keeps the event rather than discard it on a value no
    rule would have seen. An empty value does not count as found, and a
    previous winner (the hint) never changes the result on mixed-schema
    inputs; it is only kept for callers.

    XML-derived events carry values as {"#text": ...}. A channel must be a
    non-empty string and an EventID must convert to an int, the types the
    filter's set membership test needs.
    """
    found = None
    winner = hint
    # Most paths are absent at their top-level key: walk whichever is shorter,
    # the event's top-level keys (one for EVTX) or the configured ones.
    keys = event_dict if len(event_dict) < len(field_plan) else field_plan
    for key in keys:
        entries = field_plan.get(key)
        if entries is None:
            continue
        node = event_dict.get(key)
        if node is None:
            continue
        for rest, path in entries:
            raw = node
            for part in rest:
                if not isinstance(raw, dict):
                    raw = None
                    break
                raw = raw.get(part)
                if raw is None:
                    break
            if raw is None or raw == "":
                continue
            if isinstance(raw, dict):
                raw = raw.get("#text")
            value: Any
            if eventid:
                try:
                    value = int(raw) if raw is not None else None
                except (ValueError, TypeError):
                    value = None
            else:
                value = raw if isinstance(raw, str) and raw else None
            if value is None or (found is not None and value != found):
                return None, winner
            if found is None:
                found = value
                winner = path
    return found, winner
