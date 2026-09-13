"""Flattening kernel, also compiled as ``zircolite._flatten_native``.

The Python module is the reference implementation. Both builds use the same
scalar rules and keep transforms in the existing RestrictedPython sandbox.
"""

import contextlib
import operator
from typing import Any

import orjson as json
import xxhash

from .utils import _EXCLUDED_SENTINEL, _normalize_scalar, parse_timestamp


def flatten_event(
    self, event_dict: dict, filename: str, raw_bytes: bytes | None = None
) -> dict | None:
    """
    Flatten a single event dictionary and track discovered fields.
    Returns flattened dict or None if filtered out.
    """
    # Add metadata
    event_dict["OriginalLogfile"] = filename
    if self.hashes:
        # CSV, EVTXtract and JSON-array rows never reach here with a source
        # line: the readers hand over a parsed record. Hashing a canonical
        # form of that record keeps --hashes meaningful for every format
        # rather than silently producing no column at all for three of them.
        if raw_bytes is None:
            with contextlib.suppress(TypeError, json.JSONEncodeError):
                raw_bytes = json.dumps(event_dict, option=json.OPT_SORT_KEYS)
        if raw_bytes:
            event_dict["OriginalLogLinexxHash"] = xxhash.xxh64_hexdigest(raw_bytes)

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
    special_fields = self._special_fields
    seen_leaf_keys = self._seen_leaf_keys
    _sentinel = _EXCLUDED_SENTINEL

    # Result dict
    json_line: dict[str, Any] = {}

    def process_leaf(raw_field_name: str, last_part: str, obj: Any) -> None:
        cached = resolve_path(raw_field_name, last_part)
        if cached is _sentinel:
            return
        raw_field_name, mapped_key = cached  # type: ignore[misc]
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
            # Past SQLite's INTEGER range the value has to go in as text
            is_int = isinstance(value, int)
            if isinstance(value, int) and not -(1 << 63) <= value < (1 << 63):
                value = str(value)
                is_int = False
            json_line[key] = value
            if key not in seen_leaf_keys:
                key_lower = key.lower()
                if key_lower not in discovered_fields:
                    discovered_fields[key_lower] = key
                    field_types[key] = (
                        "INTEGER COLLATE NOCASE" if is_int else "TEXT COLLATE NOCASE"
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
        if transforms_enabled:
            for field_name in (key, raw_field_name):
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
                    json_line[k] = v
                    if k not in seen_leaf_keys:
                        key_lower = k.lower()
                        if key_lower not in discovered_fields:
                            discovered_fields[key_lower] = k
                            field_types[k] = "TEXT COLLATE NOCASE"
                        seen_leaf_keys.add(k)
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
        # Past SQLite's INTEGER range the value has to go in as text
        is_int = isinstance(value, int)
        if isinstance(value, int) and not -(1 << 63) <= value < (1 << 63):
            value = str(value)
            is_int = False
        for k in keys:
            if transformed_keys is not None and k in transformed_keys:
                final_value = _normalize_scalar(transformed_values[k])
            else:
                final_value = _normalize_scalar(value)
            json_line[k] = final_value
            if k not in seen_leaf_keys:
                key_lower = k.lower()
                if key_lower not in discovered_fields:
                    discovered_fields[key_lower] = k
                    field_types[k] = "INTEGER COLLATE NOCASE" if isinstance(final_value, int) else "TEXT COLLATE NOCASE"
                seen_leaf_keys.add(k)

    # Descend through the event tree, carrying the dotted path as a string
    # (cheaper than re-allocating a path tuple at every node). Leaves are
    # processed without an extra stack push/pop.
    # Only dicts are ever pushed, so every popped node is one.
    stack: list[tuple[dict[str, Any], str]] = [(event_dict, "")]
    while stack:
        obj, raw_path = stack.pop()
        if raw_path:
            for k, v in obj.items():
                new_path = f"{raw_path}.{k}"
                if isinstance(v, dict):
                    stack.append((v, new_path))
                else:
                    process_leaf(new_path, k, v)
        else:
            for k, v in obj.items():
                if isinstance(v, dict):
                    stack.append((v, k))
                else:
                    process_leaf(k, k, v)

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
            if ts_value:
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


def build_rows(batch, all_columns, all_columns_frozen, uniform):
    # Build rows – large-int normalisation already done in _flatten_event.
    # When every event shares the first event's columns (the common case for
    # a stable source), a single itemgetter beats a per-column .get genexpr.
    # Heterogeneous batches keep .get so missing columns map to NULL.
    if len(all_columns) != len(all_columns_frozen):
        # Case-collision batch: merge values across case variants per event
        # (first non-None wins) and bind against the canonical column.
        canonical_lower = tuple(col.lower() for col in all_columns)
        rows = []
        for event in batch:
            merged: dict[str, Any] = {}
            for k, v in event.items():
                kl = k.lower()
                if kl not in merged or merged[kl] is None:
                    merged[kl] = v
            rows.append(tuple(merged.get(cl) for cl in canonical_lower))
    elif uniform and len(all_columns) > 1:
        row_getter = operator.itemgetter(*all_columns)
        rows = [row_getter(event) for event in batch]
    else:
        rows = [tuple(event.get(col) for col in all_columns) for event in batch]

    return rows
