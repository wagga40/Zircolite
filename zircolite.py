#!python3

# Standard libs
import argparse
import base64
import chardet
import csv
import functools
import hashlib
import logging
import logging.config
import multiprocessing as mp
import os
import random
import re
import shutil
import signal
import sqlite3
import string
import subprocess
import sys
import time
from pathlib import Path
from sqlite3 import Error
from sys import platform as _platform

# External libs (Mandatory)
import orjson
import psutil
import xxhash
from colorama import Fore
from tqdm import tqdm
from RestrictedPython import compile_restricted
from RestrictedPython import safe_builtins
from RestrictedPython import limited_builtins
from RestrictedPython import utility_builtins
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_iter_unpack_sequence

# External libs (Optional)
update_disabled = False
try:
    import requests
except ImportError:
    update_disabled = True

sigma_conversion_disabled = False
try:
    from sigma.collection import SigmaCollection
    from sigma.backends.sqlite import sqlite
    from sigma.processing.resolver import ProcessingPipelineResolver
    from sigma.plugins import InstalledSigmaPlugins
    import yaml
except ImportError:
    sigma_conversion_disabled = True

pyevtx_disabled = False
try:
    from evtx import PyEvtxParser
except ImportError:
    pyevtx_disabled = True

jinja2_disabled = False
try:
    from jinja2 import Template
except ImportError:
    jinja2_disabled = True

xml_import_disabled = False
try:
    from lxml import etree
except ImportError:
    xml_import_disabled = True


def signal_handler(sig, frame):
    print("[-] Execution interrupted !")
    sys.exit(0)


def quit_on_error(message):
    """Log an error message and exit the program."""
    logger = logging.getLogger(__name__)
    logger.error(message)
    sys.exit(1)


def check_if_exists(path, error_message):
    """Test if path provided is a file"""
    if not (Path(path).is_file()):
        quit_on_error(error_message)


def setup_logging(debug_mode, log_file=None):
    """Set up logging configuration."""
    log_level = logging.DEBUG if debug_mode else logging.INFO

    # Define a configuration dictionary
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console_formatter": {"format": "%(message)s"},
            "file_formatter": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "console_formatter",
                "level": logging.INFO,
                "stream": "ext://sys.stdout",
            },
            "file": {
                "class": "logging.FileHandler",
                "formatter": "file_formatter",
                "level": log_level,
                "filename": log_file or "zircolite.log",
                "encoding": "utf-8",
            },
        },
        "root": {
            "handlers": ["console", "file"] if log_file else ["console"],
            "level": log_level,
        },
    }

    logging.config.dictConfig(logging_config)


# Define the authorized BUILTINS for Resticted Python
def default_guarded_getitem(ob, index):
    return ob[index]


class template_engine:
    def __init__(self, templates=[], template_outputs=[], time_field=""):
        self.logger = logging.getLogger(__name__)
        self.time_field = time_field
        self.compiled_templates = {}
        # Flatten templates and outputs if they are nested lists
        self.template_paths = [
            tpl[0] if isinstance(tpl, list) else tpl for tpl in templates
        ]
        self.template_outputs = [
            out[0] if isinstance(out, list) else out for out in template_outputs
        ]

    def generate_from_template(self, template_file, output_filename, data):
        """Use Jinja2 to output data in a specific format"""
        try:
            with open(template_file, "r", encoding="utf-8") as tmpl:
                # Use the compiled template if available, otherwise compile it
                if template_file in self.compiled_templates:
                    template = self.compiled_templates["template_file"]
                else:
                    template = Template(tmpl.read())
                    self.compiled_templates["template_file"] = template
            # Render the template and write to the output file
            with open(output_filename, "a", encoding="utf-8") as tpl:
                tpl.write(template.render(data=data, time_field=self.time_field))
        except Exception as e:
            self.logger.error(
                f"{Fore.RED}   [-] Template error, activate debug mode with '--debug' to check for errors{Fore.RESET}"
            )
            self.logger.debug(f"   [-] {e}")

    def run(self, data):
        for template, template_output in zip(
            self.template_paths, self.template_outputs
        ):
            self.logger.info(
                f'[+] Applying template "{template}", outputting to : {template_output}'
            )
            self.generate_from_template(template, template_output, data)


class json_flattener:
    """Perform JSON Flattening"""

    def __init__(
        self,
        config_file,
        time_after="1970-01-01T00:00:00",
        time_before="9999-12-12T23:59:59",
        time_field=None,
        hashes=False,
        input_format=None,
    ):
        self.logger = logging.getLogger(__name__)
        self.key_dict = {}
        self.field_stmt = ""
        self.values_stmt = []
        self.time_after = time_after
        self.time_before = time_before
        self.time_field = time_field
        self.hashes = hashes
        self.json_array = False

        # Initialize the cache for compiled code
        self.compiled_code_cache = {}

        self.chosen_input = input_format
        if self.chosen_input is None:
            self.chosen_input = "evtx_input"  # Since evtx is the default input, we force it no chosen input has been found

        if self.chosen_input == "json_array_input":
            self.json_array = True

        with open(config_file, "r", encoding="UTF-8") as field_mappings_file:
            self.field_mappings_dict = orjson.loads(field_mappings_file.read())
            self.field_exclusions = self.field_mappings_dict["exclusions"]
            self.field_mappings = self.field_mappings_dict["mappings"]
            self.useless_values = self.field_mappings_dict["useless"]
            self.aliases = self.field_mappings_dict["alias"]
            self.field_split_list = self.field_mappings_dict["split"]
            self.transforms = self.field_mappings_dict["transforms"]
            self.transforms_enabled = self.field_mappings_dict["transforms_enabled"]

        self.restricted_python_builtins = {
            "__name__": "script",
            "_getiter_": default_guarded_getiter,
            "_getattr_": getattr,
            "_getitem_": default_guarded_getitem,
            "base64": base64,
            "re": re,
            "chardet": chardet,
            "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
        }
        self.restricted_python_builtins.update(safe_builtins)
        self.restricted_python_builtins.update(limited_builtins)
        self.restricted_python_builtins.update(utility_builtins)

    def transform_value(self, code, param):
        try:
            # Get or compile bytecode using cache
            byte_code = self.compiled_code_cache.get(
                code
            ) or self.compiled_code_cache.setdefault(
                code, compile_restricted(code, filename="<inline code>", mode="exec")
            )

            # Execute transform in restricted environment
            transform_env = {}
            exec(byte_code, self.restricted_python_builtins, transform_env)
            return transform_env["transform"](param)

        except Exception as e:
            self.logger.debug(f"ERROR: Couldn't apply transform: {e}")
            return param

    def process_file(self, file):
        """
        Flatten json object with nested keys into a single level.
        Returns the flattened json object
        """
        self.logger.debug(f"FLATTENING : {file}")
        json_line = {}
        json_output = []
        field_stmt = ""

        def flatten(x, name=""):
            nonlocal field_stmt
            # If it is a Dict go deeper
            if isinstance(x, dict):
                for a in x:
                    flatten(x[a], name + a + ".")
            else:
                # Applying exclusions. Be careful, the key/value pair is discarded if there is a partial match
                if not any(
                    exclusion in name[:-1] for exclusion in self.field_exclusions
                ):
                    # Arrays are not expanded
                    value = "".join(str(x)) if isinstance(x, list) else x
                    # Excluding useless values (e.g. "null"). The value must be an exact match.
                    if value not in self.useless_values:

                        # Applying field mappings
                        raw_field_name = name[:-1]
                        key = self.field_mappings.get(
                            raw_field_name,
                            "".join(
                                e for e in raw_field_name.split(".")[-1] if e.isalnum()
                            ),
                        )

                        # Preparing aliases (work on original field name and Mapped field name)
                        keys = [key]
                        for field_name in (key, raw_field_name):
                            if field_name in self.aliases:
                                keys.append(self.aliases[key])

                        # Applying field transforms (work on original field name and Mapped field name)
                        keys_that_need_transformed_values = []
                        transformed_values_by_keys = {}
                        if self.transforms_enabled:
                            for field_name in [key, raw_field_name]:
                                if field_name in self.transforms:
                                    for transform in self.transforms[field_name]:
                                        if (
                                            transform["enabled"]
                                            and self.chosen_input
                                            in transform["source_condition"]
                                        ):
                                            transform_code = transform["code"]
                                            # If the transform rule ask for a dedicated alias
                                            if transform["alias"]:
                                                keys.append(transform["alias_name"])
                                                keys_that_need_transformed_values.append(
                                                    transform["alias_name"]
                                                )
                                                transformed_values_by_keys[
                                                    transform["alias_name"]
                                                ] = self.transform_value(
                                                    transform_code, value
                                                )
                                            else:
                                                value = self.transform_value(
                                                    transform_code, value
                                                )

                        # Applying field splitting
                        fields_to_split = set(
                            field
                            for field in (raw_field_name, key)
                            if field in self.field_split_list
                        )

                        for field in fields_to_split:
                            try:
                                separator = self.field_split_list[field]["separator"]
                                equal = self.field_split_list[field]["equal"]
                                for splitted_field in value.split(separator):
                                    k, v = splitted_field.split(equal)
                                    json_line[k] = v
                                    key_lower = k.lower()
                                    if key_lower not in self.key_dict:
                                        self.key_dict[key_lower] = k
                                        field_stmt += f"'{k}' TEXT COLLATE NOCASE,\n"
                            except Exception as e:
                                self.logger.debug(
                                    f"ERROR : Couldn't apply field splitting for {field}: {e}"
                                )

                        # Applying aliases
                        for key in keys:
                            # Set value in json_line
                            json_line[key] = transformed_values_by_keys.get(key, value)
                            # Only process schema if key not seen before
                            key_lower = key.lower()
                            if key_lower not in self.key_dict:
                                self.key_dict[key_lower] = key
                                # Determine column type
                                col_type = (
                                    "INTEGER"
                                    if isinstance(value, int)
                                    else "TEXT COLLATE NOCASE"
                                )
                                field_stmt += f"'{key}' {col_type},\n"

        # If filesize is not zero
        if os.stat(file).st_size != 0:
            filename = os.path.basename(file)
            with open(str(file), "r", encoding="utf-8") as json_file:
                logs = orjson.loads(json_file.read()) if self.json_array else json_file
                for line in logs:
                    try:
                        dict_to_flatten = (
                            line if self.json_array else orjson.loads(line)
                        )
                        dict_to_flatten["OriginalLogfile"] = filename
                        if self.hashes:
                            dict_to_flatten["OriginalLogLinexxHash"] = (
                                xxhash.xxh64_hexdigest(line[:-1])
                            )
                        flatten(dict_to_flatten)
                    except Exception as e:
                        self.logger.debug(f"JSON ERROR : {e}")
                        continue

                    if (
                        self.time_after != "1970-01-01T00:00:00"
                        or self.time_before != "9999-12-12T23:59:59"
                    ):
                        if self.time_field in json_line:
                            try:
                                timestamp = time.strptime(
                                    json_line[self.time_field]
                                    .split(".")[0]
                                    .replace("Z", ""),
                                    "%Y-%m-%dT%H:%M:%S",
                                )
                                if self.time_after < timestamp < self.time_before:
                                    json_output.append(json_line)
                            except Exception:
                                json_output.append(json_line)
                        else:
                            continue
                    else:
                        json_output.append(json_line)
                    json_line = {}
        return {"db_fields": field_stmt, "db_values": json_output}

    def save_to_file(self, output_file):
        with open(output_file, "w", encoding="utf-8") as file:
            for json_line in tqdm(self.values_stmt, colour="yellow"):
                file.write(f'{orjson.dumps(json_line).decode("utf-8")}\n')

    def run(self, evtx_json_list):
        for evtx_json in evtx_json_list:
            if os.stat(evtx_json).st_size != 0:
                results = self.process_file(evtx_json)
                self.field_stmt += results["db_fields"]
                self.values_stmt += results["db_values"]


class zircore:
    """Load data into database and apply detection rules"""

    def __init__(
        self,
        no_output=False,
        limit=-1,
        csv_output=False,
        db_location=":memory:",
        delimiter=";",
        tmp_directory=".",
        tmp_directory_db=".",
    ):
        self.logger = logging.getLogger(__name__)

        self.tmp_directory = tmp_directory
        self.tmp_directory_db = tmp_directory_db
        self.db_connection = self.create_connection(db_location)
        self.full_results = []
        self.rule_results = []
        self.ruleset = {}
        self.no_output = no_output
        self.limit = limit
        self.csv_output = csv_output
        self.delimiter = delimiter

        # if not csv_output:

        if not Path(str(tmp_directory)).is_dir():
            os.mkdir(tmp_directory)
        if "?mode=memory&cache=shared" in db_location:
            tmp_filename = f'{db_location.replace("file:", "").replace("?mode=memory&cache=shared", "")}.json'
        else:
            tmp_filename = f"{db_location}.json"
        self.tmp_file = open(f"{tmp_directory}/{tmp_filename}", "w", encoding="utf-8")

    def close(self):
        self.db_connection.close()

    def create_connection(self, db):
        """create a database connection to a SQLite database"""
        conn = None
        self.logger.debug(f"CONNECTING TO : {db}")
        try:
            if "?mode=memory&cache=shared" in db:
                conn = sqlite3.connect(db, isolation_level=None)
                conn.execute("PRAGMA journal_mode = MEMORY;")
                conn.execute("PRAGMA synchronous = OFF;")
                conn.execute("PRAGMA temp_store = MEMORY;")
            else:
                if not Path(str(self.tmp_directory_db)).is_dir():
                    os.mkdir(self.tmp_directory_db)
                conn = sqlite3.connect(f"{self.tmp_directory_db}/{db}")
            conn.row_factory = sqlite3.Row  # Allows to get a dict

            def udf_regex(x, y):
                if y is None:
                    return 0
                if re.search(x, y):
                    return 1
                else:
                    return 0

            conn.create_function(
                "regexp", 2, udf_regex
            )  # Allows to use regex in SQlite
        except Error as e:
            self.logger.error(f"{Fore.RED}   [-] {e}")
        return conn

    def create_db(self, field_stmt):
        create_table_stmt = f"CREATE TABLE logs ( row_id INTEGER, {field_stmt} PRIMARY KEY(row_id AUTOINCREMENT) );"
        self.logger.debug(f" CREATE : {create_table_stmt}")
        if not self.execute_simple_query(create_table_stmt):
            self.logger.error(f"{Fore.RED}   [-] Unable to create table{Fore.RESET}")
            sys.exit(1)

    def create_index(self):
        self.execute_simple_query('CREATE INDEX "idx_eventid" ON "logs" ("EventID");')
        self.execute_simple_query('CREATE INDEX "idx_channel" ON "logs" ("Channel");')

    def execute_simple_query(self, query):
        """Perform a SQL Query with the provided connection"""
        if self.db_connection is None:
            self.logger.error(f"{Fore.RED}   [-] No connection to Db{Fore.RESET}")
            return False
        else:
            db_handle = self.db_connection.cursor()
            self.logger.debug(f"EXECUTING : {query}")
            try:
                db_handle.execute(query)
                self.db_connection.commit()
            except Error as e:
                self.logger.debug(f"   [-] {e}")
                return False
            return True

    def execute_select_query(self, query):
        """
        Execute a SELECT SQL query and return the results as a list of dictionaries.
        """
        if self.db_connection is None:
            self.logger.error(f"{Fore.RED}   [-] No connection to Db{Fore.RESET}")
            return []
        try:
            cursor = self.db_connection.cursor()
            self.logger.debug(f"EXECUTING SELECT QUERY: {query}")
            cursor.execute(query)
            rows = cursor.fetchall()
            # Convert rows to list of dictionaries
            result = [dict(row) for row in rows]
            return result
        except sqlite3.Error as e:
            self.logger.debug(f"   [-] SQL query error: {e}")
            return []

    def load_db_in_memory(self, db):
        """In db only mode it is possible to restore an on disk Db to avoid EVTX extraction and flattening"""
        dbfile_connection = self.create_connection(db)
        dbfile_connection.backup(self.db_connection)
        dbfile_connection.close()

    def escape_identifier(self, identifier):
        """Escape SQL identifiers like table or column names."""
        return identifier.replace('"', '""')

    def insert_data_to_db(self, json_line):
        """Build a parameterized INSERT INTO query and insert data into the database."""
        columns = json_line.keys()
        columns_escaped = ", ".join([self.escape_identifier(col) for col in columns])
        placeholders = ", ".join(["?"] * len(columns))
        values = []
        for col in columns:
            value = json_line[col]
            if isinstance(value, int):
                # Check if value exceeds SQLite INTEGER limits
                if abs(value) > 9223372036854775807:
                    value = str(value)  # Convert to string
            values.append(value)
        insert_stmt = f"INSERT INTO logs ({columns_escaped}) VALUES ({placeholders})"
        try:
            self.db_connection.execute(insert_stmt, values)
            return True
        except Exception as e:
            self.logger.debug(f"   [-] {e}")
            return False

    def insert_flat_json_to_db(self, flattened_json):
        for json_line in flattened_json:
            self.insert_data_to_db(json_line)

    def save_db_to_disk(self, db_filename):
        self.logger.info("[+] Saving working data to disk as a SQLite DB")
        on_disk_db = sqlite3.connect(db_filename)
        self.db_connection.backup(on_disk_db)
        on_disk_db.close()

    def execute_rule(self, rule):
        """
        Execute a single Sigma rule against the database and return the results.
        """
        if "rule" not in rule:
            self.logger.debug("RULE FORMAT ERROR: 'rule' key missing")
            return {}

        # Set default values for missing rule keys
        rule_level = rule.get("level", "unknown")
        tags = rule.get("tags", [])
        filename = rule.get("filename", "")
        description = rule.get("description", "")
        title = rule.get("title", "Unnamed Rule")
        rule_id = rule.get("id", "")
        sigma_queries = rule["rule"]

        filtered_rows = []

        # Process each SQL query in the rule
        for sql_query in sigma_queries:
            data = self.execute_select_query(sql_query)
            if data:
                if self.csv_output:
                    # Clean values for CSV output
                    filtered_rows.extend(
                        {
                            k: str(v).replace("\n", "").replace("\r", "") or ""
                            for k, v in row.items()
                        }
                        for row in data
                    )
                else:
                    # Remove None values
                    filtered_rows.extend(
                        {k: v for k, v in row.items() if v is not None} for row in data
                    )

        if filtered_rows:
            results = {
                "title": title,
                "id": rule_id,
                "description": (
                    description.replace("\n", "").replace("\r", "")
                    if self.csv_output
                    else description
                ),
                "sigmafile": filename,
                "sigma": sigma_queries,
                "rule_level": rule_level,
                "tags": tags,
                "count": len(filtered_rows),
                "matches": filtered_rows,
            }

            if not self.csv_output:
                json_bytes = orjson.dumps(results)
                self.tmp_file.write(f"{json_bytes.decode('utf-8')}\n")

            self.logger.debug(
                f"DETECTED: {title} - Matches: {len(filtered_rows)} events"
            )
            return results
        else:
            return {}

    def load_ruleset_from_var(self, ruleset, rule_filters):
        self.ruleset = ruleset
        self.apply_ruleset_filters(rule_filters)

    def apply_ruleset_filters(self, rule_filters=None):
        # Remove empty rule and remove filtered rules
        self.ruleset = list(filter(None, self.ruleset))
        if rule_filters is not None:
            self.ruleset = [
                rule
                for rule in self.ruleset
                if not any(rule_filter in rule["title"] for rule_filter in rule_filters)
            ]

    def execute_ruleset(self):
        """
        Execute all rules in the ruleset and handle output.
        """

        for rule in self.ruleset:

            # Execute the rule
            rule_results = self.execute_rule(rule)
            if not rule_results:
                continue  # No matches, skip to next rule

            # Apply limit if set
            if self.limit != -1 and rule_results["count"] > self.limit:
                continue  # Exceeds limit, skip this result

            # Store if the rule has matched : title, level, count only
            self.rule_results.append(
                {
                    "rule_title": rule_results["title"],
                    "rule_level": rule_results["rule_level"],
                    "rule_count": rule_results["count"],
                }
            )

            # self.full_results.append(rule_results)

        self.tmp_file.close()


class evtx_extractor:

    def __init__(
        self,
        provided_tmp_dir=None,
        cores=None,
        use_external_binaries=True,
        binaries_path=None,
        encoding=None,
        input_format=None,
    ):
        self.logger = logging.getLogger(__name__)

        if Path(str(provided_tmp_dir)).is_dir():
            self.tmp_dir = f"tmp-{self.rand_string()}"
            self.logger.error(
                f"{Fore.RED}   [-] Provided directory already exists using '{self.tmp_dir}' instead{Fore.RESET}"
            )
        else:
            self.tmp_dir = provided_tmp_dir or f"tmp-{self.rand_string()}"
            os.mkdir(self.tmp_dir)

        self.cores = cores or os.cpu_count()
        self.use_external_binaries = use_external_binaries
        self.sysmon_4_linux = False
        self.xml_logs = False
        self.csv_input = False
        self.auditd_logs = False
        self.evtxtract = False

        if input_format == "sysmon_linux_input":
            self.sysmon_4_linux = True
        elif input_format == "xml_input":
            self.xml_logs = True
        elif input_format == "csv_input":
            self.csv_input = True
        elif input_format == "auditd_input":
            self.auditd_logs = True
        elif input_format == "evtxtract_input":
            self.evtxtract = True

        # Hardcoded hash list of evtx_dump binaries
        self.valid_hash_list = [
            "bbcce464533e0364",
            "e642f5c23e156deb",
            "5a7a1005885a1a11",
        ]

        # Sysmon 4 Linux default encoding is ISO-8859-1, Auditd is UTF-8
        if not encoding and self.sysmon_4_linux:
            self.encoding = "ISO-8859-1"
        elif not encoding and (self.auditd_logs or self.evtxtract or self.xml_logs):
            self.encoding = "utf-8"
        else:
            self.encoding = encoding

        self.evtx_dump_cmd = self.get_os_external_tools(binaries_path)

    def rand_string(self, length=8):
        return "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(length)
        )

    def get_os_external_tools(self, bin_path):
        """Determine which binaries to run depending on host OS : 32Bits is NOT supported for now since evtx_dump is 64bits only"""
        if bin_path is None:
            if _platform == "linux" or _platform == "linux2":
                return "bin/evtx_dump_lin"
            elif _platform == "darwin":
                return "bin/evtx_dump_mac"
            elif _platform == "win32":
                return "bin\\evtx_dump_win.exe"
        else:
            return bin_path

    def run_using_bindings(self, file):
        """
        Convert EVTX to JSON using evtx_dump bindings (slower)
        Drop resulting JSON files in a tmp folder.
        """
        if self.use_external_binaries:
            self.logger.error(
                f"{Fore.RED}   [-] Cannot use PyEvtxParser and evtx_dump is disabled or missing{Fore.RESET}"
            )
            return

        try:
            filepath = Path(file)
            output_file = f"{self.tmp_dir}/{filepath.name}-{self.rand_string()}.json"
            parser = PyEvtxParser(str(filepath))
            with open(output_file, "w", encoding="utf-8") as f:
                for record in parser.records_json():
                    f.write(record["data"].replace("\n", "") + "\n")
        except Exception as e:
            self.logger.error(
                f"{Fore.RED}   [-] Cannot use PyEvtxParser : {e}{Fore.RESET}"
            )

    def get_time(self, line):
        timestamp = line.replace("msg=audit(", "").replace("):", "").split(":")
        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(float(timestamp[0]))
        )
        return timestamp

    def auditd_line_to_json(self, auditd_line):
        """
        Convert auditd logs to JSON : code from https://github.com/csark/audit2json
        """
        event = {}
        # According to auditd specs https://github.com/linux-audit/audit-documentation/wiki/SPEC-Audit-Event-Enrichment
        # a GS ASCII character, 0x1D, will be inserted to separate original and translated fields
        # Best way to deal with it is to remove it.
        attributes = auditd_line.replace("\x1d", " ").split(" ")
        for attribute in attributes:
            if "msg=audit" in attribute:
                event["timestamp"] = self.get_time(attribute)
            else:
                try:
                    attribute = (
                        attribute.replace("msg=", "")
                        .replace("'", "")
                        .replace('"', "")
                        .split("=")
                    )
                    event[attribute[0]] = attribute[1].rstrip()
                except Exception:
                    pass
        if "host" not in event:
            event["host"] = "offline"
        return event

    def sysmon_xml_line_to_json(self, xml_line):
        """
        Remove syslog header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        if "Event" not in xml_line:
            return None
        xml_line = "<Event>" + xml_line.split("<Event>")[1]
        try:  # isolate individual line parsing errors
            root = etree.fromstring(xml_line)
            return self.xml_to_dict(root)
        except Exception as ex:
            self.logger.debug(f'Unable to parse line "{xml_line}": {ex}')
            return None

    def xml_line_to_json(self, xml_line):
        """
        Remove "Events" header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        if "<Event " not in xml_line:
            return None
        try:  # isolate individual line parsing errors
            root = etree.fromstring(xml_line)
            return self.xml_to_dict(
                root, "{http://schemas.microsoft.com/win/2004/08/events/event}"
            )
        except Exception as ex:
            self.logger.debug(f'Unable to parse line "{xml_line}": {ex}')
            return None

    def xml_to_dict(
        self, event_root, ns="http://schemas.microsoft.com/win/2004/08/events/event"
    ):

        def clean_tag(tag, ns):
            if ns in tag:
                return tag[len(ns) :]
            return tag

        child = {"#attributes": {"xmlns": ns}}
        for appt in event_root.getchildren():
            nodename = clean_tag(appt.tag, ns)
            nodevalue = {}
            for elem in appt.getchildren():
                cleaned_tag = clean_tag(elem.tag, ns)
                if not elem.text:
                    text = ""
                else:
                    try:
                        text = int(elem.text)
                    except Exception:
                        text = elem.text
                if cleaned_tag == "Data":
                    childnode = elem.get("Name")
                elif cleaned_tag == "Qualifiers":
                    text = elem.text
                else:
                    childnode = cleaned_tag
                    if elem.attrib:
                        text = {"#attributes": dict(elem.attrib)}
                obj = {str(childnode): text}
                nodevalue = {**nodevalue, **obj}
            node = {str(nodename): nodevalue}
            child = {**child, **node}
        event = {"Event": child}
        return event

    def logs_to_json(self, func, datasource, outfile, is_file=True):
        """
        Use multiprocessing to convert supported log formats to JSON
        """

        if is_file:
            with open(datasource, "r", encoding=self.encoding) as fp:
                data = fp.readlines()
        else:
            data = datasource.split("\n")

        pool = mp.Pool(self.cores)
        result = pool.map(func, data)
        pool.close()
        pool.join()
        with open(outfile, "w", encoding="UTF-8") as fp:
            for element in result:
                if element is not None:
                    fp.write(orjson.dumps(element).decode("utf-8") + "\n")

    def csv_to_json(self, csv_path, json_path):
        """
        Convert CSV Logs to JSON
        """
        with open(csv_path, encoding="utf-8") as csv_file:
            csv_reader = csv.DictReader(csv_file)
            with open(json_path, "w", encoding="utf-8") as json_file:
                for row in csv_reader:
                    json_file.write(orjson.dumps(row).decode("utf-8") + "\n")

    def evtxtract_to_json(self, file, outfile):
        """
        Convert EXVTXtract Logs to JSON using xml_to_dict and "dumps" it to a file
        """
        # Load file as a string to add enclosing document since XML doesn't support multiple documents
        with open(file, "r", encoding=self.encoding) as fp:
            data = fp.read()
        # Remove all non UTF-8 characters
        data = bytes(data.replace("\x00", "").replace("\x0B", ""), "utf-8").decode(
            "utf-8", "ignore"
        )
        data = f"<evtxtract>\n{data}\n</evtxtract>"
        # Load the XML file
        parser = etree.XMLParser(
            recover=True
        )  # Recover=True allows the parser to ignore bad characters
        root = etree.fromstring(data, parser=parser)
        with open(outfile, "w", encoding="UTF-8") as fp:
            for event in root.getchildren():
                if "Event" in event.tag:
                    extracted_event = self.xml_to_dict(
                        event, "{http://schemas.microsoft.com/win/2004/08/events/event}"
                    )
                    fp.write(orjson.dumps(extracted_event).decode("utf-8") + "\n")

    def verify_bin_hash(self, bin_path):
        """
        Verify the hash of a binary (Hashes are hardcoded)
        """
        hasher = xxhash.xxh64()
        try:
            # Open the file in binary mode and read chunks to hash
            with open(bin_path, "rb") as f:
                while chunk := f.read(4096):  # Read chunks of 4096 bytes
                    hasher.update(chunk)  # Update the hash with the chunk
            if hasher.hexdigest() in self.valid_hash_list:
                return True
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")

        return False

    def run(self, file):
        """
        Convert Logs to JSON
        Drop resulting JSON files in a tmp folder.
        """
        self.logger.debug(f"EXTRACTING : {file}")
        filename = Path(file).name
        output_json_filename = (
            f"{self.tmp_dir}/{str(filename)}-{self.rand_string()}.json"
        )
        # Auditd or Sysmon4Linux logs
        if self.sysmon_4_linux or self.auditd_logs:
            # Choose which log backend to use
            if self.sysmon_4_linux:
                func = self.sysmon_xml_line_to_json
            elif self.auditd_logs:
                func = self.auditd_line_to_json
            try:
                self.logs_to_json(func, str(file), output_json_filename)
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # XML logs
        elif self.xml_logs:
            try:
                data = ""
                # We need to read the entire file to remove annoying newlines and fields with newlines (System.evtx Logs for example...)
                with open(str(file), "r", encoding="utf-8") as xml_file:
                    data = (
                        xml_file.read()
                        .replace("\n", "")
                        .replace("</Event>", "</Event>\n")
                        .replace("<Event ", "\n<Event ")
                    )
                self.logs_to_json(
                    self.xml_line_to_json, data, output_json_filename, is_file=False
                )
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # EVTXtract
        elif self.evtxtract:
            try:
                self.evtxtract_to_json(str(file), output_json_filename)
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # CSV
        elif self.csv_input:
            try:
                self.csv_to_json(str(file), output_json_filename)
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # EVTX
        else:
            if not self.use_external_binaries or not Path(self.evtx_dump_cmd).is_file():
                self.logger.debug(
                    "   [-] No external binaries args or evtx_dump is missing"
                )
                self.run_using_bindings(file)
            else:
                # Check if the binary is valid does not avoid TOCTOU
                if self.verify_bin_hash(self.evtx_dump_cmd):
                    try:
                        cmd = [
                            self.evtx_dump_cmd,
                            "--no-confirm-overwrite",
                            "-o",
                            "jsonl",
                            str(file),
                            "-f",
                            output_json_filename,
                            "-t",
                            str(self.cores),
                        ]
                        subprocess.call(
                            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                        )
                    except Exception as e:
                        self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")

    def cleanup(self):
        shutil.rmtree(self.tmp_dir)


class gui_generator:
    """
    Generate the mini GUI
    """

    def __init__(self, package_dir, template_file, output_file=None, time_field=""):
        self.logger = logging.getLogger(__name__)
        self.template_file = template_file
        self.tmp_dir = f"tmp-zircogui-{self.rand_string()}"
        self.tmp_file = f"data-{self.rand_string()}.js"
        self.output_file = output_file or f"zircogui-output-{self.rand_string()}"
        self.package_dir = package_dir
        self.time_field = time_field

    def rand_string(self, length=4):
        return "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(length)
        )

    def unzip(self):
        try:
            shutil.unpack_archive(self.package_dir, self.tmp_dir, "zip")
        except Exception as e:
            self.logger.error(f"   [-] {e}")

    def zip(self):
        try:
            shutil.make_archive(self.output_file, "zip", f"{self.tmp_dir}/zircogui")
        except Exception as e:
            self.logger.error(f"   [-] {e}")

    def run(self, data):
        self.unzip()
        try:
            self.logger.info(
                f"[+] Generating ZircoGui package to : {self.output_file}.zip"
            )
            exportforzircoguiTmpl = template_engine(
                [self.template_file], [self.tmp_file], self.time_field
            )
            exportforzircoguiTmpl.run(data)
        except Exception as e:
            self.logger.error(f"   [-] {e}")
        shutil.move(self.tmp_file, f"{self.tmp_dir}/zircogui/data.js")
        self.zip()
        shutil.rmtree(self.tmp_dir)


class rules_updater:
    """
    Download rulesets from the https://github.com/wagga40/Zircolite-Rules repository and update if necessary.
    """

    def __init__(self):
        self.url = (
            "https://github.com/wagga40/Zircolite-Rules/archive/refs/heads/main.zip"
        )
        self.logger = logging.getLogger(__name__)
        self.temp_file = f"tmp-rules-{self.rand_string()}.zip"
        self.tmp_dir = f"tmp-rules-{self.rand_string()}"
        self.updated_rulesets = []

    def rand_string(self, length=4):
        return "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(length)
        )

    def download(self):
        resp = requests.get(self.url, stream=True)
        total = int(resp.headers.get("content-length", 0))
        with open(self.temp_file, "wb") as file, tqdm(
            desc=self.temp_file,
            total=total,
            unit="iB",
            unit_scale=True,
            unit_divisor=1024,
            colour="yellow",
        ) as bar:
            for data in resp.iter_content(chunk_size=1024):
                size = file.write(data)
                bar.update(size)

    def unzip(self):
        shutil.unpack_archive(self.temp_file, self.tmp_dir, "zip")

    def check_if_newer_and_move(self):
        count = 0
        rulesets = Path(self.tmp_dir).rglob("*.json")
        for ruleset in rulesets:
            hash_new = hashlib.md5(open(ruleset, "rb").read()).hexdigest()
            if Path(f"rules/{ruleset.name}").is_file():
                hash_old = hashlib.md5(
                    open(f"rules/{ruleset.name}", "rb").read()
                ).hexdigest()
            else:
                hash_old = ""
            if hash_new != hash_old:
                count += 1
                if not Path("rules/").exists():
                    Path("rules/").mkdir()
                shutil.move(ruleset, f"rules/{ruleset.name}")
                self.updated_rulesets.append(f"rules/{ruleset.name}")
                self.logger.info(
                    f"{Fore.CYAN}   [+] Updated : rules/{ruleset.name}{Fore.RESET}"
                )
        if count == 0:
            self.logger.info(f"{Fore.CYAN}   [+] No newer rulesets found")

    def clean(self):
        os.remove(self.temp_file)
        shutil.rmtree(self.tmp_dir)

    def run(self):
        try:
            self.download()
            self.unzip()
            self.check_if_newer_and_move()
            self.clean()
        except Exception as e:
            self.logger.error(f"   [-] {e}")


class ruleset_handler:

    def __init__(self, config=None, list_pipeline_only=False):
        self.logger = logging.getLogger(__name__)
        self.save_ruleset = config.save_ruleset
        self.ruleset_path_list = config.ruleset
        self.cores = config.cores or os.cpu_count()
        self.sigma_conversion_disabled = config.no_sigma_conversion
        self.pipelines = []

        if self.sigma_conversion_disabled:
            self.logger.info(
                f"{Fore.LIGHTYELLOW_EX}   [i] Sigma conversion is disabled (missing imports) ! {Fore.RESET}"
            )
        else:
            # Init pipelines
            plugins = InstalledSigmaPlugins.autodiscover()
            pipeline_resolver = plugins.get_pipeline_resolver()
            pipeline_list = list(pipeline_resolver.pipelines.keys())

            if list_pipeline_only:
                self.logger.info(
                    "[+] Installed pipelines : "
                    + ", ".join(pipeline_list)
                    + "\n    You can install pipelines with your Python package manager"
                    + "\n    e.g : pip install pysigma-pipeline-sysmon"
                )
            else:
                # Resolving pipelines
                if config.pipeline:
                    for pipeline_name in [
                        item for pipeline in config.pipeline for item in pipeline
                    ]:  # Flatten the list of pipeline names list
                        if pipeline_name in pipeline_list:
                            self.pipelines.append(plugins.pipelines[pipeline_name]())
                        else:
                            self.logger.error(
                                f"{Fore.RED}   [-] {pipeline_name} not found. You can list installed pipelines with '--pipeline-list'{Fore.RESET}"
                            )

        # Parse & (if necessary) convert ruleset, final list is stored in self.rulesets
        self.rulesets = self.ruleset_parsing()

        # Combining Rulesets
        # if config.combine_rulesets:
        self.rulesets = [
            item for sub_ruleset in self.rulesets if sub_ruleset for item in sub_ruleset
        ]
        # Remove duplicates based on 'id' or 'title'
        unique_rules = []
        seen_keys = set()
        for rule in self.rulesets:
            # Use 'id' or 'title' as the unique key
            rule_key = rule.get("id") or rule.get("title")
            if rule_key and rule_key not in seen_keys:
                seen_keys.add(rule_key)
                unique_rules.append(rule)

        level_order = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "informational": 5,
        }
        self.rulesets = sorted(
            unique_rules,
            key=lambda d: level_order.get(
                d.get("level", "informational"), float("inf")
            ),
        )  # Sorting by level

        if len(self.rulesets) == 0:
            self.logger.error(f"{Fore.RED}   [-] No rules to execute !{Fore.RESET}")

    def is_yaml(self, filepath):
        """Test if the file is a YAML file"""
        if filepath.suffix in {".yml", ".yaml"}:
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    yaml.safe_load(file)
                return True
            except yaml.YAMLError:
                return False

    def is_json(self, filepath):
        """Test if the file is a JSON file"""
        if filepath.suffix == ".json":
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    orjson.loads(file.read())
                return True
            except orjson.JSONDecodeError:
                return False

    def rand_ruleset_name(self, sigma_rules):
        # Clean the ruleset name
        cleaned_name = "".join(
            char if char.isalnum() else "-" for char in sigma_rules
        ).strip("-")
        cleaned_name = re.sub(r"-+", "-", cleaned_name)
        # Generate a random string
        random_string = "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(8)
        )
        return f"ruleset-{cleaned_name}-{random_string}.json"

    def convert_sigma_rules(self, backend, rule):
        try:
            return backend.convert_rule(rule, "zircolite")[0]
        except Exception as e:
            self.logger.debug(
                f"{Fore.RED}   [-] Cannot convert rule '{str(rule)}' : {e}{Fore.RESET}"
            )

    def sigma_rules_to_ruleset(self, sigma_rules_list, pipelines):
        for sigma_rules in sigma_rules_list:
            # Create the pipeline resolver
            piperesolver = ProcessingPipelineResolver()
            # Add pipelines
            for pipeline in pipelines:
                piperesolver.add_pipeline_class(pipeline)
            # Create a single sorted and prioritized pipeline
            combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
            # Instantiate backend, using our resolved pipeline
            sqlite_backend = sqlite.sqliteBackend(combined_pipeline)

            rules = Path(sigma_rules)
            if rules.is_dir():
                rule_list = list(rules.rglob("*.yml")) + list(rules.rglob("*.yaml"))
            else:
                rule_list = [rules]

            rule_collection = SigmaCollection.load_ruleset(rule_list)
            ruleset = []

            pool = mp.Pool(self.cores)
            ruleset = pool.map(
                functools.partial(self.convert_sigma_rules, sqlite_backend),
                tqdm(rule_collection, colour="yellow"),
            )
            pool.close()
            pool.join()
            ruleset = [
                rule for rule in ruleset if rule is not None
            ]  # Removing empty results
            ruleset = sorted(ruleset, key=lambda d: d["level"])  # Sorting by level

            if self.save_ruleset:
                temp_ruleset_name = self.rand_ruleset_name(str(sigma_rules))
                with open(temp_ruleset_name, "w") as outfile:
                    outfile.write(
                        orjson.dumps(ruleset, option=orjson.OPT_INDENT_2).decode(
                            "utf-8"
                        )
                    )
                    self.logger.info(
                        f"{Fore.CYAN}   [+] Saved ruleset as : {temp_ruleset_name}{Fore.RESET}"
                    )

        return ruleset

    def ruleset_parsing(self):
        ruleset_list = []
        for ruleset in self.ruleset_path_list:
            ruleset_path = Path(ruleset)
            if ruleset_path.exists():
                if ruleset_path.is_file():
                    if self.is_json(ruleset_path):  # JSON Ruleset
                        try:
                            with open(ruleset_path, encoding="utf-8") as f:
                                ruleset_list.append(orjson.loads(f.read()))
                            self.logger.info(
                                f"{Fore.CYAN}   [+] Loaded JSON/Zircolite ruleset : {str(ruleset_path)}{Fore.RESET}"
                            )
                        except Exception as e:
                            self.logger.error(
                                f"{Fore.RED}   [-] Cannot load {str(ruleset_path)} {e}{Fore.RESET}"
                            )
                    else:  # YAML Ruleset
                        if not self.sigma_conversion_disabled and self.is_yaml(
                            ruleset_path
                        ):
                            try:
                                self.logger.info(
                                    f"{Fore.CYAN}   [+] Converting Native Sigma to Zircolite ruleset : {str(ruleset_path)}{Fore.RESET}"
                                )
                                ruleset_list.append(
                                    self.sigma_rules_to_ruleset(
                                        [ruleset_path], self.pipelines
                                    )
                                )
                            except Exception as e:
                                self.logger.error(
                                    f"{Fore.RED}   [-] Cannot convert {str(ruleset_path)} {e}{Fore.RESET}"
                                )
                elif (
                    not self.sigma_conversion_disabled and ruleset_path.is_dir()
                ):  # Directory
                    try:
                        self.logger.info(
                            f"{Fore.CYAN}   [+] Converting Native Sigma to Zircolite ruleset : {str(ruleset_path)}{Fore.RESET}"
                        )
                        ruleset_list.append(
                            self.sigma_rules_to_ruleset([ruleset_path], self.pipelines)
                        )
                    except Exception as e:
                        self.logger.error(
                            f"{Fore.RED}   [-] Cannot convert {str(ruleset_path)} {e}{Fore.RESET}"
                        )
        return ruleset_list


def select_files(path_list, select_files_list):
    if select_files_list is not None:
        return [
            logs
            for logs in [str(element) for element in list(path_list)]
            if any(
                file_filters[0].lower() in logs.lower()
                for file_filters in select_files_list
            )
        ]
    return path_list


def avoid_files(path_list, avoid_files_list):
    if avoid_files_list is not None:
        return [
            logs
            for logs in [str(element) for element in list(path_list)]
            if all(
                file_filters[0].lower() not in logs.lower()
                for file_filters in avoid_files_list
            )
        ]
    return path_list


def import_error_handler(config):
    import_error_list = []

    if update_disabled:
        import_error_list.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'requests', events update is disabled{Fore.RESET}"
        )
        config.update_rules = False
    if sigma_conversion_disabled:
        import_error_list.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'sigma' from pySigma, ruleset conversion YAML -> JSON is disabled{Fore.RESET}"
        )
        config.no_sigma_conversion = True
    if pyevtx_disabled:
        import_error_list.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'evtx' from pyevtx-rs, use of external binaries is mandatory{Fore.RESET}"
        )
        config.noexternal = False
    if jinja2_disabled:
        import_error_list.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'jinja2', templating is disabled{Fore.RESET}"
        )
        config.template = None
    if xml_import_disabled:
        import_error_list.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'lxml', cannot use XML logs as input{Fore.RESET}"
        )
        if config.xml:
            return (
                f"{Fore.RED}   [-] Cannot import 'lxml', but according to command line provided it is needed{Fore.RESET}",
                config,
                True,
            )

    if config.debug or config.imports:
        return "\n".join(import_error_list), config, False

    if import_error_list == []:
        return "", config, False

    return (
        f"{Fore.LIGHTYELLOW_EX}   [i] Import errors, certain functionalities may be disabled ('--imports' for details)\n       Supplemental imports can be installed with 'requirements.full.txt'{Fore.RESET}",
        config,
        False,
    )


def runner(file, params):
    """Runner function to flatten events and apply rules with multiprocessing"""

    flattener = json_flattener(
        config_file=params["config"],
        time_after=params["events_after"],
        time_before=params["events_before"],
        time_field=params["timefield"],
        hashes=params["hashes"],
        input_format=params["input_format"],
    )

    flattener.run([file])

    # Save the flattened JSON to a file
    if params["keepflat"]:
        flattener.save_to_file(f"flattened_events_{rand_string(4)}.json")

    # Initialize zircore
    filename = os.path.basename(file)
    db_location = (
        f"{filename}-{rand_string(4)}.db"
        if params["on_disk_db"]
        else f"file:{filename}?mode=memory&cache=shared"
    )

    zircolite_core = zircore(
        limit=params["limit"],
        csv_output=params["csv_output"],
        db_location=db_location,
        delimiter=params["delimiter"],
        tmp_directory=params["tmp_directory"],
        tmp_directory_db=params["tmp_directory_db"],
    )

    zircolite_core.create_db(flattener.field_stmt)
    zircolite_core.insert_flat_json_to_db(flattener.values_stmt)
    del flattener
    zircolite_core.create_index()
    zircolite_core.load_ruleset_from_var(
        ruleset=params["rulesets"], rule_filters=params["rulefilter"]
    )
    zircolite_core.execute_ruleset()
    zircolite_core.close()

    return zircolite_core.full_results, zircolite_core.rule_results


def runner_wrapper(args):
    """Helper function to allow TQDM to display a progress bar"""
    return runner(*args)


def format_rule_level(level, reset=Fore.RESET):
    if level == "informational":
        return f"{Fore.WHITE}{level}{reset}"
    if level == "low":
        return f"{Fore.GREEN}{level}{reset}"
    if level == "medium":
        return f"{Fore.YELLOW}{level}{reset}"
    if level == "high":
        return f"{Fore.MAGENTA}{level}{reset}"
    if level == "critical":
        return f"{Fore.RED}{level}{reset}"
    return level  # Default case


def rand_string(length=10):
    return "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(length)
    )


def concatenate_files(input_dir, output_file, buffer_size=1024 * 1024):
    input_files = list(Path(input_dir).rglob("*.json"))
    with open(output_file, "wb") as outfile:
        for fname in input_files:
            if not os.path.isfile(fname):
                print(f"File not found: {fname}")
                continue
            with open(fname, "rb") as infile:
                while True:
                    buffer = infile.read(buffer_size)
                    if not buffer:
                        break
                    outfile.write(buffer)


def calculate_files_total_size(file_list):
    total_size = 0
    for file in file_list:
        total_size += file.stat().st_size
    return total_size


def get_machine_ram():
    return psutil.virtual_memory().available


def format_size(size_in_bytes):
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024**2:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024**3:
        return f"{size_in_bytes / 1024**2:.2f} MB"
    else:
        return f"{size_in_bytes / 1024**3:.2f} GB"


def calculate_system_resources(file_list):
    total_size = calculate_files_total_size(file_list)
    machine_ram = get_machine_ram()
    machine_cores = os.cpu_count()

    max_memory_usage = total_size * 2

    # Calculate memory usage per core
    per_core_usage = max_memory_usage / machine_cores
    max_cores_to_use = min(machine_cores, int(machine_ram // per_core_usage))

    return {
        "total_size": total_size,
        "machine_ram": machine_ram,
        "machine_cores": machine_cores,
        "max_cores_to_use": max_cores_to_use,
    }


################################################################
# MAIN()
################################################################
def main():
    version = "2.50.0"

    # Init Args handling
    parser = argparse.ArgumentParser()
    # Input files and filtering/selection options
    logsInputArgs = parser.add_argument_group(
        f"{Fore.BLUE}INPUT FILES AND FILTERING/SELECTION OPTIONS{Fore.RESET}"
    )
    logsInputArgs.add_argument(
        "-e",
        "--events",
        "--evtx",
        help="Specify a log file or directory containing log files in supported formats",
        type=str,
    )
    logsInputArgs.add_argument(
        "-s",
        "--select",
        help="Select only files with filenames containing the provided string. Exclusions (--avoid) will be applied after selection",
        action="append",
        nargs="+",
    )
    logsInputArgs.add_argument(
        "-a",
        "--avoid",
        help="Exclude files with filenames containing the provided string",
        action="append",
        nargs="+",
    )
    logsInputArgs.add_argument(
        "-f", "--fileext", help="Specify the extension of the log files", type=str
    )
    logsInputArgs.add_argument(
        "-fp",
        "--file-pattern",
        help="Use a Python Glob pattern to select files. This option only works with directories",
        type=str,
    )
    logsInputArgs.add_argument(
        "--no-recursion",
        help="Disable recursive search for log/event files. Only search in the provided directory",
        action="store_true",
    )
    # Events filtering options
    eventArgs = parser.add_argument_group(
        f"{Fore.BLUE}EVENTS FILTERING OPTIONS{Fore.RESET}"
    )
    eventArgs.add_argument(
        "-A",
        "--after",
        help="Limit to events that occurred after the provided timestamp (UTC). Format: 1970-01-01T00:00:00",
        type=str,
        default="1970-01-01T00:00:00",
    )
    eventArgs.add_argument(
        "-B",
        "--before",
        help="Limit to events that occurred before the provided timestamp (UTC). Format: 1970-01-01T00:00:00",
        type=str,
        default="9999-12-12T23:59:59",
    )
    # Event and log formats options
    # /!\ an option name containing '-input' must exist (It is used in JSON flattening mechanism)
    eventFormatsArgs = parser.add_mutually_exclusive_group()
    eventFormatsArgs.add_argument(
        "-j",
        "--json-input",
        "--jsononly",
        "--jsonline",
        "--jsonl",
        help="Specify if log files are already in JSON lines format ('jsonl' in evtx_dump)",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "--json-array-input",
        "--jsonarray",
        "--json-array",
        help="Specify if source logs are in JSON format as an array",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "-S",
        "--sysmon-linux-input",
        "--sysmon4linux",
        "--sysmon-linux",
        help="Use this option for Sysmon for Linux log files. Default file extension is '.log'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "-AU",
        "--auditd-input",
        "--auditd",
        help="Use this option for Auditd log files. Default file extension is '.log'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "-x",
        "--xml-input",
        "--xml",
        help="Use this option for EVTX files converted to XML format. Default file extension is '.xml'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "--evtxtract-input",
        "--evtxtract",
        help="Use this option for log files extracted with EVTXtract. Default file extension is '.log'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "--csv-input",
        "--csvonly",
        help="Specify if your log file is in CSV format '.csv'",
        action="store_true",
    )
    # Ruleset options
    rulesetsFormatsArgs = parser.add_argument_group(
        f"{Fore.BLUE}RULES AND RULESETS OPTIONS{Fore.RESET}"
    )
    rulesetsFormatsArgs.add_argument(
        "-r",
        "--ruleset",
        help="Specify Sigma ruleset: JSON (Zircolite format) or YAML/Directory containing YAML files (Native Sigma format)",
        action="append",
        nargs="+",
    )
    rulesetsFormatsArgs.add_argument(
        "-nsc", "--no-sigma-conversion", help=argparse.SUPPRESS, action="store_true"
    )
    rulesetsFormatsArgs.add_argument(
        "-sr",
        "--save-ruleset",
        help="Save converted ruleset (Sigma to Zircolite format) to disk",
        action="store_true",
    )
    rulesetsFormatsArgs.add_argument(
        "-p",
        "--pipeline",
        help="Specify pipeline(s) for native Sigma rulesets (YAML). Multiple can be used. Examples: 'sysmon', 'windows-logsources', 'windows-audit'. Use '--pipeline-list' to see available pipelines",
        action="append",
        nargs="+",
    )
    rulesetsFormatsArgs.add_argument(
        "-pl",
        "--pipeline-list",
        help="List installed pysigma pipelines",
        action="store_true",
    )
    rulesetsFormatsArgs.add_argument(
        "-pn",
        "--pipeline-null",
        help="Do not use any pipeline for native Sigma rulesets (YAML). This is the default behavior",
        action="store_true",
    )
    rulesetsFormatsArgs.add_argument(
        "-R",
        "--rulefilter",
        help="Remove rules from ruleset based on rule title (case sensitive)",
        action="append",
        nargs="*",
    )
    # Output formats and output files options
    outputFormatsArgs = parser.add_argument_group(
        f"{Fore.BLUE}OUTPUT FORMATS AND OUTPUT FILES OPTIONS{Fore.RESET}"
    )
    outputFormatsArgs.add_argument(
        "-o",
        "--outfile",
        help="Specify the file to store all detected events",
        type=str,
        default="detected_events.json",
    )
    outputFormatsArgs.add_argument(
        "--csv",
        "--csv-output",
        help="Output results in CSV format. Note that in this mode, empty fields will not be discarded from results",
        action="store_true",
    )
    outputFormatsArgs.add_argument(
        "--csv-delimiter",
        help="Specify the delimiter for CSV output",
        type=str,
        default=";",
    )
    outputFormatsArgs.add_argument(
        "-t",
        "--tmpdir",
        help="Specify the temporary directory to store events converted to JSON (parent directories must exist)",
        type=str,
    )
    outputFormatsArgs.add_argument(
        "-k",
        "--keeptmp",
        help="Retain the temporary directory containing events converted to JSON format",
        action="store_true",
    )
    outputFormatsArgs.add_argument(
        "--keepflat", help="Save flattened events as JSON", action="store_true"
    )
    outputFormatsArgs.add_argument(
        "-d", "--dbfile", help="Save all logs in a SQLite database file", type=str
    )
    outputFormatsArgs.add_argument(
        "-l",
        "--logfile",
        help="Specify the log file name",
        default="zircolite.log",
        type=str,
    )
    outputFormatsArgs.add_argument(
        "--hashes",
        help="Add an xxhash64 of the original log event to each event",
        action="store_true",
    )
    outputFormatsArgs.add_argument(
        "-L",
        "--limit",
        "--limit-results",
        help="Discard results that exceed the specified limit",
        type=int,
        default=-1,
    )
    # Advanced configuration options
    configFormatsArgs = parser.add_argument_group(
        f"{Fore.BLUE}ADVANCED CONFIGURATION OPTIONS{Fore.RESET}"
    )
    configFormatsArgs.add_argument(
        "-c",
        "--config",
        help="Specify a JSON file containing field mappings and exclusions",
        type=str,
        default="config/fieldMappings.json",
    )
    eventFormatsArgs.add_argument(
        "-LE",
        "--logs-encoding",
        help="Specify log encoding when processing Sysmon for Linux or Auditd files",
        type=str,
    )
    configFormatsArgs.add_argument(
        "--evtx_dump",
        help="Specify the binary to use for EVTX conversion. On Linux and MacOS, provide a valid path to launch the binary (e.g., './evtx_dump' instead of 'evtx_dump')",
        type=str,
        default=None,
    )
    configFormatsArgs.add_argument(
        "--noexternal",
        "--bindings",
        help="Disable the use of evtx_dump external binaries (slower processing)",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "--cores",
        help="Specify the number of cores to use. Default is all available cores",
        default=-1,
        type=int,
    )
    configFormatsArgs.add_argument(
        "--debug", help="Enable debug logging", action="store_true"
    )
    configFormatsArgs.add_argument(
        "--imports", help="Display detailed module import errors", action="store_true"
    )
    configFormatsArgs.add_argument(
        "--ondiskdb",
        "--on-disk-db",
        help="Use an on-disk database instead of an in-memory one (significantly slower). Use this option if your system has limited RAM or if your dataset is very large and cannot be split",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "-RE",
        "--remove-events",
        help="Attempt to remove submitted events/logs if analysis is successful (use at your own risk)",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "-U",
        "--update-rules",
        help="Update rulesets located in the 'rules' directory",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "-v", "--version", help="Display Zircolite version", action="store_true"
    )
    configFormatsArgs.add_argument(
        "--timefield",
        help="Specify the timestamp field name. Default is 'SystemTime'",
        default="SystemTime",
        type=str,
    )

    # Templating and Mini GUI options
    templatingFormatsArgs = parser.add_argument_group(
        f"{Fore.BLUE}TEMPLATING AND MINI GUI OPTIONS{Fore.RESET}"
    )
    templatingFormatsArgs.add_argument(
        "--template",
        help="Specify a Jinja2 template to generate output",
        type=str,
        action="append",
        nargs="+",
    )
    templatingFormatsArgs.add_argument(
        "--templateOutput",
        help="Specify the output file for the Jinja2 template",
        type=str,
        action="append",
        nargs="+",
    )
    templatingFormatsArgs.add_argument(
        "--package", help="Create a ZircoGui/Mini GUI package", action="store_true"
    )
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    # Init logging
    setup_logging(args.debug, args.logfile)
    logger = logging.getLogger()

    logger.info(
        """
    ███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗
    ╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝
      ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗
     ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝
    ███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗
    ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
   -= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-
    """
    )

    # Print version an quit
    if args.version:
        logger.info(f"Zircolite - v{version}")
        sys.exit(0)

    # Show imports status
    imports_message, args, must_quit = import_error_handler(args)
    if imports_message != "":
        logger.info(f"[+] Modules imports status: \n{imports_message}")
    else:
        logger.info("[+] Modules imports status: OK")
    if must_quit:
        sys.exit(1)

    # Update rulesets
    if args.update_rules:
        logger.info("[+] Updating rules")
        updater = rules_updater()
        updater.run()
        sys.exit(0)

    # Handle rulesets args
    if args.ruleset:
        args.ruleset = [item for args in args.ruleset for item in args]
    else:
        args.ruleset = ["rules/rules_windows_generic_pysigma.json"]

    # Check mandatory CLI options
    if not args.events:
        logger.error(
            f"{Fore.RED}   [-] No events source path provided. Use '-e <PATH TO LOGS>', '--events <PATH TO LOGS>'{Fore.RESET}"
        ), sys.exit(2)
    if args.csv and len(args.ruleset) > 1:
        logger.error(
            f"{Fore.RED}   [-] Since fields in results can change between rulesets, it is not possible to have CSV output when using multiple rulesets{Fore.RESET}"
        ), sys.exit(2)

    logger.info("[+] Checking prerequisites")

    # Checking provided timestamps
    try:
        events_after = time.strptime(args.after, "%Y-%m-%dT%H:%M:%S")
        events_before = time.strptime(args.before, "%Y-%m-%dT%H:%M:%S")
    except Exception:
        quit_on_error(
            f"{Fore.RED}   [-] Wrong timestamp format. Please use 'AAAA-MM-DDTHH:MM:SS'"
        )

    # Check templates args
    ready_for_templating = False
    if args.template is not None:
        if args.csv:
            quit_on_error(
                f"{Fore.RED}   [-] You cannot use templates in CSV mode{Fore.RESET}"
            )
        if (args.templateOutput is None) or (
            len(args.template) != len(args.templateOutput)
        ):
            quit_on_error(
                f"{Fore.RED}   [-] Number of templates output must match number of templates{Fore.RESET}"
            )
        for template in args.template:
            check_if_exists(
                template[0],
                f"{Fore.RED}   [-] Cannot find template : {template[0]}. Default templates are available here : https://github.com/wagga40/Zircolite/tree/master/templates{Fore.RESET}",
            )
        ready_for_templating = True

    # Change output filename in CSV mode
    if args.csv:
        ready_for_templating = False
        # If outfile is not provided, default to 'detected_events.csv' instead of 'detected_events.json'
        if args.outfile == "detected_events.json":
            args.outfile = "detected_events.csv"

    # Start time counting
    start_time = time.time()

    # If we are working with json file extension is changed if it is not user-provided
    if not args.fileext:
        if args.json_input or args.json_array_input:
            args.fileext = "json"
        elif args.sysmon_linux_input or args.auditd_input:
            args.fileext = "log"
        elif args.xml_input:
            args.fileext = "xml"
        elif args.csv_input:
            args.fileext = "csv"
        else:
            args.fileext = "evtx"

    # Get list of log files to process:
    # - If events path is a directory, get all matching files using glob/rglob based on recursion flag
    # - If events path is a single file, use that file directly
    # - Otherwise error out since no valid files found
    log_path = Path(args.events)
    pattern = args.file_pattern if args.file_pattern else f"*.{args.fileext}"
    if log_path.is_dir():
        # Use glob or rglob based on recursion flag
        glob_fn = log_path.glob if args.no_recursion else log_path.rglob
        log_list = list(glob_fn(pattern))
    elif log_path.is_file():
        log_list = [log_path]
    else:
        quit_on_error(
            f"{Fore.RED}   [-] Unable to find events from submitted path{Fore.RESET}"
        )

    # Applying file filters in this order : "select" than "avoid"
    file_list = avoid_files(select_files(log_list, args.select), args.avoid)
    if len(file_list) <= 0:
        quit_on_error(
            f"{Fore.RED}   [-] No file found. Please verify filters, directory or the extension with '--fileext' or '--file-pattern'{Fore.RESET}"
        )

    # If cores is not provided, calculate the number of cores to use
    system_resources = calculate_system_resources(file_list)
    logger.info(
        f"[+] File(s) size: {Fore.CYAN}{format_size(system_resources['total_size'])}{Fore.RESET} | Available RAM: {Fore.CYAN}{format_size(system_resources['machine_ram'])}{Fore.RESET}"
    )
    if args.cores == -1:
        args.cores = system_resources["max_cores_to_use"]
        logger.info(
            f"[+] CPU Cores / CPU Cores used: {Fore.CYAN}{system_resources['machine_cores']}{Fore.RESET} / {Fore.CYAN}{system_resources['machine_cores'] if args.cores > system_resources['machine_cores'] else args.cores}{Fore.RESET}"
        )
    else:
        logger.info(
            f"[+] CPU Cores used (Forced): {Fore.CYAN}{system_resources['machine_cores']}{Fore.RESET} / {Fore.CYAN}{args.cores}{Fore.RESET}"
        )

    # Loading rulesets
    logger.info("[+] Loading ruleset(s)")
    rulesets_manager = ruleset_handler(args, args.pipeline_list)
    if args.pipeline_list:
        sys.exit(0)

    args_dict = vars(args)
    # Find the chosen input format
    chosen_input = next(
        (key for key, value in args_dict.items() if "_input" in key and value), None
    )

    if not args.json_input and not args.json_array_input:
        # Init EVTX extractor object
        extractor = evtx_extractor(
            provided_tmp_dir=args.tmpdir,
            cores=args.cores,
            use_external_binaries=(not args.noexternal),
            binaries_path=args.evtx_dump,
            encoding=args.logs_encoding,
            input_format=chosen_input,
        )
        logger.info(f"[+] Extracting events using '{extractor.tmp_dir}' directory ")
        for evtx in tqdm(file_list, colour="yellow"):
            extractor.run(evtx)
        # Set the path for the next step
        log_json_list = list(Path(extractor.tmp_dir).rglob("*.json"))
    else:
        log_json_list = file_list

    check_if_exists(
        args.config,
        f"{Fore.RED}   [-] Cannot find mapping file, you can get the default one here : https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json {Fore.RESET}",
    )
    if log_json_list == []:
        quit_on_error(f"{Fore.RED}   [-] No files containing logs found.{Fore.RESET}")

    # TODO : Add option for already flattened event
    logger.info(
        f"[+] Processing events and applying {Fore.CYAN}{len(rulesets_manager.rulesets)}{Fore.RESET} rules"
    )

    # flatten array of "rulefilter" arguments
    if args.rulefilter:
        args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

    tmp_directory = f"tmp-output-{rand_string()}"
    tmp_directory_db = f"tmp-db-{rand_string()}" if args.ondiskdb else ""

    # Pack the parameters for multiprocessing
    param_list = {
        "config": args.config,
        "events_after": events_after,
        "events_before": events_before,
        "timefield": args.timefield,
        "hashes": args.hashes,
        "input_format": chosen_input,
        "csv_output": args.csv,
        "limit": args.limit,
        "on_disk_db": args.ondiskdb,
        "delimiter": args.csv_delimiter,
        "keepflat": args.keepflat,
        "rulefilter": args.rulefilter,
        "rulesets": rulesets_manager.rulesets,
        "tmp_directory": tmp_directory,
        "tmp_directory_db": tmp_directory_db,
    }

    params_map = []
    for file in log_json_list:
        params_map.append((file, param_list))

    all_full_results = []
    all_rule_results = []
    # Perform the JSON flattening and the detection process with multiprocessing
    with mp.Pool(processes=args.cores) as pool:
        with tqdm(total=len(params_map), colour="yellow") as pbar:
            for full_results, rule_results in pool.imap_unordered(
                runner_wrapper, params_map
            ):
                all_full_results.extend(full_results)
                all_rule_results.extend(rule_results)
                pbar.update()

    # Merge the rule results from all processes
    aggregated_rules = {}
    for rule in all_rule_results:
        key = rule["rule_title"]
        if key in aggregated_rules:
            aggregated_rules[key]["rule_count"] += rule["rule_count"]
        else:
            aggregated_rules[key] = rule.copy()

    level_order = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}

    aggregated_rules = sorted(
        aggregated_rules.values(),
        key=lambda d: level_order.get(
            d.get("rule_level", "informational"), float("inf")
        ),
    )  # Sort by level
    for rule in aggregated_rules:
        rule_title = rule["rule_title"]
        rule_level = rule["rule_level"]
        rule_count = rule["rule_count"]
        formatted_level = format_rule_level(rule_level, Fore.CYAN)
        logger.info(
            f"{Fore.CYAN}    - {rule_title} [{formatted_level}] : {rule_count} events{Fore.RESET}"
        )

    logger.info(f"[+] Writing results to the output file : {args.outfile}")

    concatenate_files(tmp_directory, args.outfile)
    # if not keep_tmp_output:
    shutil.rmtree(tmp_directory)
    # if not keep_tmp_db:
    if args.ondiskdb:
        shutil.rmtree(tmp_directory_db)

    # if not args.csv:
    #     with open(args.outfile, 'w', encoding='utf-8') as outfile:
    #         # Serialize the list of rule results to JSON with indentation
    #         json_bytes = json.dumps(all_full_results, option=json.OPT_INDENT_2)
    #         # Write the decoded JSON string to the file
    #         outfile.write(json_bytes.decode('utf-8'))
    # else:
    #     # For CSV mode, collect all field names
    #     fieldnames_set = set(["rule_title", "rule_description", "rule_level", "rule_count"])

    #     for rule_result in all_full_results:
    #         matches = rule_result['matches']
    #         if matches:
    #             for data in matches:
    #                 fieldnames_set.update(data.keys())

    #     # For CSV mode, write matches to CSV
    #     with open(args.outfile, 'w', encoding='utf-8', newline='') as outfile:
    #         writer = csv.DictWriter(outfile, delimiter=args.csv_delimiter, fieldnames=fieldnames_set)
    #         writer.writeheader()
    #         for rule_result in all_full_results:
    #             matches = rule_result['matches']
    #             if matches:
    #                 for data in matches:
    #                     dictCSV = {
    #                         "rule_title": rule_result["title"],
    #                         "rule_description": rule_result["description"],
    #                         "rule_level": rule_result["rule_level"],
    #                         "rule_count": rule_result["count"],
    #                         **data
    #                     }
    #                     writer.writerow(dictCSV)

    # Templating
    if ready_for_templating and all_full_results != []:
        template_generator = template_engine(
            args.template, args.templateOutput, args.timefield
        )
        template_generator.run(all_full_results)

    # Generate ZircoGui package
    if args.package and all_full_results != []:
        if (
            Path("templates/exportForZircoGui.tmpl").is_file()
            and Path("gui/zircogui.zip").is_file()
        ):
            packager = gui_generator(
                "gui/zircogui.zip",
                "templates/exportForZircoGui.tmpl",
                None,
                args.timefield,
            )
            packager.run(all_full_results)

    # Remove working directory containing logs as json
    if not args.keeptmp:
        logger.info("[+] Cleaning")
        try:
            if not args.json_input and not args.json_array_input:
                extractor.cleanup()
        except OSError as e:
            logger.error(f"{Fore.RED}   [-] Error during cleanup {e}{Fore.RESET}")

    # Remove files submitted for analysis
    if args.remove_events:
        for logs in log_list:
            try:
                os.remove(logs)
            except OSError as e:
                logger.error(f"{Fore.RED}   [-] Cannot remove files {e}{Fore.RESET}")

    logger.info(f"\nFinished in {int((time.time() - start_time))} seconds")


if __name__ == "__main__":
    main()
