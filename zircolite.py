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
import orjson as json
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
updateDisabled = False
try:
    import requests
except ImportError:
    updateDisabled = True

sigmaConversionDisabled = False
try:
    from sigma.collection import SigmaCollection
    from sigma.backends.sqlite import sqlite
    from sigma.processing.resolver import ProcessingPipelineResolver
    from sigma.plugins import InstalledSigmaPlugins
    import yaml
except ImportError:
    sigmaConversionDisabled = True

pyevtxDisabled = False
try:
    from evtx import PyEvtxParser
except ImportError:
    pyevtxDisabled = True

jinja2Disabled = False
try:
    from jinja2 import Template
except ImportError:
    jinja2Disabled = True

xmlImportDisabled = False
try:
    from lxml import etree
except ImportError:
    xmlImportDisabled = True


def signal_handler(sig, frame):
    print("[-] Execution interrupted !")
    sys.exit(0)


def quitOnError(message):
    """Log an error message and exit the program."""
    logger = logging.getLogger(__name__)
    logger.error(message)
    sys.exit(1)


def checkIfExists(path, errorMessage):
    """Test if path provided is a file"""
    if not (Path(path).is_file()):
        quitOnError(errorMessage)


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
    def __init__(self, templates=[], template_outputs=[], timeField=""):
        self.logger = logging.getLogger(__name__)
        self.timeField = timeField
        self.compiled_templates = {}
        # Flatten templates and outputs if they are nested lists
        self.template_paths = [
            tpl[0] if isinstance(tpl, list) else tpl for tpl in templates
        ]
        self.template_outputs = [
            out[0] if isinstance(out, list) else out for out in template_outputs
        ]

    def generate_from_template(self, template_file, outputFilename, data):
        """Use Jinja2 to output data in a specific format"""
        try:
            with open(template_file, "r", encoding="utf-8") as tmpl:
                # Use the compiled template if available, otherwise compile it
                if template_file in self.compiled_templates:
                    template = self.compiled_templates["templateFile"]
                else:
                    template = Template(tmpl.read())
                    self.compiled_templates["templateFile"] = template
            # Render the template and write to the output file
            with open(outputFilename, "a", encoding="utf-8") as tpl:
                tpl.write(template.render(data=data, timeField=self.timeField))
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
        configFile,
        timeAfter="1970-01-01T00:00:00",
        timeBefore="9999-12-12T23:59:59",
        timeField=None,
        hashes=False,
        input_format=None,
    ):
        self.logger = logging.getLogger(__name__)
        self.keyDict = {}
        self.fieldStmt = ""
        self.valuesStmt = []
        self.timeAfter = timeAfter
        self.timeBefore = timeBefore
        self.timeField = timeField
        self.hashes = hashes
        self.JSONArray = False

        # Initialize the cache for compiled code
        self.compiled_code_cache = {}

        self.chosen_input = input_format
        if self.chosen_input is None:
            self.chosen_input = "evtx_input"  # Since evtx is the default input, we force it no chosen input has been found

        if self.chosen_input == "json_array_input":
            self.JSONArray = True

        with open(configFile, "r", encoding="UTF-8") as fieldMappingsFile:
            self.fieldMappingsDict = json.loads(fieldMappingsFile.read())
            self.fieldExclusions = self.fieldMappingsDict["exclusions"]
            self.fieldMappings = self.fieldMappingsDict["mappings"]
            self.uselessValues = self.fieldMappingsDict["useless"]
            self.aliases = self.fieldMappingsDict["alias"]
            self.fieldSplitList = self.fieldMappingsDict["split"]
            self.transforms = self.fieldMappingsDict["transforms"]
            self.transforms_enabled = self.fieldMappingsDict["transforms_enabled"]

        self.RestrictedPython_BUILTINS = {
            "__name__": "script",
            "_getiter_": default_guarded_getiter,
            "_getattr_": getattr,
            "_getitem_": default_guarded_getitem,
            "base64": base64,
            "re": re,
            "chardet": chardet,
            "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
        }
        self.RestrictedPython_BUILTINS.update(safe_builtins)
        self.RestrictedPython_BUILTINS.update(limited_builtins)
        self.RestrictedPython_BUILTINS.update(utility_builtins)

    def transform_value(self, code, param):
        try:
            # Check if the code has already been compiled
            if code in self.compiled_code_cache:
                byte_code = self.compiled_code_cache[code]
            else:
                # Compile the code and store it in the cache
                byte_code = compile_restricted(
                    code, filename="<inline code>", mode="exec"
                )
                self.compiled_code_cache[code] = byte_code
            # Prepare the execution environment
            TransformFunction = {}
            exec(byte_code, self.RestrictedPython_BUILTINS, TransformFunction)
            return TransformFunction["transform"](param)
        except Exception as e:
            self.logger.debug(f"ERROR: Couldn't apply transform: {e}")
            return param  # Return the original parameter if transform fails

    def process_file(self, file):
        """
        Flatten json object with nested keys into a single level.
        Returns the flattened json object
        """
        self.logger.debug(f"FLATTENING : {file}")
        JSONLine = {}
        JSONOutput = []
        fieldStmt = ""

        def flatten(x, name=""):
            nonlocal fieldStmt
            # If it is a Dict go deeper
            if isinstance(x, dict):
                for a in x:
                    flatten(x[a], name + a + ".")
            else:
                # Applying exclusions. Be careful, the key/value pair is discarded if there is a partial match
                if not any(
                    exclusion in name[:-1] for exclusion in self.fieldExclusions
                ):
                    # Arrays are not expanded
                    if isinstance(x, list):
                        value = "".join(str(x))
                    else:
                        value = x
                    # Excluding useless values (e.g. "null"). The value must be an exact match.
                    if value not in self.uselessValues:

                        # Applying field mappings
                        rawFieldName = name[:-1]
                        if rawFieldName in self.fieldMappings:
                            key = self.fieldMappings[rawFieldName]
                        else:
                            # Removing all annoying character from field name
                            key = "".join(
                                e for e in rawFieldName.split(".")[-1] if e.isalnum()
                            )

                        # Preparing aliases (work on original field name and Mapped field name)
                        keys = [key]
                        for fieldName in [key, rawFieldName]:
                            if fieldName in self.aliases:
                                keys.append(self.aliases[key])

                        # Applying field transforms (work on original field name and Mapped field name)
                        keysThatNeedTransformedValues = []
                        transformedValuesByKeys = {}
                        if self.transforms_enabled:
                            for fieldName in [key, rawFieldName]:
                                if fieldName in self.transforms:
                                    for transform in self.transforms[fieldName]:
                                        if (
                                            transform["enabled"]
                                            and self.chosen_input
                                            in transform["source_condition"]
                                        ):
                                            transformCode = transform["code"]
                                            # If the transform rule ask for a dedicated alias
                                            if transform["alias"]:
                                                keys.append(transform["alias_name"])
                                                keysThatNeedTransformedValues.append(
                                                    transform["alias_name"]
                                                )
                                                transformedValuesByKeys[
                                                    transform["alias_name"]
                                                ] = self.transform_value(
                                                    transformCode, value
                                                )
                                            else:
                                                value = self.transform_value(
                                                    transformCode, value
                                                )

                        # Applying field splitting
                        fieldsToSplit = []
                        if rawFieldName in self.fieldSplitList:
                            fieldsToSplit.append(rawFieldName)
                        if key in self.fieldSplitList:
                            fieldsToSplit.append(key)

                        if len(fieldsToSplit) > 0:
                            for field in fieldsToSplit:
                                try:
                                    splittedFields = value.split(
                                        self.fieldSplitList[field]["separator"]
                                    )
                                    for splittedField in splittedFields:
                                        k, v = splittedField.split(
                                            self.fieldSplitList[field]["equal"]
                                        )
                                        keyLower = k.lower()
                                        JSONLine[k] = v
                                        if keyLower not in self.keyDict:
                                            self.keyDict[keyLower] = k
                                            fieldStmt += f"'{k}' TEXT COLLATE NOCASE,\n"
                                except Exception as e:
                                    self.logger.debug(
                                        f"ERROR : Couldn't apply field splitting, value(s) {str(splittedFields)} : {e}"
                                    )

                        # Applying aliases
                        for key in keys:
                            if key in keysThatNeedTransformedValues:
                                JSONLine[key] = transformedValuesByKeys[key]
                            else:
                                JSONLine[key] = value
                            # Creating the CREATE TABLE SQL statement
                            keyLower = key.lower()
                            if keyLower not in self.keyDict:
                                self.keyDict[keyLower] = key
                                if isinstance(value, int):
                                    fieldStmt += f"'{key}' INTEGER,\n"
                                else:
                                    fieldStmt += f"'{key}' TEXT COLLATE NOCASE,\n"

        # If filesize is not zero
        if os.stat(file).st_size != 0:
            with open(str(file), "r", encoding="utf-8") as JSONFile:
                filename = os.path.basename(file)
                logs = JSONFile
                # If the file is a json array
                if self.JSONArray:
                    try:
                        logs = json.loads(JSONFile.read())
                    except Exception as e:
                        self.logger.debug(f"JSON ARRAY ERROR : {e}")
                        logs = []
                for line in logs:
                    try:
                        if self.JSONArray:
                            dictToFlatten = line
                        else:
                            dictToFlatten = json.loads(line)
                        dictToFlatten.update({"OriginalLogfile": filename})
                        if self.hashes:
                            dictToFlatten.update(
                                {
                                    "OriginalLogLinexxHash": xxhash.xxh64_hexdigest(
                                        line[:-1]
                                    )
                                }
                            )
                        flatten(dictToFlatten)
                    except Exception as e:
                        self.logger.debug(f"JSON ERROR : {e}")
                    # Handle timestamp filters
                    if (
                        self.timeAfter != "1970-01-01T00:00:00"
                        or self.timeBefore != "9999-12-12T23:59:59"
                    ) and (self.timeField in JSONLine):
                        try:
                            timestamp = time.strptime(
                                JSONLine[self.timeField].split(".")[0].replace("Z", ""),
                                "%Y-%m-%dT%H:%M:%S",
                            )
                            if (
                                timestamp > self.timeAfter
                                and timestamp < self.timeBefore
                            ):
                                JSONOutput.append(JSONLine)
                        except Exception:
                            JSONOutput.append(JSONLine)
                    else:
                        JSONOutput.append(JSONLine)
                    JSONLine = {}
        return {"dbFields": fieldStmt, "dbValues": JSONOutput}

    def save_to_file(self, outputFile):
        with open(outputFile, "w", encoding="utf-8") as file:
            for JSONLine in tqdm(self.valuesStmt, colour="yellow"):
                file.write(f'{json.dumps(JSONLine).decode("utf-8")}\n')

    def run(self, EVTXJSONList):
        for evtxJSON in EVTXJSONList:
            if os.stat(evtxJSON).st_size != 0:
                results = self.process_file(evtxJSON)
                self.fieldStmt += results["dbFields"]
                self.valuesStmt += results["dbValues"]


class zircore:
    """Load data into database and apply detection rules"""

    def __init__(
        self,
        noOutput=False,
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
        self.fullResults = []
        self.rule_results = []
        self.ruleset = {}
        self.noOutput = noOutput
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

    def create_db(self, fieldStmt):
        createTableStmt = f"CREATE TABLE logs ( row_id INTEGER, {fieldStmt} PRIMARY KEY(row_id AUTOINCREMENT) );"
        self.logger.debug(f" CREATE : {createTableStmt}")
        if not self.execute_simple_query(createTableStmt):
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
            dbHandle = self.db_connection.cursor()
            self.logger.debug(f"EXECUTING : {query}")
            try:
                dbHandle.execute(query)
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
        dbfileConnection = self.create_connection(db)
        dbfileConnection.backup(self.db_connection)
        dbfileConnection.close()

    def escape_identifier(self, identifier):
        """Escape SQL identifiers like table or column names."""
        return identifier.replace('"', '""')

    def insert_data_to_db(self, JSONLine):
        """Build a parameterized INSERT INTO query and insert data into the database."""
        columns = JSONLine.keys()
        columnsEscaped = ", ".join([self.escape_identifier(col) for col in columns])
        placeholders = ", ".join(["?"] * len(columns))
        values = []
        for col in columns:
            value = JSONLine[col]
            if isinstance(value, int):
                # Check if value exceeds SQLite INTEGER limits
                if abs(value) > 9223372036854775807:
                    value = str(value)  # Convert to string
            values.append(value)
        insertStmt = f"INSERT INTO logs ({columnsEscaped}) VALUES ({placeholders})"
        try:
            self.db_connection.execute(insertStmt, values)
            return True
        except Exception as e:
            self.logger.debug(f"   [-] {e}")
            return False

    def insert_flat_json_to_db(self, flattenedJSON):
        for JSONLine in flattenedJSON:
            self.insert_data_to_db(JSONLine)

    def save_db_to_disk(self, dbFilename):
        self.logger.info("[+] Saving working data to disk as a SQLite DB")
        onDiskDb = sqlite3.connect(dbFilename)
        self.db_connection.backup(onDiskDb)
        onDiskDb.close()

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

        filteredRows = []

        # Process each SQL query in the rule
        for SQLQuery in sigma_queries:
            data = self.execute_select_query(SQLQuery)
            if data:
                if self.csv_output:
                    # Clean values for CSV output
                    cleaned_rows = [
                        {
                            k: str(v)
                            .replace("\n", "")
                            .replace("\r", "")
                            .replace("None", "")
                            for k, v in dict(row).items()
                        }
                        for row in data
                    ]
                else:
                    # Remove None values
                    cleaned_rows = [
                        {k: v for k, v in dict(row).items() if v is not None}
                        for row in data
                    ]
                filteredRows.extend(cleaned_rows)

        if filteredRows:
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
                "count": len(filteredRows),
                "matches": filteredRows,
            }

            if not self.csv_output:
                json_bytes = json.dumps(results)
                self.tmp_file.write(f"{json_bytes.decode('utf-8')}\n")

            self.logger.debug(
                f"DETECTED: {title} - Matches: {len(filteredRows)} events"
            )
            return results
        else:
            return {}

    def load_ruleset_from_var(self, ruleset, ruleFilters):
        self.ruleset = ruleset
        self.apply_ruleset_filters(ruleFilters)

    def apply_ruleset_filters(self, ruleFilters=None):
        # Remove empty rule and remove filtered rules
        self.ruleset = list(filter(None, self.ruleset))
        if ruleFilters is not None:
            self.ruleset = [
                rule
                for rule in self.ruleset
                if not any(ruleFilter in rule["title"] for ruleFilter in ruleFilters)
            ]

    def execute_ruleset(self):
        """
        Execute all rules in the ruleset and handle output.
        """

        for rule in self.ruleset:

            # Execute the rule
            ruleResults = self.execute_rule(rule)
            if not ruleResults:
                continue  # No matches, skip to next rule

            # Apply limit if set
            if self.limit != -1 and ruleResults["count"] > self.limit:
                continue  # Exceeds limit, skip this result

            # Store if the rule has matched : title, level, count only
            self.rule_results.append(
                {
                    "rule_title": ruleResults["title"],
                    "rule_level": ruleResults["rule_level"],
                    "rule_count": ruleResults["count"],
                }
            )

            # self.fullResults.append(ruleResults)

        self.tmp_file.close()


class evtx_extractor:

    def __init__(
        self,
        providedTmpDir=None,
        cores=None,
        use_external_binaries=True,
        binaries_path=None,
        encoding=None,
        input_format=None,
    ):
        self.logger = logging.getLogger(__name__)

        if Path(str(providedTmpDir)).is_dir():
            self.tmpDir = f"tmp-{self.rand_string()}"
            self.logger.error(
                f"{Fore.RED}   [-] Provided directory already exists using '{self.tmpDir}' instead{Fore.RESET}"
            )
        else:
            self.tmpDir = providedTmpDir or f"tmp-{self.rand_string()}"
            os.mkdir(self.tmpDir)

        self.cores = cores or os.cpu_count()
        self.use_external_binaries = use_external_binaries
        self.sysmon4linux = False
        self.xmlLogs = False
        self.csvInput = False
        self.auditdLogs = False
        self.evtxtract = False

        if input_format == "sysmon_linux_input":
            self.sysmon4linux = True
        elif input_format == "xml_input":
            self.xmlLogs = True
        elif input_format == "csv_input":
            self.csvInput = True
        elif input_format == "auditd_input":
            self.auditdLogs = True
        elif input_format == "evtxtract_input":
            self.evtxtract = True

        # Hardcoded hash list of evtx_dump binaries
        self.validHashList = [
            "bbcce464533e0364",
            "e642f5c23e156deb",
            "5a7a1005885a1a11",
        ]

        # Sysmon 4 Linux default encoding is ISO-8859-1, Auditd is UTF-8
        if not encoding and self.sysmon4linux:
            self.encoding = "ISO-8859-1"
        elif not encoding and (self.auditdLogs or self.evtxtract or self.xmlLogs):
            self.encoding = "utf-8"
        else:
            self.encoding = encoding

        self.evtx_dump_cmd = self.getOSExternalTools(binaries_path)

    def rand_string(self, length=8):
        return "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(length)
        )

    def getOSExternalTools(self, binPath):
        """Determine which binaries to run depending on host OS : 32Bits is NOT supported for now since evtx_dump is 64bits only"""
        if binPath is None:
            if _platform == "linux" or _platform == "linux2":
                return "bin/evtx_dump_lin"
            elif _platform == "darwin":
                return "bin/evtx_dump_mac"
            elif _platform == "win32":
                return "bin\\evtx_dump_win.exe"
        else:
            return binPath

    def runUsingBindings(self, file):
        """
        Convert EVTX to JSON using evtx_dump bindings (slower)
        Drop resulting JSON files in a tmp folder.
        """
        if not self.use_external_binaries:
            try:
                filepath = Path(file)
                filename = filepath.name
                parser = PyEvtxParser(str(filepath))
                with open(
                    f"{self.tmpDir}/{str(filename)}-{self.rand_string()}.json",
                    "w",
                    encoding="utf-8",
                ) as f:
                    for record in parser.records_json():
                        f.write(
                            f'{json.dumps(json.loads(record["data"])).decode("utf-8")}\n'
                        )
            except Exception as e:
                self.logger.error(
                    f"{Fore.RED}   [-] Cannot use PyEvtxParser : {e}{Fore.RESET}"
                )
        else:
            self.logger.error(
                f"{Fore.RED}   [-] Cannot use PyEvtxParser and evtx_dump is disabled or missing{Fore.RESET}"
            )

    def getTime(self, line):
        timestamp = line.replace("msg=audit(", "").replace("):", "").split(":")
        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(float(timestamp[0]))
        )
        return timestamp

    def auditdLine2JSON(self, auditdLine):
        """
        Convert auditd logs to JSON : code from https://github.com/csark/audit2json
        """
        event = {}
        # According to auditd specs https://github.com/linux-audit/audit-documentation/wiki/SPEC-Audit-Event-Enrichment
        # a GS ASCII character, 0x1D, will be inserted to separate original and translated fields
        # Best way to deal with it is to remove it.
        attributes = auditdLine.replace("\x1d", " ").split(" ")
        for attribute in attributes:
            if "msg=audit" in attribute:
                event["timestamp"] = self.getTime(attribute)
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

    def SysmonXMLLine2JSON(self, xmlLine):
        """
        Remove syslog header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        if "Event" not in xmlLine:
            return None
        xmlLine = "<Event>" + xmlLine.split("<Event>")[1]
        try:  # isolate individual line parsing errors
            root = etree.fromstring(xmlLine)
            return self.xml2dict(root)
        except Exception as ex:
            self.logger.debug(f'Unable to parse line "{xmlLine}": {ex}')
            return None

    def XMLLine2JSON(self, xmlLine):
        """
        Remove "Events" header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        if "<Event " not in xmlLine:
            return None
        try:  # isolate individual line parsing errors
            root = etree.fromstring(xmlLine)
            return self.xml2dict(
                root, "{http://schemas.microsoft.com/win/2004/08/events/event}"
            )
        except Exception as ex:
            self.logger.debug(f'Unable to parse line "{xmlLine}": {ex}')
            return None

    def xml2dict(
        self, eventRoot, ns="http://schemas.microsoft.com/win/2004/08/events/event"
    ):

        def cleanTag(tag, ns):
            if ns in tag:
                return tag[len(ns) :]
            return tag

        child = {"#attributes": {"xmlns": ns}}
        for appt in eventRoot.getchildren():
            nodename = cleanTag(appt.tag, ns)
            nodevalue = {}
            for elem in appt.getchildren():
                cleanedTag = cleanTag(elem.tag, ns)
                if not elem.text:
                    text = ""
                else:
                    try:
                        text = int(elem.text)
                    except Exception:
                        text = elem.text
                if cleanedTag == "Data":
                    childnode = elem.get("Name")
                elif cleanedTag == "Qualifiers":
                    text = elem.text
                else:
                    childnode = cleanedTag
                    if elem.attrib:
                        text = {"#attributes": dict(elem.attrib)}
                obj = {str(childnode): text}
                nodevalue = {**nodevalue, **obj}
            node = {str(nodename): nodevalue}
            child = {**child, **node}
        event = {"Event": child}
        return event

    def Logs2JSON(self, func, datasource, outfile, isFile=True):
        """
        Use multiprocessing to convert supported log formats to JSON
        """

        if isFile:
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
                    fp.write(json.dumps(element).decode("utf-8") + "\n")

    def csv2JSON(self, CSVPath, JSONPath):
        """
        Convert CSV Logs to JSON
        """
        with open(CSVPath, encoding="utf-8") as CSVFile:
            csvReader = csv.DictReader(CSVFile)
            with open(JSONPath, "w", encoding="utf-8") as JSONFile:
                for row in csvReader:
                    JSONFile.write(json.dumps(row).decode("utf-8") + "\n")

    def evtxtract2JSON(self, file, outfile):
        """
        Convert EXVTXtract Logs to JSON using xml2dict and "dumps" it to a file
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
                    extractedEvent = self.xml2dict(
                        event, "{http://schemas.microsoft.com/win/2004/08/events/event}"
                    )
                    fp.write(json.dumps(extractedEvent).decode("utf-8") + "\n")

    def verifyBinHash(self, binPath):
        """
        Verify the hash of a binary (Hashes are hardcoded)
        """
        hasher = xxhash.xxh64()
        try:
            # Open the file in binary mode and read chunks to hash
            with open(binPath, "rb") as f:
                while chunk := f.read(4096):  # Read chunks of 4096 bytes
                    hasher.update(chunk)  # Update the hash with the chunk
            if hasher.hexdigest() in self.validHashList:
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
        outputJSONFilename = f"{self.tmpDir}/{str(filename)}-{self.rand_string()}.json"
        # Auditd or Sysmon4Linux logs
        if self.sysmon4linux or self.auditdLogs:
            # Choose which log backend to use
            if self.sysmon4linux:
                func = self.SysmonXMLLine2JSON
            elif self.auditdLogs:
                func = self.auditdLine2JSON
            try:
                self.Logs2JSON(func, str(file), outputJSONFilename)
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # XML logs
        elif self.xmlLogs:
            try:
                data = ""
                # We need to read the entire file to remove annoying newlines and fields with newlines (System.evtx Logs for example...)
                with open(str(file), "r", encoding="utf-8") as XMLFile:
                    data = (
                        XMLFile.read()
                        .replace("\n", "")
                        .replace("</Event>", "</Event>\n")
                        .replace("<Event ", "\n<Event ")
                    )
                self.Logs2JSON(
                    self.XMLLine2JSON, data, outputJSONFilename, isFile=False
                )
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # EVTXtract
        elif self.evtxtract:
            try:
                self.evtxtract2JSON(str(file), outputJSONFilename)
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # CSV
        elif self.csvInput:
            try:
                self.csv2JSON(str(file), outputJSONFilename)
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # EVTX
        else:
            if not self.use_external_binaries or not Path(self.evtx_dump_cmd).is_file():
                self.logger.debug(
                    "   [-] No external binaries args or evtx_dump is missing"
                )
                self.runUsingBindings(file)
            else:
                # Check if the binary is valid does not avoid TOCTOU
                if self.verifyBinHash(self.evtx_dump_cmd):
                    try:
                        cmd = [
                            self.evtx_dump_cmd,
                            "--no-confirm-overwrite",
                            "-o",
                            "jsonl",
                            str(file),
                            "-f",
                            outputJSONFilename,
                            "-t",
                            str(self.cores),
                        ]
                        subprocess.call(
                            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                        )
                    except Exception as e:
                        self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")

    def cleanup(self):
        shutil.rmtree(self.tmpDir)


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
        self.tempFile = f"tmp-rules-{self.rand_string()}.zip"
        self.tmpDir = f"tmp-rules-{self.rand_string()}"
        self.updatedRulesets = []

    def rand_string(self, length=4):
        return "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(length)
        )

    def download(self):
        resp = requests.get(self.url, stream=True)
        total = int(resp.headers.get("content-length", 0))
        with open(self.tempFile, "wb") as file, tqdm(
            desc=self.tempFile,
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
        shutil.unpack_archive(self.tempFile, self.tmpDir, "zip")

    def checkIfNewerAndMove(self):
        count = 0
        rulesets = Path(self.tmpDir).rglob("*.json")
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
                self.updatedRulesets.append(f"rules/{ruleset.name}")
                self.logger.info(
                    f"{Fore.CYAN}   [+] Updated : rules/{ruleset.name}{Fore.RESET}"
                )
        if count == 0:
            self.logger.info(f"{Fore.CYAN}   [+] No newer rulesets found")

    def clean(self):
        os.remove(self.tempFile)
        shutil.rmtree(self.tmpDir)

    def run(self):
        try:
            self.download()
            self.unzip()
            self.checkIfNewerAndMove()
            self.clean()
        except Exception as e:
            self.logger.error(f"   [-] {e}")


class ruleset_handler:

    def __init__(self, config=None, listPipelineOnly=False):
        self.logger = logging.getLogger(__name__)
        self.saveRuleset = config.save_ruleset
        self.rulesetPathList = config.ruleset
        self.cores = config.cores or os.cpu_count()
        self.sigmaConversionDisabled = config.no_sigma_conversion
        self.pipelines = []

        if self.sigmaConversionDisabled:
            self.logger.info(
                f"{Fore.LIGHTYELLOW_EX}   [i] Sigma conversion is disabled (missing imports) ! {Fore.RESET}"
            )
        else:
            # Init pipelines
            plugins = InstalledSigmaPlugins.autodiscover()
            pipeline_resolver = plugins.get_pipeline_resolver()
            pipeline_list = list(pipeline_resolver.pipelines.keys())

            if listPipelineOnly:
                self.logger.info(
                    "[+] Installed pipelines : "
                    + ", ".join(pipeline_list)
                    + "\n    You can install pipelines with your Python package manager"
                    + "\n    e.g : pip install pysigma-pipeline-sysmon"
                )
            else:
                # Resolving pipelines
                if config.pipeline:
                    for pipelineName in [
                        item for pipeline in config.pipeline for item in pipeline
                    ]:  # Flatten the list of pipeline names list
                        if pipelineName in pipeline_list:
                            self.pipelines.append(plugins.pipelines[pipelineName]())
                        else:
                            self.logger.error(
                                f"{Fore.RED}   [-] {pipelineName} not found. You can list installed pipelines with '--pipeline-list'{Fore.RESET}"
                            )

        # Parse & (if necessary) convert ruleset, final list is stored in self.Rulesets
        self.Rulesets = self.rulesetParsing()

        # Combining Rulesets
        # if config.combine_rulesets:
        self.Rulesets = [
            item for subRuleset in self.Rulesets if subRuleset for item in subRuleset
        ]
        # Remove duplicates based on 'id' or 'title'
        unique_rules = []
        seen_keys = set()
        for rule in self.Rulesets:
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
        self.Rulesets = sorted(
            unique_rules,
            key=lambda d: level_order.get(
                d.get("level", "informational"), float("inf")
            ),
        )  # Sorting by level

        if len(self.Rulesets) == 0:
            self.logger.error(f"{Fore.RED}   [-] No rules to execute !{Fore.RESET}")

    def isYAML(self, filepath):
        """Test if the file is a YAML file"""
        if filepath.suffix == ".yml" or filepath.suffix == ".yaml":
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()
                try:
                    yaml.safe_load(content)
                    return True
                except yaml.YAMLError:
                    return False

    def isJSON(self, filepath):
        """Test if the file is a JSON file"""
        if filepath.suffix == ".json":
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()
                try:
                    json.loads(content)
                    return True
                except json.JSONDecodeError:
                    return False

    def randRulesetName(self, sigmaRules):
        # Clean the ruleset name
        cleanedName = "".join(
            char if char.isalnum() else "-" for char in sigmaRules
        ).strip("-")
        cleanedName = re.sub(r"-+", "-", cleanedName)
        # Generate a random string
        randomString = "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(8)
        )
        return f"ruleset-{cleanedName}-{randomString}.json"

    def convertSigmaRules(self, backend, rule):
        try:
            return backend.convert_rule(rule, "zircolite")[0]
        except Exception as e:
            self.logger.debug(
                f"{Fore.RED}   [-] Cannot convert rule '{str(rule)}' : {e}{Fore.RESET}"
            )

    def sigmaRulesToRuleset(self, SigmaRulesList, pipelines):
        for sigmaRules in SigmaRulesList:
            # Create the pipeline resolver
            piperesolver = ProcessingPipelineResolver()
            # Add pipelines
            for pipeline in pipelines:
                piperesolver.add_pipeline_class(pipeline)
            # Create a single sorted and prioritized pipeline
            combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
            # Instantiate backend, using our resolved pipeline
            sqlite_backend = sqlite.sqliteBackend(combined_pipeline)

            rules = Path(sigmaRules)
            if rules.is_dir():
                rule_list = list(rules.rglob("*.yml")) + list(rules.rglob("*.yaml"))
            else:
                rule_list = [rules]

            rule_collection = SigmaCollection.load_ruleset(rule_list)
            ruleset = []

            pool = mp.Pool(self.cores)
            ruleset = pool.map(
                functools.partial(self.convertSigmaRules, sqlite_backend),
                tqdm(rule_collection, colour="yellow"),
            )
            pool.close()
            pool.join()
            ruleset = [
                rule for rule in ruleset if rule is not None
            ]  # Removing empty results
            ruleset = sorted(ruleset, key=lambda d: d["level"])  # Sorting by level

            if self.saveRuleset:
                tempRulesetName = self.randRulesetName(str(sigmaRules))
                with open(tempRulesetName, "w") as outfile:
                    outfile.write(
                        json.dumps(ruleset, option=json.OPT_INDENT_2).decode("utf-8")
                    )
                    self.logger.info(
                        f"{Fore.CYAN}   [+] Saved ruleset as : {tempRulesetName}{Fore.RESET}"
                    )

        return ruleset

    def rulesetParsing(self):
        rulesetList = []
        for ruleset in self.rulesetPathList:
            rulesetPath = Path(ruleset)
            if rulesetPath.exists():
                if rulesetPath.is_file():
                    if self.isJSON(rulesetPath):  # JSON Ruleset
                        try:
                            with open(rulesetPath, encoding="utf-8") as f:
                                rulesetList.append(json.loads(f.read()))
                            self.logger.info(
                                f"{Fore.CYAN}   [+] Loaded JSON/Zircolite ruleset : {str(rulesetPath)}{Fore.RESET}"
                            )
                        except Exception as e:
                            self.logger.error(
                                f"{Fore.RED}   [-] Cannot load {str(rulesetPath)} {e}{Fore.RESET}"
                            )
                    else:  # YAML Ruleset
                        if not self.sigmaConversionDisabled and self.isYAML(
                            rulesetPath
                        ):
                            try:
                                self.logger.info(
                                    f"{Fore.CYAN}   [+] Converting Native Sigma to Zircolite ruleset : {str(rulesetPath)}{Fore.RESET}"
                                )
                                rulesetList.append(
                                    self.sigmaRulesToRuleset(
                                        [rulesetPath], self.pipelines
                                    )
                                )
                            except Exception as e:
                                self.logger.error(
                                    f"{Fore.RED}   [-] Cannot convert {str(rulesetPath)} {e}{Fore.RESET}"
                                )
                elif (
                    not self.sigmaConversionDisabled and rulesetPath.is_dir()
                ):  # Directory
                    try:
                        self.logger.info(
                            f"{Fore.CYAN}   [+] Converting Native Sigma to Zircolite ruleset : {str(rulesetPath)}{Fore.RESET}"
                        )
                        rulesetList.append(
                            self.sigmaRulesToRuleset([rulesetPath], self.pipelines)
                        )
                    except Exception as e:
                        self.logger.error(
                            f"{Fore.RED}   [-] Cannot convert {str(rulesetPath)} {e}{Fore.RESET}"
                        )
        return rulesetList


def selectFiles(pathList, selectFilesList):
    if selectFilesList is not None:
        return [
            logs
            for logs in [str(element) for element in list(pathList)]
            if any(
                fileFilters[0].lower() in logs.lower()
                for fileFilters in selectFilesList
            )
        ]
    return pathList


def avoidFiles(pathList, avoidFilesList):
    if avoidFilesList is not None:
        return [
            logs
            for logs in [str(element) for element in list(pathList)]
            if all(
                fileFilters[0].lower() not in logs.lower()
                for fileFilters in avoidFilesList
            )
        ]
    return pathList


def ImportErrorHandler(config):
    importErrorList = []

    if updateDisabled:
        importErrorList.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'requests', events update is disabled{Fore.RESET}"
        )
        config.update_rules = False
    if sigmaConversionDisabled:
        importErrorList.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'sigma' from pySigma, ruleset conversion YAML -> JSON is disabled{Fore.RESET}"
        )
        config.no_sigma_conversion = True
    if pyevtxDisabled:
        importErrorList.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'evtx' from pyevtx-rs, use of external binaries is mandatory{Fore.RESET}"
        )
        config.noexternal = False
    if jinja2Disabled:
        importErrorList.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'jinja2', templating is disabled{Fore.RESET}"
        )
        config.template = None
    if xmlImportDisabled:
        importErrorList.append(
            f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'lxml', cannot use XML logs as input{Fore.RESET}"
        )
        if config.xml:
            return (
                f"{Fore.RED}   [-] Cannot import 'lxml', but according to command line provided it is needed{Fore.RESET}",
                config,
                True,
            )

    if config.debug or config.imports:
        return "\n".join(importErrorList), config, False

    if importErrorList == []:
        return "", config, False

    return (
        f"{Fore.LIGHTYELLOW_EX}   [i] Import errors, certain functionalities may be disabled ('--imports' for details)\n       Supplemental imports can be installed with 'requirements.full.txt'{Fore.RESET}",
        config,
        False,
    )


def runner(file, params):
    """Runner function to flatten events and apply rules with multiprocessing"""

    flattener = json_flattener(
        configFile=params["config"],
        timeAfter=params["events_after"],
        timeBefore=params["events_before"],
        timeField=params["timefield"],
        hashes=params["hashes"],
        input_format=params["input_format"],
    )

    flattener.run([file])

    # Save the flattened JSON to a file
    if params["keepflat"]:
        flattener.save_to_file(f"flattened_events_{rand_string(4)}.json")

    # Initialize zircore
    filename = os.path.basename(file)
    if params["on_disk_db"]:
        db_location = f"{filename}-{rand_string(4)}.db"
    else:
        db_location = f"file:{filename}?mode=memory&cache=shared"

    zircolite_core = zircore(
        limit=params["limit"],
        csv_output=params["csv_output"],
        db_location=db_location,
        delimiter=params["delimiter"],
        tmp_directory=params["tmp_directory"],
        tmp_directory_db=params["tmp_directory_db"],
    )

    zircolite_core.create_db(flattener.fieldStmt)
    zircolite_core.insert_flat_json_to_db(flattener.valuesStmt)
    del flattener
    zircolite_core.create_index()

    ruleset = params["rulesets"]
    zircolite_core.load_ruleset_from_var(
        ruleset=ruleset, ruleFilters=params["rulefilter"]
    )
    zircolite_core.execute_ruleset()
    zircolite_core.close()

    return zircolite_core.fullResults, zircolite_core.rule_results


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
        help="Log file or directory where log files are stored in supported format",
        type=str,
    )
    logsInputArgs.add_argument(
        "-s",
        "--select",
        help="Only files with filenames containing the provided string will be used. If there is/are exclusion(s) (--avoid) they will be handled after selection",
        action="append",
        nargs="+",
    )
    logsInputArgs.add_argument(
        "-a",
        "--avoid",
        help="Files files with filenames containing the provided string will NOT be used",
        action="append",
        nargs="+",
    )
    logsInputArgs.add_argument(
        "-f", "--fileext", help="Extension of the log files", type=str
    )
    logsInputArgs.add_argument(
        "-fp",
        "--file-pattern",
        help="Use a Python Glob pattern to select files. This option only works with directories",
        type=str,
    )
    logsInputArgs.add_argument(
        "--no-recursion",
        help="By default Zircolite search log/event files recursively, by using this option only the provided directory will be used",
        action="store_true",
    )
    # Events filtering options
    eventArgs = parser.add_argument_group(
        f"{Fore.BLUE}EVENTS FILTERING OPTIONS{Fore.RESET}"
    )
    eventArgs.add_argument(
        "-A",
        "--after",
        help="Limit to events that happened after the provided timestamp (UTC). Format : 1970-01-01T00:00:00",
        type=str,
        default="1970-01-01T00:00:00",
    )
    eventArgs.add_argument(
        "-B",
        "--before",
        help="Limit to events that happened before the provided timestamp (UTC). Format : 1970-01-01T00:00:00",
        type=str,
        default="9999-12-12T23:59:59",
    )
    # Event and log formats options
    # /!\ an option name containing '-input' must exists (It is used in JSON flattening mechanism)
    eventFormatsArgs = parser.add_mutually_exclusive_group()
    eventFormatsArgs.add_argument(
        "-j",
        "--json-input",
        "--jsononly",
        "--jsonline",
        "--jsonl",
        help="If logs files are already in JSON lines format ('jsonl' in evtx_dump) ",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "--json-array-input",
        "--jsonarray",
        "--json-array",
        help="Source logs are in JSON but as an array",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "-S",
        "--sysmon-linux-input",
        "--sysmon4linux",
        "--sysmon-linux",
        help="Use this option if your log file is a Sysmon for linux log file, default file extension is '.log'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "-AU",
        "--auditd-input",
        "--auditd",
        help="Use this option if your log file is a Auditd log file, default file extension is '.log'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "-x",
        "--xml-input",
        "--xml",
        help="Use this option if your log file is a EVTX converted to XML log file, default file extension is '.xml'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "--evtxtract-input",
        "--evtxtract",
        help="Use this option if your log file was extracted with EVTXtract, default file extension is '.log'",
        action="store_true",
    )
    eventFormatsArgs.add_argument(
        "--csv-input",
        "--csvonly",
        help="You log file is in CSV format '.csv'",
        action="store_true",
    )
    # Ruleset options
    rulesetsFormatsArgs = parser.add_argument_group(
        f"{Fore.BLUE}RULES AND RULESETS OPTIONS{Fore.RESET}"
    )
    rulesetsFormatsArgs.add_argument(
        "-r",
        "--ruleset",
        help="Sigma ruleset : JSON (Zircolite format) or YAML/Directory containing YAML files (Native Sigma format)",
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
        help="For all the native Sigma rulesets (YAML) use this pipeline. Multiple can be used. Examples : 'sysmon', 'windows-logsources', 'windows-audit'. You can list installed pipelines with '--pipeline-list'.",
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
        help="For all the native Sigma rulesets (YAML) don't use any pipeline (Default)",
        action="store_true",
    )
    rulesetsFormatsArgs.add_argument(
        "-R",
        "--rulefilter",
        help="Remove rule from ruleset, comparison is done on rule title (case sensitive)",
        action="append",
        nargs="*",
    )
    # Ouput formats and output files options
    outputFormatsArgs = parser.add_argument_group(
        f"{Fore.BLUE}OUPUT FORMATS AND OUTPUT FILES OPTIONS{Fore.RESET}"
    )
    outputFormatsArgs.add_argument(
        "-o",
        "--outfile",
        help="File that will contains all detected events",
        type=str,
        default="detected_events.json",
    )
    outputFormatsArgs.add_argument(
        "--csv",
        "--csv-output",
        help="The output will be in CSV. You should note that in this mode empty fields will not be discarded from results",
        action="store_true",
    )
    outputFormatsArgs.add_argument(
        "--csv-delimiter",
        help="Choose the delimiter for CSV ouput",
        type=str,
        default=";",
    )
    outputFormatsArgs.add_argument(
        "-t",
        "--tmpdir",
        help="Temp directory that will contains events converted as JSON (parent directories must exist)",
        type=str,
    )
    outputFormatsArgs.add_argument(
        "-k",
        "--keeptmp",
        help="Do not remove the temp directory containing events converted in JSON format",
        action="store_true",
    )
    outputFormatsArgs.add_argument(
        "--keepflat", help="Save flattened events as JSON", action="store_true"
    )
    outputFormatsArgs.add_argument(
        "-d",
        "--dbfile",
        help="Save all logs in a SQLite Db to the specified file",
        type=str,
    )
    outputFormatsArgs.add_argument(
        "-l", "--logfile", help="Log file name", default="zircolite.log", type=str
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
        help="Discard results that are above the provided limit",
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
        help="JSON File containing field mappings and exclusions",
        type=str,
        default="config/fieldMappings.json",
    )
    eventFormatsArgs.add_argument(
        "-LE",
        "--logs-encoding",
        help="Specify log encoding when dealing with Sysmon for Linux or Auditd files",
        type=str,
    )
    configFormatsArgs.add_argument(
        "--fieldlist", help="Get all events fields", action="store_true"
    )
    configFormatsArgs.add_argument(
        "--evtx_dump",
        help="Tell Zircolite to use this binary for EVTX conversion, on Linux and MacOS the path must be valid to launch the binary (eg. './evtx_dump' and not 'evtx_dump')",
        type=str,
        default=None,
    )
    configFormatsArgs.add_argument(
        "--noexternal",
        "--bindings",
        help="Don't use evtx_dump external binaries (slower)",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "--cores",
        help="Specify how many cores you want to use, default is all cores, works only for EVTX extraction",
        default=os.cpu_count(),
        type=int,
    )
    configFormatsArgs.add_argument(
        "--debug", help="Activate debug logging", action="store_true"
    )
    configFormatsArgs.add_argument(
        "--imports", help="Show detailed module import errors", action="store_true"
    )
    configFormatsArgs.add_argument(
        "--ondiskdb",
        "--on-disk-db",
        help="Use an on-disk database instead of the in-memory one (much slower !). Use if your system has limited RAM or if your dataset is very large and you cannot split it",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "-RE",
        "--remove-events",
        help="Zircolite will try to remove events/logs submitted if analysis is successful (use at your own risk)",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "-U",
        "--update-rules",
        help="Update rulesets located in the 'rules' directory",
        action="store_true",
    )
    configFormatsArgs.add_argument(
        "-v", "--version", help="Show Zircolite version", action="store_true"
    )
    configFormatsArgs.add_argument(
        "--timefield",
        help="Use this option to provide timestamp field name, default is 'SystemTime'",
        default="SystemTime",
        action="store_true",
    )

    # Templating and Mini GUI options
    templatingFormatsArgs = parser.add_argument_group(
        f"{Fore.BLUE}TEMPLATING AND MINI GUI OPTIONS{Fore.RESET}"
    )
    templatingFormatsArgs.add_argument(
        "--template",
        help="If a Jinja2 template is specified it will be used to generated output",
        type=str,
        action="append",
        nargs="+",
    )
    templatingFormatsArgs.add_argument(
        "--templateOutput",
        help="If a Jinja2 template is specified it will be used to generate a crafted output",
        type=str,
        action="append",
        nargs="+",
    )
    templatingFormatsArgs.add_argument(
        "--package", help="Create a ZircoGui/Mini Gui package", action="store_true"
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
    importsMessage, args, mustQuit = ImportErrorHandler(args)
    if importsMessage != "":
        logger.info(f"[+] Modules imports status: \n{importsMessage}")
    else:
        logger.info("[+] Modules imports status: OK")
    if mustQuit:
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

    # Loading rulesets
    logger.info("[+] Loading ruleset(s)")
    rulesetsManager = ruleset_handler(args, args.pipeline_list)
    if args.pipeline_list:
        sys.exit(0)

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
        quitOnError(
            f"{Fore.RED}   [-] Wrong timestamp format. Please use 'AAAA-MM-DDTHH:MM:SS'"
        )

    # Check templates args
    readyForTemplating = False
    if args.template is not None:
        if args.csv:
            quitOnError(
                f"{Fore.RED}   [-] You cannot use templates in CSV mode{Fore.RESET}"
            )
        if (args.templateOutput is None) or (
            len(args.template) != len(args.templateOutput)
        ):
            quitOnError(
                f"{Fore.RED}   [-] Number of templates output must match number of templates{Fore.RESET}"
            )
        for template in args.template:
            checkIfExists(
                template[0],
                f"{Fore.RED}   [-] Cannot find template : {template[0]}. DEfault templates are available here : https://github.com/wagga40/Zircolite/tree/master/templates{Fore.RESET}",
            )
        readyForTemplating = True

    # Change output filename in CSV mode
    if args.csv:
        readyForTemplating = False
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

    LogPath = Path(args.events)
    if LogPath.is_dir():
        # Log recursive search in given directory with given file extension or pattern
        pattern = f"*.{args.fileext}"
        # If a Glob pattern is provided
        if args.file_pattern not in [None, ""]:
            pattern = args.file_pattern
        fnGlob = LogPath.rglob
        # If directory recursion is not wanted
        if args.no_recursion:
            fnGlob = LogPath.glob
        LogList = list(fnGlob(pattern))
    elif LogPath.is_file():
        LogList = [LogPath]
    else:
        quitOnError(
            f"{Fore.RED}   [-] Unable to find events from submitted path{Fore.RESET}"
        )

    # Applying file filters in this order : "select" than "avoid"
    FileList = avoidFiles(selectFiles(LogList, args.select), args.avoid)
    if len(FileList) <= 0:
        quitOnError(
            f"{Fore.RED}   [-] No file found. Please verify filters, directory or the extension with '--fileext' or '--file-pattern'{Fore.RESET}"
        )

    args_dict = vars(args)
    # Find the chosen input format
    chosen_input = next(
        (key for key, value in args_dict.items() if "_input" in key and value), None
    )

    if not args.json_input and not args.json_array_input:
        # Init EVTX extractor object
        extractor = evtx_extractor(
            providedTmpDir=args.tmpdir,
            cores=args.cores,
            use_external_binaries=(not args.noexternal),
            binaries_path=args.evtx_dump,
            encoding=args.logs_encoding,
            input_format=chosen_input,
        )
        logger.info(f"[+] Extracting events using '{extractor.tmpDir}' directory ")
        for evtx in tqdm(FileList, colour="yellow"):
            extractor.run(evtx)
        # Set the path for the next step
        LogJSONList = list(Path(extractor.tmpDir).rglob("*.json"))
    else:
        LogJSONList = FileList

    checkIfExists(
        args.config,
        f"{Fore.RED}   [-] Cannot find mapping file, you can get the default one here : https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json {Fore.RESET}",
    )
    if LogJSONList == []:
        quitOnError(f"{Fore.RED}   [-] No files containing logs found.{Fore.RESET}")

    # TODO : Add option for already flattened event
    logger.info(
        f"[+] Processing events and applying {Fore.CYAN}{len(rulesetsManager.Rulesets)}{Fore.RESET} rules"
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
        "rulesets": rulesetsManager.Rulesets,
        "tmp_directory": tmp_directory,
        "tmp_directory_db": tmp_directory_db,
    }

    params_map = []
    for file in LogJSONList:
        params_map.append((file, param_list))

    all_full_results = []
    all_rule_results = []
    # Perform the JSON flattening and the detection process with multiprocessing
    pool = mp.Pool(args.cores)
    with tqdm(total=len(params_map), colour="yellow") as pbar:
        for full_results, rule_results in pool.imap_unordered(
            runner_wrapper, params_map
        ):
            all_full_results.extend(full_results)
            all_rule_results.extend(rule_results)
            pbar.update()
    pool.close()
    pool.join()

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
    if readyForTemplating and all_full_results != []:
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
        for logs in LogList:
            try:
                os.remove(logs)
            except OSError as e:
                logger.error(f"{Fore.RED}   [-] Cannot remove files {e}{Fore.RESET}")

    logger.info(f"\nFinished in {int((time.time() - start_time))} seconds")


if __name__ == "__main__":
    main()
