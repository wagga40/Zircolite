#!python3

# Standard libs
import argparse
import base64
import chardet
import csv
import functools
import hashlib
import logging
import multiprocessing as mp
import os
import platform
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
    updateDisabled =  True

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

def quitOnError(message, logger=None):
    logger.error(message)
    sys.exit(1)

def checkIfExists(path, errorMessage, logger=None):
    """Test if path provided is a file"""
    if not (Path(path).is_file()):
        quitOnError(errorMessage, logger)

def initLogger(debugMode, logFile=None):
    fileLogLevel = logging.INFO
    fileLogFormat = "%(asctime)s %(levelname)-8s %(message)s"
    if debugMode:
        fileLogLevel = logging.DEBUG
        fileLogFormat = "%(asctime)s %(levelname)-8s %(module)s:%(lineno)s %(funcName)s %(message)s"

    if logFile is not None:
        logging.basicConfig(format=fileLogFormat, filename=logFile, level=fileLogLevel, datefmt='%Y-%m-%d %H:%M:%S')
        logger = logging.StreamHandler()
        formatter = logging.Formatter('%(message)s')
        logger.setFormatter(formatter)
        logger.setLevel(logging.INFO)
        logging.getLogger().addHandler(logger)
    else:
        logging.basicConfig(format='%(message)s', level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')        
    
    return logging.getLogger()

class templateEngine:
    def __init__(self, logger=None, template=[], templateOutput=[], timeField=""):
        self.logger = logger or logging.getLogger(__name__)
        self.template = template
        self.templateOutput = templateOutput
        self.timeField = timeField
    
    def generateFromTemplate(self, templateFile, outputFilename, data):
        """ Use Jinja2 to output data in a specific format """
        try:
            tmpl = open(templateFile, 'r', encoding='utf-8')
            template = Template(tmpl.read())
            
            with open(outputFilename, 'a', encoding='utf-8') as tpl:
                tpl.write(template.render(data=data, timeField=self.timeField))
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] Template error, activate debug mode to check for errors{Fore.RESET}")
            self.logger.debug(f"   [-] {e}")

    def run(self, data):
        for template, templateOutput in zip(self.template, self.templateOutput):
            self.logger.info(f'[+] Applying template "{template[0]}", outputting to : {templateOutput[0]}')
            self.generateFromTemplate(template[0], templateOutput[0], data)

class JSONFlattener:
    """ Perform JSON Flattening """

    def __init__(self, configFile, logger=None, timeAfter="1970-01-01T00:00:00", timeBefore="9999-12-12T23:59:59", timeField=None, hashes=False, args_config=None):
        self.logger = logger or logging.getLogger(__name__)
        self.keyDict = {}
        self.fieldStmt = ""
        self.valuesStmt = []
        self.timeAfter = timeAfter
        self.timeBefore = timeBefore
        self.timeField = timeField
        self.hashes = hashes
        self.args_config = args_config
        self.JSONArray = args_config.json_array_input
        # Initialize the cache for compiled code
        self.compiled_code_cache = {}

        # Convert the argparse.Namespace to a dictionary
        args_dict = vars(args_config)
        # Find the chosen input format
        self.chosen_input = next((key for key, value in args_dict.items() if "_input" in key and value), None)
        if self.chosen_input is None:
            self.chosen_input = "evtx_input" # Since evtx is the default input, we force it no chosen input has been found
        
        with open(configFile, 'r', encoding='UTF-8') as fieldMappingsFile:
            self.fieldMappingsDict = json.loads(fieldMappingsFile.read())
            self.fieldExclusions = self.fieldMappingsDict["exclusions"]
            self.fieldMappings = self.fieldMappingsDict["mappings"]
            self.uselessValues = self.fieldMappingsDict["useless"]
            self.aliases = self.fieldMappingsDict["alias"]
            self.fieldSplitList = self.fieldMappingsDict["split"]
            self.transforms = self.fieldMappingsDict["transforms"]
            self.transforms_enabled = self.fieldMappingsDict["transforms_enabled"]

        # Define the authorized BUILTINS for Resticted Python
        def default_guarded_getitem(ob, index):
            return ob[index]
        
        default_guarded_getattr = getattr

        self.RestrictedPython_BUILTINS = {
            '__name__': 'script',
            "_getiter_": default_guarded_getiter,
            '_getattr_': default_guarded_getattr,
            '_getitem_': default_guarded_getitem,
            'base64': base64,
            're': re,
            'chardet': chardet,
            '_iter_unpack_sequence_': guarded_iter_unpack_sequence
        }
        self.RestrictedPython_BUILTINS.update(safe_builtins)
        self.RestrictedPython_BUILTINS.update(limited_builtins)
        self.RestrictedPython_BUILTINS.update(utility_builtins)

    def run(self, file):
        """
            Flatten json object with nested keys into a single level.
            Returns the flattened json object
        """
        self.logger.debug(f"FLATTENING : {file}")
        JSONLine = {}
        JSONOutput = []
        fieldStmt = ""

        def transformValue(code, param):
            try:
                # Check if the code has already been compiled
                if code in self.compiled_code_cache:
                    byte_code = self.compiled_code_cache[code]
                else:
                    # Compile the code and store it in the cache
                    byte_code = compile_restricted(code, filename='<inline code>', mode='exec')
                    self.compiled_code_cache[code] = byte_code
                # Prepare the execution environment
                TransformFunction = {}
                exec(byte_code, self.RestrictedPython_BUILTINS, TransformFunction)
                return TransformFunction["transform"](param)
            except Exception as e:
                self.logger.debug(f"ERROR: Couldn't apply transform: {e}")
                return param  # Return the original parameter if transform fails

        def flatten(x, name=''):
            # Sample EVTX event : {"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"5770385F-C22A-43E0-BF4C-06F5698FFBD9"}},"EventID":16,"Version":3,"Level":4,"Task":16,"Opcode":0,"Keywords":"0x8000000000000000","TimeCreated":{"#attributes":{"SystemTime":"2021-03-03T12:47:27.371669Z"}},"EventRecordID":1,"Correlation":null,"Execution":{"#attributes":{"ProcessID":5132,"ThreadID":6404}},"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"DESKTOP-ET1DJSR","Security":{"#attributes":{"UserID":"S-1-5-21-1250304854-3630730510-2981668747-1001"}}},"EventData":{"UtcTime":"2021-03-03 12:47:27.369","Configuration":"C:\\Users\\user\\Downloads\\sysmonconfig-export.xml","ConfigurationFileHash":"SHA256=EA5133261F8C5D31A30DD852A05B90E804103837310C14A69747BA8367D6CDB5"}}}

            nonlocal fieldStmt
            # If it is a Dict go deeper
            if isinstance(x, dict):
                for a in x:
                    flatten(x[a], name + a + '.')
            else:
                # Applying exclusions. Be careful, the key/value pair is discarded if there is a partial match
                if not any(exclusion in name[:-1] for exclusion in self.fieldExclusions):
                    # Arrays are not expanded
                    if isinstance(x, list):
                        value = ''.join(str(x))
                    else:
                        value = x
                    # Excluding useless values (e.g. "null"). The value must be an exact match.
                    if value not in self.uselessValues:
                        # Applying field mappings
                        rawFieldName = name[:-1]
                        key = self.fieldMappings.get(rawFieldName, ''.join(e for e in rawFieldName.split(".")[-1] if e.isalnum()))

                        # Preparing aliases (work on original field name and Mapped field name)
                        keys = [key]
                        if key in self.aliases:
                            keys.append(self.aliases[key])
                        if rawFieldName in self.aliases:
                            keys.append(self.aliases[rawFieldName])

                        # Applying field transforms
                        keysThatNeedTransformedValues = []
                        transformedValuesByKeys = {}
                        if self.transforms_enabled:
                            for fieldName in [key, rawFieldName]:
                                if fieldName in self.transforms:
                                    for transform in self.transforms[fieldName]:
                                        if transform["enabled"] and self.chosen_input in transform["source_condition"]:
                                            transformCode = transform["code"]
                                            # If the transform rule ask for a dedicated alias
                                            if transform["alias"]:
                                                keys.append(transform["alias_name"])
                                                keysThatNeedTransformedValues.append(transform["alias_name"])
                                                transformedValuesByKeys[transform["alias_name"]] = transformValue(transformCode, value)
                                            else:
                                                value = transformValue(transformCode, value)

                        # Applying field splitting
                        fieldsToSplit = []
                        if rawFieldName in self.fieldSplitList:
                            fieldsToSplit.append(rawFieldName)
                        if key in self.fieldSplitList:
                            fieldsToSplit.append(key)
                        
                        if fieldsToSplit:
                            for field in fieldsToSplit:
                                try:
                                    splittedFields = value.split(self.fieldSplitList[field]["separator"])
                                    for splittedField in splittedFields:
                                        k, v = splittedField.split(self.fieldSplitList[field]["equal"])
                                        keyLower = k.lower()
                                        JSONLine[k] = v
                                        if keyLower not in self.keyDict:
                                            self.keyDict[keyLower] = k
                                            fieldStmt += f"'{k}' TEXT COLLATE NOCASE,\n"
                                except Exception as e:
                                    self.logger.debug(f"ERROR : Couldn't apply field splitting, value(s) {str(splittedFields)} : {e}")

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
                                fieldStmt += f"'{key}' {'INTEGER' if isinstance(value, int) else 'TEXT COLLATE NOCASE'},\n"
        
        # If filesize is not zero
        if os.stat(file).st_size != 0:
            with open(str(file), 'r', encoding='utf-8') as JSONFile:
                filename = os.path.basename(file)
                logs = JSONFile
                # If the file is a json array
                if self.JSONArray:
                    try:
                        logs = json.loads(JSONFile.read())
                    except Exception as e:
                        self.logger.debug(f'JSON ARRAY ERROR : {e}')
                        logs = []
                
                for line in logs:
                    try:
                        if self.JSONArray:
                            dictToFlatten = line
                        else:
                            dictToFlatten = json.loads(line)
                        
                        dictToFlatten["OriginalLogfile"] = filename
                        if self.hashes:
                            dictToFlatten["OriginalLogLinexxHash"] = xxhash.xxh64_hexdigest(line[:-1])
                        flatten(dictToFlatten)
                    except Exception as e:
                        self.logger.debug(f'JSON ERROR : {e}')
                    
                    # Handle timestamp filters
                    if ((self.timeAfter != "1970-01-01T00:00:00" or self.timeBefore != "9999-12-12T23:59:59") 
                            and (self.timeField in JSONLine)):
                        try:
                            timestamp = time.strptime(JSONLine[self.timeField].split(".")[0].replace("Z",""), '%Y-%m-%dT%H:%M:%S')
                            if timestamp > self.timeAfter and timestamp < self.timeBefore:
                                JSONOutput.append(JSONLine)
                        except Exception:
                            JSONOutput.append(JSONLine)
                    else:
                        JSONOutput.append(JSONLine)
                    
                    JSONLine = {}
        
        return {"dbFields": fieldStmt, "dbValues": JSONOutput}

    def runAll(self, EVTXJSONList):
        for evtxJSON in tqdm(EVTXJSONList, colour="yellow"):
            if os.stat(evtxJSON).st_size != 0:
                results = self.run(evtxJSON)
                self.fieldStmt += results["dbFields"]
                self.valuesStmt += results["dbValues"]

class zirCore:
    """ Load data into database and apply detection rules  """

    def __init__(self, config, logger=None, noOutput=False, timeAfter="1970-01-01T00:00:00", timeBefore="9999-12-12T23:59:59", limit=-1, csvMode=False, timeField=None, hashes=False, dbLocation=":memory:", delimiter=";"):
        self.logger = logger or logging.getLogger(__name__)
        self.dbConnection = self.createConnection(dbLocation)
        self.fullResults = []
        self.ruleset = {}
        self.noOutput = noOutput
        self.timeAfter = timeAfter
        self.timeBefore = timeBefore
        self.config = config
        self.limit = limit
        self.csvMode = csvMode
        self.timeField = timeField
        self.hashes = hashes
        self.delimiter = delimiter
        self.first_json_output = True  # To manage commas in JSON output
    
    def close(self):
        self.dbConnection.close()

    def createConnection(self, db):
        """ create a database connection to a SQLite database """
        conn = None
        self.logger.debug(f"CONNECTING TO : {db}")
        try:
            if db == ':memory:':
                conn = sqlite3.connect(db, isolation_level=None)
                conn.execute('PRAGMA journal_mode = MEMORY;')
                conn.execute('PRAGMA synchronous = OFF;')
                conn.execute('PRAGMA temp_store = MEMORY;')
            else:
                conn = sqlite3.connect(db)
            conn.row_factory = sqlite3.Row  # Allows to get a dict

            def udf_regex(x, y):
                if y is None: 
                    return 0
                if re.search(x, y):
                    return 1
                else:
                    return 0

            conn.create_function('regexp', 2, udf_regex) # Allows to use regex in SQlite
        except Error as e:
            self.logger.error(f"{Fore.RED}   [-] {e}")
        return conn

    def createDb(self, fieldStmt):
        createTableStmt = f"CREATE TABLE logs ( row_id INTEGER, {fieldStmt} PRIMARY KEY(row_id AUTOINCREMENT) );"
        self.logger.debug(f" CREATE : {createTableStmt}")
        if not self.executeQuery(createTableStmt):
            self.logger.error(f"{Fore.RED}   [-] Unable to create table{Fore.RESET}")
            sys.exit(1)

    def createIndex(self):
        self.executeQuery('CREATE INDEX "idx_eventid" ON "logs" ("eventid");')

    def executeQuery(self, query):
        """ Perform a SQL Query with the provided connection """
        if self.dbConnection is not None:
            dbHandle = self.dbConnection.cursor()
            self.logger.debug(f"EXECUTING : {query}")
            try:
                dbHandle.execute(query)
                self.dbConnection.commit()
                return True
            except Error as e:
                self.logger.debug(f"   [-] {e}")
                return False
        else:
            self.logger.error(f"{Fore.RED}   [-] No connection to Db{Fore.RESET}")
            return False

    def executeSelectQuery(self, query):
        """
        Execute a SELECT SQL query and return the results as a list of dictionaries.
        """
        if self.dbConnection is None:
            self.logger.error(f"{Fore.RED}   [-] No connection to Db{Fore.RESET}")
            return []
        try:
            cursor = self.dbConnection.cursor()
            self.logger.debug(f"Executing SELECT query: {query}")
            cursor.execute(query)
            rows = cursor.fetchall()
            # Convert rows to list of dictionaries
            result = [dict(row) for row in rows]
            return result
        except sqlite3.Error as e:
            self.logger.debug(f"   [-] SQL query error: {e}")
            return []

    def loadDbInMemory(self, db):
        """ In db only mode it is possible to restore an on disk Db to avoid EVTX extraction and flattening """
        dbfileConnection = self.createConnection(db)
        dbfileConnection.backup(self.dbConnection)
        dbfileConnection.close()

    def escape_identifier(self, identifier):
        """Escape SQL identifiers like table or column names."""
        return identifier.replace("\"", "\"\"")

    def insertData2Db(self, JSONLine):
        """Build a parameterized INSERT INTO query and insert data into the database."""
        columns = JSONLine.keys()
        columnsEscaped = ', '.join([self.escape_identifier(col) for col in columns])
        placeholders = ', '.join(['?'] * len(columns))
        values = []
        for col in columns:
            value = JSONLine[col]
            if isinstance(value, int):
                # Check if value exceeds SQLite INTEGER limits
                if abs(value) > 9223372036854775807:
                    value = str(value)  # Convert to string
            values.append(value)
        insertStmt = f'INSERT INTO logs ({columnsEscaped}) VALUES ({placeholders})'
        try:
            self.dbConnection.execute(insertStmt, values)
            return True
        except Exception as e:
            self.logger.debug(f"   [-] {e}")
            return False

    def insertFlattenedJSON2Db(self, flattenedJSON):
        for JSONLine in tqdm(flattenedJSON, colour="yellow"):
            self.insertData2Db(JSONLine)
        self.createIndex()

    def saveFlattenedJSON2File(self, flattenedJSON, outputFile):
        with open(outputFile, 'w', encoding='utf-8') as file:
            for JSONLine in tqdm(flattenedJSON, colour="yellow"):
                file.write(f'{json.dumps(JSONLine).decode("utf-8")}\n')

    def saveDbToDisk(self, dbFilename):
        self.logger.info("[+] Saving working data to disk as a SQLite DB")
        onDiskDb = sqlite3.connect(dbFilename)
        self.dbConnection.backup(onDiskDb)
        onDiskDb.close()

    def executeRule(self, rule):
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
            data = self.executeSelectQuery(SQLQuery)
            if data:
                if self.csvMode:
                    # Clean values for CSV output
                    cleaned_rows = [
                        {k: str(v).replace("\n", "").replace("\r", "").replace("None", "") for k, v in dict(row).items()}
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
                "description": description.replace("\n", "").replace("\r", "") if self.csvMode else description,
                "sigmafile": filename,
                "sigma": sigma_queries,
                "rule_level": rule_level,
                "tags": tags,
                "count": len(filteredRows),
                "matches": filteredRows
            }
            self.logger.debug(f'DETECTED: {title} - Matches: {len(filteredRows)} events')
            return results
        else:
            return {}

    def loadRulesetFromFile(self, filename, ruleFilters):
        try:
            with open(filename, encoding='utf-8') as f:
                self.ruleset = json.loads(f.read())
            self.applyRulesetFilters(ruleFilters)
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] Loading JSON ruleset failed, are you sure it is a valid JSON file ? : {e}{Fore.RESET}")

    def loadRulesetFromVar(self, ruleset, ruleFilters):
        self.ruleset = ruleset
        self.applyRulesetFilters(ruleFilters)
    
    def applyRulesetFilters(self, ruleFilters=None):
        # Remove empty rule and remove filtered rules
        self.ruleset = list(filter(None, self.ruleset))
        if ruleFilters is not None:
            self.ruleset = [rule for rule in self.ruleset if not any(ruleFilter in rule["title"] for ruleFilter in ruleFilters)]

    def ruleLevelPrintFormatter(self, level, orgFormat=Fore.RESET):
        if level == "informational":
            return f'{Fore.WHITE}{level}{orgFormat}'
        if level == "low":
            return f'{Fore.GREEN}{level}{orgFormat}'
        if level == "medium":
            return f'{Fore.YELLOW}{level}{orgFormat}'
        if level == "high":
            return f'{Fore.MAGENTA}{level}{orgFormat}'
        if level == "critical":
            return f'{Fore.RED}{level}{orgFormat}'

    def executeRuleset(self, outFile, writeMode='w', showAll=False,
                    KeepResults=False, lastRuleset=False):
        """
        Execute all rules in the ruleset and handle output.
        """
        csvWriter = None
        is_json_mode = not self.csvMode

        # Prepare output file handle if needed
        fileHandle = None
        if not self.noOutput:
            # Open file in text mode since we will write decoded strings
            fileHandle = open(outFile, writeMode, encoding='utf-8', newline='')
            if is_json_mode and writeMode != 'a':
                fileHandle.write('[')  # Start JSON array

        # Iterate over rules in the ruleset
        with tqdm(self.ruleset, colour="yellow") as ruleBar:
            for rule in ruleBar:
                # Show all rules if showAll is True
                if showAll and "title" in rule:
                    rule_title = rule["title"]
                    rule_level = rule.get("level", "unknown")
                    formatted_level = self.ruleLevelPrintFormatter(rule_level, Fore.BLUE)
                    ruleBar.write(f'{Fore.BLUE}    - {rule_title} [{formatted_level}]{Fore.RESET}')

                # Execute the rule
                ruleResults = self.executeRule(rule)
                if not ruleResults:
                    continue  # No matches, skip to next rule

                # Apply limit if set
                if self.limit != -1 and ruleResults["count"] > self.limit:
                    continue  # Exceeds limit, skip this result

                # Write progress message
                rule_title = ruleResults["title"]
                rule_level = ruleResults.get("rule_level", "unknown")
                formatted_level = self.ruleLevelPrintFormatter(rule_level, Fore.CYAN)
                rule_count = ruleResults["count"]
                ruleBar.write(f'{Fore.CYAN}    - {rule_title} [{formatted_level}] : {rule_count} events{Fore.RESET}')

                # Store results if needed
                if KeepResults:
                    self.fullResults.append(ruleResults)

                # Handle output to file
                if not self.noOutput:
                    if self.csvMode:
                        # Initialize CSV writer if not already done
                        if csvWriter is None:
                            fieldnames = ["rule_title", "rule_description", "rule_level", "rule_count"] + list(ruleResults["matches"][0].keys())
                            csvWriter = csv.DictWriter(fileHandle, delimiter=self.delimiter, fieldnames=fieldnames)
                            csvWriter.writeheader()
                        # Write matches to CSV
                        for data in ruleResults["matches"]:
                            dictCSV = {
                                "rule_title": ruleResults["title"],
                                "rule_description": ruleResults["description"],
                                "rule_level": ruleResults["rule_level"],
                                "rule_count": ruleResults["count"],
                                **data
                            }
                            csvWriter.writerow(dictCSV)
                    else:
                        # Write results as JSON using orjson
                        try:
                            # Handle commas between JSON objects
                            if not self.first_json_output:
                                fileHandle.write(',\n')
                            else:
                                self.first_json_output = False
                            # Serialize ruleResults to JSON bytes with indentation
                            json_bytes = json.dumps(ruleResults, option=json.OPT_INDENT_2)
                            # Write the decoded JSON string to the file
                            fileHandle.write(json_bytes.decode('utf-8'))
                        except Exception as e:
                            self.logger.error(f"Error saving some results: {e}")

        # Close output file handle if needed
        if not self.noOutput:
            if is_json_mode and lastRuleset:
                fileHandle.write(']')  # Close JSON array
            fileHandle.close()

    def run(self, EVTXJSONList, Insert2Db=True, saveToFile=False, args_config=None):
        self.logger.info("[+] Processing events")
        flattener = JSONFlattener(configFile=self.config, timeAfter=self.timeAfter, timeBefore=self.timeBefore, timeField=self.timeField, hashes=self.hashes, args_config=args_config)
        flattener.runAll(EVTXJSONList)
        if saveToFile:
            filename = f"flattened_events_{''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))}.json"
            self.logger.info(f"[+] Saving flattened JSON to : {filename}")
            self.saveFlattenedJSON2File(flattener.valuesStmt, filename)
        if Insert2Db:
            self.logger.info("[+] Creating model")
            self.createDb(flattener.fieldStmt)
            self.logger.info("[+] Inserting data")
            self.insertFlattenedJSON2Db(flattener.valuesStmt)
            self.logger.info("[+] Cleaning unused objects")
        else:
            return flattener.keyDict
        del flattener

class evtxExtractor:

    def __init__(self, logger=None, providedTmpDir=None, coreCount=None, useExternalBinaries=True, binPath = None, xmlLogs=False, sysmon4linux=False, auditdLogs=False, encoding=None, evtxtract=False, csvInput=False):
        self.logger = logger or logging.getLogger(__name__)
        if Path(str(providedTmpDir)).is_dir():
            self.tmpDir = f"tmp-{self.randString()}"
            self.logger.error(f"{Fore.RED}   [-] Provided directory already exists using '{self.tmpDir}' instead{Fore.RESET}")
        else:
            self.tmpDir = providedTmpDir or f"tmp-{self.randString()}"
            os.mkdir(self.tmpDir)
        self.cores = coreCount or os.cpu_count()
        self.useExternalBinaries = useExternalBinaries
        self.sysmon4linux = sysmon4linux
        self.xmlLogs = xmlLogs
        self.auditdLogs = auditdLogs
        self.evtxtract = evtxtract
        self.csvInput = csvInput
        # Sysmon 4 Linux default encoding is ISO-8859-1, Auditd is UTF-8
        if not encoding and sysmon4linux: 
            self.encoding = "ISO-8859-1"
        elif not encoding and (auditdLogs or evtxtract or xmlLogs): 
            self.encoding = "utf-8"
        else: 
            self.encoding = encoding
        
        self.evtxDumpCmd = self.getOSExternalTools(binPath)
        
    def randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def getOSExternalTools(self, binPath):
        """ Determine which binaries to run depending on host OS and architecture: 32Bits is NOT supported for now since evtx_dump is 64bits only"""
        if binPath is None:
            if platform.system() == "Linux":
                # Check for ARM architecture
                if platform.machine().startswith('arm') or platform.machine().startswith('aarch'):
                    return "bin/evtx_dump_lin_arm"
                else:
                    # Default to x64 architecture
                    return "bin/evtx_dump_lin"
            elif platform.system() == "Darwin":
                return "bin/evtx_dump_mac"
            elif platform.system() == "Windows":
                return "bin\\evtx_dump_win.exe"
        else:
            return binPath

    def runUsingBindings(self, file):
        """
        Convert EVTX to JSON using evtx_dump bindings (slower)
        Drop resulting JSON files in a tmp folder.
        """
        if not self.useExternalBinaries:
            try:
                filepath = Path(file)
                filename = filepath.name
                parser = PyEvtxParser(str(filepath))
                with open(f"{self.tmpDir}/{str(filename)}-{self.randString()}.json", "w", encoding="utf-8") as f:
                    for record in parser.records_json():
                        f.write(f'{json.dumps(json.loads(record["data"])).decode("utf-8")}\n')
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] Cannot use PyEvtxParser : {e}{Fore.RESET}")
        else:
            self.logger.error(f"{Fore.RED}   [-] Cannot use PyEvtxParser and evtx_dump is disabled or missing{Fore.RESET}")

    def getTime(self, line):
        timestamp = line.replace('msg=audit(','').replace('):','').split(':')
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(timestamp[0])))
        return timestamp

    def auditdLine2JSON(self, auditdLine):
        """
        Convert auditd logs to JSON : code from https://github.com/csark/audit2json
        """
        event = {}
        # According to auditd specs https://github.com/linux-audit/audit-documentation/wiki/SPEC-Audit-Event-Enrichment
        # a GS ASCII character, 0x1D, will be inserted to separate original and translated fields
        # Best way to deal with it is to remove it.
        attributes = auditdLine.replace('\x1d',' ').split(' ')
        for attribute in attributes:
            if 'msg=audit' in attribute:
                event['timestamp'] = self.getTime(attribute)
            else:
                try:
                    attribute = attribute.replace('msg=','').replace('\'','').replace('"','').split('=')
                    event[attribute[0]] = attribute[1].rstrip()
                except Exception:
                    pass
        if "host" not in event:
            event['host'] = 'offline'
        return event

    def SysmonXMLLine2JSON(self, xmlLine):
        """
        Remove syslog header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        if 'Event' not in xmlLine:
            return None
        xmlLine = "<Event>" + xmlLine.split("<Event>")[1]
        try: # isolate individual line parsing errors
            root = etree.fromstring(xmlLine)
            return self.xml2dict(root)
        except Exception as ex:
            self.logger.debug(f"Unable to parse line \"{xmlLine}\": {ex}")
            return None

    def XMLLine2JSON(self, xmlLine):
        """
        Remove "Events" header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        if '<Event ' not in xmlLine:
            return None
        try: # isolate individual line parsing errors
            root = etree.fromstring(xmlLine)
            return self.xml2dict(root, u'{http://schemas.microsoft.com/win/2004/08/events/event}')
        except Exception as ex:
            self.logger.debug(f"Unable to parse line \"{xmlLine}\": {ex}")
            return None

    def xml2dict(self, eventRoot, ns=u'http://schemas.microsoft.com/win/2004/08/events/event'):

        def cleanTag(tag, ns):
            if ns in tag: 
                return tag[len(ns):]
            return tag

        child = {"#attributes": {"xmlns": ns}}
        for appt in eventRoot.getchildren():
            nodename = cleanTag(appt.tag,ns)
            nodevalue = {}
            for elem in appt.getchildren():
                cleanedTag = cleanTag(elem.tag,ns)
                if not elem.text:
                    text = ""
                else:
                    try:
                        text = int(elem.text)
                    except Exception:
                        text = elem.text
                if cleanedTag == 'Data':
                    childnode = elem.get("Name")
                elif cleanedTag == 'Qualifiers':
                    text = elem.text
                else:
                    childnode = cleanedTag
                    if elem.attrib:
                        text = {"#attributes": dict(elem.attrib)}
                obj={str(childnode):text}
                nodevalue = {**nodevalue, **obj}
            node = {str(nodename): nodevalue}
            child = {**child, **node}
        event = { "Event": child }
        return event

    def Logs2JSON(self, func, datasource, outfile, isFile=True):
        """
        Use multiprocessing to convert supported log formats to JSON
        """
        
        if isFile:
            with open(datasource, "r", encoding=self.encoding) as fp: 
                data = fp.readlines()
        else : 
            data = datasource.split("\n")
        
        pool = mp.Pool(self.cores)
        result = pool.map(func, data)
        pool.close()
        pool.join()
        with open(outfile, "w", encoding="UTF-8") as fp:
            for element in result:
                if element is not None:
                    fp.write(json.dumps(element).decode("utf-8") + '\n')

    def csv2JSON(self, CSVPath, JSONPath):  
        """
        Convert CSV Logs to JSON
        """      
        with open(CSVPath, encoding='utf-8') as CSVFile: 
            csvReader = csv.DictReader(CSVFile) 
            with open(JSONPath, 'w', encoding='utf-8') as JSONFile: 
                for row in csvReader: 
                    JSONFile.write(json.dumps(row).decode("utf-8") + '\n')

    def evtxtract2JSON(self, file, outfile):
        """
        Convert EXVTXtract Logs to JSON using xml2dict and "dumps" it to a file
        """
        # Load file as a string to add enclosing document since XML doesn't support multiple documents
        with open(file, "r", encoding=self.encoding) as fp:
            data = fp.read()
        # Remove all non UTF-8 characters
        data = bytes(data.replace('\x00','').replace('\x0B',''), 'utf-8').decode('utf-8', 'ignore')
        data = f'<evtxtract>\n{data}\n</evtxtract>'
        # Load the XML file
        parser = etree.XMLParser(recover=True) # Recover=True allows the parser to ignore bad characters
        root = etree.fromstring(data, parser=parser)
        with open(outfile, "w", encoding="UTF-8") as fp:
            for event in root.getchildren():
                if "Event" in event.tag:
                    extractedEvent = self.xml2dict(event, u'{http://schemas.microsoft.com/win/2004/08/events/event}')
                    fp.write(json.dumps(extractedEvent).decode("utf-8") + '\n')

    def run(self, file):
        """
        Convert Logs to JSON
        Drop resulting JSON files in a tmp folder.
        """
        self.logger.debug(f"EXTRACTING : {file}")
        filename = Path(file).name
        outputJSONFilename = f"{self.tmpDir}/{str(filename)}-{self.randString()}.json"
        
        try:
            # Auditd or Sysmon4Linux logs
            if self.sysmon4linux or self.auditdLogs:
                func = self.SysmonXMLLine2JSON if self.sysmon4linux else self.auditdLine2JSON
                self.Logs2JSON(func, str(file), outputJSONFilename)
            
            # XML logs
            elif self.xmlLogs:
                with open(str(file), 'r', encoding="utf-8") as XMLFile:
                    data = XMLFile.read().replace("\n","").replace("</Event>","</Event>\n").replace("<Event ","\n<Event ")
                self.Logs2JSON(self.XMLLine2JSON, data, outputJSONFilename, isFile=False)
            
            # EVTXtract
            elif self.evtxtract:
                self.evtxtract2JSON(str(file), outputJSONFilename)
            
            # CSV
            elif self.csvInput:
                self.csv2JSON(str(file), outputJSONFilename)
            
            # EVTX
            else:
                if not self.useExternalBinaries or not Path(self.evtxDumpCmd).is_file(): 
                    self.logger.debug("   [-] No external binaries args or evtx_dump is missing")
                    self.runUsingBindings(file)
                else:
                    cmd = [self.evtxDumpCmd, "--no-confirm-overwrite", "-o", "jsonl", str(file), "-f", outputJSONFilename, "-t", str(self.cores)]
                    subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")

    def cleanup(self):
        shutil.rmtree(self.tmpDir)
        
class zircoGuiGenerator:
    """
    Generate the mini GUI
    """
    def __init__(self, packageDir, templateFile, logger=None, timeField=""):
        self.logger = logger or logging.getLogger(__name__)
        self.templateFile = templateFile
        self.tmpDir = f'tmp-zircogui-{self._randString()}'
        self.tmpFile = f'data-{self._randString()}.js'
        self.outputFile = f'zircogui-output-{self._randString()}'
        self.packageDir = packageDir
        self.timeField = timeField

    def _randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))

    def generate(self, data, directory=""):
        # Check if directory exists, fallback to current directory if not
        final_directory = directory.rstrip("/") if os.path.exists(directory) else ""
        if directory and not final_directory:
            self.logger.error(f"{Fore.RED}   [-] {directory} does not exist, fallback to current directory{Fore.RESET}")
        
        try:
            # Extract the GUI package
            shutil.unpack_archive(self.packageDir, self.tmpDir, "zip")
            
            # Generate data file
            self.logger.info(f"[+] Generating ZircoGui package to: {final_directory}/{self.outputFile}.zip")
            exportforzircoguiTmpl = templateEngine(self.logger, self.templateFile, self.tmpFile, self.timeField)
            exportforzircoguiTmpl.generateFromTemplate(exportforzircoguiTmpl.template, exportforzircoguiTmpl.templateOutput, data)
            
            # Move data file to package directory
            shutil.move(self.tmpFile, f'{self.tmpDir}/zircogui/data.js')
            
            # Create zip archive
            shutil.make_archive(self.outputFile, 'zip', f"{self.tmpDir}/zircogui")
            
            # Move to final destination if specified
            if final_directory:
                shutil.move(f"{self.outputFile}.zip", f"{final_directory}/{self.outputFile}.zip")
                
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        finally:
            # Clean up temporary directory
            if os.path.exists(self.tmpDir):
                shutil.rmtree(self.tmpDir)

class rulesUpdater:
    """ 
    Download rulesets from the https://github.com/wagga40/Zircolite-Rules repository and update if necessary.
    """

    def __init__(self, logger=None):
        self.url = "https://github.com/wagga40/Zircolite-Rules/archive/refs/heads/main.zip"
        self.logger = logger or logging.getLogger(__name__)
        self.tempFile = f'tmp-rules-{self._randString()}.zip'
        self.tmpDir = f'tmp-rules-{self._randString()}'
        self.updatedRulesets = []

    def _randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))

    def download(self):
        resp = requests.get(self.url, stream=True)
        total = int(resp.headers.get('content-length', 0))
        with open(self.tempFile, 'wb') as file, tqdm(
            desc=self.tempFile, 
            total=total, 
            unit='iB', 
            unit_scale=True, 
            unit_divisor=1024, 
            colour="yellow"
        ) as bar:
            for data in resp.iter_content(chunk_size=1024):
                size = file.write(data)
                bar.update(size)
    
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
                self.updatedRulesets.append(str(dest_file))
                self.logger.info(f"{Fore.CYAN}   [+] Updated : {dest_file}{Fore.RESET}")
                
        if count == 0: 
            self.logger.info(f"{Fore.CYAN}   [+] No newer rulesets found")
    
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

class rulesetHandler:

    def __init__(self, logger=None, config=None, listPipelineOnly=False):
        self.logger = logger or logging.getLogger(__name__)
        self.saveRuleset = config.save_ruleset
        self.rulesetPathList = config.ruleset
        self.cores = config.cores or os.cpu_count()
        self.sigmaConversionDisabled = config.no_sigma_conversion
        self.pipelines = []

        if self.sigmaConversionDisabled:
            self.logger.info(f"{Fore.LIGHTYELLOW_EX}   [i] Sigma conversion is disabled (missing imports) ! {Fore.RESET}")
        else:
            # Init pipelines
            plugins = InstalledSigmaPlugins.autodiscover()
            pipeline_resolver = plugins.get_pipeline_resolver()
            pipeline_list = list(pipeline_resolver.pipelines.keys())

            if listPipelineOnly:
                self.logger.info("[+] Installed pipelines : " 
                                + ", ".join(pipeline_list) 
                                + "\n    You can install pipelines with your Python package manager"
                                + "\n    e.g : pip install pysigma-pipeline-sysmon"
                                ) 
            else : 
                # Resolving pipelines
                if config.pipeline:
                    for pipelineName in [item for pipeline in config.pipeline for item in pipeline]: # Flatten the list of pipeline names list
                        if pipelineName in pipeline_list:
                            self.pipelines.append(plugins.pipelines[pipelineName]())
                        else:
                            self.logger.error(f"{Fore.RED}   [-] {pipelineName} not found. You can list installed pipelines with '--pipeline-list'{Fore.RESET}")

        # Parse & (if necessary) convert ruleset, final list is stored in self.Rulesets
        self.Rulesets = self.rulesetParsing()

        # Combining Rulesets 
        if config.combine_rulesets:
            self.Rulesets = [item for subRuleset in self.Rulesets if subRuleset for item in subRuleset]
            self.Rulesets = [sorted(self.Rulesets, key=lambda d: d['level'])] # Sorting by level
            
        if all(not subRuleset for subRuleset in self.Rulesets):
            self.logger.error(f"{Fore.RED}   [-] No rules to execute !{Fore.RESET}")

    def isYAML(self, filepath): 
        """ Test if the file is a YAML file """
        if (filepath.suffix == ".yml" or filepath.suffix == ".yaml"):
            with open(filepath, 'r', encoding="utf-8") as file:
                content = file.read()
                try:
                    yaml.safe_load(content)
                    return True
                except yaml.YAMLError:
                    return False

    def isJSON(self, filepath): 
        """ Test if the file is a JSON file """
        if (filepath.suffix == ".json"):
            with open(filepath, 'r', encoding="utf-8") as file:
                content = file.read()
                try:
                    json.loads(content)
                    return True
                except json.JSONDecodeError:
                    return False

    def randRulesetName(self, sigmaRules):
        # Clean the ruleset name
        cleanedName = ''.join(char if char.isalnum() else '-' for char in sigmaRules).strip('-')
        cleanedName = re.sub(r'-+', '-', cleanedName)
        # Generate a random string 
        randomString = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
        return f"ruleset-{cleanedName}-{randomString}.json"

    def convertSigmaRules(self, backend, rule):
        try: 
            return backend.convert_rule(rule, "zircolite")[0]
        except Exception as e:
            self.logger.debug(f"{Fore.RED}   [-] Cannot convert rule '{str(rule)}' : {e}{Fore.RESET}")

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
            ruleset = pool.map(functools.partial(self.convertSigmaRules, sqlite_backend), tqdm(rule_collection, colour="yellow"))
            pool.close()
            pool.join()
            ruleset = [rule for rule in ruleset if rule is not None] # Removing empty results
            ruleset = sorted(ruleset, key=lambda d: d['level']) # Sorting by level

            if self.saveRuleset:
                tempRulesetName = self.randRulesetName(str(sigmaRules))
                with open(tempRulesetName, 'w', encoding='utf-8') as outfile:
                    outfile.write(json.dumps(ruleset, option=json.OPT_INDENT_2).decode('utf-8'))
                    self.logger.info(f"{Fore.CYAN}   [+] Saved ruleset as : {tempRulesetName}{Fore.RESET}")

        return ruleset
    
    def rulesetParsing(self):
        rulesetList = []
        for ruleset in self.rulesetPathList:
            rulesetPath = Path(ruleset)
            if rulesetPath.exists():
                if rulesetPath.is_file():
                    if self.isJSON(rulesetPath): # JSON Ruleset
                        try:
                            with open(rulesetPath, encoding='utf-8') as f:
                                rulesetList.append(json.loads(f.read()))
                            self.logger.info(f"{Fore.CYAN}   [+] Loaded JSON/Zircolite ruleset : {str(rulesetPath)}{Fore.RESET}")
                        except Exception as e:
                            self.logger.error(f"{Fore.RED}   [-] Cannot load {str(rulesetPath)} {e}{Fore.RESET}")
                    else: # YAML Ruleset
                        if not self.sigmaConversionDisabled and self.isYAML(rulesetPath):
                            try:
                                self.logger.info(f"{Fore.CYAN}   [+] Converting Native Sigma to Zircolite ruleset : {str(rulesetPath)}{Fore.RESET}")
                                rulesetList.append(self.sigmaRulesToRuleset([rulesetPath], self.pipelines))
                            except Exception as e:
                                self.logger.error(f"{Fore.RED}   [-] Cannot convert {str(rulesetPath)} {e}{Fore.RESET}")
                elif not self.sigmaConversionDisabled and rulesetPath.is_dir(): # Directory
                    try:
                        self.logger.info(f"{Fore.CYAN}   [+] Converting Native Sigma to Zircolite ruleset : {str(rulesetPath)}{Fore.RESET}")
                        rulesetList.append(self.sigmaRulesToRuleset([rulesetPath], self.pipelines))
                    except Exception as e:
                        self.logger.error(f"{Fore.RED}   [-] Cannot convert {str(rulesetPath)} {e}{Fore.RESET}")
        return rulesetList

def selectFiles(pathList, selectFilesList):
    if selectFilesList is not None:
        return [evtx for evtx in [str(element) for element in list(pathList)] if any(fileFilters[0].lower() in evtx.lower() for fileFilters in selectFilesList)]
    return pathList

def avoidFiles(pathList, avoidFilesList):
    if avoidFilesList is not None:
        return [evtx for evtx in [str(element) for element in list(pathList)] if all(fileFilters[0].lower() not in evtx.lower() for fileFilters in avoidFilesList)]
    return pathList

def ImportErrorHandler(config):
    importErrorList = []

    if updateDisabled:
        importErrorList.append(f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'requests', events update is disabled{Fore.RESET}")
        config.update_rules = False
    if sigmaConversionDisabled:
        importErrorList.append(f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'sigma' from pySigma, ruleset conversion YAML -> JSON is disabled{Fore.RESET}")
        config.no_sigma_conversion = True
    if pyevtxDisabled:
        importErrorList.append(f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'evtx' from pyevtx-rs, use of external binaries is mandatory{Fore.RESET}")
        config.noexternal = False
    if jinja2Disabled:
        importErrorList.append(f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'jinja2', templating is disabled{Fore.RESET}")
        config.template = None
    if xmlImportDisabled:
        importErrorList.append(f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'lxml', cannot use XML logs as input{Fore.RESET}")
        if config.xml_input:
            return f"{Fore.RED}   [-] Cannot import 'lxml', but according to command line provided it is needed{Fore.RESET}", config, True

    if config.debug or config.imports: 
        return "\n".join(importErrorList), config, False
        
    if importErrorList == []:
        return "", config, False
    
    return f"{Fore.LIGHTYELLOW_EX}   [i] Import errors, certain functionalities may be disabled ('--imports' for details)\n       Supplemental imports can be installed with 'requirements.full.txt'{Fore.RESET}", config, False

################################################################
# MAIN()
################################################################
def main():
    version = "2.40.0"

    # Init Args handling
    parser = argparse.ArgumentParser()
    # Input files and filtering/selection options
    logs_input_args = parser.add_argument_group(f'{Fore.BLUE}INPUT FILES AND FILTERING/SELECTION OPTIONS{Fore.RESET}')
    logs_input_args.add_argument("-e", "--evtx", "--events", help="Path to log file or directory containing log files in supported format", type=str)
    logs_input_args.add_argument("-s", "--select", help="Process only files with filenames containing the specified string (applied before exclusions)", action='append', nargs='+')
    logs_input_args.add_argument("-a", "--avoid", help="Skip files with filenames containing the specified string", action='append', nargs='+')
    logs_input_args.add_argument("-f", "--fileext", help="File extension of the log files to process", type=str)    
    logs_input_args.add_argument("-fp", "--file-pattern", help="Python Glob pattern to select files (only works with directories)", type=str)
    logs_input_args.add_argument("--no-recursion", help="Search for log files only in the specified directory (disable recursive search)", action="store_true")

    # Events filtering options
    event_args = parser.add_argument_group(f'{Fore.BLUE}EVENTS FILTERING OPTIONS{Fore.RESET}')
    event_args.add_argument("-A", "--after", help="Process only events after this timestamp (UTC format: 1970-01-01T00:00:00)", type=str, default="1970-01-01T00:00:00")
    event_args.add_argument("-B", "--before", help="Process only events before this timestamp (UTC format: 1970-01-01T00:00:00)", type=str, default="9999-12-12T23:59:59")
    # Event and log formats options
    # /!\ an option name containing '-input' must exists (It is used in JSON flattening mechanism)
    event_formats_args = parser.add_mutually_exclusive_group()
    event_formats_args.add_argument("-j", "--json-input", "--jsononly", "--jsonline", "--jsonl", help="Input logs are in JSON lines format", action='store_true')
    event_formats_args.add_argument("--json-array-input", "--jsonarray", "--json-array", help="Input logs are in JSON array format", action='store_true')
    event_formats_args.add_argument("--db-input", "-D", "--dbonly", help="Use a previously saved database file (time range filters will not work)", action='store_true')
    event_formats_args.add_argument("-S", "--sysmon-linux-input", "--sysmon4linux", "--sysmon-linux", help="Process Sysmon for Linux log files (default extension: '.log')", action='store_true')
    event_formats_args.add_argument("-AU", "--auditd-input", "--auditd", help="Process Auditd log files (default extension: '.log')", action='store_true')
    event_formats_args.add_argument("-x", "--xml-input", "--xml", help="Process EVTX files converted to XML format (default extension: '.xml')", action='store_true')
    event_formats_args.add_argument("--evtxtract-input", "--evtxtract", help="Process log files extracted with EVTXtract (default extension: '.log')", action='store_true')
    event_formats_args.add_argument("--csv-input", "--csvonly", help="Process log files in CSV format (extension: '.csv')", action='store_true')
    # Ruleset options
    rulesets_formats_args = parser.add_argument_group(f'{Fore.BLUE}RULES AND RULESETS OPTIONS{Fore.RESET}')  
    rulesets_formats_args.add_argument("-r", "--ruleset", help="Sigma ruleset in JSON (Zircolite format) or YAML/directory of YAML files (Native Sigma format)", action='append', nargs='+')
    rulesets_formats_args.add_argument("-nsc", "--no-sigma-conversion", help=argparse.SUPPRESS, action='store_true')
    rulesets_formats_args.add_argument("-cr", "--combine-rulesets", help="Merge all provided rulesets into one", action='store_true')
    rulesets_formats_args.add_argument("-sr", "--save-ruleset", help="Save converted ruleset (from Sigma to Zircolite format) to disk", action='store_true')
    rulesets_formats_args.add_argument("-p", "--pipeline", help="Use specified pipeline for native Sigma rulesets (YAML). Examples: 'sysmon', 'windows-logsources', 'windows-audit'. Use '--pipeline-list' to see available pipelines.", action='append', nargs='+')
    rulesets_formats_args.add_argument("-pl", "--pipeline-list", help="List all installed pysigma pipelines", action='store_true')
    rulesets_formats_args.add_argument("-pn", "--pipeline-null", help="Don't use any pipeline for native Sigma rulesets (Default)", action='store_true')
    rulesets_formats_args.add_argument("-R", "--rulefilter", help="Remove rules from ruleset by matching rule title (case sensitive)", action='append', nargs='*')
    # Ouput formats and output files options
    output_formats_args = parser.add_argument_group(f'{Fore.BLUE}OUPUT FORMATS AND OUTPUT FILES OPTIONS{Fore.RESET}')
    output_formats_args.add_argument("-o", "--outfile", help="Output file for detected events", type=str, default="detected_events.json")
    output_formats_args.add_argument("--csv", "--csv-output", help="Output results in CSV format (empty fields will be included)", action='store_true')
    output_formats_args.add_argument("--csv-delimiter", help="Delimiter for CSV output", type=str, default=";")
    output_formats_args.add_argument("-t", "--tmpdir", help="Temporary directory for JSON-converted events (parent directories must exist)", type=str)
    output_formats_args.add_argument("-k", "--keeptmp", help="Keep the temporary directory with JSON-converted events", action='store_true')
    output_formats_args.add_argument("--keepflat", help="Save flattened events as JSON", action='store_true')
    output_formats_args.add_argument("-d", "--dbfile", help="Save all logs to a SQLite database file", type=str)
    output_formats_args.add_argument("-l", "--logfile", help="Log file name", default="zircolite.log", type=str)
    output_formats_args.add_argument("--hashes", help="Add xxhash64 of the original log event to each event", action='store_true')
    output_formats_args.add_argument("-L", "--limit", "--limit-results", help="Discard results exceeding this limit from output file", type=int, default=-1)
    # Advanced configuration options
    config_formats_args = parser.add_argument_group(f'{Fore.BLUE}ADVANCED CONFIGURATION OPTIONS{Fore.RESET}')  
    config_formats_args.add_argument("-c", "--config", help="JSON file containing field mappings and exclusions", type=str, default="config/fieldMappings.json")
    event_formats_args.add_argument("-LE", "--logs-encoding", help="Specify encoding for Sysmon for Linux or Auditd files", type=str)
    config_formats_args.add_argument("--fieldlist", help="List all event fields", action='store_true')
    config_formats_args.add_argument("--evtx_dump", help="Path to evtx_dump binary for EVTX conversion (on Linux/MacOS use './evtx_dump' format)", type=str, default=None)
    config_formats_args.add_argument("--noexternal", "--bindings", help="Use Python bindings instead of external evtx_dump binaries (slower)", action='store_true')
    config_formats_args.add_argument("--cores", help="Number of CPU cores to use for EVTX extraction (default: all cores)", type=str)
    config_formats_args.add_argument("--debug", help="Enable debug logging", action='store_true')
    config_formats_args.add_argument("--imports", help="Show detailed module import errors", action='store_true')
    config_formats_args.add_argument("--showall", help="Show all events (helps identify slow rules)", action='store_true')
    config_formats_args.add_argument("-n", "--nolog", help="Don't create log or result files", action='store_true')
    config_formats_args.add_argument("--ondiskdb", help="Use on-disk database instead of in-memory (slower but uses less RAM)", type=str, default=":memory:")
    config_formats_args.add_argument("-RE", "--remove-events", help="Remove processed log files after successful analysis (use with caution)", action='store_true')
    config_formats_args.add_argument("-U", "--update-rules", help="Update rulesets in the 'rules' directory", action='store_true')
    config_formats_args.add_argument("-v", "--version", help="Display Zircolite version", action='store_true')
    config_formats_args.add_argument("--timefield", help="Specify time field name for event forwarding (default: 'SystemTime')", default="SystemTime", action="store_true")
    # Templating and Mini GUI options
    templating_formats_args = parser.add_argument_group(f'{Fore.BLUE}TEMPLATING AND MINI GUI OPTIONS{Fore.RESET}')
    templating_formats_args.add_argument("--template", help="Jinja2 template to use for output generation", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("--templateOutput", help="Output file for Jinja2 template results", type=str, action='append', nargs='+')
    templating_formats_args.add_argument("--package", help="Create a ZircoGui/Mini GUI package", action='store_true')
    templating_formats_args.add_argument("--package-dir", help="Directory to save the ZircoGui/Mini GUI package", type=str, default="")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler) 

    # Init logging
    if args.nolog: 
        args.logfile = None
    console_logger = initLogger(args.debug, args.logfile)

    console_logger.info("""
    ███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗
    ╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝
      ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗
     ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝
    ███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗
    ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
   -= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-
    """)

    # Print version and quit
    if args.version: 
        console_logger.info(f"Zircolite - v{version}")
        sys.exit(0)

    # Show imports status
    imports_message, args, must_quit = ImportErrorHandler(args)
    if imports_message: 
        console_logger.info(f"[+] Modules imports status: \n{imports_message}")
    else:
        console_logger.info("[+] Modules imports status: OK")
    if must_quit: 
        sys.exit(1)

    # Update rulesets
    if args.update_rules:
        console_logger.info("[+] Updating rules")
        updater = rulesUpdater(logger=console_logger)
        updater.run()
        sys.exit(0)

    # Handle rulesets args 
    if args.ruleset:
        args.ruleset = [item for args in args.ruleset for item in args]
    else: 
        args.ruleset = ["rules/rules_windows_generic_pysigma.json"]

    # Loading rulesets
    console_logger.info("[+] Loading ruleset(s)")
    rulesets_manager = rulesetHandler(console_logger, args, args.pipeline_list)
    if args.pipeline_list:
        sys.exit(0)

    # Check mandatory CLI options
    if not args.evtx: 
        console_logger.error(f"{Fore.RED}   [-] No events source path provided. Use '-e <PATH TO LOGS>', '--events <PATH TO LOGS>'{Fore.RESET}")
        sys.exit(2)
    if args.csv and len(args.ruleset) > 1: 
        console_logger.error(f"{Fore.RED}   [-] Since fields in results can change between rulesets, it is not possible to have CSV output when using multiple rulesets{Fore.RESET}")
        sys.exit(2)
    
    console_logger.info("[+] Checking prerequisites")

    # Checking provided timestamps
    try:
        events_after = time.strptime(args.after, '%Y-%m-%dT%H:%M:%S')
        events_before = time.strptime(args.before, '%Y-%m-%dT%H:%M:%S')
    except Exception:
        quitOnError(f"{Fore.RED}   [-] Wrong timestamp format. Please use 'YYYY-MM-DDTHH:MM:SS'", console_logger)

    # Check templates args
    ready_for_templating = False
    if args.template is not None:
        if args.csv: 
            quitOnError(f"{Fore.RED}   [-] You cannot use templates in CSV mode{Fore.RESET}", console_logger)
        if args.templateOutput is None or len(args.template) != len(args.templateOutput):
            quitOnError(f"{Fore.RED}   [-] Number of templates output must match number of templates{Fore.RESET}", console_logger)
        for template in args.template:
            checkIfExists(template[0], f"{Fore.RED}   [-] Cannot find template: {template[0]}. Default templates are available here: https://github.com/wagga40/Zircolite/tree/master/templates{Fore.RESET}", console_logger)
        ready_for_templating = True
    
    # Change output filename in CSV mode
    if args.csv: 
        ready_for_templating = False
        if args.outfile == "detected_events.json": 
            args.outfile = "detected_events.csv"

    # If on-disk DB already exists, quit
    if args.ondiskdb != ":memory:" and Path(args.ondiskdb).is_file():
        quitOnError(f"{Fore.RED}   [-] On-disk database already exists{Fore.RESET}", console_logger)

    # Start time counting
    start_time = time.time()

    # Initialize zirCore
    zircolite_core = zirCore(args.config, logger=console_logger, noOutput=args.nolog, timeAfter=events_after, timeBefore=events_before, limit=args.limit, csvMode=args.csv, timeField=args.timefield, hashes=args.hashes, dbLocation=args.ondiskdb, delimiter=args.csv_delimiter)
    
    # If we are not working directly with the db
    if not args.db_input:
        # Set appropriate file extension if not user-provided
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
        
        # Find log files based on path and pattern
        log_path = Path(args.evtx)
        if log_path.is_dir():
            pattern = f"*.{args.fileext}"
            if args.file_pattern not in [None, ""]:
                pattern = args.file_pattern
            
            # Use appropriate glob function based on recursion setting
            fn_glob = log_path.rglob if not args.no_recursion else log_path.glob
            log_list = list(fn_glob(pattern))
        elif log_path.is_file():
            log_list = [log_path]
        else:
            quitOnError(f"{Fore.RED}   [-] Unable to find events from submitted path{Fore.RESET}", console_logger)

        # Apply file filters
        file_list = avoidFiles(selectFiles(log_list, args.select), args.avoid)
        if not file_list:
            quitOnError(f"{Fore.RED}   [-] No file found. Please verify filters, directory or the extension with '--fileext' or '--file-pattern'{Fore.RESET}", console_logger)

        # Process logs based on input type
        if args.json_input or args.json_array_input:
            log_json_list = file_list
        else:
            # Initialize extractor for non-JSON formats
            extractor = evtxExtractor(
                logger=console_logger,
                providedTmpDir=args.tmpdir,
                coreCount=args.cores,
                useExternalBinaries=(not args.noexternal),
                binPath=args.evtx_dump,
                xmlLogs=args.xml_input,
                sysmon4linux=args.sysmon_linux_input,
                auditdLogs=args.auditd_input,
                evtxtract=args.evtxtract_input,
                encoding=args.logs_encoding,
                csvInput=args.csv_input
            )
            
            # Extract events
            console_logger.info(f"[+] Extracting events Using '{extractor.tmpDir}' directory ")
            for evtx in tqdm(file_list, colour="yellow"):
                extractor.run(evtx)
                
            # Set path for extracted JSON files
            log_json_list = list(Path(extractor.tmpDir).rglob("*.json"))

        # Verify config file exists
        checkIfExists(args.config, f"{Fore.RED}   [-] Cannot find mapping file, you can get the default one here : https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json {Fore.RESET}", console_logger)
        
        if not log_json_list:
            quitOnError(f"{Fore.RED}   [-] No files containing logs found.{Fore.RESET}", console_logger)

        # Print field list and exit if requested
        if args.fieldlist:
            fields = zircolite_core.run(log_json_list, Insert2Db=False, args_config=args)
            zircolite_core.close()
            if not (args.json_input or args.json_array_input or args.keeptmp):
                extractor.cleanup()
            [print(sorted_field) for sorted_field in sorted([field for field in fields.values()])]
            sys.exit(0)
        
        # Process logs and insert into database
        zircolite_core.run(log_json_list, saveToFile=args.keepflat, args_config=args)
        
        # Save in-memory DB to disk if requested
        if args.dbfile is not None:
            zircolite_core.saveDbToDisk(args.dbfile)
    else:
        console_logger.info(f"[+] Creating model from disk : {args.evtx}")
        zircolite_core.loadDbInMemory(args.evtx)

    # flatten array of "rulefilter" arguments
    if args.rulefilter: 
        args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

    write_mode = "w"
    for i, ruleset in enumerate(rulesets_manager.Rulesets):
        zircolite_core.loadRulesetFromVar(ruleset=ruleset, ruleFilters=args.rulefilter)
        
        if args.limit > 0: 
            console_logger.info(f"[+] Limited mode : detections with more than {args.limit} events will be discarded")
            
        console_logger.info(f"[+] Executing ruleset - {len(zircolite_core.ruleset)} rules")
        is_last_ruleset = (i == len(rulesets_manager.Rulesets) - 1)
        zircolite_core.executeRuleset(
            args.outfile, 
            writeMode=write_mode, 
            showAll=args.showall, 
            KeepResults=(ready_for_templating or args.package), 
            lastRuleset=is_last_ruleset
        )
        write_mode = "a"  # Next iterations will append to results file

    console_logger.info(f"[+] Results written in : {args.outfile}")

    # Process templates if needed
    if ready_for_templating and zircolite_core.fullResults:
        template_generator = templateEngine(console_logger, args.template, args.templateOutput, args.timefield)
        template_generator.run(zircolite_core.fullResults)

    # Generate ZircoGui package if requested
    if args.package and zircolite_core.fullResults:
        template_path = Path("templates/exportForZircoGui.tmpl")
        gui_zip_path = Path("gui/zircogui.zip")
        if template_path.is_file() and gui_zip_path.is_file():
            packager = zircoGuiGenerator(str(gui_zip_path), str(template_path), console_logger, args.timefield)
            packager.generate(zircolite_core.fullResults, args.package_dir)
    
    # Cleanup temporary files
    if not args.keeptmp:
        console_logger.info("[+] Cleaning")
        try:
            if not (args.json_input or args.json_array_input or args.db_input):
                extractor.cleanup()
        except OSError as e:
            console_logger.error(f"{Fore.RED}   [-] Error during cleanup {e}{Fore.RESET}")

    # Remove original event files if requested
    if args.remove_events:
        for evtx in log_list:
            try:
                os.remove(evtx)
            except OSError as e:
                console_logger.error(f"{Fore.RED}   [-] Cannot remove file {e}{Fore.RESET}")

    zircolite_core.close()
    console_logger.info(f"\nFinished in {int((time.time() - start_time))} seconds")

if __name__ == "__main__":
    main()
