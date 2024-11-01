#!python3

# Standard libs
import argparse
import asyncio
import base64
import chardet
import csv
import functools
import hashlib
import logging
import multiprocessing as mp
import os
import random
import re
import shutil
import signal
import socket
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
from tqdm.asyncio import tqdm as tqdmAsync
from RestrictedPython import compile_restricted
from RestrictedPython import safe_builtins
from RestrictedPython import limited_builtins
from RestrictedPython import utility_builtins
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_iter_unpack_sequence

# External libs (Optional)
forwardingDisabled = False
try: 
    import aiohttp 
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError: 
    forwardingDisabled = True

elasticForwardingDisabled = False
try: 
    from elasticsearch import AsyncElasticsearch
except ImportError: 
    elasticForwardingDisabled = True

updateDisabled = False
try:
    import requests
except ImportError:
    forwardingDisabled = True
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

class eventForwarder:
    """ Class for handling event forwarding """
    def __init__(self, remote, timeField, token, logger=None, index=None, login='', password='', pipeline=''):
        self.logger = logger or logging.getLogger(__name__)
        self.remoteHost = remote
        self.token = token
        self.localHostname = socket.gethostname()
        self.userAgent = "zircolite/2.x"
        self.index = index
        self.login = login
        self.password = password
        self.pipeline = pipeline
        self.queueSize = 20
        self.connectionFailed = False
        self.timeField = timeField

    def send(self, payloads, forwardAll=False):
        if payloads: 
            if self.remoteHost:
                try:
                    # Change EventLoopPolicy on Windows https://stackoverflow.com/questions/45600579/asyncio-event-loop-is-closed-when-getting-loop
                    if _platform == "win32": 
                        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                    # Splunk HEC
                    if self.token:
                        asyncio.run(self.sendAllAsyncQueue(payloads, timeField=self.timeField, sigmaEvents=(not forwardAll), mode="HEC"))
                    # ElasticSearch
                    elif self.index:
                        self.disableESDefaultLogging()
                        asyncio.run(self.sendAllAsyncQueue(payloads, timeField=self.timeField, sigmaEvents=(not forwardAll), mode="ES"))
                    # HTTP
                    else:
                        asyncio.run(self.sendAllAsyncQueue(payloads, timeField=self.timeField, sigmaEvents=(not forwardAll), mode="HTTP"))
                except Exception as e:
                    self.logger.debug(f"{Fore.RED}   [-] {e}")
        
    def networkCheck(self):
        """ Check remote connectivity """
        self.logger.info(f'[+] Check connectivity to {self.remoteHost}')
        try:
            requests.get(self.remoteHost, headers={'user-agent': self.userAgent}, timeout=10, verify=False)
        except (requests.ConnectionError, requests.Timeout):
            return False
        return True

    def formatToEpoch(self, timestamp):
        try:
            return str(time.mktime(time.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f%z'))) + timestamp.split(".")[1][:-1]
        except ValueError:
            try:
                return str(time.mktime(time.strptime(timestamp, '%Y-%m-%dT%H:%M:%S%z'))) + timestamp.split(".")[1][:-1]
            except Exception:
                self.logger.debug(f"{Fore.RED}   [-] Timestamp error: {timestamp}{Fore.RESET}")

    def disableESDefaultLogging(self):
        """ By Default Elastic client has a logger set to INFO level """
        es_log = logging.getLogger("elasticsearch")
        es_log.setLevel(logging.ERROR)
        es_log = logging.getLogger("elastic_transport")
        es_log.setLevel(logging.ERROR)

    async def HECWorker(self, session, queue, sigmaEvents):
        while True:
            if self.index:
                providedIndex = f"?index={self.index}"
            else:
                providedIndex = ""
            data = await queue.get() # Pop data from Queue
            resp = await session.post(f"{self.remoteHost}/services/collector/event{providedIndex}", headers={'Authorization': f"Splunk {self.token}"}, json=data) # Exec action from Queue
            queue.task_done() # Notify Queue action ended
            if str(resp.status)[0] in ["4", "5"]:
                self.logger.error(f"{Fore.RED}   [-] Forwarding failed for event {Fore.RESET}")

    async def ESWorker(self, session, queue, sigmaEvents):
        while True:
            data = await queue.get() # Pop data from Queue
            index = self.index
            if sigmaEvents:
                index = f'{self.index}-sigma'
            else:
                if "OriginalLogfile" in data["payload"]:
                    index = f'{index}-{("".join([char for char in data["payload"]["OriginalLogfile"].split(".")[0] if (char.isalpha() or char == "-")])).lower()}'
            try:
                await session.index(index=index, document=data["payload"], id=data["hash"]) # Exec action from Queue
            except Exception as e:
                if "error" in e.body: 
                    if  e.body["error"]["type"] == "mapper_parsing_exception":
                        errField = e.body["error"]["reason"].split("[")[1].split("]")[0]
                        errType = e.body["error"]["reason"].split("[")[2].split("]")[0]
                        errValue = e.body["error"]["reason"].split("value: '")[1].split("'")[0]
                        canInsert = False

                        if errType == "long" and errValue.startswith("0x"): # Hex value in long field
                            data["payload"][errField] = int(data["payload"][errField], 16)
                            canInsert = True
                        elif errType == "boolean" and errValue.startswith("0"): # 0 value in bool field
                            data["payload"][errField] = "false"
                            canInsert = True
                        elif errType == "boolean" and errValue.startswith("1"): # 1 value in bool field
                            data["payload"][errField] = "true"
                            canInsert = True
                        elif errType == "long" and isinstance((data["payload"][errField]), int) and data["payload"][errField] > (2**63 -1): # ES limit
                            data["payload"][errField] = 2 ** 63 - 1
                            canInsert = True
                        elif errType == "long" and isinstance((data["payload"][errField]), int) and data["payload"][errField] < -(2**63): # ES limit
                            data["payload"][errField] = -(2 ** 63)
                            canInsert = True
                        elif errType == "long" and isinstance(data["payload"][errField], argparse.BooleanOptionalAction):
                            if type(data["payload"][errField]):
                                data["payload"][errField] = 1
                            else: 
                                data["payload"][errField] = 0
                            canInsert = True
                        else:
                            self.logger.debug(f"{Fore.RED}   [-] ES Mapping parser error : {e}{Fore.RESET}")
                        if canInsert: 
                            try:
                                await session.index(index=index, document=data["payload"], id=data["hash"])
                            except Exception as e:
                                self.logger.debug(f"{Fore.RED}   [-] ES error : {e}{Fore.RESET}")
                    elif e.body["error"]["type"] == "illegal_argument_exception":
                        errField = e.body["error"]["reason"].split("[")[1].split("]")[0]
                        data["payload"].pop(errField, None) # remove value from payload
                        try:
                            await session.index(index=index, document=data["payload"], id=data["hash"])
                        except Exception as e:
                            self.logger.debug(f"{Fore.RED}   [-] ES error : {e}{Fore.RESET}")
                    else:
                        self.logger.debug(f"{Fore.RED}   [-] ES error : {e}{Fore.RESET}")

            queue.task_done() # Notify Queue action ended
        
    async def HTTPWorker(self, session, queue, sigmaEvents):
        while True:
            data = await queue.get() # Pop data from Queue
            resp = await session.post(self.remoteHost, headers={"user-agent": self.userAgent}, json=data) # Exec action from Queue
            queue.task_done() # Notify Queue action ended
            if str(resp.status)[0] in ["4", "5"]:
                self.logger.error(f"{Fore.RED}   [-] Forwarding failed for event {Fore.RESET}")

    def formatEventForES(self, payload, match={}, timeField="", sigmaEvents=False):
        if self.pipeline != "":
            payload["pipeline"] = self.pipeline
        if sigmaEvents:
            payload = {"title": payload["title"], "id": payload["id"],"sigmafile": payload["sigmafile"], "description": payload["description"], "sigma": payload["sigma"], "rule_level": payload["rule_level"], "tags": payload["tags"], "host": self.localHostname}
            [payload.update({key: eval(value)}) if value in ["False", "True"] else payload.update({key: value}) for key, value in match.items()] # In detected events boolean are stored as strings

        return {"payload": payload, "hash":xxhash.xxh64_hexdigest(str(payload))}

    def formatEventForSplunk(self, payload, match={}, timeField="", sigmaEvents=False):
        if sigmaEvents:
            payload = {"title": payload["title"], "id": payload["id"],"sigmafile": payload["sigmafile"], "description": payload["description"], "sigma": payload["sigma"], "rule_level": payload["rule_level"], "tags": payload["tags"]}
            [payload.update({key: value}) for key, value in match.items()]
        if (timeField == ""):
            return {"sourcetype": "_json", "event": payload, "host": self.localHostname }
        elif (timeField not in payload):
            self.logger.error(f"{Fore.RED}   [-] Provided time field was not found {Fore.RESET}")
            return {"sourcetype": "_json", "event": payload, "host": self.localHostname }
        else:
            return {"sourcetype": "_json", "event": payload, "host": self.localHostname, "time": self.formatToEpoch(payload[timeField])}
    
    def formatEventForHTTTP(self, payload, match={}, timeField="", sigmaEvents=False):
        payload.update({"host": self.localHostname})
        return payload

    def initESSession(self):
        if self.login == "":
            session = AsyncElasticsearch(hosts=[self.remoteHost], verify_certs=False)
        else:
            session = AsyncElasticsearch(hosts=[self.remoteHost], verify_certs=False, basic_auth=(self.login, self.password))
        return session

    async def testESSession(self, session):
        try:
            await session.info()
        except Exception:
            self.logger.error(f"{Fore.RED}   [-] Connection to ES failed {Fore.RESET}")
            await session.close()
            self.connectionFailed = True

    async def testSplunkSession(self, session):
        data = {"sourcetype": "_json", "event": {}, "host": self.localHostname }
        resp = await session.post(f"{self.remoteHost}/services/collector/event", headers={'Authorization': f"Splunk {self.token}"}, json=data)
        if str(resp.status)[0] in ["4", "5"]:
            await session.close()
            self.logger.error(f"{Fore.RED}   [-] Connection to Splunk HEC failed - Forwarding disabled {Fore.RESET}")
            self.connectionFailed = True

    async def testHTTPSession(self, session):
        resp = await session.post(self.remoteHost, headers={"user-agent": self.userAgent}, json={})
        if str(resp.status)[0] in ["4", "5"]:
            await session.close()
            self.logger.error(f"{Fore.RED}   [-] Connection to HTTP Server failed - Forwarding disabled {Fore.RESET}")
            self.connectionFailed = True

    async def sendAllAsyncQueue(self, payloads, timeField="", sigmaEvents=False, mode=""):

        if self.connectionFailed: 
            return

        if mode == "ES":
            session = self.initESSession()
            await self.testESSession(session)
            if self.connectionFailed: 
                return
            fnformatEvent = self.formatEventForES
            fnWorker = self.ESWorker
        elif mode == "HEC":
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            await self.testSplunkSession(session)
            if self.connectionFailed: 
                return
            fnformatEvent = self.formatEventForSplunk
            fnWorker = self.HECWorker
        elif mode == "HTTP":
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            await self.testHTTPSession(session)
            if self.connectionFailed: 
                return
            fnformatEvent = self.formatEventForHTTTP
            fnWorker = self.HTTPWorker
        else: 
            return

        # Init queue
        queue = asyncio.Queue()
        tasks = []

        if not sigmaEvents: 
            self.logger.info('[+] Gathering events to forward')
            payloads = tqdmAsync(payloads, colour="yellow") 

        for payload in payloads:
            if sigmaEvents:
                for match in payload["matches"]:
                    queue.put_nowait(fnformatEvent(payload=payload, match=match, timeField=timeField, sigmaEvents=sigmaEvents))
            else:
                queue.put_nowait(fnformatEvent(payload=payload, timeField=timeField, sigmaEvents=sigmaEvents))

        # Create workers to process Queue
        for i in range(20):
            task = asyncio.create_task(fnWorker(session, queue, sigmaEvents=sigmaEvents))
            tasks.append(task)
        if not sigmaEvents:    
            self.logger.info(f'[+] Forwarding {queue.qsize()} events to {self.remoteHost} {Fore.CYAN}(Don\'t panic if nothing change for a long time){Fore.RESET}')
        await queue.join()
        # Cancel our worker tasks.
        for task in tasks:
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await asyncio.gather(*tasks, return_exceptions=True)
        await session.close()

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
                        if rawFieldName in self.fieldMappings:
                            key = self.fieldMappings[rawFieldName]
                        else:
                            # Removing all annoying character from field name
                            key = ''.join(e for e in rawFieldName.split(".")[-1] if e.isalnum())

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
                                        if transform["enabled"] and self.chosen_input in transform["source_condition"] :
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
                        
                        if len(fieldsToSplit) > 0:
                            for field in fieldsToSplit:
                                try:
                                    splittedFields = value.split(self.fieldSplitList[field]["separator"])
                                    for splittedField in splittedFields:
                                        k,v = splittedField.split(self.fieldSplitList[field]["equal"])
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
                                if isinstance(value, int):
                                    fieldStmt += f"'{key}' INTEGER,\n"
                                else:
                                    fieldStmt += f"'{key}' TEXT COLLATE NOCASE,\n"
        
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
                        dictToFlatten.update({"OriginalLogfile": filename})
                        if self.hashes: 
                            dictToFlatten.update({"OriginalLogLinexxHash": xxhash.xxh64_hexdigest(line[:-1])})
                        flatten(dictToFlatten)
                    except Exception as e:
                        self.logger.debug(f'JSON ERROR : {e}')
                    # Handle timestamp filters
                    if (self.timeAfter != "1970-01-01T00:00:00" or self.timeBefore != "9999-12-12T23:59:59") and (self.timeField in JSONLine):
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

    def insertFlattenedJSON2Db(self, flattenedJSON, forwarder=None):
        if forwarder:
            forwarder.send(flattenedJSON, forwardAll=True) 
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

    def executeRuleset(self, outFile, writeMode='w', forwarder=None, showAll=False,
                    KeepResults=False, remote=None, stream=False, lastRuleset=False):
        """
        Execute all rules in the ruleset and handle output.
        """
        csvWriter = None
        first_json_output = True  # To manage commas in JSON output
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
                if KeepResults or (remote and not stream):
                    self.fullResults.append(ruleResults)

                # Forward results if streaming
                if stream and forwarder:
                    forwarder.send([ruleResults], False)

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
                            if not first_json_output:
                                fileHandle.write(',\n')
                            else:
                                first_json_output = False
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

    def run(self, EVTXJSONList, Insert2Db=True, saveToFile=False, forwarder=None, args_config=None):
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
            self.insertFlattenedJSON2Db(flattener.valuesStmt, forwarder)
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
        # Hardcoded hash list of evtx_dump binaries
        self.validHashList = ["bbcce464533e0364", "e642f5c23e156deb", "5a7a1005885a1a11"]
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
        """ Determine which binaries to run depending on host OS : 32Bits is NOT supported for now since evtx_dump is 64bits only"""
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

    def verifyBinHash(self, binPath):
        """
        Verify the hash of a binary (Hashes are hardcoded)
        """
        hasher =  xxhash.xxh64()
        try:
            # Open the file in binary mode and read chunks to hash
            with open(binPath, 'rb') as f:
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
        outputJSONFilename = f"{self.tmpDir}/{str(filename)}-{self.randString()}.json"
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
                with open(str(file), 'r', encoding="utf-8") as XMLFile:
                    data = XMLFile.read().replace("\n","").replace("</Event>","</Event>\n").replace("<Event ","\n<Event ")
                self.Logs2JSON(self.XMLLine2JSON, data, outputJSONFilename, isFile=False)
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
            if not self.useExternalBinaries or not Path(self.evtxDumpCmd).is_file(): 
                self.logger.debug("   [-] No external binaries args or evtx_dump is missing")
                self.runUsingBindings(file)
            else:
                # Check if the binary is valid does not avoid TOCTOU 
                if self.verifyBinHash(self.evtxDumpCmd):
                    try:
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
    def __init__(self, packageDir, templateFile, logger=None, outputFile = None, timeField = ""):
        self.logger = logger or logging.getLogger(__name__)
        self.templateFile = templateFile
        self.tmpDir = f'tmp-zircogui-{self.randString()}'
        self.tmpFile = f'data-{self.randString()}.js'
        self.outputFile = outputFile or f'zircogui-output-{self.randString()}'
        self.packageDir = packageDir
        self.timeField = timeField

    def randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))

    def unzip(self):
        try:
            shutil.unpack_archive(self.packageDir, self.tmpDir, "zip")
        except Exception as e:
            self.logger.error(f"   [-] {e}")
        
    def zip(self):
        try:
            shutil.make_archive(self.outputFile, 'zip', f"{self.tmpDir}/zircogui")
        except Exception as e:
            self.logger.error(f"   [-] {e}")

    def generate(self, data):
        self.unzip()
        try:
            self.logger.info(f"[+] Generating ZircoGui package to : {self.outputFile}.zip")
            exportforzircoguiTmpl = templateEngine(self.logger, self.templateFile, self.tmpFile, self.timeField)
            exportforzircoguiTmpl.generateFromTemplate(exportforzircoguiTmpl.template, exportforzircoguiTmpl.templateOutput, data)
        except Exception as e:
            self.logger.error(f"   [-] {e}")
        shutil.move(self.tmpFile, f'{self.tmpDir}/zircogui/data.js')
        self.zip()
        shutil.rmtree(self.tmpDir)

class rulesUpdater:
    """ 
    Download rulesets from the https://github.com/wagga40/Zircolite-Rules repository and update if necessary.
    """

    def __init__(self, logger=None):
        self.url = "https://github.com/wagga40/Zircolite-Rules/archive/refs/heads/main.zip"
        self.logger = logger or logging.getLogger(__name__)
        self.tempFile = f'tmp-rules-{self.randString()}.zip'
        self.tmpDir = f'tmp-rules-{self.randString()}'
        self.updatedRulesets = []

    def randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4))

    def download(self):
        resp = requests.get(self.url, stream=True)
        total = int(resp.headers.get('content-length', 0))
        with open(self.tempFile, 'wb') as file, tqdm(desc=self.tempFile, total=total, unit='iB', unit_scale=True, unit_divisor=1024, colour="yellow") as bar:
            for data in resp.iter_content(chunk_size=1024):
                size = file.write(data)
                bar.update(size)
    
    def unzip(self):
        shutil.unpack_archive(self.tempFile, self.tmpDir, "zip")
    
    def checkIfNewerAndMove(self):
        count = 0
        rulesets = Path(self.tmpDir).rglob("*.json")
        for ruleset in rulesets:
            hash_new = hashlib.md5(open(ruleset,'rb').read()).hexdigest()
            if Path(f'rules/{ruleset.name}').is_file():
                hash_old = hashlib.md5(open(f'rules/{ruleset.name}','rb').read()).hexdigest()
            else: 
                hash_old = ""
            if hash_new != hash_old:
                count += 1
                if not Path('rules/').exists():
                    Path('rules/').mkdir()
                shutil.move(ruleset, f'rules/{ruleset.name}')
                self.updatedRulesets.append(f'rules/{ruleset.name}')
                self.logger.info(f"{Fore.CYAN}   [+] Updated : rules/{ruleset.name}{Fore.RESET}")
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
                with open(tempRulesetName, 'w') as outfile:
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

    if forwardingDisabled:
        importErrorList.append(f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'aiohttp' or 'urllib3' or 'requests', events forwarding is disabled{Fore.RESET}")
        config.remote = None
    if elasticForwardingDisabled:
        importErrorList.append(f"{Fore.LIGHTYELLOW_EX}   [i] Cannot import 'elasticsearch[async]', events forwarding to Elastic is disabled{Fore.RESET}")
        config.index = None
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
        if config.xml:
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
    version = "2.30.1"

    # Init Args handling
    parser = argparse.ArgumentParser()
    # Input files and filtering/selection options
    logsInputArgs = parser.add_argument_group(f'{Fore.BLUE}INPUT FILES AND FILTERING/SELECTION OPTIONS{Fore.RESET}')
    logsInputArgs.add_argument("-e", "--evtx", "--events", help="Log file or directory where log files are stored in supported format", type=str)
    logsInputArgs.add_argument("-s", "--select", help="Only files with filenames containing the provided string will be used. If there is/are exclusion(s) (--avoid) they will be handled after selection", action='append', nargs='+')
    logsInputArgs.add_argument("-a", "--avoid", help="Files files with filenames containing the provided string will NOT be used", action='append', nargs='+')
    logsInputArgs.add_argument("-f", "--fileext", help="Extension of the log files", type=str)    
    logsInputArgs.add_argument("-fp", "--file-pattern", help="Use a Python Glob pattern to select files. This option only works with directories", type=str)
    logsInputArgs.add_argument("--no-recursion", help="By default Zircolite search log/event files recursively, by using this option only the provided directory will be used", action="store_true")
    # Events filtering options
    eventArgs = parser.add_argument_group(f'{Fore.BLUE}EVENTS FILTERING OPTIONS{Fore.RESET}')
    eventArgs.add_argument("-A", "--after", help="Limit to events that happened after the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="1970-01-01T00:00:00")
    eventArgs.add_argument("-B", "--before", help="Limit to events that happened before the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="9999-12-12T23:59:59")
    # Event and log formats options
    # /!\ an option name containing '-input' must exists (It is used in JSON flattening mechanism)
    eventFormatsArgs = parser.add_mutually_exclusive_group()
    eventFormatsArgs.add_argument("-j", "--json-input", "--jsononly", "--jsonline", "--jsonl", help="If logs files are already in JSON lines format ('jsonl' in evtx_dump) ", action='store_true')
    eventFormatsArgs.add_argument("--json-array-input", "--jsonarray", "--json-array", help="Source logs are in JSON but as an array", action='store_true')
    eventFormatsArgs.add_argument("--db-input", "-D", "--dbonly", help="Directly use a previously saved database file, timerange filters will not work", action='store_true')
    eventFormatsArgs.add_argument("-S", "--sysmon-linux-input", "--sysmon4linux", "--sysmon-linux", help="Use this option if your log file is a Sysmon for linux log file, default file extension is '.log'", action='store_true')
    eventFormatsArgs.add_argument("-AU", "--auditd-input", "--auditd", help="Use this option if your log file is a Auditd log file, default file extension is '.log'", action='store_true')
    eventFormatsArgs.add_argument("-x", "--xml-input", "--xml", help="Use this option if your log file is a EVTX converted to XML log file, default file extension is '.xml'", action='store_true')
    eventFormatsArgs.add_argument("--evtxtract-input", "--evtxtract", help="Use this option if your log file was extracted with EVTXtract, default file extension is '.log'", action='store_true')
    eventFormatsArgs.add_argument("--csv-input", "--csvonly", help="You log file is in CSV format '.csv'", action='store_true')
    # Ruleset options
    rulesetsFormatsArgs = parser.add_argument_group(f'{Fore.BLUE}RULES AND RULESETS OPTIONS{Fore.RESET}')  
    rulesetsFormatsArgs.add_argument("-r", "--ruleset", help="Sigma ruleset : JSON (Zircolite format) or YAML/Directory containing YAML files (Native Sigma format)", action='append', nargs='+')
    rulesetsFormatsArgs.add_argument("-nsc", "--no-sigma-conversion", help=argparse.SUPPRESS, action='store_true')
    rulesetsFormatsArgs.add_argument("-cr", "--combine-rulesets", help="Merge all rulesets provided into one", action='store_true')
    rulesetsFormatsArgs.add_argument("-sr", "--save-ruleset", help="Save converted ruleset (Sigma to Zircolite format) to disk", action='store_true')
    rulesetsFormatsArgs.add_argument("-p", "--pipeline", help="For all the native Sigma rulesets (YAML) use this pipeline. Multiple can be used. Examples : 'sysmon', 'windows-logsources', 'windows-audit'. You can list installed pipelines with '--pipeline-list'.", action='append', nargs='+')
    rulesetsFormatsArgs.add_argument("-pl", "--pipeline-list", help="List installed pysigma pipelines", action='store_true')
    rulesetsFormatsArgs.add_argument("-pn", "--pipeline-null", help="For all the native Sigma rulesets (YAML) don't use any pipeline (Default)", action='store_true')
    rulesetsFormatsArgs.add_argument("-R", "--rulefilter", help="Remove rule from ruleset, comparison is done on rule title (case sensitive)", action='append', nargs='*')
    # Ouput formats and output files options
    outputFormatsArgs = parser.add_argument_group(f'{Fore.BLUE}OUPUT FORMATS AND OUTPUT FILES OPTIONS{Fore.RESET}')
    outputFormatsArgs.add_argument("-o", "--outfile", help="File that will contains all detected events", type=str, default="detected_events.json")
    outputFormatsArgs.add_argument("--csv", "--csv-output", help="The output will be in CSV. You should note that in this mode empty fields will not be discarded from results", action='store_true')
    outputFormatsArgs.add_argument("--csv-delimiter", help="Choose the delimiter for CSV ouput", type=str, default=";")
    outputFormatsArgs.add_argument("-t", "--tmpdir", help="Temp directory that will contains events converted as JSON (parent directories must exist)", type=str)
    outputFormatsArgs.add_argument("-k", "--keeptmp", help="Do not remove the temp directory containing events converted in JSON format", action='store_true')
    outputFormatsArgs.add_argument("--keepflat", help="Save flattened events as JSON", action='store_true')
    outputFormatsArgs.add_argument("-d", "--dbfile", help="Save all logs in a SQLite Db to the specified file", type=str)
    outputFormatsArgs.add_argument("-l", "--logfile", help="Log file name", default="zircolite.log", type=str)
    outputFormatsArgs.add_argument("--hashes", help="Add an xxhash64 of the original log event to each event", action='store_true')
    outputFormatsArgs.add_argument("-L", "--limit", "--limit-results", help="Discard results (in output file or forwarded events) that are above the provided limit", type=int, default=-1)
    # Advanced configuration options
    configFormatsArgs = parser.add_argument_group(f'{Fore.BLUE}ADVANCED CONFIGURATION OPTIONS{Fore.RESET}')  
    configFormatsArgs.add_argument("-c", "--config", help="JSON File containing field mappings and exclusions", type=str, default="config/fieldMappings.json")
    eventFormatsArgs.add_argument("-LE", "--logs-encoding",  help="Specify log encoding when dealing with Sysmon for Linux or Auditd files", type=str)
    configFormatsArgs.add_argument("--fieldlist", help="Get all events fields", action='store_true')
    configFormatsArgs.add_argument("--evtx_dump", help="Tell Zircolite to use this binary for EVTX conversion, on Linux and MacOS the path must be valid to launch the binary (eg. './evtx_dump' and not 'evtx_dump')", type=str, default=None)
    configFormatsArgs.add_argument("--noexternal", "--bindings", help="Don't use evtx_dump external binaries (slower)", action='store_true')
    configFormatsArgs.add_argument("--cores", help="Specify how many cores you want to use, default is all cores, works only for EVTX extraction", type=str)
    configFormatsArgs.add_argument("--debug", help="Activate debug logging", action='store_true')
    configFormatsArgs.add_argument("--imports", help="Show detailed module import errors", action='store_true')
    configFormatsArgs.add_argument("--showall", help="Show all events, useful to check what rule takes takes time to execute", action='store_true')
    configFormatsArgs.add_argument("-n", "--nolog", help="Don't create a log file or a result file (useful when forwarding)", action='store_true')
    configFormatsArgs.add_argument("--ondiskdb", help="Use an on-disk database instead of the in-memory one (much slower !). Use if your system has limited RAM or if your dataset is very large and you cannot split it", type=str, default=":memory:")
    configFormatsArgs.add_argument("-RE", "--remove-events", help="Zircolite will try to remove events/logs submitted if analysis is successful (use at your own risk)", action='store_true')
    configFormatsArgs.add_argument("-U", "--update-rules", help="Update rulesets located in the 'rules' directory", action='store_true')
    configFormatsArgs.add_argument("-v", "--version", help="Show Zircolite version", action='store_true')
    # Forwarding options
    forwardingFormatsArgs = parser.add_argument_group(f'{Fore.BLUE}FORWARDING OPTIONS{Fore.RESET}')
    forwardingFormatsArgs.add_argument("--remote", help="Forward results to a HTTP/Splunk/Elasticsearch, please provide the full address e.g http[s]://address:port[/uri]", type=str)
    forwardingFormatsArgs.add_argument("--token", help="Use this to provide Splunk HEC Token", type=str)
    forwardingFormatsArgs.add_argument("--index", help="Use this to provide ES index", type=str)
    forwardingFormatsArgs.add_argument("--eslogin", help="ES login", type=str, default="")
    forwardingFormatsArgs.add_argument("--espass", help="ES password", type=str, default="")
    forwardingFormatsArgs.add_argument("--stream", help="By default event forwarding is done at the end, this option activate forwarding events when detected", action="store_true")
    forwardingFormatsArgs.add_argument("--forwardall", help="Forward all events", action="store_true")
    forwardingFormatsArgs.add_argument("--timefield", help="Provide time field name for event forwarding, default is 'SystemTime'", default="SystemTime", action="store_true")
    # Templating and Mini GUI options
    templatingFormatsArgs = parser.add_argument_group(f'{Fore.BLUE}TEMPLATING AND MINI GUI OPTIONS{Fore.RESET}')
    templatingFormatsArgs.add_argument("--template", help="If a Jinja2 template is specified it will be used to generated output", type=str, action='append', nargs='+')
    templatingFormatsArgs.add_argument("--templateOutput", help="If a Jinja2 template is specified it will be used to generate a crafted output", type=str, action='append', nargs='+')
    templatingFormatsArgs.add_argument("--package", help="Create a ZircoGui/Mini Gui package", action='store_true')
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler) 

    # Init logging
    if args.nolog: 
        args.logfile = None
    consoleLogger = initLogger(args.debug, args.logfile)

    consoleLogger.info("""
    ███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗
    ╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝
      ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗
     ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝
    ███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗
    ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
   -= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-
    """)

    # Print version an quit
    if args.version: 
        consoleLogger.info(f"Zircolite - v{version}")
        sys.exit(0)

    # Show imports status
    importsMessage, args, mustQuit = ImportErrorHandler(args)
    if importsMessage != "": 
        consoleLogger.info(f"[+] Modules imports status: \n{importsMessage}")
    else:
        consoleLogger.info("[+] Modules imports status: OK")
    if mustQuit: 
        sys.exit(1)

    # Update rulesets
    if args.update_rules:
        consoleLogger.info("[+] Updating rules")
        updater = rulesUpdater(logger=consoleLogger)
        updater.run()
        sys.exit(0)

    # Handle rulesets args 
    if args.ruleset:
        args.ruleset = [item for args in args.ruleset for item in args]
    else: 
        args.ruleset = ["rules/rules_windows_generic_pysigma.json"]

    # Loading rulesets
    consoleLogger.info("[+] Loading ruleset(s)")
    rulesetsManager = rulesetHandler(consoleLogger, args, args.pipeline_list)
    if args.pipeline_list:
        sys.exit(0)

    # Check mandatory CLI options
    if not args.evtx: 
        consoleLogger.error(f"{Fore.RED}   [-] No events source path provided. Use '-e <PATH TO LOGS>', '--events <PATH TO LOGS>'{Fore.RESET}"), sys.exit(2)
    if args.forwardall and args.db_input: 
        consoleLogger.error(f"{Fore.RED}   [-] Can't forward all events in db only mode {Fore.RESET}"), sys.exit(2)
    if args.csv and len(args.ruleset) > 1: 
        consoleLogger.error(f"{Fore.RED}   [-] Since fields in results can change between rulesets, it is not possible to have CSV output when using multiple rulesets{Fore.RESET}"), sys.exit(2)
    
    consoleLogger.info("[+] Checking prerequisites")

    # Init Forwarding
    forwarder = None
    if args.remote is not None: 
        consoleLogger.info(f"{Fore.LIGHTRED_EX}[!] Forwarding is not tested anymore and will be removed in the future{Fore.RESET}")
        forwarder = eventForwarder(remote=args.remote, timeField=args.timefield, token=args.token, logger=consoleLogger, index=args.index, login=args.eslogin, password=args.espass)
        if not forwarder.networkCheck(): 
            quitOnError(f"{Fore.RED}   [-] Remote host cannot be reached : {args.remote}{Fore.RESET}", consoleLogger)
    
    # Checking provided timestamps
    try:
        eventsAfter = time.strptime(args.after, '%Y-%m-%dT%H:%M:%S')
        eventsBefore = time.strptime(args.before, '%Y-%m-%dT%H:%M:%S')
    except Exception:
        quitOnError(f"{Fore.RED}   [-] Wrong timestamp format. Please use 'AAAA-MM-DDTHH:MM:SS'", consoleLogger)

    # Check templates args
    readyForTemplating = False
    if (args.template is not None):
        if args.csv: 
            quitOnError(f"{Fore.RED}   [-] You cannot use templates in CSV mode{Fore.RESET}", consoleLogger)
        if (args.templateOutput is None) or (len(args.template) != len(args.templateOutput)):
            quitOnError(f"{Fore.RED}   [-] Number of templates output must match number of templates{Fore.RESET}", consoleLogger)
        for template in args.template:
            checkIfExists(template[0], f"{Fore.RED}   [-] Cannot find template : {template[0]}. DEfault templates are available here : https://github.com/wagga40/Zircolite/tree/master/templates{Fore.RESET}", consoleLogger)
        readyForTemplating = True
    
    # Change output filename in CSV mode
    if args.csv: 
        readyForTemplating = False
        if args.outfile == "detected_events.json": 
            args.outfile = "detected_events.csv"

    # If on-disk DB already exists, quit.
    if args.ondiskdb != ":memory:" and (Path(args.ondiskdb).is_file()):
        quitOnError(f"{Fore.RED}   [-] On-disk database already exists{Fore.RESET}", consoleLogger) 

    # Start time counting
    start_time = time.time()

    # Initialize zirCore
    zircoliteCore = zirCore(args.config, logger=consoleLogger, noOutput=args.nolog, timeAfter=eventsAfter, timeBefore=eventsBefore, limit=args.limit, csvMode=args.csv, timeField=args.timefield, hashes=args.hashes, dbLocation=args.ondiskdb, delimiter=args.csv_delimiter)
    
    # If we are not working directly with the db
    if not args.db_input:
        # If we are working with json we change the file extension if it is not user-provided
        if not args.fileext:
            if args.json_input or args.json_array_input:
                args.fileext = "json"
            elif (args.sysmon_linux_input or args.auditd_input):
                args.fileext = "log"
            elif args.xml_input:
                args.fileext = "xml"
            elif args.csv_input:
                args.fileext = "csv"
            else:
                args.fileext = "evtx"
        
        LogPath = Path(args.evtx)
        if LogPath.is_dir():
            # Log recursive search in given directory with given file extension or pattern
            pattern = f"*.{args.fileext}"
            # If a Glob pattern is provided
            if args.file_pattern not in [None, ""]: 
                pattern = args.file_pattern
            fnGlob = LogPath.rglob

            if args.no_recursion: 
                fnGlob = LogPath.glob
            LogList = list(fnGlob(pattern))
        elif LogPath.is_file():
            LogList = [LogPath]
        else:
            quitOnError(f"{Fore.RED}   [-] Unable to find events from submitted path{Fore.RESET}", consoleLogger)

        # Applying file filters in this order : "select" than "avoid"
        FileList = avoidFiles(selectFiles(LogList, args.select), args.avoid)
        if len(FileList) <= 0:
            quitOnError(f"{Fore.RED}   [-] No file found. Please verify filters, directory or the extension with '--fileext' or '--file-pattern'{Fore.RESET}", consoleLogger)

        if not args.json_input and not args.json_array_input:
            # Init EVTX extractor object
            extractor = evtxExtractor(logger=consoleLogger, providedTmpDir=args.tmpdir, coreCount=args.cores, useExternalBinaries=(not args.noexternal), binPath=args.evtx_dump, xmlLogs=args.xml_input, sysmon4linux=args.sysmon_linux_input, auditdLogs=args.auditd_input, evtxtract=args.evtxtract_input, encoding=args.logs_encoding, csvInput=args.csv_input)
            consoleLogger.info(f"[+] Extracting events Using '{extractor.tmpDir}' directory ")
            for evtx in tqdm(FileList, colour="yellow"):
                extractor.run(evtx)
            # Set the path for the next step
            LogJSONList = list(Path(extractor.tmpDir).rglob("*.json"))
        else:
            LogJSONList = FileList

        checkIfExists(args.config, f"{Fore.RED}   [-] Cannot find mapping file, you can get the default one here : https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json {Fore.RESET}", consoleLogger)
        if LogJSONList == []:
            quitOnError(f"{Fore.RED}   [-] No files containing logs found.{Fore.RESET}", consoleLogger)

        # Print field list and exit
        if args.fieldlist:
            fields = zircoliteCore.run(LogJSONList, Insert2Db=False, args_config=args)
            zircoliteCore.close()
            if not args.json_input and not args.json_array_input and not args.keeptmp:
                extractor.cleanup()
            [print(sortedField) for sortedField in sorted([field for field in fields.values()])]
            sys.exit(0)
        
        # Flatten and insert to Db
        if args.forwardall:
            zircoliteCore.run(LogJSONList, saveToFile=args.keepflat, forwarder=forwarder, args_config=args)
        else:
            zircoliteCore.run(LogJSONList, saveToFile=args.keepflat, args_config=args)
        # Unload In memory DB to disk. Done here to allow debug in case of ruleset execution error
        if args.dbfile is not None: 
            zircoliteCore.saveDbToDisk(args.dbfile)
    else:
        consoleLogger.info(f"[+] Creating model from disk : {args.evtx}")
        zircoliteCore.loadDbInMemory(args.evtx)

    # flatten array of "rulefilter" arguments
    if args.rulefilter: 
        args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

    writeMode = "w"
    for ruleset in rulesetsManager.Rulesets:
        zircoliteCore.loadRulesetFromVar(ruleset=ruleset, ruleFilters=args.rulefilter)
        if args.limit > 0: 
            consoleLogger.info(f"[+] Limited mode : detections with more than {args.limit} events will be discarded")
        consoleLogger.info(f"[+] Executing ruleset - {len(zircoliteCore.ruleset)} rules")
        zircoliteCore.executeRuleset(args.outfile, writeMode=writeMode, forwarder=forwarder, showAll=args.showall, KeepResults=(readyForTemplating or args.package), remote=args.remote, stream=args.stream, lastRuleset=(ruleset == rulesetsManager.Rulesets[-1]))
        writeMode = "a" # Next iterations will append to results file

    consoleLogger.info(f"[+] Results written in : {args.outfile}")

    # Forward events
    if args.remote is not None and not args.stream: # If not in stream mode
        consoleLogger.info(f"[+] Forwarding to : {args.remote}")
        forwarder.send(zircoliteCore.fullResults, False)
    if args.remote is not None and args.stream: 
        consoleLogger.info(f"[+] Forwarded to : {args.remote}")

    # Templating
    if readyForTemplating and zircoliteCore.fullResults != []:
        templateGenerator = templateEngine(consoleLogger, args.template, args.templateOutput, args.timefield)
        templateGenerator.run(zircoliteCore.fullResults)

    # Generate ZircoGui package
    if args.package and zircoliteCore.fullResults != []:
        if Path("templates/exportForZircoGui.tmpl").is_file() and Path("gui/zircogui.zip").is_file():
            packager = zircoGuiGenerator("gui/zircogui.zip", "templates/exportForZircoGui.tmpl", consoleLogger, None, args.timefield)
            packager.generate(zircoliteCore.fullResults)
    
    # Remove working directory containing logs as json
    if not args.keeptmp:
        consoleLogger.info("[+] Cleaning")
        try:
            if not args.json_input and not args.json_array_input and not args.db_input:
                extractor.cleanup()
        except OSError as e:
            consoleLogger.error(f"{Fore.RED}   [-] Error during cleanup {e}{Fore.RESET}")

    # Remove files submitted for analysis
    if args.remove_events:
        for EVTX in LogList:
            try:
                os.remove(EVTX)
            except OSError as e:
                consoleLogger.error(f"{Fore.RED}   [-] Cannot remove files {e}{Fore.RESET}")

    zircoliteCore.close()
    consoleLogger.info(f"\nFinished in {int((time.time() - start_time))} seconds")

if __name__ == "__main__":
    main()