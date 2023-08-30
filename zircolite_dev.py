#!python3

# Standard libs
import argparse
import csv
import hashlib
import logging
import multiprocessing as mp
import os
from pathlib import Path
import random
import re
import shutil
import signal
import socket
import sqlite3
from sqlite3 import Error
import string
import subprocess
import time
import sys
from sys import platform as _platform

# External libs
import aiohttp
import asyncio
from colorama import Fore
from elasticsearch import AsyncElasticsearch
from evtx import PyEvtxParser
from jinja2 import Template
from lxml import etree
import orjson as json
import requests
import socket
from tqdm import tqdm
from tqdm.asyncio import tqdm as tqdmAsync
import urllib3
import xxhash

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    
    def generateFromTemplate(self, templateFile, outpoutFilename, data):
        """ Use Jinja2 to output data in a specific format """
        try:
            
            tmpl = open(templateFile, 'r', encoding='utf-8')
            template = Template(tmpl.read())
            
            with open(outpoutFilename, 'a', encoding='utf-8') as tpl:
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
                    if _platform == "win32": asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
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
        except (requests.ConnectionError, requests.Timeout) as exception:
            return False
        return True

    def formatToEpoch(self, timestamp):
        try:
            return str(time.mktime(time.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f%z'))) + timestamp.split(".")[1][:-1]
        except ValueError:
            try:
                return str(time.mktime(time.strptime(timestamp, '%Y-%m-%dT%H:%M:%S%z'))) + timestamp.split(".")[1][:-1]
            except Exception as e:
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
                        elif errType == "long" and type(data["payload"][errField]) is int and data["payload"][errField] > (2**63 -1): # ES limit
                            data["payload"][errField] = 2 ** 63 - 1
                            canInsert = True
                        elif errType == "long" and type(data["payload"][errField]) is int and data["payload"][errField] < -(2**63): # ES limit
                            data["payload"][errField] = -(2 ** 63)
                            canInsert = True
                        elif errType == "long" and type(data["payload"][errField]) is argparse.BooleanOptionalAction:
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
        except Exception as e:
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
        if self.connectionFailed: return

        if mode == "ES":
            session = self.initESSession()
            await self.testESSession(session)
            if self.connectionFailed: return
            fnformatEvent = self.formatEventForES
            fnWorker = self.ESWorker
        elif mode == "HEC":
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            await self.testSplunkSession(session)
            if self.connectionFailed: return
            fnformatEvent = self.formatEventForSplunk
            fnWorker = self.HECWorker
        elif mode == "HTTP":
            session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
            await self.testHTTPSession(session)
            if self.connectionFailed: return
            fnformatEvent = self.formatEventForHTTTP
            fnWorker = self.HTTPWorker
        else: 
            return

        # Init queue
        queue = asyncio.Queue()
        tasks = []

        if not sigmaEvents: 
            self.logger.info(f'[+] Gathering events to forward')
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

    def __init__(self, configFile, logger=None, timeAfter="1970-01-01T00:00:00", timeBefore="9999-12-12T23:59:59", timeField=None, hashes=False):
        self.logger = logger or logging.getLogger(__name__)
        self.keyDict = {}
        self.fieldStmt = ""
        self.valuesStmt = []
        self.timeAfter = timeAfter
        self.timeBefore = timeBefore
        self.timeField = timeField
        self.hashes = hashes
        
        with open(configFile, 'r', encoding='UTF-8') as fieldMappingsFile:
            self.fieldMappingsDict = json.loads(fieldMappingsFile.read())
            self.fieldExclusions = self.fieldMappingsDict["exclusions"]
            self.fieldMappings = self.fieldMappingsDict["mappings"]
            self.uselessValues = self.fieldMappingsDict["useless"]
            self.aliases = self.fieldMappingsDict["alias"]
            self.fieldSplitList = self.fieldMappingsDict["split"]

    def run(self, file):
        """
            Flatten json object with nested keys into a single level.
            Returns the flattened json object
        """
        self.logger.debug(f"FLATTENING : {file}")
        JSONLine = {}
        JSONOutput = []
        fieldStmt = ""

        def flatten(x, name=''):
            nonlocal fieldStmt
            # If it is a Dict go deeper
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + '.')
            else:
                # Applying exclusions. Be careful, the key/value pair is discarded if there is a partial match
                if not any(exclusion in name[:-1] for exclusion in self.fieldExclusions):
                    # Arrays are not expanded
                    if type(x) is list:
                        value = ''.join(str(x))
                    else:
                        value = x
                    # Excluding useless values (e.g. "null"). The value must be an exact match.
                    if not value in self.uselessValues:
                        # Applying field mappings
                        rawFieldName = name[:-1]
                        if rawFieldName in self.fieldMappings:
                            key = self.fieldMappings[rawFieldName]
                        else:
                            # Removing all annoying character from field name
                            key = ''.join(e for e in rawFieldName.split(".")[-1] if e.isalnum())

                        # Preparing aliases
                        keys = [key]
                        if key in self.aliases: keys.append(self.aliases[key])
                        if rawFieldName in self.aliases: keys.append(self.aliases[rawFieldName])

                        # Applying field splitting
                        fieldsToSplit = []
                        if rawFieldName in self.fieldSplitList: fieldsToSplit.append(rawFieldName)
                        if key in self.fieldSplitList: fieldsToSplit.append(key)
                        
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
                            JSONLine[key] = value
                            # Creating the CREATE TABLE SQL statement
                            keyLower =key.lower()
                            if keyLower not in self.keyDict:
                                self.keyDict[keyLower] = key
                                if type(value) is int:
                                    fieldStmt += f"'{key}' INTEGER,\n"
                                else:
                                    fieldStmt += f"'{key}' TEXT COLLATE NOCASE,\n"

        # If filesize is not zero
        if os.stat(file).st_size != 0:
            with open(str(file), 'r', encoding='utf-8') as JSONFile:
                filename = os.path.basename(file)
                for line in JSONFile:
                    try:
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
                        except:
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
        self.logger.debug(" CREATE : " + createTableStmt.replace('\n', ' ').replace('\r', ''))
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
        """ Perform a SQL Query -SELECT only- with the provided connection """
        if self.dbConnection is not None:
            dbHandle = self.dbConnection.cursor()
            self.logger.debug(f"EXECUTING : {query}")
            try:
                data = dbHandle.execute(query)
                return data
            except Error as e:
                self.logger.debug(f"   [-] {e}")
                return {}
        else:
            self.logger.error(f"{Fore.RED}   [-] No connection to Db{Fore.RESET}")
            return {}

    def loadDbInMemory(self, db):
        """ In db only mode it is possible to restore an on disk Db to avoid EVTX extraction and flattening """
        dbfileConnection = self.createConnection(db)
        dbfileConnection.backup(self.dbConnection)
        dbfileConnection.close()

    def insertData2Db(self, JSONLine):
        """ Build INSERT INTO Query and insert data into Db """
        columnsStr = ""
        valuesStr = ""

        for key in sorted(JSONLine.keys()):
            columnsStr += "'" + key + "',"
            if type(JSONLine[key]) is int:
                valuesStr += str(JSONLine[key]) + ", "
            else:
                valuesStr += "'" + str(JSONLine[key]).replace("'", "''") + "', "

        insertStrmt = f"INSERT INTO logs ({columnsStr[:-1]}) VALUES ({valuesStr[:-2]});"
        return self.executeQuery(insertStrmt)

    def insertFlattenedJSON2Db(self, flattenedJSON, forwarder=None):
        if forwarder:
            forwarder.send(flattenedJSON, forwardAll=True) 
        for JSONLine in tqdm(flattenedJSON, colour="yellow"):
            self.insertData2Db(JSONLine)
        self.createIndex()

    def saveFlattenedJSON2File(self, flattenedJSON, outputFile):
        with open(outputFile, 'w', encoding='utf-8') as file:
            for JSONLine in tqdm(flattenedJSON, colour="yellow"):
                file.write(json.dumps(JSONLine).decode('utf-8') + '\n')

    def saveDbToDisk(self, dbFilename):
        consoleLogger.info("[+] Saving working data to disk as a SQLite DB")
        onDiskDb = sqlite3.connect(dbFilename)
        self.dbConnection.backup(onDiskDb)
        onDiskDb.close()

    def executeRule(self, rule):
        results = {}
        filteredRows = []
        counter = 0
        if "rule" in rule:
            # for each SQL Query in the SIGMA rule
            for SQLQuery in rule["rule"]:
                data = self.executeSelectQuery(SQLQuery)
                if data != {}:
                    # Convert to array of dict
                    rows = [dict(row) for row in data.fetchall()]
                    if len(rows) > 0:
                        counter += len(rows)
                        for row in rows:
                            if self.csvMode: # Cleaning "annoying" values for CSV
                                match = {k: str(v).replace("\n","").replace("\r","").replace("None","") for k, v in row.items()}
                            else: # Cleaning null/None fields
                                match = {k: v for k, v in row.items() if v is not None}
                            filteredRows.append(match)
            if "level" not in rule:
                rule["level"] = "unknown"
            if "tags" not in rule:
                rule["tags"] = []
            if "filename" not in rule:
                rule["filename"] = ""
            if self.csvMode: 
                results = ({"title": rule["title"], "id": rule["id"], "description": rule["description"].replace("\n","").replace("\r",""), "sigmafile": rule["filename"], "sigma": rule["rule"], "rule_level": rule["level"], "tags": rule["tags"], "count": counter, "matches": filteredRows})
            else:
                results = ({"title": rule["title"], "id": rule["id"], "description": rule["description"], "sigmafile": rule["filename"], "sigma": rule["rule"], "rule_level": rule["level"], "tags": rule["tags"], "count": counter, "matches": filteredRows})
            if counter > 0:
                self.logger.debug(f'DETECTED : {rule["title"]} - Matches : {counter} events')
        else:
            self.logger.debug("RULE FORMAT ERROR : rule key Missing")
        if filteredRows == []:
            return {}
        return results

    def loadRulesetFromFile(self, filename, ruleFilters):
        try:
            with open(filename, encoding='utf-8') as f:
                self.ruleset = json.loads(f.read())
            self.applyRulesetFilters(ruleFilters)
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] Load JSON ruleset failed, are you sure it is a valid JSON file ? : {e}{Fore.RESET}")

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

    def executeRuleset(self, outFile, writeMode='w', forwarder=None, showAll=False, KeepResults=False, remote=None, stream=False, lastRuleset=False):
        csvWriter = None
        # Results are written upon detection to allow analysis during execution and to avoid losing results in case of error.
        with open(outFile, writeMode, encoding='utf-8', newline='') as fileHandle:
            with tqdm(self.ruleset, colour="yellow") as ruleBar:
                if not self.noOutput and not self.csvMode and writeMode != "a": fileHandle.write('[')
                for rule in ruleBar:  # for each rule in ruleset
                    if showAll and "title" in rule: ruleBar.write(f'{Fore.BLUE}    - {rule["title"]} [{self.ruleLevelPrintFormatter(rule["level"], Fore.BLUE)}]{Fore.RESET}')  # Print all rules
                    ruleResults = self.executeRule(rule)
                    if ruleResults != {}:
                        if self.limit == -1 or ruleResults["count"] <= self.limit:
                            ruleBar.write(f'{Fore.CYAN}    - {ruleResults["title"]} [{self.ruleLevelPrintFormatter(rule["level"], Fore.CYAN)}] : {ruleResults["count"]} events{Fore.RESET}')
                            # Store results for templating and event forwarding (only if stream mode is disabled)
                            if KeepResults or (remote is not None and not stream): self.fullResults.append(ruleResults)
                            if stream and forwarder is not None: forwarder.send([ruleResults], False)
                            if not self.noOutput:
                                # To avoid printing this twice on stdout but in the logs...
                                logLevel = self.logger.getEffectiveLevel()
                                self.logger.setLevel(logging.DEBUG)
                                self.logger.debug(f'    - {ruleResults["title"]} [{ruleResults["rule_level"]}] : {ruleResults["count"]} events')
                                self.logger.setLevel(logLevel)
                                # Output to json or csv file
                                if self.csvMode: 
                                    if not csvWriter: # Creating the CSV header and the fields ("agg" is for queries with aggregation)
                                        csvWriter = csv.DictWriter(fileHandle, delimiter=self.delimiter, fieldnames=["rule_title", "rule_description", "rule_level", "rule_count", "agg"] + list(ruleResults["matches"][0].keys()))
                                        csvWriter.writeheader()
                                    for data in ruleResults["matches"]:
                                        dictCSV = { "rule_title": ruleResults["title"], "rule_description": ruleResults["description"], "rule_level": ruleResults["rule_level"], "rule_count": ruleResults["count"], **data}                                        
                                        csvWriter.writerow(dictCSV)
                                else:
                                    try:
                                        fileHandle.write(json.dumps(ruleResults, option=json.OPT_INDENT_2).decode('utf-8'))
                                        fileHandle.write(',\n')
                                    except Exception as e:
                                        self.logger.error(f"{Fore.RED}   [-] Error saving some results : {e}{Fore.RESET}")
                if not self.noOutput and not self.csvMode and lastRuleset: fileHandle.write('{}]') # Added to produce a valid JSON Array

    def run(self, EVTXJSONList, Insert2Db=True, saveToFile=False, forwarder=None):
        self.logger.info("[+] Processing events")
        flattener = JSONFlattener(configFile=self.config, timeAfter=self.timeAfter, timeBefore=self.timeBefore, timeField=self.timeField, hashes=self.hashes)
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

    def __init__(self, logger=None, providedTmpDir=None, coreCount=None, useExternalBinaries=True, binPath = None, xmlLogs=False, sysmon4linux=False, auditdLogs=False, encoding=None, evtxtract=False):
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
        # Sysmon 4 Linux default encoding is ISO-8859-1, Auditd is UTF-8
        if not encoding and sysmon4linux: self.encoding = "ISO-8859-1"
        elif not encoding and (auditdLogs or evtxtract or xmlLogs): self.encoding = "utf-8"
        else: self.encoding = encoding
        
        self.evtxDumpCmd = self.getOSExternalTools(binPath)
        
    def randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def makeExecutable(self, path):
        mode = os.stat(path).st_mode
        mode |= (mode & 0o444) >> 2
        os.chmod(path, mode)
    
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
        try:
            filepath = Path(file)
            filename = filepath.name
            parser = PyEvtxParser(str(filepath))
            with open(f"{self.tmpDir}/{str(filename)}-{self.randString()}.json", "w", encoding="utf-8") as f:
                for record in parser.records_json():
                    f.write(f'{json.dumps(json.loads(record["data"])).decode("utf-8")}\n')
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")

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
                    if 'cmd' in attribute[0] or 'proctitle' in attribute[0]:
                        attribute[1] = str(bytearray.fromhex(attribute[1]).decode()).replace('\x00',' ')
                    event[attribute[0]] = attribute[1]
                except:
                    pass
        if "host" not in event:
            event['host'] = 'offline'
        return event

    def SysmonXMLLine2JSON(self, xmlLine):
        """
        Remove syslog header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        if not 'Event' in xmlLine:
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
        if not '<Event ' in xmlLine:
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
                    except:
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
        Use multiprocessing to convert Sysmon for Linux XML our Auditd logs to JSON
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
        # Auditd or Sysmon4Linux logs
        if self.sysmon4linux or self.auditdLogs:
            # Choose which log backend to use
            if self.sysmon4linux: func = self.SysmonXMLLine2JSON
            else: func = self.auditdLine2JSON 
            try:
                self.Logs2JSON(func, str(file), f"{self.tmpDir}/{str(filename)}-{self.randString()}.json")
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # XML logs
        elif self.xmlLogs:
            try:
                data = ""
                # We need to read the entire file to remove annoying newlines and fields with newlines (System.evtx Logs for example...)
                with open(str(file), 'r') as XMLFile:
                    data = XMLFile.read().replace("\n","").replace("</Event>","</Event>\n").replace("<Event ","\n<Event ")
                self.Logs2JSON(self.XMLLine2JSON, data, f"{self.tmpDir}/{str(filename)}-{self.randString()}.json", isFile=False)
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # EVTXtract
        elif self.evtxtract:
            try:
                self.evtxtract2JSON(str(file), f"{self.tmpDir}/{str(filename)}-{self.randString()}.json")
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}{Fore.RESET}")
        # EVTX
        else:
            if not self.useExternalBinaries or not Path(self.evtxDumpCmd).is_file(): 
                self.logger.debug(f"   [-] No external binaries args or evtx_dump is missing")
                self.runUsingBindings(file)
            else:
                try:
                    cmd = [self.evtxDumpCmd, "--no-confirm-overwrite", "-o", "jsonl", str(file), "-f", f"{self.tmpDir}/{str(filename)}-{self.randString()}.json", "-t", str(self.cores)]
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
            else: hash_old = ""
            if hash_new != hash_old:
                count += 1
                if not Path(f'rules/').exists():
                    Path(f'rules/').mkdir()
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

def selectFiles(pathList, selectFilesList):
    if selectFilesList is not None:
        return [evtx for evtx in [str(element) for element in list(pathList)] if any(fileFilters[0].lower() in evtx.lower() for fileFilters in selectFilesList)]
    return pathList

def avoidFiles(pathList, avoidFilesList):
    if avoidFilesList is not None:
        return [evtx for evtx in [str(element) for element in list(pathList)] if all(fileFilters[0].lower() not in evtx.lower() for fileFilters in avoidFilesList)]
    return pathList

################################################################
# MAIN()
################################################################
def main():
    version = "2.9.14"

    # Init Args handling
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--evtx", "--events", help="Log file or directory where log files are stored in JSON, Auditd, Sysmon for Linux, or EVTX format", type=str)
    parser.add_argument("-s", "--select", help="Only files containing the provided string will be used. If there is/are exclusion(s) (--avoid) they will be handled after selection", action='append', nargs='+')
    parser.add_argument("-a", "--avoid", help="EVTX files containing the provided string will NOT be used", action='append', nargs='+')
    parser.add_argument("-r", "--ruleset", help="JSON File containing SIGMA rules", action='append', nargs='+')
    parser.add_argument("--fieldlist", help="Get all events fields", action='store_true')
    parser.add_argument("--evtx_dump", help="Tell Zircolite to use this binary for EVTX conversion, on Linux and MacOS the path must be valid to launch the binary (eg. './evtx_dump' and not 'evtx_dump')", type=str, default=None)
    parser.add_argument("-R", "--rulefilter", help="Remove rule from ruleset, comparison is done on rule title (case sensitive)", action='append', nargs='*')
    parser.add_argument("-L", "--limit", help="Discard results (in output file or forwarded events) that are above the provided limit", type=int, default=-1)
    parser.add_argument("-c", "--config", help="JSON File containing field mappings and exclusions", type=str, default="config/fieldMappings.json")
    parser.add_argument("-o", "--outfile", help="File that will contains all detected events", type=str, default="detected_events.json")
    parser.add_argument("--csv", help="The output will be in CSV. You should note that in this mode empty fields will not be discarded from results", action='store_true')
    parser.add_argument("--csv-delimiter", help="Choose the delimiter for CSV ouput", type=str, default=";")
    parser.add_argument("-f", "--fileext", help="Extension of the log files", type=str)
    parser.add_argument("-fp", "--file-pattern", help="Use a Python Glob pattern to select files. This option only works with directories", type=str)
    parser.add_argument("--no-recursion", help="By default Zircolite search recursively, by using this option only the provided directory will be used", action="store_true")
    parser.add_argument("-t", "--tmpdir", help="Temp directory that will contains events converted as JSON (parent directories must exist)", type=str)
    parser.add_argument("-k", "--keeptmp", help="Do not remove the temp directory containing events converted in JSON format", action='store_true')
    parser.add_argument("-K", "--keepflat", help="Save flattened events as JSON", action='store_true')
    parser.add_argument("-d", "--dbfile", help="Save all logs in a SQLite Db to the specified file", type=str)
    parser.add_argument("-l", "--logfile", help="Log file name", default="zircolite.log", type=str)
    parser.add_argument("-n", "--nolog", help="Don't create a log file or a result file (useful when forwarding)", action='store_true')
    parser.add_argument("-j", "--jsononly", help="If logs files are already in JSON lines format ('jsonl' in evtx_dump) ", action='store_true')
    parser.add_argument("-D", "--dbonly", help="Directly use a previously saved database file, timerange filters will not work", action='store_true')
    parser.add_argument("-S", "--sysmon4linux", help="Use this option if your log file is a Sysmon for linux log file, default file extension is '.log'", action='store_true')
    parser.add_argument("-AU", "--auditd", help="Use this option if your log file is a Auditd log file, default file extension is '.log'", action='store_true')
    parser.add_argument("-x", "--xml", help="Use this option if your log file is a EVTX converted to XML log file, default file extension is '.xml'", action='store_true')
    parser.add_argument("--evtxtract", help="Use this option if your log file was extracted with EVTXtract, default file extension is '.log'", action='store_true')
    parser.add_argument("-LE", "--logs-encoding",  help="Specify log encoding when dealing with Sysmon for Linux or Auditd files", type=str)
    parser.add_argument("-A", "--after", help="Limit to events that happened after the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="1970-01-01T00:00:00")
    parser.add_argument("-B", "--before", help="Limit to events that happened before the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="9999-12-12T23:59:59")
    parser.add_argument("--remote", help="Forward results to a HTTP/Splunk/Elasticsearch, please provide the full address e.g http[s]://address:port[/uri]", type=str)
    parser.add_argument("--token", help="Use this to provide Splunk HEC Token", type=str)
    parser.add_argument("--index", help="Use this to provide ES index", type=str)
    parser.add_argument("--eslogin", help="ES login", type=str, default="")
    parser.add_argument("--espass", help="ES password", type=str, default="")
    parser.add_argument("--stream", help="By default event forwarding is done at the end, this option activate forwarding events when detected", action="store_true")
    parser.add_argument("--forwardall", help="Forward all events", action="store_true")
    parser.add_argument("--hashes", help="Add an xxhash64 of the original log event to each event", action='store_true')
    parser.add_argument("--timefield", help="Provide time field name for event forwarding, default is 'SystemTime'", default="SystemTime", action="store_true")
    parser.add_argument("--cores", help="Specify how many cores you want to use, default is all cores, works only for EVTX extraction", type=str)
    parser.add_argument("--template", help="If a Jinja2 template is specified it will be used to generated output", type=str, action='append', nargs='+')
    parser.add_argument("--templateOutput", help="If a Jinja2 template is specified it will be used to generate a crafted output", type=str, action='append', nargs='+')
    parser.add_argument("--debug", help="Activate debug logging", action='store_true')
    parser.add_argument("--showall", help="Show all events, useful to check what rule takes takes time to execute", action='store_true')
    parser.add_argument("--noexternal", help="Don't use evtx_dump external binaries (slower)", action='store_true')
    parser.add_argument("--ondiskdb", help="Use an on-disk database instead of the in-memory one (much slower !). Use if your system has limited RAM or if your dataset is very large and you cannot split it.", type=str, default=":memory:")
    parser.add_argument("--package", help="Create a ZircoGui package (not available in embedded mode)", action='store_true')
    parser.add_argument("-RE", "--remove-events", help="Zircolite will try to remove events/logs submitted if analysis is successful (use at your own risk)", action='store_true')
    parser.add_argument("-U", "--update-rules", help="Update rulesets located in the 'rules' directory", action='store_true')
    parser.add_argument("-v", "--version", help="Show Zircolite version", action='store_true')

    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler) 

    # Init logging
    if args.nolog: args.logfile = None
    consoleLogger = initLogger(args.debug, args.logfile)

    consoleLogger.info("""
    ███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗
    ╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝
      ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗
     ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝
    ███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗
    ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
   -= Standalone SIGMA Detection tool for EVTX/Auditd/Sysmon Linux =-
    """)

    # Print version an quit
    if args.version: consoleLogger.info(f"Zircolite - v{version}"), sys.exit(0)

    if args.update_rules:
        consoleLogger.info(f"[+] Updating rules")
        updater = rulesUpdater(logger=consoleLogger)
        updater.run()
        sys.exit(0)

    # Handle rulesets args 
    if args.ruleset:
        args.ruleset = [item for args in args.ruleset for item in args]
    else: 
        args.ruleset = ["rules/rules_windows_generic.json"]

    # Check mandatory CLI options
    if not args.evtx: consoleLogger.error(f"{Fore.RED}   [-] No events source path provided{Fore.RESET}"), sys.exit(2)
    if int(args.sysmon4linux) + int(args.auditd) + int(args.evtxtract) > 1 : consoleLogger.error(f"{Fore.RED}   [-] --sysmon4linux, --auditd and --evtxtract arguments cannot be used together{Fore.RESET}"), sys.exit(2)
    if args.forwardall and args.dbonly: consoleLogger.error(f"{Fore.RED}   [-] Can't forward all events in db only mode {Fore.RESET}"), sys.exit(2)
    if args.csv and len(args.ruleset) > 1 : consoleLogger.error(f"{Fore.RED}   [-] Since fields in results can change between rulesets, it is not possible to have CSV output when using multiple rulesets{Fore.RESET}"), sys.exit(2)
    
    consoleLogger.info("[+] Checking prerequisites")

    # Init Forwarding
    forwarder = eventForwarder(remote=args.remote, timeField=args.timefield, token=args.token, logger=consoleLogger, index=args.index, login=args.eslogin, password=args.espass)
    if args.remote is not None: 
        if not forwarder.networkCheck(): quitOnError(f"{Fore.RED}   [-] Remote host cannot be reached : {args.remote}{Fore.RESET}", consoleLogger)
    
    # Checking provided timestamps
    try:
        eventsAfter = time.strptime(args.after, '%Y-%m-%dT%H:%M:%S')
        eventsBefore = time.strptime(args.before, '%Y-%m-%dT%H:%M:%S')
    except:
        quitOnError(f"{Fore.RED}   [-] Wrong timestamp format. Please use 'AAAA-MM-DDTHH:MM:SS'", consoleLogger)

    binPath = args.evtx_dump

    # Check ruleset arg
    for ruleset in args.ruleset:
        checkIfExists(ruleset, f"{Fore.RED}   [-] Cannot find ruleset : {ruleset}. Default rulesets are available here : https://github.com/wagga40/Zircolite-Rules{Fore.RESET}", consoleLogger)
    # Check templates args
    readyForTemplating = False
    if (args.template is not None):
        if args.csv: quitOnError(f"{Fore.RED}   [-] You cannot use templates in CSV mode{Fore.RESET}", consoleLogger)
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
    if args.ondiskdb != ":memory:" and (Path(args.ondiskdb).is_file()): quitOnError(f"{Fore.RED}   [-] On-disk database already exists{Fore.RESET}", consoleLogger) 

    # Start time counting
    start_time = time.time()

    # Initialize zirCore
    zircoliteCore = zirCore(args.config, logger=consoleLogger, noOutput=args.nolog, timeAfter=eventsAfter, timeBefore=eventsBefore, limit=args.limit, csvMode=args.csv, timeField=args.timefield, hashes=args.hashes, dbLocation=args.ondiskdb, delimiter=args.csv_delimiter)
    
    # If we are not working directly with the db
    if not args.dbonly:
        # If we are working with json we change the file extension if it is not user-provided
        if not args.fileext:
            if args.jsononly: args.fileext = "json"
            elif (args.sysmon4linux or args.auditd): args.fileext = "log"
            elif args.xml: args.fileext = "xml"
            else: args.fileext = "evtx"
        
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

        if not args.jsononly:
            # Init EVTX extractor object
            extractor = evtxExtractor(logger=consoleLogger, providedTmpDir=args.tmpdir, coreCount=args.cores, useExternalBinaries=(not args.noexternal), binPath=binPath, xmlLogs=args.xml, sysmon4linux=args.sysmon4linux, auditdLogs=args.auditd, evtxtract=args.evtxtract, encoding=args.logs_encoding)
            consoleLogger.info(f"[+] Extracting events Using '{extractor.tmpDir}' directory ")
            for evtx in tqdm(FileList, colour="yellow"):
                extractor.run(evtx)
            # Set the path for the next step
            LogJSONList = list(Path(extractor.tmpDir).rglob("*.json"))
        else:
            LogJSONList = FileList

        checkIfExists(args.config, f"{Fore.RED}   [-] Cannot find mapping file, you can get the default one here : https://github.com/wagga40/Zircolite/blob/master/config/fieldMappings.json {Fore.RESET}", consoleLogger)
        if LogJSONList == []:
            quitOnError(f"{Fore.RED}   [-] No JSON files found.{Fore.RESET}", consoleLogger)

        # Print field list and exit
        if args.fieldlist:
            fields = zircoliteCore.run(LogJSONList, Insert2Db=False)
            zircoliteCore.close()
            if not args.jsononly and not args.keeptmp: extractor.cleanup()
            [print(sortedField) for sortedField in sorted([field for field in fields.values()])]
            sys.exit(0)
        
        # Flatten and insert to Db
        if args.forwardall:
            zircoliteCore.run(LogJSONList, saveToFile=args.keepflat, forwarder=forwarder)
        else:
            zircoliteCore.run(LogJSONList, saveToFile=args.keepflat)
        # Unload In memory DB to disk. Done here to allow debug in case of ruleset execution error
        if args.dbfile is not None: zircoliteCore.saveDbToDisk(args.dbfile)
    else:
        consoleLogger.info(f"[+] Creating model from disk : {args.evtx}")
        zircoliteCore.loadDbInMemory(args.evtx)

    # flatten array of "rulefilter" arguments
    if args.rulefilter: args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

    writeMode = "w"
    for ruleset in args.ruleset:
        consoleLogger.info(f"[+] Loading ruleset from : {ruleset}")
        zircoliteCore.loadRulesetFromFile(filename=ruleset, ruleFilters=args.rulefilter)
        if args.limit > 0: consoleLogger.info(f"[+] Limited mode : detections with more than {args.limit} events will be discarded")
        consoleLogger.info(f"[+] Executing ruleset - {len(zircoliteCore.ruleset)} rules")
        zircoliteCore.executeRuleset(args.outfile, writeMode=writeMode, forwarder=forwarder, showAll=args.showall, KeepResults=(readyForTemplating or args.package), remote=args.remote, stream=args.stream, lastRuleset=(ruleset == args.ruleset[-1]))
        writeMode = "a" # Next iterations will append to results file

    consoleLogger.info(f"[+] Results written in : {args.outfile}")

    # Forward events
    if args.remote is not None and not args.stream: # If not in stream mode
        consoleLogger.info(f"[+] Forwarding to : {args.remote}")
        forwarder.send(zircoliteCore.fullResults, False)
    if args.remote is not None and args.stream: consoleLogger.info(f"[+] Forwarded to : {args.remote}")

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
            if not args.jsononly and not args.dbonly: extractor.cleanup()
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