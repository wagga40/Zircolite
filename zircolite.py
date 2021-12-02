#!python3
# -*- coding: utf-8 -*-

# Standard libs
import argparse
import base64
import csv
import json
import logging
import multiprocessing as mp
import os
from pathlib import Path
import random
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
import zlib

# External libs
import aiohttp
import asyncio
from colorama import Fore
from evtx import PyEvtxParser
from lxml import etree
import socket
from tqdm import tqdm
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from jinja2 import Template

def signal_handler(sig, frame):
    consoleLogger.info("[-] Execution interrupted !")
    sys.exit(0)

def quitOnError(message):
    consoleLogger.error(message)
    sys.exit(1)

def checkIfExists(path, errorMessage):
    """ Test if path provided is a file """
    if not (Path(path).is_file()):
        quitOnError(errorMessage)

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
    def __init__(self, logger=None, template=[], templateOutput=[]):
        self.logger = logger or logging.getLogger(__name__)
        self.template = template
        self.templateOutput = templateOutput
    
    def generateFromTemplate(self, templateFile, outpoutFilename, data):
        """ Use Jinja2 to output data in a specific format """
        try:
            #{% if not embeddedMode %}
            tmpl = open(templateFile, 'r', encoding='utf-8')
            template = Template(tmpl.read())
            #{% else %}
            #{{ templateOpenCode }}
            #{% endif %}
            with open(outpoutFilename, 'a', encoding='utf-8') as tpl:
                tpl.write(template.render(data=data))
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] Template error, activate debug mode to check for errors")
            self.logger.debug(f"   [-] {e}")

    def run(self, data):
        for template, templateOutput in zip(self.template, self.templateOutput):
            self.logger.info(f'[+] Applying template "{template[0]}", outputting to : {templateOutput[0]}')
            self.generateFromTemplate(template[0], templateOutput[0], data)

class eventForwarder:
    """ Class for handling event forwarding """
    def __init__(self, remote, token,logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.remoteHost = remote
        self.token = token
        self.localHostname = socket.gethostname()
        self.userAgent = "zircolite/2.0.x"

    def send(self, payloads, bypassToken=True, noError=False):
        if payloads: 
            if self.remoteHost is not None:
                try:
                    if self.token is not None and not bypassToken: #Bypass token is only used to test connectivity
                        # Change EventLoopPolicy on Windows https://stackoverflow.com/questions/45600579/asyncio-event-loop-is-closed-when-getting-loop
                        if _platform == "win32": asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                        asyncio.run(self.sendHECAsync(payloads, "SystemTime"))
                    else:
                        # Change EventLoopPolicy on Windows https://stackoverflow.com/questions/45600579/asyncio-event-loop-is-closed-when-getting-loop
                        if _platform == "win32": asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                        asyncio.run(self.sendHTTPAsync(payloads, noError))
                    return True
                except Exception as e:
                    self.logger.debug(f"{Fore.RED}   [-] {e}")
                    return False
        
    def networkCheck(self):
        """ Check remote connectivity """
        if (self.remoteHost is not None):
            if not self.send(payloads=[{"Zircolite": "Forwarder"}], noError=True):
                return False
            else:
                return True
        return False

    def formatToEpoch(self, timestamp):
        return str(time.mktime(time.strptime(timestamp.split(".")[0], '%Y-%m-%dT%H:%M:%S')))[:-1] + timestamp.split(".")[1][:-1]

    async def HTTPPostData(self, session, data):
        async with session.post(self.remoteHost, headers={"user-agent": self.userAgent}, data={"data": base64.b64encode(json.dumps(data).encode('utf-8')).decode('ascii')}) as resp:
            await resp.text()
            return str(resp.status)[0]

    async def sendHTTPAsync(self, payloads, noError=False):
        """ Just send provided payload to provided web server. Non-async code. """
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            tasks = []
            for payload in payloads:
                payload.update({"host": self.localHostname})
                tasks.append(asyncio.ensure_future(self.HTTPPostData(session, payload)))
            statusCodes = await asyncio.gather(*tasks)
            if ("4" in statusCodes or "5" in statusCodes) and not noError:
                self.logger.error(f"{Fore.RED}   [-] Forwarding failed for some events (got 4xx or 5xx HTTP Status Code){Fore.RESET}")

    async def HECPostData(self, session, splunkURL, data):
        async with session.post(splunkURL, headers={'Authorization': f"Splunk {self.token}"}, json=data) as resp:
            await resp.text()
            return str(resp.status)[0]

    async def sendHECAsync(self, payloads, timeField = ""):
        """ Just send provided payload to provided Splunk HEC. Async code. """
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            tasks = []
            for payload in payloads:
                # Flatten detected events
                for match in payload["matches"]:
                    jsonEventData = {}
                    for key, value in match.items():
                        jsonEventData.update({key: value})
                    jsonEventData.update({"title": payload["title"], "description": payload["description"], "sigma": payload["sigma"], "rule_level": payload["rule_level"], "tags": payload["tags"]})
                    # Send events with timestamps and default Splunk JSON sourcetype
                    splunkURL = f"{self.remoteHost}/services/collector/event"
                    data = {"sourcetype": "_json", "event": jsonEventData, "event": jsonEventData, "host": self.localHostname }
                    if timeField != "": 
                        data.update({"time": self.formatToEpoch(jsonEventData[timeField])})
                    tasks.append(asyncio.ensure_future(self.HECPostData(session, splunkURL, data)))
            statusCodes = await asyncio.gather(*tasks)
            if "4" in statusCodes or "5" in statusCodes:
                self.logger.error(f"{Fore.RED}   [-] Forwarding failed for some events (got 4xx or 5xx HTTP Status Code){Fore.RESET}")

class JSONFlattener:
    """ Perform JSON Flattening """

    def __init__(self, configFile, logger=None, timeAfter="1970-01-01T00:00:00", timeBefore="9999-12-12T23:59:59"):
        self.logger = logger or logging.getLogger(__name__)
        self.keyDict = {}
        self.fieldStmt = ""
        self.valuesStmt = []
        self.timeAfter = timeAfter
        self.timeBefore = timeBefore
        #{% if embeddedMode %}
        #{% for line in fieldMappingsLines -%}
        #{{ line }}
        #{% endfor %}
        #{% else %}
        with open(configFile, 'r', encoding='UTF-8') as fieldMappingsFile:
            self.fieldMappingsDict = json.load(fieldMappingsFile)
            self.fieldExclusions = self.fieldMappingsDict["exclusions"]
            self.fieldMappings = self.fieldMappingsDict["mappings"]
            self.uselessValues = self.fieldMappingsDict["useless"]
        #{% endif %}

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
                # Applying exclusions. Be carefull, the key/value pair is discarded if there is a partial match
                if not any(exclusion in name[:-1] for exclusion in self.fieldExclusions):
                    # Arrays are not expanded
                    if type(x) is list:
                        value = ''.join(str(x))
                    else:
                        value = x
                    # Excluding useless values (e.g. "null"). The value must be an exact match.
                    if not value in self.uselessValues:
                        # Applying field mappings
                        if name[:-1] in self.fieldMappings:
                            key = self.fieldMappings[name[:-1]]
                        else:
                            # Removing all annoying character from field name
                            key = ''.join(e for e in name[:-1].split(".")[-1] if e.isalnum())
                        JSONLine[key] = value
                        # Creating the CREATE TABLE SQL statement
                        if key.lower() not in self.keyDict:
                            self.keyDict[key.lower()] = key
                            if type(value) is int:
                                fieldStmt += f"'{key}' INTEGER,\n"
                            else:
                                fieldStmt += f"'{key}' TEXT COLLATE NOCASE,\n"
        # If filesize is not zero
        if os.stat(file).st_size != 0:
            with open(str(file), 'r', encoding='utf-8') as JSONFile:
                for line in JSONFile:
                    try:
                        flatten(json.loads(line))
                    except Exception as e:
                        self.logger.debug(f'JSON ERROR : {e}')
                    # Handle timestamp filters
                    if (self.timeAfter != "1970-01-01T00:00:00" and self.timeBefore != "9999-12-12T23:59:59") and "SystemTime" in JSONLine:
                        timestamp = time.strptime(JSONLine["SystemTime"].split(".")[0].replace("Z",""), '%Y-%m-%dT%H:%M:%S')
                        if timestamp > self.timeAfter and timestamp < self.timeBefore:
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

    def __init__(self, config, logger=None, noOutput=False, timeAfter="1970-01-01T00:00:00", timeBefore="9999-12-12T23:59:59", limit=-1, csvMode=False):
        self.logger = logger or logging.getLogger(__name__)
        self.dbConnection = self.createConnection(":memory:")
        self.fullResults = []
        self.ruleset = {}
        self.noOutput = noOutput
        self.timeAfter = timeAfter
        self.timeBefore = timeBefore
        self.config = config
        self.limit = limit
        self.csvMode = csvMode
    
    def close(self):
        self.dbConnection.close()

    def createConnection(self, db):
        """ create a database connection to a SQLite database """
        conn = None
        self.logger.debug(f"CONNECTING TO : {db}")
        try:
            conn = sqlite3.connect(db)
            conn.row_factory = sqlite3.Row  # Allows to get a dict
        except Error as e:
            self.logger.error(f"{Fore.RED}   [-] {e}")
        return conn

    def createDb(self, fieldStmt):
        createTableStmt = f"CREATE TABLE logs ( row_id INTEGER, {fieldStmt} PRIMARY KEY(row_id AUTOINCREMENT) );"
        self.logger.debug(" CREATE : " + createTableStmt.replace('\n', ' ').replace('\r', ''))
        if not self.executeQuery(createTableStmt):
            self.logger.error(f"{Fore.RED}   [-] Unable to create table")
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
            self.logger.error(f"{Fore.RED}   [-] No connection to Db")
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
            self.logger.error(f"{Fore.RED}   [-] No connection to Db")
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

    def insertFlattenedJSON2Db(self, flattenedJSON):
        for JSONLine in tqdm(flattenedJSON, colour="yellow"):
            self.insertData2Db(JSONLine)
        self.createIndex()

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
            results = ({"title": rule["title"], "description": rule["description"],"sigmafile":rule["filename"], "sigma": rule["rule"], "rule_level": rule["level"], "tags": rule["tags"], "count": counter, "matches": filteredRows})
            if counter > 0:
                self.logger.debug(f'DETECTED : {rule["title"]} - Matchs : {counter} events')
        else:
            self.logger.debug("RULE FORMAT ERROR : rule key Missing")
        if filteredRows == []:
            return {}
        return results

    def loadRulesetFromFile(self, filename, ruleFilters):
        try:
            with open(filename, encoding='utf-8') as f:
                self.ruleset = json.load(f)
            self.applyRulesetFilters(ruleFilters)
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] Load JSON ruleset failed, are you sure it is a valid JSON file ? : {e}")

    def loadRulesetFromVar(self, ruleset, ruleFilters):
        self.ruleset = ruleset
        self.applyRulesetFilters(ruleFilters)
    
    def applyRulesetFilters(self, ruleFilters=None):
        # Remove empty rule and remove filtered rules
        self.ruleset = list(filter(None, self.ruleset))
        if ruleFilters is not None:
            self.ruleset = [rule for rule in self.ruleset if not any(ruleFilter in rule["title"] for ruleFilter in ruleFilters)]

    def executeRuleset(self, outFile, writeMode='w', forwarder=None, showAll=False, KeepResults=False, remote=None, stream=False):
        csvWriter = None
        # Results are writen upon detection to allow analysis during execution and to avoid loosing results in case of error.
        with open(outFile, writeMode, encoding='utf-8', newline='') as fileHandle:
            with tqdm(self.ruleset, colour="yellow") as ruleBar:
                if not self.noOutput and not self.csvMode: fileHandle.write('[')
                for rule in ruleBar:  # for each rule in ruleset
                    if showAll and "title" in rule: ruleBar.write(f'{Fore.BLUE}    - {rule["title"]}')  # Print all rules
                    ruleResults = self.executeRule(rule)
                    if ruleResults != {} :
                        if self.limit == -1 or ruleResults["count"] < self.limit:
                            ruleBar.write(f'{Fore.CYAN}    - {ruleResults["title"]} [{ruleResults["rule_level"]}] : {ruleResults["count"]} events{Fore.RESET}')
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
                                    if not csvWriter: # Creating the CSV header and the fields (agg is for queries with aggregation)
                                        csvWriter = csv.DictWriter(fileHandle, delimiter=';', fieldnames=["rule_title", "rule_description", "rule_level", "rule_count", "agg"] + list(ruleResults["matches"][0].keys()))
                                        csvWriter.writeheader()
                                    for data in ruleResults["matches"]:
                                        dictCSV = { "rule_title": ruleResults["title"], "rule_description": ruleResults["description"], "rule_level": ruleResults["rule_level"], "rule_count": ruleResults["count"], **data}                                        
                                        csvWriter.writerow(dictCSV)
                                else:
                                    try:
                                        json.dump(ruleResults, fileHandle, indent=4, ensure_ascii=False)
                                        fileHandle.write(',\n')
                                    except Exception as e:
                                        self.logger.error(f"{Fore.RED}   [-] Error saving some results : {e}")
                if not self.noOutput and not self.csvMode: fileHandle.write('{}]')  

    def run(self, EVTXJSONList, Insert2Db=True):
        self.logger.info("[+] Processing EVTX")
        flattener = JSONFlattener(configFile=self.config, timeAfter=self.timeAfter, timeBefore=self.timeBefore)
        flattener.runAll(EVTXJSONList)
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

    def __init__(self, logger=None, providedTmpDir=None, coreCount=None, useExternalBinaries=True, binPath = None, xmlLogs=False):
        self.logger = logger or logging.getLogger(__name__)
        if Path(str(providedTmpDir)).is_dir():
            self.tmpDir = f"tmp-{self.randString()}"
            self.logger.error(f"{Fore.RED}   [-] Provided directory already exists using '{self.tmpDir}' instead")
        else:
            self.tmpDir = providedTmpDir or f"tmp-{self.randString()}"
            os.mkdir(self.tmpDir)
        self.cores = coreCount or os.cpu_count()
        self.useExternalBinaries = useExternalBinaries
        self.xmlLogs = xmlLogs
        #{% if not embeddedMode %}
        self.evtxDumpCmd = self.getOSExternalTools(binPath)
        #{% else %}
        #{{ evtxDumpCmdEmbed }}
        #{% endif %}

    def randString(self):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))

    def makeExecutable(self, path):
        mode = os.stat(path).st_mode
        mode |= (mode & 0o444) >> 2
        os.chmod(path, mode)

    #{% if embeddedMode %}
    def getOSExternalToolsEmbed(self):
        if self.useExternalBinaries:
            with open("{{ externalTool }}", 'wb') as f:
                f.write(zlib.decompress(base64.b64decode(b'{{ externalToolB64 }}')))
            self.makeExecutable("{{ externalTool }}")
            return "{{ externalTool }}"
    #{% else %}
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
    #{% endif %}

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
                    f.write(f'{json.dumps(json.loads(record["data"]))}\n')
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] {e}")

    def SysmonXMLLine2JSON(self, xmlLine):
        """
        Remove syslog header and convert xml data to json : code from ZikyHD (https://github.com/ZikyHD)
        """
        def cleanTag(tag, ns):
            if ns in tag: 
                return tag[len(ns):]
            return tag

        if not 'Event' in xmlLine:
            return None
        xmlLine = "<Event>" + xmlLine.split("<Event>")[1]
        root = etree.fromstring(xmlLine)
        ns = u'http://schemas.microsoft.com/win/2004/08/events/event'
        child = {"#attributes": {"xmlns": ns}}
        for appt in root.getchildren():
            nodename = cleanTag(appt.tag,ns)
            nodevalue = {}
            for elem in appt.getchildren():
                if not elem.text:
                    text = ""
                else:
                    try:
                        text = int(elem.text)
                    except:
                        text = elem.text
                if elem.tag == 'Data':
                    childnode = elem.get("Name")
                else:
                    childnode = cleanTag(elem.tag,ns)
                    if elem.attrib:
                        text = {"#attributes": dict(elem.attrib)}
                obj={childnode:text}
                nodevalue = {**nodevalue, **obj}
            node = {nodename: nodevalue}
            child = {**child, **node}
        event = { "Event": child }
        return event

    def SysmonXMLLogs2JSON(self, file, outfile):
        """
        Use multiprocessing to convert Sysmon for Linux XML logs to JSON
        """
        with open(file, "r", encoding="ISO-8859-1") as fp:
            data = fp.readlines()
        pool = mp.Pool(self.cores)
        result = pool.map(self.SysmonXMLLine2JSON, data)
        pool.close()
        pool.join()
        with open(outfile, "w", encoding="UTF-8") as fp:
                for element in result:
                    if element is not None:
                        fp.write(json.dumps(element) + '\n')

    def run(self, file):
        """
        Convert EVTX to JSON using evtx_dump : https://github.com/omerbenamram/evtx.
        Drop resulting JSON files in a tmp folder.
        """
        self.logger.debug(f"EXTRACTING : {file}")

        if self.xmlLogs: 
            try:
                filename = Path(file).name
                self.SysmonXMLLogs2JSON(str(file), f"{self.tmpDir}/{str(filename)}-{self.randString()}.json")
            except Exception as e:
                self.logger.error(f"{Fore.RED}   [-] {e}")
        else:
            if not self.useExternalBinaries or not Path(self.evtxDumpCmd).is_file(): 
                self.logger.debug(f"   [-] No external binaries args or evtx_dump is missing")
                self.runUsingBindings(file)
            else:
                try:
                    filepath = Path(file)
                    filename = filepath.name
                    cmd = [self.evtxDumpCmd, "--no-confirm-overwrite", "-o", "jsonl", str(file), "-f", f"{self.tmpDir}/{str(filename)}-{self.randString()}.json", "-t", str(self.cores)]
                    subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                except Exception as e:
                    self.logger.error(f"{Fore.RED}   [-] {e}")
  
    def cleanup(self):
        shutil.rmtree(self.tmpDir)
        #{% if embeddedMode %}
        #{{ removeTool }}
        #{% endif %}

#{% if not embeddedMode -%}
class zircoGuiGenerator:
    """
    Generate the mini GUI (BETA)
    """
    def __init__(self, packageDir, templateFile, logger=None, outputFile = None):
        self.logger = logger or logging.getLogger(__name__)
        self.templateFile = templateFile
        self.tmpDir = f'tmp-zircogui-{self.randString()}'
        self.tmpFile = f'data-{self.randString()}.js'
        self.outputFile = outputFile or f'zircogui-output-{self.randString()}'
        self.packageDir = packageDir

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
            exportforzircoguiTmpl = templateEngine(self.logger, self.templateFile, self.tmpFile)
            exportforzircoguiTmpl.generateFromTemplate(exportforzircoguiTmpl.template, exportforzircoguiTmpl.templateOutput, data)
        except Exception as e:
            self.logger.error(f"   [-] {e}")
        shutil.move(self.tmpFile, f'{self.tmpDir}/zircogui/data.js')
        self.zip()
        shutil.rmtree(self.tmpDir)
#{% endif %}

class rulesetGenerator:
    def __init__(self, sigmac, config, table, rulesToConvert, fileext="yml"):
        self.table = table
        self.config = config
        self.sigmac = sigmac
        self.rules = rulesToConvert
        self.fileext = fileext
    
    def run(self):
        recurse = ""
        if Path(self.rules).is_dir(): # it is a dir, adding the recurse args.
            recurse = "-r"
        cmd = [self.sigmac, "-d", "--target", "sqlite", "-c", self.config, recurse, self.rules, "--output-fields", "title,id,description,author,tags,level,falsepositives", "-oF", "json", "--backend-option", f'table={self.table}']
        outputRaw = subprocess.run(args=cmd, capture_output=True, text=True, encoding='utf-8')
        try:
            rules =  json.loads(outputRaw.stdout)
        except json.decoder.JSONDecodeError:
            return {"ruleset": [], "errors": ""}
        # Get Sigmac conversion errors and only keep the rule filepath
        errors = [error[error.find("(")+1:error.find(")")] for error in outputRaw.stderr.split("\n") if "unsupported" in error]
        return {"ruleset": rules, "errors": errors}

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
if __name__ == '__main__':
    version = "2.6.1"

    # Init Args handling
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--evtx", help="EVTX log file or directory where EVTX log files are stored in JSON or EVTX format", type=str)
    parser.add_argument("-s", "--select", help="Only EVTX files containing the provided string will be used. If there is/are exclusion(s) (--avoid) they will be handled after selection", action='append', nargs='+')
    parser.add_argument("-a", "--avoid", help="EVTX files containing the provided string will NOT be used", action='append', nargs='+')
    #{% if not embeddedMode %}
    parser.add_argument("-r", "--ruleset", help="JSON File containing SIGMA rules", type=str)
    parser.add_argument("--fieldlist", help="Get all EVTX fields", action='store_true')
    parser.add_argument("-sg", "--sigma", help="Tell Zircolite to directly use SIGMA rules (slower) instead of the converted ones, you must provide SIGMA config file path", type=str)
    parser.add_argument("-sc", "--sigmac", help="Sigmac path (version >= 0.20), this arguments is mandatary only if you use '--sigma'", type=str)
    parser.add_argument("-se", "--sigmaerrors", help="Show rules conversion error (i.e not supported by the SIGMA SQLite backend)", action='store_true')
    parser.add_argument("--evtx_dump", help="Tell Zircolite to use this binary for EVTX conversion, on Linux and MacOS the path must be valid to launch the binary (eg. './evtx_dump' and not 'evtx_dump')", type=str, default=None)
    #{% else %}
    #{% for rule in rules %}
    #{{ rule -}}
    #{% endfor %}
    #{% endif %}
    parser.add_argument("-R", "--rulefilter", help="Remove rule from ruleset, comparison is done on rule title (case sensitive)", action='append', nargs='*')
    parser.add_argument("-L", "--limit", help="Discard results (in output file or forwarded events) that are above the provide limit", type=int, default=-1)
    parser.add_argument("-c", "--config", help="JSON File containing field mappings and exclusions", type=str, default="config/fieldMappings.json")
    parser.add_argument("-o", "--outfile", help="File that will contains all detected events", type=str, default="detected_events.json")
    parser.add_argument("--csv", help="The output will be in CSV. You should note that in this mode empty fields will not be discarded from results", action='store_true')
    parser.add_argument("-f", "--fileext", help="EVTX file extension", type=str, default="evtx")
    parser.add_argument("-t", "--tmpdir", help="Temp directory that will contains EVTX converted as JSON", type=str)
    parser.add_argument("-k", "--keeptmp", help="Do not remove the temp directory containing EVTX converted in JSON format", action='store_true')
    parser.add_argument("-d", "--dbfile", help="Save all logs in a SQLite Db to the specified file", type=str)
    parser.add_argument("-l", "--logfile", help="Log file name", default="zircolite.log", type=str)
    parser.add_argument("-n", "--nolog", help="Don't create a log file or a result file (useful when forwarding)", action='store_true')
    parser.add_argument("-j", "--jsononly", help="If logs files are already in JSON lines format ('jsonl' in evtx_dump) ", action='store_true')
    parser.add_argument("-D", "--dbonly", help="Directly use a previously saved database file, timerange filters will not work", action='store_true')
    parser.add_argument("-S", "--sysmon4linux", help="Use this option if your log file is a Sysmon for linux log file, default file extension is '.log'", action='store_true')
    parser.add_argument("-A", "--after", help="Limit to events that happened after the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="1970-01-01T00:00:00")
    parser.add_argument("-B", "--before", help="Limit to events that happened before the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="9999-12-12T23:59:59")
    parser.add_argument("--remote", help="Forward results to a HTTP/Splunk, please provide the full address e.g [http://]address:port[/uri]", type=str)
    parser.add_argument("--cores", help="Specify how many cores you want to use, default is all cores", type=str)
    parser.add_argument("--token", help="Use this to provide Splunk HEC Token", type=str)
    parser.add_argument("--stream", help="By default event forwarding is done at the end, this option activate forwarding events when detected", action="store_true")
    #{% if not embeddedMode %}
    parser.add_argument("--template", help="If a Jinja2 template is specified it will be used to generated output", type=str, action='append', nargs='+')
    parser.add_argument("--templateOutput", help="If a Jinja2 template is specified it will be used to generate a crafted output", type=str, action='append', nargs='+')
    #{% else %}
    #{% for template in templates %}
    #{{ template -}}
    #{% endfor %}
    #{% endif %}
    parser.add_argument("--debug", help="Activate debug logging", action='store_true')
    parser.add_argument("--showall", help="Show all events, usefull to check what rule takes takes time to execute", action='store_true')
    parser.add_argument("--noexternal", help="Don't use evtx_dump external binaries (slower)", action='store_true')
    parser.add_argument("--package", help="Create a ZircoGui package (not available in embedded mode)", action='store_true')
    parser.add_argument("-v", "--version", help="Show Zircolite version", action='store_true')

    args = parser.parse_args()

    #{% if embeddedMode %}
    #{% for ruleB64 in rulesB64 %}
    #{{ ruleB64 -}}
    #{% endfor %}
    #{% for template in templatesB64 %}
    #{{ template -}}
    #{% endfor %}
    #{% endif %}

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
             -= Standalone SIGMA Detection tool for EVTX =-
    """)

    #{% if embeddedMode %}#{{ embeddedText }}#{% endif %}
    #{% if embeddedMode %}
    #{{ rulesCheck }}
    #{{ noPackage }}
    #{{ noExternal }}
    #{% endif %}

    # Print version an quit
    if args.version: consoleLogger.info(f"Zircolite - v{version}"), sys.exit(0)

    # Check mandatory CLI options
    if not args.evtx: consoleLogger.error(f"{Fore.RED}   [-] No EVTX source path provided{Fore.RESET}"), sys.exit(2)
    #{% if not embeddedMode %}
    if args.evtx and not (args.fieldlist or args.ruleset): 
        consoleLogger.error(f"{Fore.RED}   [-] Cannot use Zircolite with EVTX source and without the fiedlist or ruleset option{Fore.RESET}"), sys.exit(2)
    #{% endif %}

    consoleLogger.info("[+] Checking prerequisites")

    # Init Forwarding
    forwarder = eventForwarder(args.remote, args.token, consoleLogger)
    if args.remote is not None: 
        if not forwarder.networkCheck(): quitOnError(f"{Fore.RED}   [-] Remote host cannot be reached : {args.remote}")
    
    # Checking provided timestamps
    try:
        eventsAfter = time.strptime(args.after, '%Y-%m-%dT%H:%M:%S')
        eventsBefore = time.strptime(args.before, '%Y-%m-%dT%H:%M:%S')
    except:
        quitOnError(f"{Fore.RED}   [-] Wrong timestamp format. Please use 'AAAA-MM-DDTHH:MM:SS'")

    #{% if embeddedMode %}
    readyForTemplating = True
    #{{ binPathVar }}
    #{% else %}
    binPath = args.evtx_dump
    # Check Sigma config file & Sigmac path
    if args.sigma and args.sigmac :
        checkIfExists(args.sigma, f"{Fore.RED}   [-] Cannot find SIGMA config file : {args.sigma}")
        checkIfExists(args.sigmac, f"{Fore.RED}   [-] Cannot find Sigmac converter : {args.sigmac}")
    elif (args.sigma and not args.sigmac) or (args.sigmac and not args.sigma):
        consoleLogger.info(f"{Fore.RED}   [-] the '--sigma' and '--sigmac' options must be used together") 

    # Check ruleset arg
    if args.sigma is None and args.sigma is None and not args.fieldlist:
        checkIfExists(args.ruleset, f"{Fore.RED}   [-] Cannot find ruleset : {args.ruleset}")
    # Check templates args
    readyForTemplating = False
    if (args.template is not None):
        if args.csv: quitOnError(f"{Fore.RED}   [-] You cannot use templates in CSV mode ")
        if (args.templateOutput is None) or (len(args.template) != len(args.templateOutput)):
            quitOnError(f"{Fore.RED}   [-] Number of template ouput must match number of template ")
        for template in args.template:
            checkIfExists(template[0], f"{Fore.RED}   [-] Cannot find template : {template[0]}")
        readyForTemplating = True
    #{% endif %}
    if args.csv: 
        readyForTemplating = False
        if args.outfile == "detected_events.json": 
            args.outfile = "detected_events.csv"

    # Start time counting
    start_time = time.time()

    # Initialize zirCore
    zircoliteCore = zirCore(args.config, logger=consoleLogger, noOutput=args.nolog, timeAfter=eventsAfter, timeBefore=eventsBefore, limit=args.limit, csvMode=args.csv)

    # If we are not working directly with the db
    if not args.dbonly:
        # If we are working with json we change the file extension if it is not user-provided
        if args.jsononly and args.fileext == "evtx": args.fileext = "json"
        if args.sysmon4linux and args.fileext == "evtx": args.fileext = "log"

        EVTXPath = Path(args.evtx)
        if EVTXPath.is_dir():
            # EVTX recursive search in given directory with given file extension
            EVTXList = list(EVTXPath.rglob(f"*.{args.fileext}"))
        elif EVTXPath.is_file():
            EVTXList = [EVTXPath]
        else:
            quitOnError(f"{Fore.RED}   [-] Unable to find EVTX from submitted path")

        # Applying file filters in this order : "select" than "avoid"
        FileList = avoidFiles(selectFiles(EVTXList, args.select), args.avoid)
        if len(FileList) <= 0:
            quitOnError(f"{Fore.RED}   [-] No file found. Please verify filters, the directory or the extension with '--fileext'")

        if not args.jsononly:
            # Init EVTX extractor object
            extractor = evtxExtractor(logger=consoleLogger, providedTmpDir=args.tmpdir, coreCount=args.cores, useExternalBinaries=(not args.noexternal), binPath=binPath, xmlLogs=args.sysmon4linux)
            consoleLogger.info(f"[+] Extracting EVTX Using '{extractor.tmpDir}' directory ")
            for evtx in tqdm(FileList, colour="yellow"):
                extractor.run(evtx)
            # Set the path for the next step
            EVTXJSONList = list(Path(extractor.tmpDir).rglob("*.json"))
        else:
            EVTXJSONList = FileList

        #{% if not embeddedMode -%}
        checkIfExists(args.config, f"{Fore.RED}   [-] Cannot find mapping file")
        #{% endif %}
        if EVTXJSONList == []:
            quitOnError(f"{Fore.RED}   [-] No JSON files found.")

        #{% if not embeddedMode -%}
        # Print field list and exit
        if args.fieldlist:
            fields = zircoliteCore.run(EVTXJSONList, False)
            zircoliteCore.close()
            if not args.jsononly and not args.keeptmp: extractor.cleanup()
            [print(sortedField) for sortedField in sorted([field for field in fields.values()])]
            sys.exit(0)
        #{% endif %}

        # Flatten and insert to Db
        zircoliteCore.run(EVTXJSONList)
        # Unload In memory DB to disk. Done here to allow debug in case of ruleset execution error
        if args.dbfile is not None: zircoliteCore.saveDbToDisk(args.dbfile)
    else:
        consoleLogger.info(f"[+] Creating model from disk : {args.evtx}")
        zircoliteCore.loadDbInMemory(args.evtx)

    # flatten array of "rulefilter" arguments
    if args.rulefilter: args.rulefilter = [item for sublist in args.rulefilter for item in sublist]
    
    #{% if embeddedMode -%}
    #{% for ruleIf in rulesIf -%}
    #{{ ruleIf }}
    #{% endfor %}
    #{{ executeRuleSetFromVar }}
    #{% else -%}
    consoleLogger.info(f"[+] Loading ruleset from : {args.ruleset}")
    # If Raw SIGMA rules are used, they must be converted 
    if args.sigma and args.sigmac:
        consoleLogger.info(f"[+] Raw SIGMA rules conversion (use '--sigmaerrors' option to show not supported rules)")
        rulesGeneratorInstance = rulesetGenerator(args.sigmac, args.sigma, "logs", args.ruleset)
        convertedRules = rulesGeneratorInstance.run()
        if not convertedRules["ruleset"]: quitOnError(f"{Fore.RED}   [-] No rule to execute, check your sigma rules and sigmac paths, or use '--sigmaerrors' to show not supported rules")
        # If provided rules are not supported
        if args.sigmaerrors and len(convertedRules["errors"]) > 0:
            consoleLogger.info(f"[+] These rules were not converted (not supported by backend) : ")
            for error in convertedRules["errors"]:
                consoleLogger.info(f'{Fore.LIGHTYELLOW_EX}   [-] "{error}"{Fore.RESET}')
        zircoliteCore.loadRulesetFromVar(ruleset=convertedRules["ruleset"], ruleFilters=args.rulefilter)
    else:
        zircoliteCore.loadRulesetFromFile(filename=args.ruleset, ruleFilters=args.rulefilter)
    #{% endif %}

    if args.limit > 0: consoleLogger.info(f"[+] Limited mode : detections with more than {args.limit} events will be discarded")
    consoleLogger.info(f"[+] Executing ruleset - {len(zircoliteCore.ruleset)} rules")
    zircoliteCore.executeRuleset(args.outfile, forwarder=forwarder, showAll=args.showall, KeepResults=(readyForTemplating or args.package), remote=args.remote, stream=args.stream)
    consoleLogger.info(f"[+] Results written in : {args.outfile}")

    # Forward events
    if args.remote is not None and not args.stream: # If not in stream mode
        consoleLogger.info(f"[+] Forwarding to : {args.remote}")
        forwarder.send(zircoliteCore.fullResults, False)
    if args.remote is not None and args.stream: consoleLogger.info(f"[+] Forwarded to : {args.remote}")

    # Templating
    if readyForTemplating and zircoliteCore.fullResults != []:
        #{% if not embeddedMode -%}
        templateGenerator = templateEngine(consoleLogger, args.template, args.templateOutput)
        templateGenerator.run(zircoliteCore.fullResults)
        #{% else -%}
        #{% for templateB64Fn in templatesB64Fn -%}
        #{% for line in templateB64Fn %}
        #{{ line -}}
        #{% endfor %}
        #{% endfor %}
        #{% endif %}

    #{% if not embeddedMode -%}
    # Generate ZircoGui package
    if args.package and zircoliteCore.fullResults != []:
        if Path("templates/exportForZircoGui.tmpl").is_file() and Path("gui/zircogui.zip").is_file():
            packager = zircoGuiGenerator("gui/zircogui.zip", "templates/exportForZircoGui.tmpl", consoleLogger)
            packager.generate(zircoliteCore.fullResults)
    #{% endif %}

    # Removing Working directory containing logs as json
    if not args.keeptmp:
        consoleLogger.info("[+] Cleaning")
        try:
            if not args.jsononly and not args.dbonly: extractor.cleanup()
        except OSError as e:
            consoleLogger.error(f"{Fore.RED}   [-] Error during cleanup {e}")

    zircoliteCore.close()
    consoleLogger.info(f"\nFinished in {int((time.time() - start_time))} seconds")
