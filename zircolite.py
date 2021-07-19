#!python3
# -*- coding: utf-8 -*-

# Standard libs
import json
import sqlite3
import logging
from sqlite3 import Error
import os
import socket
import subprocess
import argparse
import sys
import time
import random
import string
import signal
import base64
from pathlib import Path
import shutil
from sys import platform as _platform
from multiprocessing import Pool
import zlib

# External libs
from tqdm import tqdm
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from colorama import Fore
from jinja2 import Template
from evtx import PyEvtxParser
import aiohttp
import asyncio

def signal_handler(sig, frame):
    consoleLogger.info("[-] Execution interrupted !")
    sys.exit(0)

def generateFromTemplate(templateFile, outpoutFilename, data):
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
        consoleLogger.error(f"{Fore.RED}   [-] Template error, activate debug mode to check for errors")
        consoleLogger.debug(f"   [-] {e}")

def quitOnError(message):
    consoleLogger.error(message)
    sys.exit(1)

def checkIfExists(path, errorMessage):
    """ Test if path provided is a file """
    if not (Path(path).is_file()):
        quitOnError(errorMessage)

def initLogger(debugMode, logFile=None):
    logLevel = logging.INFO
    if logFile is not None:
        logFormat = "%(asctime)s %(levelname)-8s %(message)s"
    else: 
        logFormat = "%(message)s"
    if debugMode:
        logLevel = logging.DEBUG
        logFormat = "%(asctime)s %(levelname)-8s %(module)s:%(lineno)s %(funcName)s %(message)s"

    logging.basicConfig(format=logFormat, filename=logFile, level=logLevel, datefmt='%Y-%m-%d %H:%M:%S')

    if logFile is not None:
        logger = logging.StreamHandler()
        logger.setLevel(logging.INFO)
        logging.getLogger().addHandler(logger)
    return logging.getLogger()

class eventForwarder:
    """ Class for handling event forwarding """
    def __init__(self, remote, token, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.remoteHost = remote
        self.token = token
        self.localHostname = socket.gethostname()
        self.userAgent = "zircolite/2.0.x"

    def send(self, payloads, bypassToken=True, noError=False):
        if payloads: 
            if self.remoteHost is not None:
                try:
                    if self.token is not None and not bypassToken:
                        asyncio.run(self.sendHECAsync(payloads, "SystemTime"))
                    else:
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
        with open(configFile, 'r') as fieldMappingsFile:
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
                            self.keyDict[key.lower()] = ""
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

    def __init__(self, config, logger=None, noOutput=False, timeAfter="1970-01-01T00:00:00", timeBefore="9999-12-12T23:59:59"):
        self.logger = logger or logging.getLogger(__name__)
        self.dbConnection = self.createConnection(":memory:")
        self.fullResults = []
        self.ruleset = {}
        self.noOutput = noOutput
        self.timeAfter = timeAfter
        self.timeBefore = timeBefore
        self.config = config
    
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
                        # Cleaning null/None fields
                        for row in rows:
                            match = {k: v for k, v in row.items() if v is not None}
                            filteredRows.append(match)
            if "level" not in rule:
                rule["level"] = "unknown"
            if "tags" not in rule:
                rule["tags"] = []
            results = ({"title": rule["title"], "description": rule["description"], "sigma": rule["rule"], "rule_level": rule["level"], "tags": rule["tags"], "count": counter, "matches": filteredRows})
            if counter > 0:
                self.logger.debug(f'DETECTED : {rule["title"]} - Matchs : {counter} events')
        else:
            self.logger.debug("RULE FORMAT ERROR : rule key Missing")
        if filteredRows == []:
            return {}
        return results

    def loadRulesetFromFile(self, filename, ruleFilters):
        with open(filename) as f:
            self.ruleset = json.load(f)
        self.applyRulesetFilters(ruleFilters)

    def loadRulesetFromVar(self, ruleset, ruleFilters):
        self.ruleset = ruleset
        self.applyRulesetFilters(ruleFilters)
    
    def applyRulesetFilters(self, ruleFilters=None):
        # Remove empty rule and remove filtered rules
        self.ruleset = list(filter(None, self.ruleset))
        if ruleFilters is not None:
            self.ruleset = [rule for rule in self.ruleset if not any(ruleFilter in rule["title"] for ruleFilter in ruleFilters)]

    def executeRuleset(self, outFile, writeMode='w', forwarder=None, showAll=False, readyForTemplating=False, remote=None, stream=False):
        # Results are writen upon detection to allow analysis during execution and to avoid loosing results in case of error.
        with open(outFile, writeMode, encoding='utf-8') as fileHandle:
            with tqdm(self.ruleset, colour="yellow") as ruleBar:
                if not self.noOutput: fileHandle.write('[')
                for rule in ruleBar:  # for each rule in ruleset
                    if showAll and "title" in rule: ruleBar.write(f'{Fore.BLUE}    - {rule["title"]}')  # Print all rules
                    ruleResults = self.executeRule(rule)
                    if ruleResults != {}:
                        ruleBar.write(f'{Fore.CYAN}    - {ruleResults["title"]} : {ruleResults["count"]} events{Fore.RESET}')
                        # Store results for templating and event forwarding (only if stream mode is disabled)
                        if readyForTemplating or (remote is not None and not stream): self.fullResults.append(ruleResults)
                        if stream and forwarder is not None: forwarder.send([ruleResults], False)
                        # Output to json file
                        try:
                            if not self.noOutput: 
                                json.dump(ruleResults, fileHandle, indent=4, ensure_ascii=False)
                                fileHandle.write(',\n')
                        except Exception as e:
                            self.logger.error(f"{Fore.RED}   [-] Error saving some results : {e}")
                if not self.noOutput: fileHandle.write('{}]')  

    def run(self, EVTXJSONList):
        self.logger.info("[+] Processing EVTX")
        flattener = JSONFlattener(configFile=self.config, timeAfter=self.timeAfter, timeBefore=self.timeBefore)
        flattener.runAll(EVTXJSONList)
        self.logger.info("[+] Creating model")
        self.createDb(flattener.fieldStmt)
        self.logger.info("[+] Inserting data")
        self.insertFlattenedJSON2Db(flattener.valuesStmt)
        self.logger.info("[+] Cleaning unused objects")
        del flattener

class evtxExtractor:

    def __init__(self, logger=None, providedTmpDir=None, coreCount=None, useExternalBinaries=True):
        self.logger = logger or logging.getLogger(__name__)
        if Path(str(providedTmpDir)).is_dir():
            self.tmpDir = f"tmp-{self.randString()}"
            self.logger.error(f"{Fore.RED}   [-] Provided directory already exists using '{self.tmpDir}' instead")
        else:
            self.tmpDir = providedTmpDir or f"tmp-{self.randString()}"
            os.mkdir(self.tmpDir)
        self.cores = coreCount or os.cpu_count()
        self.useExternalBinaries = useExternalBinaries
        #{% if not embeddedMode %}
        self.evtxDumpCmd = self.getOSExternalTools()
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
        with open("{{ externalTool }}", 'wb') as f:
            f.write(zlib.decompress(base64.b64decode(b'{{ externalToolB64 }}')))
        self.makeExecutable("{{ externalTool }}")
        return "{{ externalTool }}"
    #{% else %}
    def getOSExternalTools(self):
        """ Determine wich binaries to run depending on host OS : 32Bits is NOT supported for now since evtx_dump is 64bits only"""
        if _platform == "linux" or _platform == "linux2":
            return "bin/evtx_dump_lin"
        elif _platform == "darwin":
            return "bin/evtx_dump_mac"
        elif _platform == "win32":
            return "bin\\evtx_dump_win.exe"
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
            with open(f"{self.tmpDir}/{str(filename)}-{self.randString()}.json", "w") as f:
                for record in parser.records_json():
                    f.write(f'{json.dumps(json.loads(record["data"]))}\n')
        except Exception as e:
            self.logger.error(f"{Fore.RED}   [-] {e}")

    def run(self, file):
        """
        Convert EVTX to JSON using evtx_dump : https://github.com/omerbenamram/evtx.
        Drop resulting JSON files in a tmp folder.
        """
        self.logger.debug(f"EXTRACTING : {file}")

        if not self.useExternalBinaries or not Path(self.evtxDumpCmd).is_file(): 
            self.logger.debug(f"No external binaries args or evtx_dump is missing")
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
        #{{ removeTool }}
        #{% endif %}

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

    # Init Args handling
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--evtx", help="EVTX log file or directory where EVTX log files are stored in JSON or EVTX format", type=str, required=True)
    parser.add_argument("-s", "--select", help="Only EVTX files containing the provided string will be used. If there is/are exclusion(s) (--avoid) they will be handled after selection", action='append', nargs='+')
    parser.add_argument("-a", "--avoid", help="EVTX files containing the provided string will NOT be used", action='append', nargs='+')
    #{% if not embeddedMode %}
    parser.add_argument("-r", "--ruleset", help="JSON File containing SIGMA rules", type=str, required=True)
    #{% else %}
    #{% for rule in rules %}
    #{{ rule -}}
    #{% endfor %}
    #{% endif %}
    parser.add_argument("-R", "--rulefilter", help="Remove rule from ruleset, comparison is done on rule title (case sensitive)", action='append', nargs='*')
    parser.add_argument("-c", "--config", help="JSON File containing field mappings and exclusions", type=str, default="config/fieldMappings.json")
    parser.add_argument("-o", "--outfile", help="JSON file that will contains all detected events", type=str, default="detected_events.json")
    parser.add_argument("-f", "--fileext", help="EVTX file extension", type=str, default="evtx")
    parser.add_argument("-t", "--tmpdir", help="Temp directory that will contains EVTX converted as JSON", type=str)
    parser.add_argument("-k", "--keeptmp", help="Do not remove the Temp directory", action='store_true')
    parser.add_argument("-d", "--dbfile", help="Save all logs in a SQLite Db to the specified file", type=str)
    parser.add_argument("-l", "--logfile", help="Log file name", default="zircolite.log", type=str)
    parser.add_argument("-n", "--nolog", help="Don't create a log file", action='store_true')
    parser.add_argument("-j", "--jsononly", help="If logs files are already in JSON lines format ('jsonl' in evtx_dump) ", action='store_true')
    parser.add_argument("-D", "--dbonly", help="Directly use a previously saved database file, timerange filters will not work", action='store_true')
    parser.add_argument("-A", "--after", help="Limit to events that happened after the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="1970-01-01T00:00:00")
    parser.add_argument("-B", "--before", help="Limit to events that happened before the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="9999-12-12T23:59:59")
    parser.add_argument("--remote", help="Forward results to a HTTP server, please provide the full address e.g http://address:port/uri (except for Splunk)", type=str)
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

    print("""
    ███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗
    ╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝
      ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗
     ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝
    ███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗
    ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
    """)
    #{% if embeddedMode %}#{{ embeddedText }}#{% endif %}
    #{% if embeddedMode %}
    #{{ rulesCheck -}}
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
    #{% else %}
    # Checking ruleset arg
    checkIfExists(args.ruleset, f"{Fore.RED}   [-] Cannot find ruleset : {args.ruleset}")
    # Checking templates args
    readyForTemplating = False
    if (args.template is not None):
        if (args.templateOutput is None) or (len(args.template) != len(args.templateOutput)):
            quitOnError(f"{Fore.RED}   [-] Number of template ouput must match number of template ")
        for template in args.template:
            checkIfExists(template[0], f"{Fore.RED}   [-] Cannot find template : {template[0]}")
        readyForTemplating = True
    #{% endif %}

    # Start time counting
    start_time = time.time()
    
    # Initialize zirCore
    zircoliteCore = zirCore(args.config, logger=consoleLogger, noOutput=args.nolog, timeAfter=eventsAfter, timeBefore=eventsBefore)

    # If we are not working directly with the db
    if not args.dbonly:
        # Init EVTX extractor object
        extractor = evtxExtractor(logger=consoleLogger, providedTmpDir=args.tmpdir, coreCount=args.cores, useExternalBinaries=(not args.noexternal))
        # If we are working with json we change the file extension if it is not user-provided
        if args.jsononly and args.fileext == "evtx": args.fileext = "json"
        if not args.jsononly: consoleLogger.info(f"[+] Extracting EVTX Using '{extractor.tmpDir}' directory ")
        EVTXPath = Path(args.evtx)
        if EVTXPath.is_dir():
            # EVTX recursive search in given directory with given file extension
            EVTXList = list(EVTXPath.rglob(f"*.{args.fileext}"))
        elif EVTXPath.is_file():
            EVTXList = [EVTXPath]
        else:
            quitOnError(f"{Fore.RED}   [-] Unable to extract EVTX from submitted path")

        # Applying file filters in this order : "select" than "avoid"
        FileList = avoidFiles(selectFiles(EVTXList, args.select), args.avoid)
        if len(FileList) <= 0:
            quitOnError(f"{Fore.RED}   [-] No file found. Please verify filters, the directory or the extension with '--fileext'")

        if not args.jsononly:
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
    zircoliteCore.loadRulesetFromFile(filename=args.ruleset, ruleFilters=args.rulefilter)
    #{% endif %}
    
    consoleLogger.info(f"[+] Executing ruleset - {len(zircoliteCore.ruleset)} rules")
    zircoliteCore.executeRuleset(args.outfile, forwarder=forwarder, showAll=args.showall, readyForTemplating=readyForTemplating, remote=args.remote, stream=args.stream)
    consoleLogger.info(f"[+] Results written in : {args.outfile}")      

    # Forward events
    if args.remote is not None and not args.stream: # If not in stream mode
        consoleLogger.info(f"[+] Forwarding to : {args.remote}")
        forwarder.send(zircoliteCore.fullResults, False)
    if args.remote is not None and args.stream: consoleLogger.info(f"[+] Forwarded to : {args.remote}")

    # Templating
    if readyForTemplating and zircoliteCore.fullResults != []:
        #{% if not embeddedMode -%}
        for template, templateOutput in zip(args.template, args.templateOutput):
            consoleLogger.info(f'[+] Applying template "{template[0]}", outputting to : {templateOutput[0]}')
            generateFromTemplate(template[0], templateOutput[0], zircoliteCore.fullResults)
        #{% else -%}
        #{% for templateB64Fn in templatesB64Fn -%}
        #{% for line in templateB64Fn %}
        #{{ line -}}
        #{% endfor %}
        #{% endfor %}
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
