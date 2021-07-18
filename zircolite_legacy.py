#!python3
# -*- coding: utf-8 -*-

# Std library
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

# Optional imports
# TQDM - Progress bar
try:
    from tqdm import tqdm
    hasTqdm = True
except ImportError:  # If the module is not available creating a fake function that return the first argument value
    def tqdm(arg, colour):
        return arg
    hasTqdm = False

# Requests 
try: 
    import requests
    import urllib3
    hasRequests = True
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    hasRequests = False

# Coloroma - Living in colors
try:
    import colorama
    from colorama import Fore
    colorama.init(autoreset=True)
except ImportError:  # If the module is not available creating a fake object
    class ColorFake:
        def __init__(self):
            self.CYAN = ""
            self.RED = ""
    Fore = ColorFake()

# Jinja2 templating
try:
    from jinja2 import Template
    hasJinja2 = True
except ImportError:  # If the module is not available
    hasJinja2 = False

def signal_handler(sig, frame):
    consoleLogger.info("[-] Execution interrupted !")
    sys.exit(0)

def createConnection(db):
    """ create a database connection to a SQLite database """
    conn = None
    consoleLogger.debug(f"CONNECTING TO : {db}")
    try:
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row  # Allow to get a dict
    except Error as e:
        consoleLogger.error(f"{Fore.RED}   [-] {e}")
    return conn

def executeQuery(dbConnection, query):
    """ Perform a SQL Query with the provided connection """
    if dbConnection is not None:
        dbHandle = dbConnection.cursor()
        consoleLogger.debug(f"EXECUTING : {query}")
        try:
            dbHandle.execute(query)
            dbConnection.commit()
            return True
        except Error as e:
            consoleLogger.debug(f"   [-] {e}")
            return False
    else:
        consoleLogger.error(f"{Fore.RED}   [-] No connection to Db")
        return False

def executeSelectQuery(dbConnection, query):
    """ Perform a SQL Query with the provided connection """
    if dbConnection is not None:
        dbHandle = dbConnection.cursor()
        consoleLogger.debug(f"EXECUTING : {query}")
        try:
            data = dbHandle.execute(query)
            return data
        except Error as e:
            consoleLogger.debug(f"   [-] {e}")
            return {}
    else:
        consoleLogger.error(f"{Fore.RED}   [-] No connection to Db")
        return {}

def extractEvtx(file, tmpDir, evtx_dumpBinary):
    """
    Convert EVTX to JSON using evtx_dump : https://github.com/omerbenamram/evtx.
    Drop resulting JSON files in a tmp folder.
    """

    consoleLogger.debug(f"EXTRACTING : {file}")
    try:
        filepath = Path(file)
        filename = filepath.name
        randString = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
        cmd = [evtx_dumpBinary, "--no-confirm-overwrite", "-o", "jsonl", str(file), "-f", tmpDir + "/" + str(filename) + randString + ".json"]
        subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        consoleLogger.error(f"{Fore.RED}   [-] {e}")

def flattenJSON(file, timeAfter, timeBefore):
    """
        Flatten json object with nested keys into a single level.
        Returns the flattened json object
    """

    consoleLogger.debug(f"FLATTENING : {file}")
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
            # Applying exclusions. Key/value pair is discarded if there is a partial match
            if not any(exclusion in name[:-1] for exclusion in fieldExclusions):
                # Arrays are not expanded
                if type(x) is list:
                    value = ''.join(str(x))
                else:
                    value = x
                # Excluding useless values (e.g. "null"). The value must be an exact match.
                if not value in uselessValues:
                    # Applying field mappings
                    if name[:-1] in fieldMappings:
                        key = fieldMappings[name[:-1]]
                    else:
                        # Removing all annoying character from field name
                        key = ''.join(e for e in name[:-1].split(".")[-1] if e.isalnum())
                    JSONLine[key] = value
                    # Generate the CREATE TABLE SQL statement
                    if key.lower() not in keyDict:
                        if type(value) is int:
                            keyDict[key.lower()] = ""
                            fieldStmt += f"'{key}' INTEGER,\n"
                        else:
                            keyDict[key.lower()] = ""
                            fieldStmt += f"'{key}' TEXT COLLATE NOCASE,\n"

    with open(str(file), 'r', encoding='utf-8') as JSONFile:
        for line in JSONFile:
            try:
                flatten(json.loads(line))
            except Exception as e:
                consoleLogger.debug(f'JSON ERROR : {e}')
            # Handle timestamp filters
            if timeAfter != "1970-01-01T00:00:00" and timeBefore != "9999-12-12T23:59:59":
                timestamp = time.strptime(JSONLine["SystemTime"].split(".")[0].replace("Z",""), '%Y-%m-%dT%H:%M:%S')
                if timestamp > timeAfter and timestamp < timeBefore:
                    JSONOutput.append(JSONLine)
            else:
                JSONOutput.append(JSONLine)
            JSONLine = {}

    return {"dbFields": fieldStmt, "dbValues": JSONOutput}

def insertData2Db(JSONLine):
    columnsStr = ""
    valuesStr = ""

    for key in sorted(JSONLine.keys()):
        columnsStr += "'" + key + "',"
        if type(JSONLine[key]) is int:
            valuesStr += str(JSONLine[key]) + ", "
        else:
            valuesStr += "'" + str(JSONLine[key]).replace("'", "''") + "', "

    insertStrmt = f"INSERT INTO logs ({columnsStr[:-1]}) VALUES ({valuesStr[:-2]});"
    return executeQuery(dbConnection, insertStrmt)

def executeRule(rule):
    results = {}
    filteredRows = []
    counter = 0
    if "rule" in rule:
        # for each SQL Query in the SIGMA rule
        for SQLQuery in rule["rule"]:
            data = executeSelectQuery(dbConnection, SQLQuery)
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
            consoleLogger.debug(f'DETECTED : {rule["title"]} - Matchs : {counter} events')
    else:
        consoleLogger.debug("RULE FORMAT ERROR : rule key Missing")
    if filteredRows == []:
        return {}
    return results

def getOSExternalTools():
    """ Determine wich binaries to run depending on host OS : 32Bits is NOT supported for now since evtx_dump is 64bits only"""
    if _platform == "linux" or _platform == "linux2":
        return "bin/evtx_dump_lin"
    elif _platform == "darwin":
        return "bin/evtx_dump_mac"
    elif _platform == "win32":
        return "bin\\evtx_dump_win.exe"

def generateFromTemplate(templateFile, outpoutFilename, data):
    """ Use Jinja2 to output data in a specific format """
    try:
        with open(templateFile, 'r', encoding='utf-8') as tmpl:
            template = Template(tmpl.read())
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
    def __init__(self, remote, token):
        self.remoteHost = remote
        self.token = token
        self.localHostname = socket.gethostname()
        self.userAgent = "zircolite/1.4.x"

    def sendAll(self, payloads):
        """ Send an array of events """
        for payload in payloads:
            self.send(payload, False)

    def sendMP(self, payload):
        self.send(payload, False)

    def send(self, payload, bypassToken = True):
        """ Send events to standard HTTP or Splunk HEC if there is a token provided and bypassToken is False """
        if payload: 
            if self.remoteHost is not None:
                try:
                    if self.token is not None and not bypassToken:
                        self.sendHEC(payload, "SystemTime")
                    else:
                        self.sendHTTP(payload)
                    return True
                except Exception as e:
                    consoleLogger.debug(f"{Fore.RED}   [-] {e}")
                    return False
        
    def networkCheck(self):
        """ Check remote connectivity """
        if (self.remoteHost is not None):
            if not self.send({"Zircolite": "Forwarder"}):
                return False
            else:
                return True
        return False

    def formatToEpoch(self, timestamp):
        return str(time.mktime(time.strptime(timestamp.split(".")[0], '%Y-%m-%dT%H:%M:%S')))[:-1] + timestamp.split(".")[1][:-1]
        
    def sendHTTP(self, payload = {}):
        """ Just send provided payload to provided web server. Non-async code. """
        payload.update({"host": self.localHostname})
        r = requests.post(self.remoteHost, headers={"user-agent": self.userAgent}, data={"data": base64.b64encode(json.dumps(payload).encode('utf-8')).decode('ascii')}, verify=False)

    def sendHEC(self, payload = {}, timeField = ""):
        """ Just send provided payload to provided Splunk HEC. Non-async code. """
        # Flatten detected events
        for match in payload["matches"]:
            jsonEventData = {}
            for key, value in match.items():
                jsonEventData.update({key: value})
            jsonEventData.update({"title": payload["title"], "description": payload["description"], "sigma": payload["sigma"], "rule_level": payload["rule_level"], "tags": payload["tags"]})
            # Send events with timestamps and default Splunk JSON sourcetype
            splunkURL = f"{self.remoteHost}/services/collector/event"
            data = {"sourcetype": "_json", "event": jsonEventData, "event": jsonEventData, "host": self.localHostname }
            if timeField != "": data.update({"time": self.formatToEpoch(jsonEventData[timeField])})
            r = requests.post(splunkURL, headers={'Authorization': f"Splunk {self.token}"}, json=data, verify=False)

def selectFiles(pathList, selectFilesList):
    if selectFilesList is not None:
        return [evtx for evtx in [str(element) for element in list(pathList)] if any(fileFilters[0].lower() in evtx.lower() for fileFilters in selectFilesList)]
    return pathList

def avoidFiles(pathList, avoidFilesList):
    if avoidFilesList is not None:
        return [evtx for evtx in [str(element) for element in list(pathList)] if all(fileFilters[0].lower() not in evtx.lower() for fileFilters in avoidFilesList)]
    return pathList

def saveDbToDisk(dbConnection, dbFilename):
    consoleLogger.info("[+] Saving working data to disk as a SQLite DB")
    onDiskDb = sqlite3.connect(dbFilename)
    dbConnection.backup(onDiskDb)
    onDiskDb.close()

################################################################
# MAIN()
################################################################
if __name__ == '__main__':

    # Init Args handling
    tmpDir = "tmp-" + ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--evtx", help="EVTX log file or directory where EVTX log files are stored in JSON, DB or EVTX format", type=str, required=True)
    parser.add_argument("-s", "--select", help="Only EVTX files containing the provided string will be used. If there is/are exclusion(s) ('--avoid') they will be handled after selection", action='append', nargs='+')
    parser.add_argument("-a", "--avoid", help="EVTX files containing the provided string will NOT be used", nargs='+')
    parser.add_argument("-r", "--ruleset", help="JSON File containing SIGMA rules", type=str, required=True)
    parser.add_argument("-R", "--rulefilter", help="Remove rule from ruleset, comparison is done on rule title (case sensitive)", action='append', nargs='*')
    parser.add_argument("-c", "--config", help="JSON File containing field mappings and exclusions", type=str, default="config/fieldMappings.json")
    parser.add_argument("-o", "--outfile", help="JSON file that will contains all detected events", type=str, default="detected_events.json")
    parser.add_argument("-f", "--fileext", help="EVTX file extension", type=str, default="evtx")
    parser.add_argument("-t", "--tmpdir", help="Temp directory that will contains EVTX converted as JSON", type=str, default=tmpDir)
    parser.add_argument("-k", "--keeptmp", help="Do not remove the Temp directory", action="store_true")
    parser.add_argument("-d", "--dbfile", help="Save data as a SQLite Db to the specified file on disk", type=str)
    parser.add_argument("-l", "--logfile", help="Log file name", default="zircolite.log", type=str)
    parser.add_argument("-n", "--nolog", help="Don't create a log file", action='store_true')
    parser.add_argument("-j", "--jsononly", help="If logs files are already in JSON lines format ('jsonl' in evtx_dump)", action="store_true")
    parser.add_argument("-D", "--dbonly", help="Directly use a previously saved database file, timerange filters will not work", action='store_true')
    parser.add_argument("-A", "--after", help="Work on events that happened after the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="1970-01-01T00:00:00")
    parser.add_argument("-B", "--before", help="Work on events that happened before the provided timestamp (UTC). Format : 1970-01-01T00:00:00", type=str, default="9999-12-12T23:59:59")
    parser.add_argument("--remote", help="Forward results to a HTTP server, please provide the full address e.g http://address:port/uri (except for Splunk)", type=str)
    parser.add_argument("--token", help="Use this to provide Splunk HEC Token", type=str)
    parser.add_argument("--stream", help="By default event forwarding is done at the end, this option activate forwarding events when detected", action="store_true")
    parser.add_argument("--template", help="If a Jinja2 template is specified it will be used to generated output", type=str, action='append', nargs='+')
    parser.add_argument("--templateOutput", help="If a Jinja2 template is specified it will be used to generate a crafted output", type=str, action='append', nargs='+')
    parser.add_argument("--debug", help="Activate debug logging", action="store_true")
    parser.add_argument("--showall", help="Show all events, usefull to check what rule takes takes time to execute", action='store_true')
    args = parser.parse_args()

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

    # flatten array of "rulefilter" arguments
    if args.rulefilter: args.rulefilter = [item for sublist in args.rulefilter for item in sublist]

    # Init Forwarding
    forwarder = eventForwarder(args.remote, args.token)
    if args.remote is not None: 
        if hasRequests:
            if not forwarder.networkCheck(): quitOnError(f"{Fore.RED}   [-] Remote host cannot be reached : {args.remote}")
        else: quitOnError(f"{Fore.RED}   [-] Requests is not installed.")
    
    consoleLogger.info("[+] Checking prerequisites")

    # Checking provided timestamps
    try:
        eventsAfter = time.strptime(args.after, '%Y-%m-%dT%H:%M:%S')
        eventsBefore = time.strptime(args.before, '%Y-%m-%dT%H:%M:%S')
    except:
        quitOnError(f"{Fore.RED}   [-] Wrong timestamp format. Please use 'AAAA-MM-DDTHH:MM:SS'")

    # If we are not working directly with the db
    if not args.dbonly:
        # Cheking for evtx_dump binaries
        evtx_dumpBinary = getOSExternalTools()
        checkIfExists(evtx_dumpBinary, f"{Fore.RED}   [-] Cannot find Evtx_dump")
        # Checking ruleset arg
        checkIfExists(args.ruleset, f"{Fore.RED}   [-] Cannot find ruleset : {args.ruleset}")
        # Checking if tmpdir is empty
        if (Path(args.tmpdir).is_dir()):
            quitOnError(f"{Fore.RED}   [-] The Temp working directory exists: {args.tmpdir}. Please remove it or rename it")

    # Checking templates args
    readyForTemplating = False
    if (args.template is not None):
        if not hasJinja2:
            quitOnError(f"{Fore.RED}   [-] You provided a template but Jinja2 module is not installed : {args.template}")
        if (args.templateOutput is None) or (len(args.template) != len(args.templateOutput)):
            quitOnError(f"{Fore.RED}   [-] Number of template ouput must match number of template ")
        for template in args.template:
            checkIfExists(template[0], f"{Fore.RED}   [-] Cannot find template : {template[0]}")
        readyForTemplating = True

    # Start time counting
    start_time = time.time()

   # Only if we are not working directly with the db
    if not args.dbonly:
        # Initialize configuration dictionaries 
        fieldExclusions = {}  # Will contain fields to discard
        fieldMappings = {}  # Will contain fields to rename during flattening
        uselessValues = {}  # Will contain values to discard during flattening

        checkIfExists(args.config, f"{Fore.RED}   [-] Cannot find mapping file")
        with open(args.config, 'r') as fieldMappingsFile:
            fieldMappingsDict = json.load(fieldMappingsFile)
            fieldExclusions = fieldMappingsDict["exclusions"]
            fieldMappings = fieldMappingsDict["mappings"]
            uselessValues = fieldMappingsDict["useless"]

        # If we are working with json we force the file extension if it is not user-provided
        if args.jsononly and args.fileext == "evtx": args.fileext = "json"
        if not args.jsononly: consoleLogger.info(f"[+] Extracting EVTX Using '{args.tmpdir}' directory ")
        EVTXPath = Path(args.evtx)
        if EVTXPath.is_dir():
            # EVTX recursive search in given directory with given file extension
            EVTXList = list(EVTXPath.rglob(f"*.{args.fileext}"))
        elif EVTXPath.is_file():
            EVTXList = [EVTXPath]
        else:
            quitOnError(f"{Fore.RED}   [-] Unable to extract EVTX from submitted path")
        FileList = avoidFiles(selectFiles(EVTXList, args.select), args.avoid)  # Apply file filters in this order : "select" than "avoid"
        if len(FileList) > 0:
            if not args.jsononly:
                for evtx in tqdm(FileList, colour="yellow"):
                    extractEvtx(evtx, args.tmpdir, evtx_dumpBinary)
                # Set the path for the next step
                EVTXJSONList = list(Path(args.tmpdir).rglob("*.json"))
            else:
                EVTXJSONList = FileList
        else:
            quitOnError(f"{Fore.RED}   [-] No file found. Please verify filters, the directory or the extension with '--fileext'")

        consoleLogger.info("[+] Processing EVTX")

        fieldStmt = ""
        valuesStmt = []
        results = {}
        keyDict = {}

        if EVTXJSONList == []:
            quitOnError(f"{Fore.RED}   [-] No JSON files found.")
        for evtxJSON in tqdm(EVTXJSONList, colour="yellow"):
            if os.stat(evtxJSON).st_size != 0:
                results = flattenJSON(evtxJSON, eventsAfter, eventsBefore)
                fieldStmt += results["dbFields"]
                valuesStmt += results["dbValues"]

        consoleLogger.info("[+] Creating model")
        dbConnection = createConnection(":memory:")
        createTableStmt = "CREATE TABLE logs ( row_id INTEGER, " + fieldStmt + " PRIMARY KEY(row_id AUTOINCREMENT) );"
        consoleLogger.debug(" CREATE : " + createTableStmt.replace('\n', ' ').replace('\r', ''))
        if not executeQuery(dbConnection, createTableStmt):
            quitOnError(f"{Fore.RED}   [-] Unable to create table")
        del createTableStmt

        consoleLogger.info("[+] Inserting data")
        for JSONLine in tqdm(valuesStmt, colour="yellow"):
            insertData2Db(JSONLine)
        # Creating index to speed up queries
        executeQuery(dbConnection, 'CREATE INDEX "idx_eventid" ON "logs" ("eventid");')

        consoleLogger.info("[+] Cleaning unused objects")
        del valuesStmt
        del results

        # Unload In memory DB to disk. Done here to allow debug in case of ruleset execution error
        if args.dbfile is not None: saveDbToDisk(dbConnection, args.dbfile)
    else:
        consoleLogger.info(f"[+] Creating model from disk : {args.evtx}")
        dbfileConnection = createConnection(args.evtx)
        dbConnection = createConnection(":memory:")
        dbfileConnection.backup(dbConnection)
        dbfileConnection.close()

    consoleLogger.info(f"[+] Loading ruleset from : {args.ruleset}")
    with open(args.ruleset) as f:
        ruleset = json.load(f)
    # Remove empty rule and remove filtered rules
    ruleset = list(filter(None, ruleset))
    if args.rulefilter is not None:
        ruleset = [rule for rule in ruleset if not any(ruleFilter in rule["title"] for ruleFilter in args.rulefilter)]

    consoleLogger.info(f"[+] Executing ruleset - {len(ruleset)} rules")
    # Results are writen upon detection to allow analysis during execution and to avoid loosing results in case of error.
    fullResults = []
    with open(args.outfile, 'w', encoding='utf-8') as f:
        if hasTqdm:  # If tqdm is installed
            with tqdm(ruleset, colour="yellow") as ruleBar:
                if not args.nolog: f.write('[')
                for rule in ruleBar:  # for each rule in ruleset
                    if args.showall: ruleBar.write(f'{Fore.BLUE}    - {rule["title"]}')  # Print all rules
                    ruleResults = executeRule(rule)
                    if ruleResults != {}:
                        ruleBar.write(f'{Fore.CYAN}    - {ruleResults["title"]} : {ruleResults["count"]} events')
                        # To avoid printing this one on stdout but in the logs...
                        consoleLogger.setLevel(logging.ERROR)
                        consoleLogger.info(f'{Fore.CYAN}    - {ruleResults["title"]} : {ruleResults["count"]} events')
                        consoleLogger.setLevel(logging.INFO)
                        # Store results for templating and event forwarding (only if stream mode is disabled)
                        if readyForTemplating or (args.remote is not None and not args.stream): fullResults.append(ruleResults)
                        if args.stream: forwarder.send(ruleResults, False)
                        # Output to json file
                        if not args.nolog: 
                            try:
                                json.dump(ruleResults, f, indent=4, ensure_ascii=False)
                                f.write(',\n')
                            except Exception as e:
                                consoleLogger.error(f"{Fore.RED}   [-] Error saving some results : {e}")
                if not args.nolog: f.write('{}]')
        else:
            if not args.nolog: f.write('[')
            for rule in ruleset:
                if args.showall: consoleLogger.info(f'{Fore.BLUE}    - {rule["title"]}')  # Print all rules
                ruleResults = executeRule(rule)
                if ruleResults != {}:
                    consoleLogger.info(f'{Fore.CYAN}    - {ruleResults["title"]} : {ruleResults["count"]} events')
                    # Store results for templating and event forwarding (only if stream mode is disabled)
                    if readyForTemplating or (args.remote is not None and not args.stream): fullResults.append(ruleResults)
                    if args.stream: forwarder.send(ruleResults, False)
                    # Output to json file
                    if not args.nolog: 
                        try:
                            json.dump(ruleResults, f, indent=4, ensure_ascii=False)
                            f.write(',\n')
                        except Exception as e:
                            consoleLogger.error(f"{Fore.RED}   [-] Error saving some results : {e}")
            if not args.nolog: f.write('{}]')
    consoleLogger.info(f"[+] Results written in : {args.outfile}")

    # Forward events
    if args.remote is not None and not args.stream: 
        consoleLogger.info(f"[+] Forwarding to : {args.remote}")
        forwarder.sendAll(fullResults)

    # Apply templates
    if readyForTemplating and fullResults != []:
        for template, templateOutput in zip(args.template, args.templateOutput):
            consoleLogger.info(f'[+] Applying template "{template[0]}", outputting to : {templateOutput[0]}')
            generateFromTemplate(template[0], templateOutput[0], fullResults)

    # Removing Working directory containing logs as json
    if not args.keeptmp:
        consoleLogger.info("[+] Cleaning")
        try:
            if not args.jsononly and not args.dbonly: shutil.rmtree(args.tmpdir)
        except OSError as e:
            consoleLogger.error(f"{Fore.RED}   [-] Error during cleanup {e}")

    dbConnection.close()
    consoleLogger.info(f"\nFinished in {int((time.time() - start_time))} seconds")
