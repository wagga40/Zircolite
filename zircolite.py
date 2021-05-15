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
    hasRequests = True
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

# Trap signal for less ugly exit
def signal_handler(sig, frame):
    logging.info("[-] Execution interrupted !")
    sys.exit(0)

# SQlite related functions
def createConnection(db):
    """ create a database connection to a SQLite database """
    conn = None
    logging.debug(f"CONNECTING TO : {db}")
    try:
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row  # Allow to get a dict
    except Error as e:
        logging.error(f"{Fore.RED}   [-] {e}")
    return conn

def executeQuery(dbConnection, query):
    """ Perform a SQL Query with the provided connection """
    if dbConnection is not None:
        dbHandle = dbConnection.cursor()
        logging.debug(f"EXECUTING : {query}")
        try:
            dbHandle.execute(query)
            dbConnection.commit()
            return True
        except Error as e:
            logging.debug(f"   [-] {e}")
            return False
    else:
        logging.error(f"{Fore.RED}   [-] No connection to Db")
        return False

def executeSelectQuery(dbConnection, query):
    """ Perform a SQL Query with the provided connection """
    if dbConnection is not None:
        dbHandle = dbConnection.cursor()
        logging.debug(f"EXECUTING : {query}")
        try:
            data = dbHandle.execute(query)
            return data
        except Error as e:
            logging.debug(f"   [-] {e}")
            return {}
    else:
        logging.error(f"{Fore.RED}   [-] No connection to Db")
        return {}

# Zircolite core functions
def extractEvtx(file, tmpDir, evtx_dumpBinary):
    """
    Convert EVTX to JSON using evtx_dump : https://github.com/omerbenamram/evtx.
    Drop resulting JSON files in a tmp folder.
    @params:
        file            - Required  : EVTX file to convert
        tmpDir          - Required  : directory where the JSON files will be saved
        evtx_dumpBinary - Required  : evtx_dump binary location
    """

    logging.debug(f"EXTRACTING : {file}")
    try:
        filepath = Path(file)
        filename = filepath.name
        randString = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
        cmd = [evtx_dumpBinary, "--no-confirm-overwrite", "-o", "jsonl", str(file), "-f", tmpDir + "/" + str(filename) + randString + ".json"]
        subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        logging.error(f"{Fore.RED}   [-] {e}")

def flattenJSON(file):
    """
        Flatten json object with nested keys into a single level.
        Returns the flattened json object
        @params:
            file    - Required  : A JSON converted EVTX file
    """

    logging.debug(f"FLATTENING : {file}")
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
                    key = key.lower()
                    JSONLine[key] = value
                    if name[:-1] not in fullFieldNames:
                        fullFieldNames[name[:-1]] = key
                    # Creating the CREATE TABLE SQL statement
                    if key not in keyDict:
                        if type(value) is int:
                            keyDict[key] = ""
                            fieldStmt += "'" + key + "' INTEGER,\n"
                        else:
                            keyDict[key] = ""
                            fieldStmt += "'" + key + "' TEXT COLLATE NOCASE,\n"

    with open(str(file), 'r', encoding='utf-8') as JSONFile:
        for line in JSONFile:
            flatten(json.loads(line))
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

    insertStrmt = "INSERT INTO logs (" + columnsStr[:-1] + ") VALUES (" + valuesStr[:-2] + ");"
    return executeQuery(dbConnection, insertStrmt)

def executeRule(rule, forwardTo = None):
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
            logging.debug(f'DETECTED : {rule["title"]} - Matchs : {counter} events')
    else:
        logging.debug("RULE FORMAT ERROR : rule key Missing")
    if filteredRows == []:
        return {}
    # Forward results to HTTP server
    if forwardTo is not None:
        sendLogsHTTP(forwardTo, base64.b64encode(json.dumps({"host": socket.gethostname(), "title": rule["title"], "description": rule["description"], "sigma": rule["rule"], "rule_level": rule["level"], "tags": rule["tags"], "count": counter, "matches": filteredRows}).encode('utf-8')).decode('ascii'))
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
        logging.error(f"{Fore.RED}   [-] Template error, activate debug mode to check for errors")
        logging.debug(f"   [-] {e}")

def quitOnError(message):
    logging.error(message)
    sys.exit(1)

def checkIfExists(path, errorMessage):
    """ Test if path provided is a file """
    if not (Path(path).is_file()):
        quitOnError(errorMessage)

def initLogger(debugMode, logFile):
    logLevel = logging.INFO
    logFormat = "%(asctime)s %(levelname)-8s %(message)s"
    if debugMode:
        logLevel = logging.DEBUG
        logFormat = "%(asctime)s %(levelname)-8s %(module)s:%(lineno)s %(funcName)s %(message)s"

    logging.basicConfig(format=logFormat, filename=logFile, level=logLevel, datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.StreamHandler()
    logger.setLevel(logging.INFO)
    logging.getLogger().addHandler(logger)
    return logger

def sendLogsHTTP(host, payload = ""):
    """ Just send provided payload to provided web server. Not very clean. Non-async code for now """
    try:
        r = requests.post(host, headers={'user-agent': 'zircolite/1.2.x'}, data={"data": payload})
        logging.debug(f"{Fore.RED}   [-] {r}")
        return True
    except Exception as e:
        logging.debug(f"{Fore.RED}   [-] {e}")
        return False

################################################################
# MAIN()
################################################################
if __name__ == '__main__':
    print("""
    ███████╗██╗██████╗  ██████╗ ██████╗ ██╗     ██╗████████╗███████╗
    ╚══███╔╝██║██╔══██╗██╔════╝██╔═══██╗██║     ██║╚══██╔══╝██╔════╝
      ███╔╝ ██║██████╔╝██║     ██║   ██║██║     ██║   ██║   █████╗
     ███╔╝  ██║██╔══██╗██║     ██║   ██║██║     ██║   ██║   ██╔══╝
    ███████╗██║██║  ██║╚██████╗╚██████╔╝███████╗██║   ██║   ███████╗
    ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚══════╝
    """)

    # Init Args handling
    tmpDir = "tmp-" + ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--evtx", help="EVTX log file or directory where EVTX log files are stored in JSON or EVTX format", type=str, required=True)
    parser.add_argument("-r", "--ruleset", help="JSON File containing SIGMA rules", type=str, required=True)
    parser.add_argument("-c", "--config", help="JSON File containing field mappings and exclusions", type=str, default="config/fieldMappings.json")
    parser.add_argument("-o", "--outfile", help="JSON file that will contains all detected events", type=str, default="detected_events.json")
    parser.add_argument("-f", "--fileext", help="EVTX file extension", type=str, default="evtx")
    parser.add_argument("-t", "--tmpdir", help="Temp directory that will contains EVTX converted as JSON", type=str, default=tmpDir)
    parser.add_argument("-k", "--keeptmp", help="Do not remove the Temp directory", action='store_true')
    parser.add_argument("-d", "--dbfile", help="Save data as a SQLite Db to the specified file on disk", type=str)
    parser.add_argument("-l", "--logfile", help="Log file name", default="zircolite.log", type=str)
    parser.add_argument("-j", "--jsononly", help="If logs files are already in JSON lines format ('jsonl' in evtx_dump) ", action='store_true')
    parser.add_argument("--remote", help="Forward results to a HTTP server, arg must be the full address e.g http://address:port/uri", type=str)
    parser.add_argument("--template", help="If a Jinja2 template is specified it will be used to generated output", type=str, action='append', nargs='+')
    parser.add_argument("--templateOutput", help="If a Jinja2 template is specified it will be used to generate a crafted output", type=str, action='append', nargs='+')
    parser.add_argument("--fields", help="Show all fields in full format", action='store_true')
    parser.add_argument("--debug", help="Activate debug logging", action='store_true')
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    # Init logging
    consoleLogger = initLogger(args.debug, args.logfile)

    logging.info("[+] Checking prerequisites")
    # Init network
    if (args.remote is not None):
        if hasRequests:
            if not sendLogsHTTP(args.remote):
                quitOnError(f"{Fore.RED}   [-] Remote host cannot be reached : {args.remote}")
        else:
            quitOnError(f"{Fore.RED}   [-] Requests lib missing, you cannot use '--remote'")
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

    # Initialize all configuration dict
    fieldExclusions = {}  # Will contain fields to discard
    fieldMappings = {}  # Will contain fields to rename during flattening
    uselessValues = {}  # Will contain values to discard during flattening

    checkIfExists(args.config, f"{Fore.RED}   [-] Cannot find mapping file")
    with open(args.config, 'r') as fieldMappingsFile:
        fieldMappingsDict = json.load(fieldMappingsFile)
        fieldExclusions = fieldMappingsDict["exclusions"]
        fieldMappings = fieldMappingsDict["mappings"]
        uselessValues = fieldMappingsDict["useless"]

    # Skipping extracting if jsononly parameter is set
    if not args.jsononly:
        logging.info(f"[+] Extracting EVTX Using '{args.tmpdir}' directory ")
        EVTXPath = Path(args.evtx)
        if EVTXPath.is_dir():
            # EVTX recursive search in given directory with given file extension
            EVTXList = list(EVTXPath.rglob(f"*.{args.fileext}"))
        elif EVTXPath.is_file():
            EVTXList = [EVTXPath]
        else:
            quitOnError(f"{Fore.RED}   [-] Unable to extract EVTX from submitted path")
        if len(EVTXList) > 0:
            for evtx in tqdm(EVTXList, colour="yellow"):
                extractEvtx(evtx, args.tmpdir, evtx_dumpBinary)
            # Set the path for the next step
            EVTXJSONList = list(Path(args.tmpdir).rglob("*.json"))
        else:
            quitOnError(f"{Fore.RED}   [-] No EVTX files found. Please verify the directory or the extension with '--fileext'")
    else:
        EVTXJSONList = list(Path(args.evtx).rglob("*.json"))

    logging.info("[+] Processing EVTX")

    fieldStmt = ""
    valuesStmt = []
    fullFieldNames = {}
    results = {}
    keyDict = {}

    if EVTXJSONList == []:
        quitOnError(f"{Fore.RED}   [-] No JSON files found.")
    for evtxJSON in tqdm(EVTXJSONList, colour="yellow"):
        if os.stat(evtxJSON).st_size != 0:
            results = flattenJSON(evtxJSON)
            fieldStmt += results["dbFields"]
            valuesStmt += results["dbValues"]

    if args.fields:
        logging.info("[+] Saving fields to fields.json")
        with open("fields.json", 'w', encoding='utf-8') as f:
            json.dump(fullFieldNames, f, indent=4)
        sys.exit(0)

    logging.info("[+] Creating model")
    dbConnection = createConnection(":memory:")
    createTableStmt = "CREATE TABLE logs ( row_id INTEGER, " + fieldStmt + " PRIMARY KEY(row_id AUTOINCREMENT) );"
    logging.debug(" CREATE : " + createTableStmt.replace('\n', ' ').replace('\r', ''))
    if not executeQuery(dbConnection, createTableStmt):
        quitOnError(f"{Fore.RED}   [-] Unable to create table")
    del createTableStmt

    logging.info("[+] Inserting data")
    for JSONLine in tqdm(valuesStmt, colour="yellow"):
        insertData2Db(JSONLine)
    # Creating index to speed up queries
    executeQuery(dbConnection, 'CREATE INDEX "idx_eventid" ON "logs" ("eventid");')

    logging.info("[+] Cleaning unused objects")
    del valuesStmt

    # Unload In memory DB to disk. Done here to permit debug in case of ruleset execution error
    if args.dbfile is not None:
        logging.info("[+] Saving working data to disk as a SQLite DB")
        onDiskDb = sqlite3.connect(args.dbfile)
        dbConnection.backup(onDiskDb)
        onDiskDb.close()

    logging.info(f"[+] Loading ruleset from : {args.ruleset}")
    with open(args.ruleset) as f:
        ruleset = json.load(f)
    rulesetSize = len(ruleset)
    logging.info(f"[+] Executing ruleset - {str(rulesetSize)} rules")
    # Results are writen upon detection to allow analysis during execution and to avoid loosing results in case of error.
    fullResults = []
    with open(args.outfile, 'w', encoding='utf-8') as f:
        if hasTqdm:  # If tqdm is installed
            with tqdm(ruleset, colour="yellow") as ruleBar:
                f.write('[')
                for rule in ruleBar:  # for each rule in ruleset
                    ruleResults = executeRule(rule, args.remote)
                    if ruleResults != {}:
                        ruleBar.write(f'{Fore.CYAN}    - {ruleResults["title"]} - Matchs : {ruleResults["count"]} events')
                        # To avoid printing this one on stdout but in the logs...
                        consoleLogger.setLevel(logging.ERROR)
                        logging.info(f'{Fore.CYAN}    - {ruleResults["title"]} - Matchs : {ruleResults["count"]} events')
                        consoleLogger.setLevel(logging.INFO)
                        # Store results for templating
                        if readyForTemplating:
                            fullResults.append(ruleResults)
                        # Output to default json file
                        try:
                            json.dump(ruleResults, f, indent=4, ensure_ascii=False)
                            f.write(',\n')
                        except Exception as e:
                            logging.error(f"{Fore.RED}   [-] Error saving some results : {e}")
                            logging.debug(f"   [-] {e}")
                f.write('{}]')
        else:
            f.write('[')
            for rule in ruleset:
                ruleResults = executeRule(rule)
                if ruleResults != {}:
                    logging.info(f'{Fore.CYAN}    - {ruleResults["title"]} - Matchs : {ruleResults["count"]} events')
                    # Store results for templating
                    if readyForTemplating:
                        fullResults.append(ruleResults)
                    # Output to default json file
                    try:
                        json.dump(ruleResults, f, indent=4, ensure_ascii=False)
                        f.write(',\n')
                    except Exception as e:
                        logging.error(f"{Fore.RED}   [-] Error saving some results : {e}")
                        logging.debug(f"   [-] {e}")
            f.write('{}]')
    logging.info(f"[+] Results written in : {args.outfile}")

    # Templating
    if readyForTemplating and fullResults != []:
        for template, templateOutput in zip(args.template, args.templateOutput):
            logging.info(f'[+] Applying template "{template[0]}", outputting to : {templateOutput[0]}')
            generateFromTemplate(template[0], templateOutput[0], fullResults)

    # Removing Working directory containing logs as json
    if not args.keeptmp:
        logging.info("[+] Cleaning")
        try:
            shutil.rmtree(args.tmpdir)
        except OSError as e:
            logging.error(f"{Fore.RED}   [-] Error during cleanup {e}")

    dbConnection.close()
    logging.info(f"\nFinished in {int((time.time() - start_time))} seconds")
