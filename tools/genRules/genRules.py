#!python3
# -*- coding: utf-8 -*-

import subprocess
import argparse
import yaml
import json
import binascii
import sys
from tqdm.contrib.concurrent import process_map
from pathlib import Path

class rulesetGenerator:
    def __init__(self, sigmac, config, table, rulesToConvert, fileext="yml"):
        self.table = table
        self.config = config
        self.sigmac = sigmac
        self.rules = rulesToConvert
        self.fileext = fileext

    def CRC32_from_string(self, string):
        buf = (binascii.crc32(string.encode('utf8')) & 0xFFFFFFFF)
        return "%08X" % buf   

    def retrieveRule(self, ruleFile):
        d={}
        cmd = [self.sigmac, "-d", "--target", "sqlite", "-c", self.config, ruleFile, "--backend-option", f'table={self.table}']
        outputRaw = subprocess.run(args=cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
        output = [rule for rule in outputRaw.stdout.split("\n") if not "Feel free" in rule]
        if "unsupported" in str(output):
            return {"rule": "", "file": ruleFile, "notsupported": True}
        else:
            with open(ruleFile, 'r') as stream:
                docs = yaml.load_all(stream, Loader=yaml.FullLoader)
                for doc in docs:
                    for k,v in doc.items():
                        if k == 'title':
                            title = v
                        if k == 'id':
                            d['title'] = title + " - " + self.CRC32_from_string(v)
                        if k in ['description','tags','level','author']:
                            d[k] = v
            d['rule']=output[:-1]
            return {"rule": d.copy(), "file": ruleFile, "notsupported": False}
    
    def run(self):
        if Path(self.rules).is_file():
            outputList = [self.retrieveRule(self.rules)] # OutputList is an array
        elif Path(self.rules).is_dir():
            files = list(Path(self.rules).rglob(f'*.{self.fileext}'))
            outputList = process_map(self.retrieveRule, files, chunksize = 1)
        return outputList

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rulesdirectory", help="A directory of Sigma rules or a Sigma rule file", type=str)
    parser.add_argument("-s", "--sigmac", help="Sigmac location", type=str, required=True)
    parser.add_argument("-o", "--output", help="Converted rules output filename", default="rules.json", type=str)
    parser.add_argument("-c", "--config", help="Sigmac config location", type=str, required=True)
    parser.add_argument("-R", "--rule", help="Sigma rule file", type=str)
    parser.add_argument("-t", "--table", help="Table name", default="logs", type=str)
    parser.add_argument("-f", "--fileext", help="Rule file extension", default="yml", type=str)
    args = parser.parse_args()

    print("\n-= genRules - Sigma ruleset generator for Zircolite =-\nThis tool will be progressively deprecated since Sigmac v0.20 is now able output the right rule format\n")
    if not Path(args.sigmac).is_file() or not Path(args.config).is_file():
        print("Cannot find Sigmac or Config file please set a correct location with '--sigmac'/'--config'")
        sys.exit(1)
    print(" [+] Generating ruleset")
    if args.rule: args.rulesdirectory = args.rule # Existence of both args is kept for backward compatibility

    rulesGeneratorInstance = rulesetGenerator(args.sigmac, args.config, args.table, args.rulesdirectory)
    generatedRules = rulesGeneratorInstance.run()

    # If provided rules are not supported
    if len([rule["rule"] for rule in generatedRules if rule["notsupported"]]) > 0:
        print(" [+] Rules not supported by Sigmac SQLite backend : ")
        for rule in generatedRules:
            if rule["notsupported"]: print(f'      [-] "{rule["file"]}"')

    print(f' [+] Exporting to : {args.output}')
    exportList = [rule["rule"] for rule in generatedRules if not rule["notsupported"]]
    if exportList != []:
        with open(args.output, 'w') as f:
            json.dump(exportList, f, indent=4)
    else: print(f'      [-] No rule to export')
