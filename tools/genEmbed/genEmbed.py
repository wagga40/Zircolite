#!python3
# -*- coding: utf-8 -*-

from jinja2 import Template
from shutil import copyfile
import base64
from pathlib import Path
import zlib
import argparse
import os
import random
import string
from datetime import datetime
import sys

def quitOnError(message):
    print(message)
    sys.exit(1)

def checkIfExists(path, errorMessage):
    """ Test if path provided is a file """
    if not (Path(path).is_file()):
        quitOnError(errorMessage)

class zircoGen:

    def fileToB64String(self, file):
        fileData = open(file, "rb").read()
        encoded = base64.b64encode(zlib.compress(fileData)).decode("utf-8")
        return encoded

    def __init__(self, configFilePath, originalFilePath, evtxdumpPath, outputFilename, rulesDir, templatesDir, isEmbedded=True):
        
        self.filePath = originalFilePath
        self.embeddedMode = isEmbedded
        self.rules = rulesDir
        self.templates = templatesDir
        self.output = outputFilename

        # Filename of the evtx_dump that will be dropped during Zircolite execution
        self.evtxdumpPath = evtxdumpPath
        self.externalTool = f'./{"".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))}_{Path(self.evtxdumpPath).name}'

        # Templates related var
        self.templatesArgs = []
        self.templatesB64 = []
        self.templatesB64Fn = []

        # Rules related var
        self.rulesArgs = []
        self.rulesArgsB64 = []
        self.rulesIf = []
        self.rulesArgNameFiltered = []
        self.rulesCheck = ""

        # Config & Field mappings related var 
        self.configFileB64=self.fileToB64String(configFilePath)
        self.fieldMappingsLines = []
        self.fieldMappingsLines.append(f'self.fieldMappingsDict = json.loads(zlib.decompress(base64.b64decode(b\'{self.configFileB64}\')))')
        self.fieldMappingsLines.append(f'self.fieldExclusions = self.fieldMappingsDict["exclusions"]')
        self.fieldMappingsLines.append(f'self.fieldMappings = self.fieldMappingsDict["mappings"]')
        self.fieldMappingsLines.append(f'self.uselessValues = self.fieldMappingsDict["useless"]')

    def fileDirCheck(self, providedPath, fileExtension):
        fileList = None
        if Path(providedPath).is_dir():
            fileList = list(Path(providedPath).rglob(fileExtension))
        elif Path(providedPath).is_file():
            fileList = [Path(providedPath)]
        return fileList

    def genTemplatesCode(self):
        # Generate code for templating
        templatesB64FnLines = []

        templatesList = self.fileDirCheck(self.templates, "*.tmpl")
        if templatesList is None: return

        for template in templatesList:
            templateNameFiltered = ''.join(filter(str.isalpha, template.name.replace(".tmpl", "").lower()))
            self.templatesArgs.append(f'parser.add_argument("--{templateNameFiltered}", help="Use {templateNameFiltered} template", action="store_true")')
            templatesB64FnLines.append(f'if args.{templateNameFiltered}:')
            templatesB64FnLines.append(f'   randomName = "export-{templateNameFiltered}-" + "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(4)) + ".out"')
            templatesB64FnLines.append(f'   consoleLogger.info("[+] Applying template, output to :" + randomName)')
            templatesB64FnLines.append(f'   generateFromTemplate({templateNameFiltered}, randomName, zircoliteCore.fullResults)')
            self.templatesB64Fn.append(templatesB64FnLines)
            self.templatesB64.append(f'{templateNameFiltered} = zlib.decompress(base64.b64decode(b\'{self.fileToB64String(template)}\'))')
            templatesB64FnLines = []

    def genRulesCode(self):
        # Generate code for rules
        rulesArgNameFiltered = []

        rulesList = self.fileDirCheck(self.rules, "*.json")
        if rulesList is None: return

        for rule in rulesList:
            argNameFiltered = ''.join(filter(str.isalpha, rule.name.replace("rules_windows_", "").replace(".json", "").lower()))
            self.rulesArgs.append(f'parser.add_argument("--{argNameFiltered}", help="Use {argNameFiltered} ruleset", action="store_true")')
            self.rulesArgsB64.append(f'{argNameFiltered} = json.loads(zlib.decompress(base64.b64decode(b\'{self.fileToB64String(rule)}\')))')
            self.rulesIf.append(f'if args.{argNameFiltered}: ruleset = {argNameFiltered}')
            rulesArgNameFiltered.append(argNameFiltered)
        for ruleArgNameFiltered in rulesArgNameFiltered:
            self.rulesCheck += f'(not args.{ruleArgNameFiltered}) and '
        self.rulesCheck = f'if {self.rulesCheck[:-5]}: quitOnError(f"{{Fore.RED}}   [-] In embedded mode you must provide the \'--<ruleset>\' argument\")'

    def render(self):
        with open(self.filePath, 'r') as tmpl :
            jinjaTemplate = Template(tmpl.read())
        with open(self.output, 'w', encoding='utf-8') as tpl:
            tpl.write(jinjaTemplate.render(  
                                        embeddedMode=self.embeddedMode, 
                                        embeddedText=f'print("-= Embedded version - Generated on {datetime.now().strftime("%Y%m%dT%H:%M:%S")} =-")',
                                        evtxDumpCmdEmbed='self.evtxDumpCmd = self.getOSExternalToolsEmbed()',
                                        externalTool=self.externalTool,
                                        externalToolB64=self.fileToB64String(self.evtxdumpPath),
                                        removeTool=f'os.remove("{self.externalTool}")',
                                        configFileB64=self.configFileB64,
                                        templates=self.templatesArgs,
                                        templatesB64=self.templatesB64,
                                        templatesB64Fn=self.templatesB64Fn,
                                        templateOpenCode = 'template = Template(str(templateFile.decode("utf-8")))',
                                        rules=self.rulesArgs,
                                        rulesB64=self.rulesArgsB64,
                                        rulesIf=self.rulesIf,
                                        rulesCheck=self.rulesCheck,
                                        executeRuleSetFromVar='zircoliteCore.loadRulesetFromVar(ruleset=ruleset, ruleFilters=args.rulefilter)',
                                        fieldMappingsLines=self.fieldMappingsLines
                                    ))

    def run(self):
        self.genTemplatesCode()
        self.genRulesCode()
        self.render()

if __name__ == "__main__":
    print("-= Zircolite versions generator =-")

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", help="Mode to use for generation", choices=['embedded', 'standard'], default="embedded")
    parser.add_argument("-z", "--zircolite", help="Zircolite python file", type=str, required=True)
    parser.add_argument("-e", "--evtxdump", help="Evtx_dump directory, if not provided zircolite will be slower", type=str)
    parser.add_argument("-c", "--config", help="Config file path", type=str, required=True)
    parser.add_argument("-o", "--output", help="Generated python file name", type=str, default="generated.py")
    parser.add_argument("-r", "--rulesets", help="Rulesets to embed", type=str)
    parser.add_argument("-t", "--templates", help="Templates to embed")
    args = parser.parse_args()

    isEmbedded = False
    if args.mode == 'embedded':
        isEmbedded = True
        if args.rulesets is None:
            print("    [-] Error : no rulesets directory provided")

    print("    [+] Check prerequisites")
    checkIfExists(args.zircolite, "    [-] Error : Zircolite path check failed")
    checkIfExists(args.config, "    [-] Error : Config file path check failed")
    filename = f'tmp-{"".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))}.tmpl'
    copyfile(args.zircolite, filename)

    print(f"    [+] Cleaning source file : {filename}")
    # Read in the file
    with open(filename, 'r') as file :
        filedata = file.read()
    # Uncomment all Jinja markup
    filedata = filedata.replace("#{%", "{%").replace("#{{", "{{")
    # Write the file out again
    with open(filename, 'w') as file:
        file.write(filedata)
    
    print(f"    [+] Render file : {args.output}")
    # init Renderer
    zircoliteRenderer = zircoGen(args.config, filename, args.evtxdump, args.output, args.rulesets, args.templates, isEmbedded)
    # Render 
    zircoliteRenderer.run()

    os.remove(filename)
    