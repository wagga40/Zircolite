#!/usr/bin/python3
# -*- coding: utf-8 -*-

import subprocess
import argparse
import sys
import time
from pathlib import Path
from multiprocessing import Pool
from functools import partial

# I love my colors...
class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKCYAN = '\033[96m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

def executeZircolite(directory, ruleset):
	if directory.is_dir():
		print(bcolors.OKBLUE + "    [+] Executing Zircolite on : " + str(directory) + "                   ")
		name = str(directory).split("/")[-1]
		cmd = ["python3", "zircolite.py", "-e", str(directory), "-r", ruleset, "-o", "detected_events_" + name + ".json", "-l", "zircolite_" + name + ".log"]
		subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read()

################################################################
# MAIN()
################################################################
if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument("-e", "--evtx", help="Directory with subdirectories containing EVTX", type=str, required = True)
	parser.add_argument("-r", "--ruleset", help="JSON File containing SIGMA rules", type=str, required = True)
	parser.add_argument("--core", help="Number of core", type=str, default = "all")
	parser.add_argument("--monocore", help="Number of core", action='store_true')
	args = parser.parse_args()

	print(bcolors.OKGREEN + "[+] Checking prerequisites")

	# Checking ruleset
	if not (Path(args.ruleset).is_file()):
		print (bcolors.FAIL + "   [-] Cannot find ruleset : " + args.ruleset)
		sys.exit(1)

	# Start time counting
	start_time = time.time()

	# Skipping extracting if jsononly parameter is set
	EVTXDir = Path(args.evtx)
	if EVTXDir.is_dir():
		# Directory recursive search in given directory 
		EVTXDirList = list(EVTXDir.glob("*"))
	else:
		print (bcolors.FAIL + "   [-] No directory found in submitted path")
		sys.exit(1)

	if len(EVTXDirList) > 0:
		# As for now, evtx_dump will always use all available cores !
		# If "monocore" argument was specified or if the "core" argument is equal to 1
		if args.monocore or (args.core == 1):
			for directory in EVTXDirList:
				if directory.is_dir():
					executeZircolite(directory, args.ruleset)
		else:
			# Checking core argument beforce executing with the provided core count
			if args.core == "all":
				pool = Pool()
			elif args.core.isdigit():
				pool = Pool(processes = int(args.core))
			else:
				print (bcolors.FAIL + "   [-] No directory found from submitted path")
				sys.exit(1)
			pool.map(partial(executeZircolite, ruleset = args.ruleset), EVTXDirList)
			pool.close() 
			pool.join()
	else:
		print(bcolors.FAIL + "   [-] No directory found within provided directory")
		sys.exit(1)


	print(bcolors.OKGREEN + "\nFinished in  %s seconds" % int((time.time() - start_time)))
