#Use a binary with symbols to export info; use info to restore function names in binaries without symbols.
#@author databomb
#@category _NEW_
#@keybinding 
#@menupath
#@toolbar

import json
from collections import defaultdict

from ghidra.program.model.symbol.SourceType import USER_DEFINED
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtils
from ghidra.program.database.function import FunctionManagerDB

OPTION_EXPORT = "Export"
OPTION_IMPORT = "Import"

def renameFromImportData(importProgramData):
	dCurrentProgram = defaultdict(list)
	print("Generating list of strings inside functions...")

	# build a list of strings in each function's starting address
	for string in DefinedDataIterator.definedStrings(currentProgram):
		for ref in XReferenceUtils.getXReferences(string, -1):
			fm = currentProgram.getFunctionManager()
			fn = fm.getFunctionContaining(ref.getFromAddress())
			if fn and not fn.getName().startswith('png_'):
				refString = string.toString()
				# are we even a string?
				if not refString.startswith('ds '):
					continue
				# format to isolate content from [ds "<content>"]
				refString = refString[4:-1]

				if refString not in dCurrentProgram[fn.getEntryPoint()]:
					dCurrentProgram[fn.getEntryPoint()].append(refString)

	# cross-check to see if each matching string is in the same function on the imported data
	renameCount = 0
	for func in dCurrentProgram:
		canidateFunction = 0
		for string in dCurrentProgram[func]:
			if string in importProgramData:
				if canidateFunction == 0:
					canidateFunction = importProgramData[string]
				else:
					if canidateFunction != importProgramData[string]:
						canidateFunction = -1
						continue
			# check for last one
			if string == dCurrentProgram[func][-1]:
				if canidateFunction > 0:
					# we're reasonably certain that we want to rename the function now
					theFunction = fm.getFunctionContaining(func)
					# did we already rename it?
					if theFunction.getName() != canidateFunction:
						print("Renaming " + theFunction.getName() + " to " + canidateFunction + "...")
						theFunction.setName(canidateFunction, USER_DEFINED)
						renameCount = renameCount + 1

	print("Renamed a total of " + str(renameCount) + " functions.")

def generateStringDictionary(strings):
	Dict = {}
	print("Generating list of string to function cross-references...")

	# find string-function pairings where the string uniquely matches to the function
	for string in strings:
		for ref in XReferenceUtils.getXReferences(string, -1):
			fm = currentProgram.getFunctionManager()
			fn = fm.getFunctionContaining(ref.getFromAddress())
			if fn and not fn.getName().startswith('png_'):
				key = string.toString()
				# are we a string?
				if not key.startswith('ds '):
					continue
				# format to isolate content from [ds "<content>"]
				key = key[4:-1]

				if key in Dict:
					# check for lack of uniqueness with the pairing
					if Dict[key] != fn.getName(True):
						Dict[key] = 'invalid'
				else:
					# add to dictionary
					Dict[key] = fn.getName(True)

	# remove the non-unique strings
	for key in Dict.keys():
		if Dict[key] == 'invalid':
			del Dict[key]

	print("Found " + str(len(Dict.keys())) + " string-function pairings.")
	return Dict

def handleChoice(choice):
	if choice == OPTION_EXPORT:
		Dictionary = generateStringDictionary(DefinedDataIterator.definedStrings(currentProgram))
		jsonObject = json.dumps(Dictionary)

		# save to file
		fileNameExport = askFile("Choose file to save data to", "Save")
		fileExport = open(str(fileNameExport), 'w')
		fileExport.write(str(jsonObject))
		fileExport.close()
		print("Saved information to file: " + str(fileNameExport))

	elif choice == OPTION_IMPORT:
		# grab dictionary from file
		fileNameImport = askFile("Choose file to import from", "Open")
		print("Importing data from file (" + str(fileNameImport) + ")...")
		fileImport = open(str(fileNameImport), 'r')
		data = fileImport.read()
		jsonObject = json.loads(data)

		# rename functions
		renameFromImportData(jsonObject)

if __name__ == "__main__":
	choice = askChoice("Select one", "Export names from this program or import existing names to this program?", [OPTION_IMPORT, OPTION_EXPORT], OPTION_EXPORT)
	handleChoice(choice)
