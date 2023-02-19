#Generates string signatures for named functions in a binary with symbols to export info; use info to restore function names in binaries without symbols.
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
import hashlib

OPTION_EXPORT = "Export"
OPTION_IMPORT = "Import"

# build a list of string signatures for each function
def buildStringSigsInFuncs(Dict):
	print("Generating list of string signatures for each function...")
	# generate a list of each string in the function
	dProgram = defaultdict(list)
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

				# we need to pay attention to the ordering of the strings in the func to get more unique string signatures
				dProgram[fn.getName(True)].append([refString, ref.getFromAddress()])

	# remove functions with only one string
	delete_list = [key for key,val in dProgram.iteritems() if len(val) < 2]
	for key in delete_list:
		del dProgram[key]

	# sort the strings by where they appear in the function
	for name in dProgram:
		dProgram[name].sort(key = lambda x: x[1])

	# take a hash of the concatenated strings to gen a sig for each function
	for name in dProgram:
		h = hashlib.new('sha256')
		strings = ''
		for entry in dProgram[name]:
			string = entry[0]
			h.update(string.encode('utf-8'))
		# check for lack of uniqueness with the pairing
		key = h.hexdigest()
		if key in Dict:
			# check for lack of uniqueness with the pairing
			if Dict[key] != name:
				Dict[key] = 'invalid'
		else:
			# add to dictionary
			Dict[key] = name
            
	# remove the non-unique strings
	for key in Dict.keys():
		if Dict[key] == 'invalid':
			del Dict[key]

	print("Found " + str(len(Dict)) + " unique string signatures.")

	return Dict

def renameFromImportData(importProgramData):
	dCurrentProgram = generateStringDictionary()

	# cross-check to find any matching string signatures
	renameCount = 0
	fm = currentProgram.getFunctionManager()
	for stringsig in dCurrentProgram:
		# only check functions that haven't been renamed yet
		if stringsig in importProgramData and dCurrentProgram[stringsig].startswith('FUN_'):
			print("Renaming " + dCurrentProgram[stringsig] + " to " + importProgramData[stringsig] + "...")
			# drop FUN_ and goto address
			theAddress = currentProgram.getAddressFactory().getAddress(dCurrentProgram[stringsig][4:])
			theFunction = fm.getFunctionContaining(theAddress)
			theFunction.setName(importProgramData[stringsig], USER_DEFINED)
			renameCount = renameCount + 1

	print("Renamed a total of " + str(renameCount) + " functions.")

def generateStringDictionary():
	Dict = {}
	buildStringSigsInFuncs(Dict)
	#print(Dict)
	
	return Dict

def handleChoice(choice):
	if choice == OPTION_EXPORT:
		Dictionary = generateStringDictionary()
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
