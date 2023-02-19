# Ghidra-Scripts
A few random Ghidra scripts that may be useful

### makesigi.py

Immediately generate a SourceMod-ready signature at the start of the current function. The goal for this script is to have the same masking strategy as the original IDA makesig.idc. It's based on the converted Ghidra script by nosoop (https://github.com/nosoop/ghidra_scripts).

### stringsigs.py

Export function names and string signatures from a binary with symbols and use the data to restore the function names in a similiar binary without symbols. String signatures are generated for each function that has more than one string entry. Each string signature consists of a SHA256(string1 || string2 || string3 || ...). The order of the strings used to generate the hash is the same order the strings appear in the function.

### symbolsmasher.py

Export function names from a binary with symbols and use the data to restore the function names in a similar binary without symbols. The technique is currently based on unique string cross-references, but it may be possible to play a game of Ghidra-soduku building off the information here. The name for the script is credited to Scags who made an IDA script for the same purpose (https://github.com/Scags/IDA-Scripts).

  
  

| Script  | Number of Functions Matched (CS:GO server binary 15 Feb. 2023)|
| ------------- | ------------- |
| symbolsmasher.py  | ~3450  |
| stringsigs.py  | ~1600 individually or ~+250 after running symbolsmasher.py  |

Total FUN_ in the binary: ~60,000
