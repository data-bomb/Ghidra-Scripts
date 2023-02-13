# Ghidra-Scripts
A few random Ghidra scripts that may be useful

### symbolsmasher.py

Export function names from a binary with symbols and use the data to restore the function names in a similar binary without symbols. The technique is currently based on unique string cross-references, but it may be possible to play a game of Ghidra-soduku building off the information here. The name for the script is credited to Scags who made an IDA script for the same purpose (https://github.com/Scags/IDA-Scripts).

### makesigi.py

Immediately generate a SourceMod-ready signature at the start of the current function. The goal for this script is to have the same masking strategy as the original IDA makesig.idc. It's based on the converted Ghidra script by nosoop (https://github.com/nosoop/ghidra_scripts).
