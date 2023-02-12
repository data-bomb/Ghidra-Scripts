# Ghidra-Scripts
A few random Ghidra scripts that may be useful

### symbolsmasher.py

Export function names from a binary with symbols and use the data to restore the function names in a similar binary without symbols. The technique is currently based on unique string cross-references, but it may be possible to play a game of Ghidra-soduku building off the information here. The name for the script is credited to Scags who made an IDA script for the same purpose (https://github.com/Scags/IDA-Scripts).
