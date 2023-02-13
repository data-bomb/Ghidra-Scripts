#Immediately generates a SourceMod-ready signature with the same masking as the IDA makesig.
#@author nosoop, databomb
#@category _NEW_
#@keybinding
#@menupath
#@toolbar

from __future__ import print_function

import collections
import ghidra.program.model.lang.OperandType as OperandType
import ghidra.program.model.lang.Register as Register
import ghidra.program.model.address.AddressSet as AddressSet

MINIMUM_SIGNATURE_LENGTH = 11
HIGH_MATCH_THRESHOLD = 5

BytePattern = collections.namedtuple('BytePattern', ['is_wildcard', 'byte'])

def __bytepattern_ida_str(self):
	# return an IDA-style binary search string
	return '{:02X}'.format(self.byte) if not self.is_wildcard else '?'

def __bytepattern_sig_str(self):
	# return a SourceMod-style byte signature
	return r'\x{:02X}'.format(self.byte) if not self.is_wildcard else r'\x2A'

BytePattern.ida_str = __bytepattern_ida_str
BytePattern.sig_str = __bytepattern_sig_str

def dumpOperandInfo(ins, op):
	t = hex(ins.getOperandType(op))
	print('  ' + str(ins.getPrototype().getOperandValueMask(op)) + ' ' + str(t))

	# TODO if register
	for opobj in ins.getOpObjects(op):
		print('  - ' + str(opobj))

def shouldMaskOperand(ins, opIndex):
	"""
	Returns True if the given instruction operand mask should be masked in the signature.
	"""
	optype = ins.getOperandType(opIndex)
	return optype & (OperandType.ADDRESS or OperandType.DATA) or optype & (OperandType.ADDRESS or OperandType.SCALAR)

def getMaskedInstruction(ins):
	"""
	Returns a generator that outputs either a byte to match or None if the byte should be masked.
	"""

	# resulting mask should match the instruction length
	mask = [0] * ins.length

	proto = ins.getPrototype()
	# iterate over operands and mask bytes
	for op in range(proto.getNumOperands()):
		# dumpOperandInfo(ins, op)

		# TODO deal with partial byte masks
		if shouldMaskOperand(ins, op):
			mask = [ m | v & 0xFF for m, v in zip(mask, proto.getOperandValueMask(op).getBytes()) ]

	for m, b in zip(mask, ins.getBytes()):
		if m == 0xFF:
			# we only check for fully masked bytes at the moment
			yield BytePattern(is_wildcard = True, byte = None)
		else:
			yield BytePattern(byte = b & 0xFF, is_wildcard = False)

def cleanupWilds(byte_pattern):
	"""
	Removes any trailing wildcards leftover from the last instruction.
	"""
	for byte in reversed(byte_pattern):
		if byte.is_wildcard is False:
			break
		del byte_pattern[-1]

def gensig():
	extended_sig = False
	extended_highmatch = False
	fm = currentProgram.getFunctionManager()
	fn = fm.getFunctionContaining(currentAddress)
	cm = currentProgram.getCodeManager()

	ins = cm.getInstructionAt(fn.getEntryPoint())

	if not ins:
		raise Exception("Could not find entry point to function")

	pattern = "" # contains pattern string (supports regular expressions)
	byte_pattern = [] # contains BytePattern instances

	# keep track of our matches
	matches = []
	match_limit = 128

	while fm.getFunctionContaining(ins.getAddress()) == fn:
		for entry in getMaskedInstruction(ins):
			byte_pattern.append(entry)
			if entry.is_wildcard:
				pattern += '.'
			else:
				pattern += r'\x{:02x}'.format(entry.byte)

		expected_next = ins.getAddress().add(ins.length)
		ins = ins.getNext()

		if ins.getAddress() != expected_next:
			break

		if 0 < len(matches) < match_limit:
			# we have all the remaining matches, start only searching those addresses
			match_set = AddressSet()
			for addr in matches:
				match_set.add(addr, addr.add(len(byte_pattern)))
			matches = findBytes(match_set, pattern, match_limit, 1)
		else:
			# the matches are sorted in ascending order, so the first match will be the start
			matches = findBytes(matches[0] if len(matches) else None, pattern, match_limit)

		if len(matches) < 2:
			# add instructions if the sig isn't long enough
			if len(byte_pattern) > MINIMUM_SIGNATURE_LENGTH and extended_sig:
				if prev_matches < HIGH_MATCH_THRESHOLD or extended_highmatch:
					break
				extended_highmatch = True
			# grab one additional instruction even if we are already at the min sig length
			extended_sig = True

		# store how much overlap there was before we reached a unique sig
		if len(matches) > 1:
			prev_matches = len(matches)

	if not len(matches) == 1:
		print(*(b.ida_str() for b in byte_pattern))
		print('Signature matched', len(matches), 'locations:', *(matches))
		printerr("Could not find unique signature")
	else:
		cleanupWilds(byte_pattern)
		print("Signature for", fn.getName())
		print(*(b.ida_str() for b in byte_pattern))
		print("".join(b.sig_str() for b in byte_pattern))

if __name__ == "__main__":
	fm = currentProgram.getFunctionManager()
	fn = fm.getFunctionContaining(currentAddress)
	if not fn:
		printerr("Not in a function")
	else:
		gensig()
