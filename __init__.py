from binaryninja import *

import struct

def parseSections(offsets, addresses, sizes):
	sections = []
	for i in range(len(offsets)):
		if offsets[i] == 0:
			break
		sections.append({
			"offset": offsets[i],
			"address": addresses[i],
			"size": sizes[i],
		})
	return sections


def parseHeader(data):
	textOffsets = struct.unpack(">7L", data[0x00:0x1c])
	dataOffsets = struct.unpack(">11L", data[0x1c:0x48])
	textAddresses = struct.unpack(">7L", data[0x48:0x64])
	dataAddresses = struct.unpack(">11L", data[0x64:0x90])
	textSizes = struct.unpack(">7L", data[0x90:0xac])
	dataSizes = struct.unpack(">11L", data[0xac:0xd8])
	bssAddress = struct.unpack(">L", data[0xd8:0xdc])[0]
	bssSize = struct.unpack(">L", data[0xdc:0xe0])[0]
	entrypoint = struct.unpack(">L", data[0xe0:0xe4])[0]
	textSections = parseSections(textOffsets, textAddresses, textSizes)
	dataSections = parseSections(dataOffsets, dataAddresses, dataSizes)
	if bssAddress != 0:
		# The BSS section may overlap data sections, creating multiple separate BSS sections where the data sections aren't.
		sorted_carving_sections = textSections + dataSections
		sorted_carving_sections.sort(key = lambda x: x["address"])

		bssSections = []
		current_start = bssAddress
		current_end = bssAddress + bssSize
		for carving_section in sorted_carving_sections:
			carving_start = carving_section["address"]
			carving_end = carving_start + carving_section["size"]

			# Overlap
			if carving_start <= current_start and carving_end >= current_end: # Carving contains all of carved
				#print("DOL: Annihilated")
				current_start = current_end # Done with no leftover
				break
			elif carving_start <= current_start and carving_end > current_start and carving_end < current_end: # Overlapping from the left
				#print("DOL: Overlap left {}".format(carving_end - current_start))
				current_start = carving_end
			elif carving_start > current_start: # Overlapping from the right or contained
				#print("DOL: Overlap right or contain")
				bssSections.append({
					"address": current_start,
					"size": carving_start - current_start
				})
				current_start = min(carving_end, current_end)

			# Early-out
			if current_start >= current_end:
				break

		# Flush out last section
		if current_start < current_end:
			bssSections.append({
				"address": current_start,
				"size": current_end - current_start
			})
		#print("DOL: BSS sections: {}".format(bssSections))
	else:
		bssSections = []

	return {
		"textSections": textSections,
		"dataSections": dataSections,
		"bssSections": bssSections,
		"entrypoint": entrypoint
	}

def validateHeader(header, filesize):
	textSections = header["textSections"]
	dataSections = header["dataSections"]
	bssSections = header["bssSections"]
	entrypoint = header["entrypoint"]

	# Validate individual sections
	initializedSections = textSections + dataSections
	allSections = initializedSections + bssSections

	# There must be at least one text section
	if len(textSections) < 1:
		return False

	# Check that all initialized sections are inside the file
	for section in initializedSections:
		if section["offset"] + section["size"] > filesize:
			return False

	# Check that all sections are loaded into valid memory
	for section in allSections:
		if not 0x80000000 <= section["address"] < 0x81800000:
			return False
		if not 0x80000000 <= section["address"] + section["size"] <= 0x81800000:
			return False

	# Section offset overlap check
	sectionsByOffset = initializedSections.copy()
	sectionsByOffset.sort(key = lambda x: x["offset"])
	for i in range(len(sectionsByOffset) - 1):
		firstSection = sectionsByOffset[i]
		secondSection = sectionsByOffset[i + 1]
		if firstSection["offset"] + firstSection["size"] > secondSection["offset"]:
			return False

	# Section address overlap check
	sectionsByAddress = allSections.copy()
	sectionsByAddress.sort(key = lambda x: x["address"])
	for i in range(len(sectionsByAddress) - 1):
		firstSection = sectionsByAddress[i]
		secondSection = sectionsByAddress[i + 1]
		if firstSection["address"] + firstSection["size"] > secondSection["address"]:
			#print("DOL: {} overlaps {}".format(firstSection, secondSection))
			return False

	# Entrypoint must be in text section
	entrypointValid = False
	for section in textSections:
		if section["address"] <= entrypoint < section["address"] + section["size"]:
			entrypointValid = True
			break
	if not entrypointValid:
		return False

	return True

class DOLView(BinaryView):
	name = "DOL"
	long_name = "Nintendo DOL"

	def __init__(self, parent):
		BinaryView.__init__(self, file_metadata = parent.file, parent_view = parent)
		self.raw = parent

	@classmethod
	def is_valid_for_data(self, data):
		# Must have enough data for the header
		header_data = data.read(0, 0xe4)
		if len(header_data) < 0xe4:
			return False

		header = parseHeader(header_data)
		return validateHeader(header, len(data))

	def init(self):
		self.arch = Architecture["ppc"]
		self.platform = Architecture["ppc"].standalone_platform
		header = parseHeader(self.raw.read(0, 0xe4))
		self.textSections = header["textSections"]
		self.dataSections = header["dataSections"]
		self.bssSections = header["bssSections"]
		self.entrypoint = header["entrypoint"]

		for sectionIndex in range(len(self.textSections)):
			section = self.textSections[sectionIndex]
			self.add_auto_segment(
				section["address"],
				section["size"],
				section["offset"],
				section["size"],
				SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
			)
			self.add_auto_section(
				".text{}".format(sectionIndex),
				section["address"],
				section["size"],
				SectionSemantics.ReadOnlyCodeSectionSemantics
			)
		for sectionIndex in range(len(self.dataSections)):
			section = self.dataSections[sectionIndex]
			self.add_auto_segment(
				section["address"],
				section["size"],
				section["offset"],
				section["size"],
				SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
			)
			self.add_auto_section(
				".data{}".format(sectionIndex),
				section["address"],
				section["size"],
				SectionSemantics.ReadWriteDataSectionSemantics
			)
		for sectionIndex in range(len(self.bssSections)):
			section = self.bssSections[sectionIndex]
			self.add_auto_segment(
				section["address"],
				section["size"],
				0,
				0,
				SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
			)
			self.add_auto_section(
				".bss{}".format(sectionIndex),
				section["address"],
				section["size"],
				SectionSemantics.ReadWriteDataSectionSemantics
			)

		self.define_auto_symbol(Symbol(
			SymbolType.FunctionSymbol,
			self.entrypoint,
			"_start"
		))
		self.add_function(self.entrypoint)
		self.add_entry_point(self.entrypoint)

		return True

	def perform_is_executable(self):
		return True

	def perform_get_entry_point(self):
		return self.entrypoint

DOLView.register()