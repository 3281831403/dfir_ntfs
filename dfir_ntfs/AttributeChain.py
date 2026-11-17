# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module locates in-place (resident) $LogFile updates against the real attribute chain
# of a target file record segment (FRS) and decodes the before/after byte values.

import struct
from . import MFT
from . import Attributes
from . import LogFile

# $STANDARD_INFORMATION value fields: (offset within the value, field name).
STANDARD_INFORMATION_TIMESTAMP_FIELDS = [
	(0, 'creation time (C)'),
	(8, 'modification time (M)'),
	(16, 'MFT entry change time (E)'),
	(24, 'last access time (A)')
]

# Classification categories (each in-place update ends up in exactly one of them):
CLASSIFICATION_INSIDE_ATTRIBUTE = 'inside_attribute'
"""The whole update is covered by a single attribute record of the target FRS."""

CLASSIFICATION_CROSSES_ATTRIBUTE_BOUNDARY = 'crosses_attribute_boundary'
"""The update starts inside an attribute record but extends past its end."""

CLASSIFICATION_OUTSIDE_ATTRIBUTES = 'outside_attributes'
"""The update starts outside of any attribute record of the target FRS."""

CLASSIFICATION_TARGET_RECORD_MISSING = 'target_record_missing'
"""The target file record segment (FRS) cannot be read or parsed from the supplied $MFT."""

CLASSIFICATION_NOT_IN_PLACE = 'not_in_place'
"""The log record is not an in-place (resident) update of an $MFT file record segment."""

# Subregions of an attribute record (offsets are relative to the attribute record start).
ATTRIBUTE_REGION_RECORD_HEADER = 'attribute_record_header'
ATTRIBUTE_REGION_NAME = 'attribute_name'
ATTRIBUTE_REGION_RESIDENT_VALUE = 'resident_value'
ATTRIBUTE_REGION_NONRESIDENT_HEADER = 'nonresident_header'
ATTRIBUTE_REGION_MAPPING_PAIRS = 'mapping_pairs'
ATTRIBUTE_REGION_PADDING_OR_UNKNOWN = 'padding_or_unknown'

FORM_RESIDENT = 0
FORM_NONRESIDENT = 1

class AttributeChainException(MFT.MasterFileTableException):
	"""This exception is raised when an attribute chain cannot be parsed."""

	pass

class AttributeRecordDescriptor(object):
	"""This class describes a single attribute record within a file record segment (FRS).

	All offsets are relative to the start of the containing file record segment (FRS).
	"""

	type_code = None
	"""A type code of this attribute record."""

	type_name = None
	"""A resolved type name of this attribute record."""

	name = None
	"""A name of this attribute record (or None, if it is unnamed)."""

	form_code = None
	"""A form code of this attribute record (0 is resident, 1 is nonresident)."""

	instance = None
	"""An attribute instance number."""

	record_offset = None
	"""An offset of this attribute record within the FRS."""

	record_length = None
	"""A length of this attribute record."""

	name_offset = None
	"""An offset of the attribute name, relative to the attribute record start (or None, if unnamed)."""

	name_length = None
	"""A length of the attribute name in bytes (or 0, if unnamed)."""

	value_offset = None
	"""For resident attributes: an offset of the value, relative to the attribute record start."""

	value_length = None
	"""For resident attributes: a length of the value in bytes."""

	mapping_pairs_offset = None
	"""For nonresident attributes: an offset of the mapping pairs, relative to the attribute record start."""

	def is_resident(self):
		"""Check if this is a resident attribute record."""

		return self.form_code == FORM_RESIDENT

	def type_and_name(self):
		"""Return a human-readable attribute identifier (the type name plus the attribute name, if any)."""

		if self.name is None:
			return self.type_name

		return '{}:{}'.format(self.type_name, self.name)

	def __str__(self):
		form_str = 'resident' if self.is_resident() else 'nonresident'

		return 'AttributeRecordDescriptor, {}, {}, offset: {}, length: {}'.format(self.type_name, form_str, self.record_offset, self.record_length)

class FileRecordAttributeChain(object):
	"""This class is a defensive parser for the attribute chain of a file record segment (FRS).

	Unlike FileRecordSegment.attributes(), this parser works on raw FRS bytes, never raises on the
	first malformed attribute record, and exposes the exact byte ranges of each attribute record.
	"""

	frs_number = None
	"""An $MFT number of this file record segment (FRS)."""

	frs_size = None
	"""A size of this file record segment (FRS), in bytes."""

	frs_data = None
	"""Raw bytes of this file record segment (FRS), with the update sequence array applied."""

	first_attribute_offset = None
	"""An offset of the first attribute record."""

	first_free_byte_offset = None
	"""An offset of the first free byte in this file record segment (FRS)."""

	descriptors = None
	"""A list of AttributeRecordDescriptor objects parsed from this FRS."""

	parse_error = None
	"""An error message (a string) if the attribute chain is truncated or malformed, None otherwise."""

	def __init__(self, frs_data, frs_number, frs_size = None):
		"""Create an object from raw FRS bytes (the 'frs_data' argument) for a given $MFT number (the 'frs_number' argument).
		The update sequence array must already be applied. If 'frs_size' is not given, the length of the buffer is used.
		"""

		self.frs_data = bytes(frs_data)
		self.frs_number = frs_number
		self.descriptors = []

		if frs_size is None:
			self.frs_size = len(self.frs_data)
		else:
			self.frs_size = frs_size

		if len(self.frs_data) < 42:
			raise AttributeChainException('File record segment is too short: {}'.format(len(self.frs_data)))

		self.first_attribute_offset = struct.unpack('<H', self.frs_data[20 : 22])[0]
		self.first_free_byte_offset = struct.unpack('<L', self.frs_data[24 : 28])[0]

		if self.first_attribute_offset < 8 or self.first_attribute_offset % 8 != 0 or self.first_attribute_offset >= len(self.frs_data):
			raise AttributeChainException('Invalid offset to the first attribute: {}'.format(self.first_attribute_offset))

		if self.first_free_byte_offset < self.first_attribute_offset or self.first_free_byte_offset > len(self.frs_data):
			# Do not trust a bogus first-free-byte offset: clamp it to the buffer end.
			self.first_free_byte_offset = len(self.frs_data)
			self.parse_error = 'Invalid offset to the first free byte, clamped to the buffer end'

		self.parse_chain()

	def parse_chain(self):
		"""Parse the attribute chain, collecting as many valid descriptors as possible."""

		pos = self.first_attribute_offset

		while pos + 4 <= self.first_free_byte_offset:
			type_code = struct.unpack('<L', self.frs_data[pos : pos + 4])[0]
			if type_code == Attributes.ATTR_TYPE_END:
				break

			if pos + 16 > self.first_free_byte_offset:
				self.parse_error = 'Truncated attribute record header at offset {}'.format(pos)
				break

			try:
				type_code, record_length, form_code, name_length, name_offset, flags, instance = MFT.UnpackAttributeRecordPartialHeader(self.frs_data[pos : pos + 16])
			except struct.error:
				self.parse_error = 'Malformed attribute record header at offset {}'.format(pos)
				break

			if record_length < 8 or record_length % 8 != 0 or pos + record_length > self.first_free_byte_offset:
				self.parse_error = 'Invalid attribute record length {} at offset {}'.format(record_length, pos)
				break

			descriptor = AttributeRecordDescriptor()
			descriptor.type_code = type_code
			descriptor.type_name = MFT.ResolveAttributeType(type_code)
			descriptor.form_code = form_code
			descriptor.instance = instance
			descriptor.record_offset = pos
			descriptor.record_length = record_length
			descriptor.name = None
			descriptor.name_length = 0
			descriptor.name_offset = None
			descriptor.value_offset = None
			descriptor.value_length = None
			descriptor.mapping_pairs_offset = None

			name_ok = True
			if name_length > 0:
				name_length_in_bytes = name_length * 2
				descriptor.name_length = name_length_in_bytes
				descriptor.name_offset = name_offset

				if name_offset + name_length_in_bytes > record_length:
					name_ok = False
					self.parse_error = 'Invalid attribute name at offset {}'.format(pos)
				else:
					descriptor.name = self.frs_data[pos + name_offset : pos + name_offset + name_length_in_bytes].decode('utf-16le', errors = 'replace')

			if form_code == FORM_RESIDENT:
				if pos + 24 > self.first_free_byte_offset:
					self.parse_error = 'Truncated resident attribute header at offset {}'.format(pos)
					break

				value_length, value_offset, resident_flags, reserved = MFT.UnpackAttributeRecordRemainingHeaderResident(self.frs_data[pos + 16 : pos + 24])
				descriptor.value_length = value_length
				descriptor.value_offset = value_offset

				if value_offset < 8 or value_offset + value_length > record_length:
					# Keep the descriptor (the record header is still locatable), but flag the chain.
					if self.parse_error is None:
						self.parse_error = 'Invalid resident value bounds at offset {}'.format(pos)

			elif form_code == FORM_NONRESIDENT:
				if pos + 64 > self.first_free_byte_offset:
					self.parse_error = 'Truncated nonresident attribute header at offset {}'.format(pos)
					break

				lowest_vcn, highest_vcn, mapping_pairs_offset, compression_unit, reserved, allocated_length, file_size, valid_data_length = struct.unpack('<QQHB5sqqq', self.frs_data[pos + 16 : pos + 64])
				descriptor.mapping_pairs_offset = mapping_pairs_offset

				if mapping_pairs_offset >= record_length:
					if self.parse_error is None:
						self.parse_error = 'Invalid mapping pairs offset at offset {}'.format(pos)

			else:
				if self.parse_error is None:
					self.parse_error = 'Invalid form code {} at offset {}'.format(form_code, pos)

			self.descriptors.append(descriptor)

			if not name_ok:
				break

			pos += record_length

	def find_attribute_at_offset(self, offset):
		"""Find and return the descriptor of the attribute record containing the given FRS-relative offset.

		Return None if the offset is outside every attribute record (or within the end marker).
		"""

		for descriptor in self.descriptors:
			if descriptor.record_offset <= offset < descriptor.record_offset + descriptor.record_length:
				return descriptor

		return None

	def describe_offset(self, offset):
		"""Return a tuple (descriptor, region, offset_in_attribute, offset_in_region) for an FRS-relative offset.

		The descriptor is None when the offset is not covered by any attribute record.
		"""

		descriptor = self.find_attribute_at_offset(offset)
		if descriptor is None:
			return (None, None, None, None)

		offset_in_attribute = offset - descriptor.record_offset

		if descriptor.is_resident():
			if offset_in_attribute < 24:
				region = ATTRIBUTE_REGION_RECORD_HEADER
				offset_in_region = offset_in_attribute
			elif descriptor.name_length > 0 and descriptor.name_offset is not None and descriptor.name_offset <= offset_in_attribute < descriptor.name_offset + descriptor.name_length:
				region = ATTRIBUTE_REGION_NAME
				offset_in_region = offset_in_attribute - descriptor.name_offset
			elif descriptor.value_offset is not None and descriptor.value_offset <= offset_in_attribute < descriptor.value_offset + descriptor.value_length:
				region = ATTRIBUTE_REGION_RESIDENT_VALUE
				offset_in_region = offset_in_attribute - descriptor.value_offset
			else:
				region = ATTRIBUTE_REGION_PADDING_OR_UNKNOWN
				offset_in_region = offset_in_attribute
		else:
			if offset_in_attribute < 64:
				region = ATTRIBUTE_REGION_NONRESIDENT_HEADER
				offset_in_region = offset_in_attribute
			elif descriptor.name_length > 0 and descriptor.name_offset is not None and descriptor.name_offset <= offset_in_attribute < descriptor.name_offset + descriptor.name_length:
				region = ATTRIBUTE_REGION_NAME
				offset_in_region = offset_in_attribute - descriptor.name_offset
			elif descriptor.mapping_pairs_offset is not None and offset_in_attribute >= descriptor.mapping_pairs_offset:
				region = ATTRIBUTE_REGION_MAPPING_PAIRS
				offset_in_region = offset_in_attribute - descriptor.mapping_pairs_offset
			else:
				region = ATTRIBUTE_REGION_PADDING_OR_UNKNOWN
				offset_in_region = offset_in_attribute

		return (descriptor, region, offset_in_attribute, offset_in_region)


class InPlaceUpdateLocation(object):
	"""This class holds the result of locating a single in-place update against an attribute chain."""

	lsn = None
	"""A log sequence number (LSN) of the log record."""

	transaction_id = None
	"""A transaction ID of the log record."""

	redo_operation = None
	"""A redo operation code."""

	undo_operation = None
	"""An undo operation code."""

	target_frs_number = None
	"""A target file record segment (FRS) number (or None, if not applicable)."""

	frs_size = None
	"""A target file record segment (FRS) size in bytes, as claimed by the log record."""

	offset_in_target = None
	"""An offset of the update within the target FRS."""

	redo_length = None
	"""A length of the redo (after) data."""

	undo_length = None
	"""A length of the undo (before) data."""

	write_length = None
	"""A byte span covered by the update (the longest of the redo and undo data)."""

	classification = None
	"""One of the CLASSIFICATION_* constants."""

	classification_reason = None
	"""A human-readable explanation of the classification (set for the non-inside categories)."""

	descriptor = None
	"""An AttributeRecordDescriptor of the containing attribute (None unless inside an attribute record)."""

	region = None
	"""An attribute subregion hit (one of the ATTRIBUTE_REGION_* constants, or None)."""

	offset_in_attribute = None
	"""An offset relative to the attribute record start (or None)."""

	offset_in_region = None
	"""An offset relative to the start of the hit subregion (or None)."""

	redo_data = None
	"""Raw redo (after) bytes."""

	undo_data = None
	"""Raw undo (before) bytes."""

	parse_error = None
	"""An attribute-chain parse warning (a string), if the target chain is malformed, None otherwise."""

	def is_inside(self):
		"""Check if the whole update is covered by a single attribute record."""

		return self.classification == CLASSIFICATION_INSIDE_ATTRIBUTE

	def __str__(self):
		return 'InPlaceUpdateLocation (LSN: {}), classification: {}, target FRS: {}, offset: {}'.format(self.lsn, self.classification, self.target_frs_number, self.offset_in_target)


class InPlaceUpdateAnalyzer(object):
	"""This class locates in-place (resident) $LogFile updates against the attribute chains of target file records.

	The supplied $MFT parser is only used to read raw file record segments; each lookup is fully isolated,
	so a single malformed target record never interrupts analysis of the remaining log records.
	"""

	mft_parser = None
	"""A MasterFileTableParser object."""

	frs_chain_cache = None
	"""A cache of FileRecordAttributeChain objects keyed by the FRS number."""

	frs_error_cache = None
	"""A cache of error messages keyed by the FRS number (for unreadable target records)."""

	def __init__(self, mft_parser):
		self.mft_parser = mft_parser
		self.frs_chain_cache = dict()
		self.frs_error_cache = dict()

	def get_attribute_chain(self, frs_number):
		"""Get and return a FileRecordAttributeChain for the given FRS number, or None if it cannot be parsed."""

		if frs_number in self.frs_chain_cache.keys():
			return self.frs_chain_cache[frs_number]

		if frs_number in self.frs_error_cache.keys():
			return None

		try:
			frs = self.mft_parser.get_file_record_segment_by_number(frs_number)
		except MFT.MasterFileTableException as e:
			self.frs_error_cache[frs_number] = 'target record missing or unreadable: {}'.format(str(e))
			return None

		try:
			chain = FileRecordAttributeChain(frs.frs_data, frs_number, self.mft_parser.file_record_segment_size)
		except (AttributeChainException, MFT.MasterFileTableException, struct.error) as e:
			self.frs_error_cache[frs_number] = 'target record missing or unreadable: {}'.format(str(e))
			return None

		self.frs_chain_cache[frs_number] = chain
		return chain

	@staticmethod
	def is_in_place_update(log_record):
		"""Check if a log record carries an in-place (resident) update."""

		redo_op = log_record.get_redo_operation()
		undo_op = log_record.get_undo_operation()

		return redo_op in LogFile.LOGGED_RESIDENT_UPDATES or undo_op in LogFile.LOGGED_RESIDENT_UPDATES

	def locate(self, log_record):
		"""Locate a single log record and return an InPlaceUpdateLocation object.

		Non-resident records are classified as CLASSIFICATION_NOT_IN_PLACE and still returned,
		so callers can produce a complete report.
		"""

		location = InPlaceUpdateLocation()
		location.lsn = log_record.lsn
		location.transaction_id = log_record.transaction_id
		location.redo_operation = log_record.get_redo_operation()
		location.undo_operation = log_record.get_undo_operation()
		location.redo_data = log_record.get_redo_data()
		location.undo_data = log_record.get_undo_data()
		location.redo_length = len(location.redo_data)
		location.undo_length = len(location.undo_data)
		location.write_length = max(location.redo_length, location.undo_length)
		location.target_frs_number = log_record.calculate_mft_target_number()
		location.offset_in_target = log_record.calculate_offset_in_target()

		target_block_size = log_record.get_target_block_size()
		location.frs_size = target_block_size * 512 if target_block_size > 0 else LogFile.FILE_RECORD_SEGMENT_SIZE_DEFAULT

		if not self.is_in_place_update(log_record):
			location.classification = CLASSIFICATION_NOT_IN_PLACE
			location.classification_reason = 'the redo and undo operations are not in-place (resident) $MFT updates'
			return location

		if location.target_frs_number is None or location.offset_in_target is None:
			location.classification = CLASSIFICATION_TARGET_RECORD_MISSING
			location.classification_reason = 'the log record does not identify a target file record segment and an offset'
			return location

		chain = self.get_attribute_chain(location.target_frs_number)
		if chain is None:
			location.classification = CLASSIFICATION_TARGET_RECORD_MISSING
			location.classification_reason = self.frs_error_cache.get(location.target_frs_number, 'target record missing or unreadable')
			return location

		if chain.parse_error is not None:
			location.parse_error = chain.parse_error

		if location.offset_in_target >= chain.frs_size or location.offset_in_target >= len(chain.frs_data):
			location.classification = CLASSIFICATION_OUTSIDE_ATTRIBUTES
			location.classification_reason = 'offset {} is outside the target file record segment (size {})'.format(location.offset_in_target, chain.frs_size)
			return location

		descriptor = chain.find_attribute_at_offset(location.offset_in_target)
		if descriptor is None:
			location.classification = CLASSIFICATION_OUTSIDE_ATTRIBUTES
			location.classification_reason = 'offset {} is not covered by any attribute record (first attribute: {}, first free byte: {})'.format(location.offset_in_target, chain.first_attribute_offset, chain.first_free_byte_offset)
			return location

		update_end = location.offset_in_target + location.write_length
		attribute_end = descriptor.record_offset + descriptor.record_length

		if update_end > attribute_end:
			location.classification = CLASSIFICATION_CROSSES_ATTRIBUTE_BOUNDARY
			location.classification_reason = 'the {} byte update at offset {} ends at {}, past the end of {} at offset {}'.format(location.write_length, location.offset_in_target, update_end, descriptor.type_and_name(), attribute_end)
			descriptor, region, offset_in_attribute, offset_in_region = chain.describe_offset(location.offset_in_target)
			location.descriptor = descriptor
			location.region = region
			location.offset_in_attribute = offset_in_attribute
			location.offset_in_region = offset_in_region
			return location

		location.classification = CLASSIFICATION_INSIDE_ATTRIBUTE
		descriptor, region, offset_in_attribute, offset_in_region = chain.describe_offset(location.offset_in_target)
		location.descriptor = descriptor
		location.region = region
		location.offset_in_attribute = offset_in_attribute
		location.offset_in_region = offset_in_region

		return location

	def analyze(self, log_parser, recover_log_data = True):
		"""Yield an InPlaceUpdateLocation object for each NTFS log record of the given log parser.

		Restart areas are skipped. Each record is handled independently and exceptions are converted
		into CLASSIFICATION_TARGET_RECORD_MISSING results instead of being propagated.
		"""

		for log_item in log_parser.parse_ntfs_records(recover_log_data):
			if type(log_item) is not LogFile.NTFSLogRecord:
				continue

			try:
				yield self.locate(log_item)
			except Exception as e:
				location = InPlaceUpdateLocation()
				location.lsn = getattr(log_item, 'lsn', None)
				location.transaction_id = getattr(log_item, 'transaction_id', None)
				location.redo_operation = getattr(log_item, 'redo_operation', None)
				if location.redo_operation is None and hasattr(log_item, 'get_redo_operation'):
					try:
						location.redo_operation = log_item.get_redo_operation()
					except Exception:
						location.redo_operation = None

				location.undo_operation = getattr(log_item, 'undo_operation', None)
				if location.undo_operation is None and hasattr(log_item, 'get_undo_operation'):
					try:
						location.undo_operation = log_item.get_undo_operation()
					except Exception:
						location.undo_operation = None

				location.redo_data = b''
				location.undo_data = b''
				location.redo_length = 0
				location.undo_length = 0
				location.write_length = 0
				location.target_frs_number = None
				location.offset_in_target = None
				location.frs_size = None
				location.classification = CLASSIFICATION_TARGET_RECORD_MISSING
				location.classification_reason = 'unexpected failure while locating this record: {}: {}'.format(type(e).__name__, str(e))

				yield location


def decode_standard_information_timestamps(location):
	"""Decode before/after $STANDARD_INFORMATION timestamps from a located update.

	Return a list of (field_name, redo_datetime, undo_datetime) tuples, one per timestamp field
	fully covered by both the value-region offset and the redo/undo buffers. Fields not fully
	covered (or non-$STANDARD_INFORMATION updates) are omitted. This is a best-effort, never-raising
	helper; the byte-level redo/undo values remain the authoritative output.
	"""

	if location is None or not location.is_inside():
		return []

	if location.descriptor is None or location.descriptor.type_code != Attributes.ATTR_TYPE_STANDARD_INFORMATION:
		return []

	if location.region != ATTRIBUTE_REGION_RESIDENT_VALUE:
		return []

	value_relative_offset = location.offset_in_region
	results = []

	for field_offset, field_name in STANDARD_INFORMATION_TIMESTAMP_FIELDS:
		redo = _read_filetime(location.redo_data, value_relative_offset, field_offset)
		undo = _read_filetime(location.undo_data, value_relative_offset, field_offset)

		if redo is None and undo is None:
			continue

		results.append((field_name, redo, undo))

	return results


def _read_filetime(buffer_data, value_relative_offset, field_offset):
	"""Read and decode a FILETIME field from an update buffer, or return None if it is not fully covered."""

	start = field_offset - value_relative_offset
	if start < 0 or start + 8 > len(buffer_data):
		return None

	timestamp_int = struct.unpack('<Q', buffer_data[start : start + 8])[0]
	return Attributes.DecodeFiletime(timestamp_int)
