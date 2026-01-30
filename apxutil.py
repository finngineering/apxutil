import struct
import zipfile
import argparse
import sys
import zlib
import copy
import os
import configparser

CRC16_Kermit_table = [
    0x0000, 0x1189, 0x2312, 0x329B,   0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3,   0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A,   0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52,   0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399,   0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1,   0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318,   0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50,   0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F,   0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7,   0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E,   0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56,   0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D,   0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5,   0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C,   0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54,   0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693,   0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB,   0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612,   0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A,   0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791,   0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9,   0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710,   0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58,   0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497,   0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF,   0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416,   0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E,   0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595,   0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD,   0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514,   0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C,   0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
    ]

def CRC16_Kermit(bytes, init=0xffff):
    crc = init

    for b in bytes:
        lu_idx = (b ^ crc) & 0xff
        crc = crc >> 8
        crc = (crc ^ CRC16_Kermit_table[lu_idx]) & 0xffff

    return crc

def hexascii(bytes):
    return "".join(chr(c) if c >= 32 and c < 127 else "." for c in bytes)

def hexlines(bytes, offset=0, bytes_per_line=16):

    # Pad spaces to make the last row same width as the rest
    # We later replace these character in the hex view with space
    remainder = len(bytes) % bytes_per_line
    if remainder > 0:
        bytes = bytes + b" "*(bytes_per_line - remainder)


    chunks = [f"{offset + i:08x}  " \
            + bytes[i:i+bytes_per_line].hex(" ") \
            + "  |" + hexascii(bytes[i:i+bytes_per_line]) + "|" \
            for i in range(0,len(bytes),bytes_per_line)]
    
    # Replace the hex values for the added spaces with blanks in the last line
    if remainder > 0:
        start_replacement = 10+remainder*3
        end_replacement = 10+bytes_per_line*3
        replacement_str = " "*(end_replacement - start_replacement)
        chunks[-1] = chunks[-1][:start_replacement] + replacement_str + chunks[-1][end_replacement:]
    return chunks

def hexdump(bytes, offset=0, bytes_per_line=16, firstlinetext=""):
    firstline = 1
    for line in hexlines(bytes, offset, bytes_per_line):
        if firstline:
            print(line + " " + firstlinetext)
            firstline = 0
        else:
            print(line)

# Class for working with .sta (project archive) files
class StaFile:
    def __init__(self):
        self.archive = None
        self.apxfile = ApxFile()

    def __del__(self):
        if self.archive is not None:
            self.archive.close()

    def load_file(self, filename):
        self.archive = zipfile.ZipFile(filename, "r")
        self.apxfile = ApxFile()
        self.apxfile.load_bytes(self.archive.read("BinAppli/Station.apx"))
    
    # Extract inner files to directory and create a manifest file list
    def extract(self, directory):
        try:
            os.mkdir(directory)
        except FileExistsError:
            pass
        self.archive.extractall(directory)

        # Create and save manifest file list
        manifest = configparser.ConfigParser()
        manifest["STAFILE"] = {}
        for i, info in enumerate(self.archive.infolist()):
            manifest["STAFILE"][f"FILE_{i:02x}"] = info.filename

        with open (os.path.join(directory, "sta_manifest.ini"), "w") as file:
            manifest.write(file)

    # Create a .sta files based on the files in the provided manifest (path)
    def assemble(self, manifestpath, stafile, include_apd=False):
        if os.path.isdir(manifestpath):
            manifestpath = os.path.join(manifestpath, "sta_manifest.ini")
        dirname = os.path.dirname(manifestpath)

        stafile = zipfile.ZipFile(stafile, "w", zipfile.ZIP_DEFLATED, compresslevel=zlib.Z_BEST_COMPRESSION)

        manifest = configparser.ConfigParser()
        manifest.read(manifestpath)

        # Include all files mentioned in manifest (except perhaps station.apd)
        for key in manifest["STAFILE"]:
            if not key.lower().startswith("file_"):
                continue

            arcfile = manifest["STAFILE"][key]
            # Skip Station.apd "backup file" by default
            if manifest["STAFILE"][key].lower().endswith("station.apd") and not include_apd:
                continue
            # Add file to archive
            filepath = os.path.join(dirname, arcfile)
            if os.path.isdir(filepath):
                stafile.mkdir(arcfile)
            else:
                stafile.write(filepath, arcname=arcfile)

        stafile.close()

# Description of a field/variable of a specific type and a specific offset inside a binary blob
class ApxField:
    def __init__(self, name, spec, offset, buffer=b"", formatter=None):
        self.name = name
        self.spec = spec
        self.offset = offset
        if len(buffer) > 0:
            self.value = struct.unpack_from(self.spec, buffer, offset)[0]
        elif "s" in spec:
            self.value = b"\x00"
        else:
            self.value = 0

        if formatter:
            self.formatter = formatter
        else:
            self.create_default_formatter()

    def create_default_formatter(self):
        alpha = None
        for c in self.spec:
            if c.isalpha():
                alpha = c
                break
        if alpha in "cbBhHiIlLqQP": # We are looking at an interger
            len = struct.calcsize(alpha)
            self.formatter = lambda x: ("0x{:0" + str(struct.calcsize(self.spec)*2) + "x}").format(x)
        elif alpha == "s": # binary data
            self.formatter = lambda x: x.hex()
        else: # unspecified
            self.formatter = lambda x: str(x)
        
    def strvalue(self):
        return self.formatter(self.value)
    
    def __repr__(self):
        return self.name + "=" + self.strvalue()
    
    def value_from_bytes(self, bytes):
        self.value = struct.unpack_from(self.spec, bytes, self.offset)[0]

    def value_from_string(self, valuestr):
        valuestr = valuestr.strip().lower()
        alpha = None
        for c in self.spec:
            if c.isalpha():
                alpha = c
                break
        if alpha in "cbBhHiIlLqQP": # We are looking at an interger
            if valuestr.startswith("0x"):
                self.value = int(valuestr, 16)
            elif valuestr.startswith("0b"):
                self.value = int(valuestr, 2)
            else:
                self.value = int(valuestr)
        elif alpha == "s": # binary data
            self.value = bytes.fromhex(valuestr)

# Container for ApxFields to provide some helper functions.
class ApxFieldContainer:
    def __init__(self, size=0):
        self.fields = []
        self._size = size

    def append(self, field):
        already_present = any([x for x in self.fields if x.name == field.name])
        if already_present:
            # TODO: Should the field be updated or not??
            return
        self.fields.append(field)
        self._size = max(self._size, self.calculated_size())
    
    def remove(self, fieldlist):
        for fieldname in fieldlist:
            try:
                self.fields.remove(self[fieldname])
            except KeyError:
                pass

    def __getitem__(self, key):
        item = next((f for f in self.fields if f.name == key), None)
        if item == None:
            raise KeyError
        return item

    def __iter__(self):
        return self.fields.__iter__()
    
    def __next__(self):
        return self.fields.__next__()

#    def __setitem__(self, key, value):
#        pass

    @property
    def size(self):
        return self._size
    
    @size.setter
    def size(self, value):
        if value < self.calculated_size():
            return
        self._size = value
    
    # Calculate the (minimum) size based on the given fields
    def calculated_size(self):
        max_offset = -1
        max_spec = ""
        for f in self.fields:
            if f.offset > max_offset:
                max_offset = f.offset
                max_spec = f.spec
        return max_offset + struct.calcsize(max_spec)

    # Create a binary blob based on the fields and size
    def bytes(self):
        buffer = bytearray(b"\x00"*self.size)
        for f in self.fields:
            struct.pack_into(f.spec, buffer, f.offset, f.value)
        return bytes(buffer)
    
    # Update field values from binary blob
    def values_from_bytes(self, bytes):
        for f in self.fields:
            f.value_from_bytes(bytes)

    # Update field values from name/value pairs in dict
    def values_from_dict(self, valuedict):
        for key, value in valuedict.items():
            try:
                self[key].value_from_string(value)
            except KeyError:
                pass

# Class for working with .apx (Station.apx) files
class ApxFile:
    def __init__(self):
        self.header = ApxFileHeader()
        self.sections = []

    def load_file(self, filename):
        f = open(filename, "rb")
        data = f.read()
        f.close()
        self.parse(data)
    
    def save_file(self, filename):
        f = open(filename, "wb")
        f.write(self.bytes)
        f.close()

    @property
    def bytes(self):
        ba = bytearray()
        ba += self.header.bytes
        for s in self.sections:
            ba += s.bytes
        return bytes(ba)

    def load_bytes(self, bytes):
        self.parse(bytes)

    def parse(self, bytes):
        self.header = ApxFileHeader(bytes[:32])

        offset = 32        
        while offset < len(bytes):
            s = ApxSection(self)
            s.parse(bytes[offset:])
            self.sections.append(s)
            offset = offset + s.size()

    def extract(self, directory, decompress=False, manifest=configparser.ConfigParser()):
        try:
            os.mkdir(directory)
        except FileExistsError:
            pass
        
        manifest = configparser.ConfigParser()
        self.header.export_config(manifest)

        for s in self.sections:
            s.export_config(manifest)

            section_numstr = f"{s.header.fields["section_num"].value:04x}"
            section_name = f"APX_SECTION_{section_numstr}"
            filename = f"section_0x{section_numstr}"
            fileloc = os.path.join(directory, filename)
            if len(s.data) > 0:
                appendix = "_00"
                ctype = s.compression_name()
                if decompress == False or ctype == "none":
                    # Overrides to prevent decompression
                    ctype = "none"
                    manifest[section_name]["compression_type"] = ctype
                    # Save data
                    manifest[section_name]["datafile" + appendix] = filename + appendix
                    with open(fileloc + appendix, "wb") as f:
                        f.write(s.data)
                else:
                    for i, data in enumerate(s.decompress()):
                        appendix = f"_{i:02x}"
                        manifest[section_name]["datafile" + appendix] = filename + appendix
                        with open(fileloc + appendix, "wb") as f:
                            f.write(data)
        
        manifestfile = os.path.join(directory, "apx_manifest.ini")
        with open(manifestfile, "w") as mfile:
            manifest.write(mfile)
                

    def assemble(self, manifestpath):
        if os.path.isdir(manifestpath):
            manifestpath = os.path.join(manifestpath, "apx_manifest.ini")
        dirname = os.path.dirname(manifestpath)

        manifest = configparser.ConfigParser()
        manifest.read(manifestpath)

        self.header.from_dict(manifest["APX_HEADER"])
        sects = [s for s in manifest.sections() if s.upper().startswith("APX_SECTION_")]
        sects.sort()
        self.sections = []

        for sectionkey in sects:
            s = ApxSection(self)
            s.from_dict(manifest[sectionkey])

            datafiles = [d for d in manifest[sectionkey].keys() if d.lower().startswith("datafile_")]
            datafiles.sort()
            for dfile in datafiles:
                fileloc = os.path.join(dirname, manifest[sectionkey][dfile])
                with open(fileloc, "rb") as file:
                    data = file.read()
                    if manifest[sectionkey]["compression_type"] == "none":
                        s.data = s.data + data
                    else:
                        tmpdata = s.data
                        s.compress(data, manifest[sectionkey]["compression_type"])
                        s.data = tmpdata + s.data
            
            self.sections.append(s)
        
        self.recalculate()

    def recalculate(self):
        for s in self.sections:
            s.recalculate()
        
        # TODO: better identification of special "RT" section, if possible
        rt_section = self.get_section(0x11)
        rt_section.rte.fields["crc16"].value = self.calculate_rt_crc16()

    def hexdump(self, offset=0, restart_offset=False, decompress=False):
        firstline = 1
        for line in hexlines(self.header.bytes):
            if firstline:
                print(line + " " + str(self.header))
                firstline = 0
            else:
                print(line)
        
        offset = len(self.header.bytes)
        for i, s in enumerate(self.sections):
            print("")
            if restart_offset:
                s.hexdump(0, decompress)
            else:
                s.hexdump(offset, decompress)
            
            offset = offset + s.size()

    def manifest(self, manifest=configparser.ConfigParser()):
        manifest = self.header.export_config(manifest)
        return manifest

    def get_section(self, number):
        return next(s for s in self.sections if s.header.fields["section_num"].value == number)
    
    def calculate_rt_crc16(self):
        rtsection = self.get_section(0x11)
        crc16 = CRC16_Kermit(rtsection.data)
        for s in self.sections:
            if s.header.fields["section_num"].value == 0x11:
                rte = copy.deepcopy(s.rte)
                attr = rte.fields["attributes"].value
                if (attr >> 28) & 1 == 1:
                    continue

                rte.fields["crc16"].value = 0
                rte.fields["attributes"].value = rte.fields["attributes"].value | 0x40000000
                crc16 = CRC16_Kermit(rte.bytes, crc16)
            else:
                crc16 = CRC16_Kermit(s.rte.bytes, crc16)
        return crc16

class ApxFileHeader:
    def __init__(self, bytes=b"\x00"*32):
        self.fields = ApxFieldContainer(32)
        self.fields.append(ApxField("magic",                "I", 0, bytes))
        self.fields.append(ApxField("version_maybe",        "H", 4, bytes))
        self.fields.append(ApxField("rte_type",             "B", 6, bytes))
        self.fields.append(ApxField("header_count_maybe",   "B", 7, bytes))
        self.fields.append(ApxField("sdsection_total_size", "H", 8, bytes))
        self.fields.append(ApxField("rte_size",             "B", 10, bytes))
        self.fields.append(ApxField("sdsection_39_4",       "I", 11, bytes))
        self.fields.append(ApxField("sdsection_35_4",       "I", 15, bytes))
        self.fields.append(ApxField("sesection_8_2",        "H", 19, bytes))
        self.fields.append(ApxField("zero_pad_21_11",       "11s", 21, bytes))
    
    def __repr__(self):
        str = f"{self.__class__.__name__}(" + ", ".join([f.__str__() for f in self.fields]) + ")"
        return str

    @property
    def bytes(self):
        return self.fields.bytes()

    def export_config(self, config=configparser.ConfigParser()):
        config["APX_HEADER"] = {}
        for f in self.fields:
            config["APX_HEADER"][f.name] = f.strvalue()

        return config
    
    def from_dict(self, fields):
        self.fields.values_from_dict(fields)


class ApxSectionHeader:
    def __init__(self, context, bytes=b"\x00"*32):
        self.context = context
        rte_type = self.context.header.fields["rte_type"].value

        section_type = struct.unpack_from("H", bytes, 0)[0]
        self.fields = ApxFieldContainer()
        self.retype(section_type)

        if section_type == 0:
            self.fields.append(ApxField("unknown_6_2", "H", 6))
            self.fields.values_from_bytes(bytes)
        elif section_type == 1:
            # TODO: unknown_6_4 and unknown_10_4 have some meaining, based on FW AnalyseHeader
            # TODO: byte [0xe] has some meaning I think, based on FW AnalyseHeader
            self.fields.append(ApxField("unknown_6_10", "10s", 6))
            self.fields.values_from_bytes(bytes)
        elif section_type == 2:
            # We need to look ahead to the Rte attributes to know what to do with mem_offset and data_size
            if rte_type == 1:
                rte_attributes = struct.unpack_from("I", bytes, self.fields.size + 6)[0]
            elif rte_type == 2:
                rte_attributes = struct.unpack_from("I", bytes, self.fields.size + 8)[0]
            else:
                raise Exception("Invalid APX type encountered when parsing APX section header")
            self.fields.append(ApxField("mem_offset", "I", 6))
            self.fields.append(ApxField("data_size", "I", 10))
            self.fields.values_from_bytes(bytes)
            if (rte_attributes >> 0x1c) & 1 == 1: # or is_apd_file: ## This is a condition in the SE parsing TODO: fixme
                # Force the fields to value 0
                self.fields["mem_offset"].value = 0
                self.fields["data_size"].value = 0

        elif section_type == 3:
            raise Exception("Unhandled header type 0x03")
        elif section_type == 4:
            raise Exception("Unhandled header type 0x04")
        else:
            raise Exception("Encountered invalid APX section header type")
        
        self.update()

    def retype(self, header_type):
        # If the fields are already present, they will not be modified, but fields not used
        # for the particular type are removed
        self.fields.append(ApxField("type", "H", 0))
        self.fields.append(ApxField("unknown_2_2", "H", 2))
        self.fields.append(ApxField("section_num", "H", 4))
        if header_type == 0:
            self.fields.remove(["unknown_6_10", "mem_offset", "data_size", "unknown_14_2"])
            self.fields.append(ApxField("unknown_6_2", "H", 6))
            self.fields.size = 8
        elif header_type == 1:
            self.fields.remove(["unknown_6_2", "mem_offset", "data_size", "unknown_14_2"])
            self.fields.append(ApxField("unknown_6_10", "10s", 6))
            self.fields.size = 16
        elif header_type == 2:
            self.fields.remove(["unknown_6_2", "unknown_6_10"])
            self.fields.append(ApxField("mem_offset", "I", 6))
            self.fields.append(ApxField("data_size", "I", 10))
            self.fields.append(ApxField("unknown_14_2", "H", 14))
            self.fields.size = 16
        elif header_type == 3 or header_type == 4:
            self.fields.size = 24

    @property
    def bytes(self):
        return self.fields.bytes()

    def __repr__(self):
        str = f"{self.__class__.__name__}(" + ", ".join([f.__str__() for f in self.fields]) + ")"
        return str

    def values_from_dict(self, fields):
        # Header has variable size and fields based on type
        try:
            self.retype(int(fields["type"], 16)) # TODO: maybe not hardcode hexadecimal base
        except KeyError:
            pass
        self.fields.values_from_dict(fields)
        self.update()

    def update(self):
        self.type = self.fields["type"].value
        if self.type == 0:
            self.data_size = 0
        elif self.type == 1:
            self.data_size = 0
        elif self.type == 2:
            self.data_size = self.fields["data_size"].value
        else:
            self.data_size = 0

    def hexdump(self, offset=0):
        hexdump(self.bytes, offset, 16, str(self))

    def export_config(self):
        config = {}
        for f in self.fields:
            config[f.name] = f.strvalue()
        return config

class ApxRte:
    def __init__(self, context, bytes=b"\x00"*16):
        self.context = context

        self.fields = ApxFieldContainer(16)
        self.fields.append(ApxField("block_count", "I", 0)) # TODO: probably not block count, but something else...
        self.fields.append(ApxField("size_minus1", "I", 4))
        self.fields.append(ApxField("attributes", "I", 8))
        self.fields.append(ApxField("crc16", "H", 12))
        self.fields.append(ApxField("membyte", "B", 14))
        self.fields.values_from_bytes(bytes)

        self.parse(bytes)

    @property
    def bytes(self):
        return self.fields.bytes()

    def parse(self, bytes):
        self.fields.values_from_bytes(bytes)
        membyte = self.fields["membyte"].value
        self.mem_area_num = membyte >> 3
        self.mem_folio_num = membyte & 0x7
        
    def __repr__(self):
        str = f"{self.__class__.__name__}(" + ", ".join([f.__str__() for f in self.fields]) + ")"
        return str

    def values_from_dict(self, fields):
        self.fields.values_from_dict(fields)

    def hexdump(self, offset=0):
        hexdump(self.bytes, offset, 16, str(self))

    def export_config(self):
        config = {}
        for f in self.fields:
            config[f.name] = f.strvalue()
        return config
    
    def is_compressed(self):
        return self.fields["attributes"].value >> 13 & 1

class ApxSection:
    def __init__(self, context):
        self.context = context
        self.data = b''
        self.header = ApxSectionHeader(context)
        self.rte = ApxRte(context)
    
    @property
    def bytes(self):
        ba = bytearray()
        ba += self.header.bytes
        ba += self.rte.bytes
        ba += self.data
        return bytes(ba)

    def parse(self, bytes):
        self.header = ApxSectionHeader(self.context, bytes)
        self.rte = ApxRte(self.context, bytes[self.header.fields.size:])

        try:
            data_offset = self.header.fields.size + self.context.header.fields["rte_size"].value
            self.data = bytes[data_offset:(data_offset + self.header.data_size)]
        except KeyError:
            pass

    def recalculate(self):
        if len(self.data) > 0:
            self.header.fields["data_size"].value = len(self.data)
            self.rte.fields["size_minus1"].value = len(self.data) - 1
            self.rte.fields["crc16"].value = CRC16_Kermit(self.data)
        
        # TODO: better "detection" of the special RT section
        if self.header.fields["section_num"].value == 0x11:
            rte_count = struct.unpack_from("H", self.data, 5)[0]
            rte_size = self.context.header.fields["rte_size"].value
            self.rte.fields["size_minus1"].value = len(self.data) - 1 + rte_count * rte_size

    def printHeader(self):
        self.header.print()
    
    def __repr__(self):
        str = f"{self.__class__.__name__}("
        str = str + f"data_size=0x{len(self.data):08x}, "
        str = str + f"calc_crc16=0x{CRC16_Kermit(self.data):04x}"
        if len(self.data) > 4:
            str = str + f", data_magic=0x{self.data[:4].hex()}"
        str = str + ")"
        return str

    def from_dict(self, fields):
        self.header.values_from_dict(fields)
        self.rte.values_from_dict(fields)

    def size(self):
        return self.header.fields.size + self.context.header.fields["rte_size"].value + len(self.data)

    def hexdump(self, offset, decompress=False):
        self.header.hexdump(offset)
        offset = offset + len(self.header.bytes)

        self.rte.hexdump(offset)
        offset = offset + len(self.rte.bytes)

        if decompress:
            data = b"".join(self.decompress())
        else:
            data = self.bytes
        hexdump(data, offset, 16, str(self))

    def compress(self, rawdata, compression_name):
        if compression_name == "pk":
            # TODO: use calculated instead of hardcoded date/time values
            dosdate = 0x231d
            dostime = 0x0fb4
            pkheader = bytearray(b"\x00"*0x2e)
            struct.pack_into("12s", pkheader, 0, b"PK\x01\x02\x14\x0b\x14\x00\x00\x00\x08\x00")
            struct.pack_into("H", pkheader, 0xc, dostime)
            struct.pack_into("H", pkheader, 0xe, dosdate)
            struct.pack_into("H", pkheader, 0x12, dostime)
            struct.pack_into("I", pkheader, 0x14, 0x7fffffff)
            struct.pack_into("H", pkheader, 0x24, 0xffff)
            # Skip zlib header and "EOF" CRC32 from compressed data
            self.data = bytes(pkheader) + zlib.compress(rawdata, zlib.Z_BEST_COMPRESSION)[2:-4]
        elif compression_name == "zlib":
            zlibheader = b"ZLIB" + struct.pack("H", len(rawdata)) + b"\x00"*10
            self.data = zlibheader + zlib.compress(rawdata, zlib.Z_BEST_COMPRESSION)
        elif compression_name == "deflate":
            self.data = zlib.compress(rawdata, zlib.Z_BEST_COMPRESSION)
        self.recalculate()

    def decompress(self):
        if not self.rte.is_compressed():
            return b""
        
        if self.data[:4] == b"PK\01\02":
            return [zlib.decompress(self.data[0x2e:], wbits=-15)]
        elif self.data[:4] == b"ZLIB":
            return [zlib.decompress(self.data[0x10:])]
        elif self.data[0] == 0x78:
            # Apparently there can be several deflate streams in one
            # section, and we need to handle them all. Using python zlib
            # gets a bit clunky for this...
            datalist = []
            offset = 0
            while offset < len(self.data):
                zobj = zlib.decompressobj()
                datalist.append(zobj.decompress(self.data[offset:]))
                offset = len(self.data) - len(zobj.unused_data)
            return datalist
        else:
            return []

    def compression_name(self):
        if self.rte.is_compressed():
            if self.data[:4] == b"PK\01\02":
                return "pk"
            elif self.data[:4] == b"ZLIB":
                return "zlib"
            elif self.data[0] == 0x78:
                return "deflate"
        return "none"

    def export_config(self, config=configparser.ConfigParser()):
        section = f"APX_SECTION_{self.header.fields["section_num"].value:04x}"
        config[section] = {}

        for key, value in self.header.export_config().items():
            config[section][key] = value

        for key, value in self.rte.export_config().items():
            config[section][key] = value

        config[section]["compression_type"] = self.compression_name()

        return config

class ApxSectionSD(ApxSection):
    def __init__(self, context):
        super().__init__(context)

    def parse(self, bytes):
        # Parse header and split out data
        super().parse(bytes)
        
        self.magic = struct.unpack_from("H", self.data, 0)[0] # 0x0000445d or "SD\x00\x00" in ASCII
        self.mem_header_offset = struct.unpack_from("H", self.data, 4)[0]
        self.data_size = struct.unpack_from("H", self.data, 6)[0]
        self.data_flag = struct.unpack_from("H", self.data, 12)[0]
        self.mem_header_size = struct.unpack_from("H", self.data, self.mem_header_offset)[0]
        self.mem_area_size = struct.unpack_from("H", self.data, self.mem_header_offset + 2)[0]
        self.mem_folio_size = struct.unpack_from("H", self.data, self.mem_header_offset + 4)[0]
        self.mem_area_count = struct.unpack_from("B", self.data, self.mem_header_offset + 6)[0]
        self.mem_areas = []
        offset = self.mem_header_offset + self.mem_header_size
        for i in range(self.mem_area_count):
            area_num = struct.unpack_from("B", self.data, offset)[0]
            folio_count = struct.unpack_from("B", self.data, offset + 1)[0]
            area_type = struct.unpack_from("B", self.data, offset + 2)[0]
            area_address = struct.unpack_from("I", self.data, offset + 3)[0]


            offset = offset + self.mem_area_size

            folio_arr = []
            for j in range(folio_count):
                folio_num_maybe = struct.unpack_from("B", self.data, offset)[0]
                folio_size = struct.unpack_from("I", self.data, offset + 1)[0]
                folio_attributes = struct.unpack_from("H", self.data, offset + 5)[0]
                folio_size2 = struct.unpack_from("I", self.data, offset + 9)[0]

                folio = {
                    "folio_num": folio_num_maybe,
                    "folio_size": folio_size,
                    "folio_attributes": folio_attributes,
                    "folio_size2": folio_size2
                }
                folio_arr.append(folio)
                offset = offset + self.mem_folio_size

            area = {
                "area_num": area_num,
                "folio_count": folio_count,
                "area_type": area_type,
                "area_address": area_address,
                "folios": folio_arr
            }

            self.mem_areas.append(area)
    
    def print(self):
        print("SD SECTION DATA")
        
        print("magic: 0x{:08x}".format(self.magic))
        print("mem_header_offset: 0x{:04x}".format(self.mem_header_offset))
        print("data_size: 0x{:04x}".format(self.data_size))
        print("data_flag: 0x{:04x}".format(self.data_flag))
        print("mem_header_size: 0x{:04x}".format(self.mem_header_size))
        print("mem_area_size: 0x{:04x}".format(self.mem_area_size))
        print("mem_folio_size: 0x{:04x}".format(self.mem_folio_size))
        print("mem_area_count: 0x{:02x}".format(self.mem_area_count))

        for i, area in enumerate(self.mem_areas):
            print("Mem area: {}".format(i))
            print("area_num: 0x{:02x}".format(area["area_num"]))
            print("folio_count: 0x{:02x}".format(area["folio_count"]))
            print("area_type: 0x{:02x}".format(area["area_type"]))
            print("area_address: 0x{:08x}".format(area["area_address"]))

            for j, folio in enumerate(area["folios"]):
                print("Mem number: {}".format(j))
                print("folio_num_maybe: 0x{:02x}".format(folio["folio_num"]))
                print("folio_size: 0x{:08x}".format(folio["folio_size"]))
                print("folio_attributes: 0x{:04x}".format(folio["folio_attributes"]))
                print("folio_size2: 0x{:08x}".format(folio["folio_size2"]))


class ApxSectionRT(ApxSection):
    def __init__(self, context):
        super().__init__(context)

    def parse(self, bytes):
        # Parse header and split out data
        super().parse(bytes)
        
        self.magic = struct.unpack_from("I", self.data, 0)[0]
        self.rte_size = struct.unpack_from("B", self.data, 4)[0]
        self.rte_elements = struct.unpack_from("H", self.data, 5)[0]
        self.rte_base_maybe = struct.unpack_from("H", self.data, 7)[0]
        self.rte_max = struct.unpack_from("H", self.data, 9)[0]

    def __repr__(self):
        str = f"{self.__class__.__name__}("
        str = str + f"magic=0x{self.magic:08x}, "
        str = str + f"rte_size=0x{self.rte_size:02x}, "
        str = str + f"rte_elements=0x{self.rte_elements:04x}, "
        str = str + f"rte_base_maybe=0x{self.rte_base_maybe:04x}, "
        str = str + f"rte_max=0x{self.rte_max:04x}, "
        str = str + ")\n"
        return str

    

    def print(self):
        print("RT SECTION DATA")
        print("mem_header_offset: 0x{:04x}".format(self.mem_header_offset))
        print("data_size: 0x{:04x}".format(self.data_size))
        print("data_flag: 0x{:04x}".format(self.data_flag))
        print("mem_header_size: 0x{:04x}".format(self.mem_header_size))
        print("mem_area_size: 0x{:04x}".format(self.mem_area_size))
    


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Tool to manipulate Schneider Electric .sta and .apx files")
    # TODO: make sure arguments make sense, for instance require either -f or -F argument
    parser.add_argument("-f", "--apxfile", metavar="filaname-apx", help=".apx file to read or write")
    parser.add_argument("-F", "--stafile", metavar="filaname-sta", help=".sta file to read or write")
    parser.add_argument("-e", "--extract-apx", metavar="dir", help="extract contents of the Station.apx file")
    parser.add_argument("-E", "--extract-sta", metavar="dir", help="extract contents of the .sta file")
    parser.add_argument("-a", "--assemble-apx", metavar="manifestpath", help="create Station.apx file based on apx_manifest.ini")
    parser.add_argument("-A", "--assemble-sta", metavar="manifestpath", help="create a .sta file from files in sta_manifest.ini")
    parser.add_argument("-d", "--decompress", help="decompress Station.apx sections that are compressed", action="store_true")
    parser.add_argument("-x", "--hexdump", help="print hexdump of Station.apx with header information", action="store_true")
    parser.add_argument("-B", "--include-apd", help="include Station.apd when creating .sta archive", action="store_true")
    parser.add_argument("-r", "--restart-offsets", help="restart offsets at 0 for each section in hexdump print (useful for diffing)", action="store_true")

    args = parser.parse_args()

    if args.extract_sta:
        stafile = StaFile()
        stafile.load_file(args.stafile)
        stafile.extract(args.extract_sta)
    
    if args.extract_apx:
        apxfile = ApxFile()
        apxfile.load_file(args.apxfile)
        apxfile.extract(args.extract_apx, args.decompress)

    if args.assemble_sta:
        stafile = StaFile()
        stafile.assemble(args.assemble_sta, args.stafile, args.include_apd)
        sys.exit(0)
    
    if args.assemble_apx:
        apxfile = ApxFile()
        apxfile.assemble(args.assemble_apx)
        apxfile.save_file(args.apxfile)
        sys.exit(0)

    if args.hexdump:
        if args.stafile:
            stafile = StaFile()
            stafile.load_file(args.stafile)
            apxfile = stafile.apxfile
        elif args.apxfile:
            apxfile = ApxFile()
            apxfile.load_file(args.apxfile)

        apxfile.hexdump(0, args.restart_offsets, args.decompress)


"""
attributes:

bit[0-3] defines a variable e.g. var = [0, 15]. Bit number "var" in folio attributes must be set, otherwise it is an error

bit[13] block data is compressed
bit[17] needs fixed allocation maybe? (ReadRte last function call)

bit[23] if clear then no crc check needed
bit[28] should be backed up maybe? In separate station.ap[b,p]? file
bit[29] has section data maybe, yes, looks like it is correct (CMALRte32::copyData)
bit[30] if set then no crc check needed, bit is also set after successful crc verification
bit[31] if clear then no crc check needed. Bit is set after rte has been added successfully (in ReadRte)

"""
