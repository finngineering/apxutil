# A tool to manipulate Schneider Electric PLC archive files
This tool can extract and reassemble PLC "archive" files, used by several Schneider Electric PLC:s, including at least M580, M340 and Quantum. The archive files with an extension of .sta are really a zip archive containing a few files. Inside the archive, the truly important file is named Station.apx. The contents of that file is what is transferred to/from the PLC during a (full) program download/upload. Naturally, it contains the actual executable code for the PLC program. But it also contains all information neccessary to edit the PLC program in Control Expert Classic (or Unity Pro). The .apx file format is proprietary, and little information about it is available. A bit of information is available from [Liras en la red](https://lirasenlared.blogspot.com/2018/10/the-apx-logic-file-format.html) and [Team82](https://claroty.com/team82/research/white-papers/evil-plc-attack-weaponizing-plcs), but this work goes deeper than what they published. With this tool, the different "sections" from the Station.apx can be extracted (and decompressed if needed) for examination. The tool can also reassemble the Station.apx from previously extracted - and perhaps modified - section data and metadata. And this reassembled file will open without errors in Control Expert Classic / Unity Pro, provided the changes made does not break "section logic".

## Motivation
There never was any grand plan with this project. I use Schneider Electric PLC:s every once in a while, and was interested in how they work (or don't) at a more fundamental level. It turned out this investigation was suitably complex to keep me entertained (probably like solving crosswords is for normal people), and I ended up with this tool.

## Warning
The tool does its best to extract and reassemble the files it works with. However, the user should be aware that the tool was developed with:
* A limited understanding of the .apx (and .sta) file format
* Limited input validation, meaning it will rather crash or do something wrong than give up without trying
* Overwrite previous files without questions
* Limited testing of different PLC:s and programming software versions
* Limited testing of the code functionality

Using reassembled files on a real PLC may cause issues, especially if you have modified the sections or metadata. It is even possible that it could brick the PLC. So upload modified archive files to the PLC at your own peril.

## Usage
The tool is used from the command line with the python interpreter:
```
python apxutil.py -h

usage: apxutil.py [-h] [-f filaname-apx] [-F filaname-sta] [-e dir] [-E dir] [-a manifestpath] [-A manifestpath] [-d]
                  [-x] [-B] [-r]

Tool to manipulate Schneider Electric .sta and .apx files

options:
  -h, --help            show this help message and exit
  -f, --apxfile filaname-apx
                        .apx file to read or write
  -F, --stafile filaname-sta
                        .sta file to read or write
  -e, --extract-apx dir
                        extract contents of the Station.apx file
  -E, --extract-sta dir
                        extract contents of the .sta file
  -a, --assemble-apx manifestpath
                        create Station.apx file based on apx_manifest.ini
  -A, --assemble-sta manifestpath
                        create a .sta file from files in sta_manifest.ini
  -d, --decompress      decompress Station.apx sections that are compressed
  -x, --hexdump         print hexdump of Station.apx with header information
  -B, --include-apd     include Station.apd when creating .sta archive
  -r, --restart-offsets
                        restart offsets at 0 for each section in hexdump print (useful for diffing)
```
The help should be failry self-explanatory. Generally, short-hand options with capital letters work on .sta files, and lower case letters work on .apx files. A few examples of usage is given below.

To extract the contents of a .sta file to directory "extracted", you would use:
```
python apxutil.py -F archive.sta -E extracted
```

To extract the contents of Station.apx to directory "contents", you would use:
```
python apxutil.py -f extracted/BinAppli/Station.apx -e contents -d
```
The "-d" option means compressed sections will be decompressed, but can be left out if (all) raw section data is wanted.

To reassemble Station.apx, you would use:
```
python apxutil.py -f extracted/BinAppli/Station.apx -a contents
```
This will assemble the Station.apx based on the apx_manifest.ini found in the contents directory, compressing section data if it was previously decompressed. Section sizes and CRC:s will be recalculated, and not read from the apx_manifest.ini.

To reassemble a .sta file, you would use:
```
python apxutil.py -F modified-archive.sta -A extracted
```
This will by default omit the Station.apd file (which appears to be mainly a integrity check for the Station.apx file header). If you want that included, add the "-B" option. But that may very well mean that Control Expert Classic will fail to open the project archive file.

To directly "view" the contents of the Station.apx file, the following command can be used:
```
python apxutil.py -F modified-archive.sta -x
```
This will output a "canonical hexdump" of the Station.apx file, meaning you see the offsets, hex data, and ASCII data, 16 bytes at a time, including the metadata. The "-d" option can be used to decompress compressed sections (but beware that the offsets make little sense in that case). The "-r" option can be used to restart the offset at 0 for every section. This is useful if you have made changes and want to be able to "diff" them without offsets.


## APX file format structure
If you want to understand the APX file format (to the level of myself and this tool), the best way is really to look at the source code of apxutil.py. The code should not be too difficult to read even with little programming experience. But it may make real programmers nauseous. In any case, a high-level overview of the file format is given here. The APX file begins with a 32 byte file header. The rest of the file is divided into different sections, each with a similar structure. Each section starts with a section header, whose length depends on the section type (defined in the beginning of the header). The section header is followed by an RTE (header). Following the RTE comes the section data (if such is present). And after the section data the following section (header) starts. It appears that the section header is more related to the Station.apx format and the RTE is more related to the execution environment (RunTime Environment or RealTime Environment maybe?), but it's not a clear distinction.

### APX file header
The APX file header is 32 bytes long and starts with ASCII text "APX", followed by some metadata. Maybe most importantly, it defines the type and size of RTE used. Type 0x02 is what I have seen. It seems likely that type 0x01 is for 16 bit address space and type 0x02 is for 32 bit address space, but this is far from certain. There are a few unknowns that probably have some significance. A couple of 32-bit values and one 16-bit value are "repeated" in section "SD" 0x0001, but their meaning is unknown. The last 11 bytes appear to always be zeroes. An example below (in canonical hexdump format, with metadata):
```
00000000  41 50 58 00 00 01 02 01 10 01 10 60 f6 c3 30 00  |APX........`..0.| ApxFileHeader(magic=0x00585041, version_maybe=0x0100, rte_type=0x02, header_count_maybe=0x01, sdsection_total_size=0x0110, rte_size=0x10, sdsection_39_4=0x30c3f660, sdsection_35_4=0x0b926500, sesection_8_2=0x0106, zero_pad_21_11=0000000000000000000000)
00000010  65 92 0b 06 01 00 00 00 00 00 00 00 00 00 00 00  |e...............|
```

### APX section header
The APX section header starts with a 16-bit value defining its type. Types 0x0001 - 0x0004 appears to be valid, but I have only seen types 0x0000, 0x0001 and 0x0002. The section header length depends on the type. For 0x0000 the length is 8 bytes, for 0x0001 - 0x0002 it is 16 bytes and for types 0x0003 - 0x0004 it should be 24 bytes. The section number is given by a 16-bit value at byte offset 4. For section types 0x0000 and 0x0001, that is all I know, and they don't have any section data. For section type 0x0002, the 32-bit value at byte offset 10 specifies the size of the section data, as present in the Station.apx file.

### APX RTE
The RTE header following the section header is 16 bytes long (at least for type 0x02). The meaning of the first 32-bit value is unknown (but here named "block_count"). The 32-bit value staring at offset 4 is the section data size (from the section header) minus 1, in case the section has data. If the section does not have data, the meaning is unknown (and section 0x0011 breaks this rule). The 32-bit value starting at byte offset 8 are attributes/flags, most of which have unknown meaning. Some thoughts are listed in the end of apxutil.py. The 16-bit value starting at byte offset 12 is the CRC16/Kermit checksum of the section data (and again, section 0x0011 breaks this rule). The 3 high bits of byte 14 defines the memory area and the low 5 bits the memory folio. The last byte 15 is likely unused.

### APX section data
The section data is in general "raw" data, which may contain executable code, project information, compressed data, etc. It appear that if bit 13 in the RTE attributes is set, then the section data is compressed. The compression types seen are zip/"pk", zlib with non-standard header and "raw deflate".

### Noteworthy sections
While all sections have their own meaning, it appears that sections 0x0001 "RT" and 0x0011 "SD" are fundamental than the rest. They appear to be related to the RTE:s and the actualy memory layout of the PLC execution environment. A partial decoding of these sections is included towards the end of apxutil.py, but is currently not used by the tool itself.

## Remaining mysteries
There is a lot of "low hanging" fruit in case somebody wants to investigate. Some open questions:
* Where is the executable data stored? In one section or in many?
* Where are passwords stored, and how does password protection/encryption work?
* What is the detailed meaning of the more opaque parts of the APX section header and RTE fields
* What data is contained in the different sections?
* What does the section number mean? It appears some numbers are "hard-coded" while other are dynamic.
In case you are interested in working on this., feel free to fork the repo and continue, or perhaps submit a PR.