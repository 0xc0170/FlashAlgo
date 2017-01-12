#!/usr/bin/env python
"""
 mbed
 Copyright (c) 2017-2017 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from __future__ import print_function
import os
import struct
import binascii
import argparse
import StringIO
import jinja2

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def main():
    parser = argparse.ArgumentParser(description='Algo Extracter')
    parser.add_argument("input", help="File to extract flash algo from")
    parser.add_argument("output", help="Output directory")
    args = parser.parse_args()

    elf = ElfFileSimple(args.input)
    flash_algo = PackFlashAlgo(elf)
    print("%s" % flash_algo.flash_info)

    data = {}
    data['name'] = "test_gen"
    data['dir'] = "."
    data['algo'] = flash_algo
    generate_blob(os.path.join(args.output, 'py_blob.tmpl'), 'py', data)


def generate_blob(template_path_file, ext, data):
    output = data['dir'] + '\\' + data['name'] + '_prog_blob.' + ext

    template_path = template_path_file
    template_text = open(template_path).read()
    template = jinja2.Template(template_text)
    target_text = template.render(data)

    open(output, 'w').write(target_text)
    return


class PackFlashAlgo(object):
    """Class to wrap a flash algo"""

    REQUIRED_SYMBOLS = set([
        "Init",
        "UnInit",
        "EraseChip",
        "EraseSector",
        "ProgramPage",
    ])

    EXTRA_SYMBOLS = set([
        "BlankCheck",
        "FlashCommandSequence",
        "FlashEraseAllBlock",
        "FlashEraseBlock",
        "FlashEraseSector",
        "FlashInit",
        "FlashVerifySection",
    ])

    def __init__(self, elf_simple):
        self.flash_info = PackFlashInfo(elf_simple)
        self.algo_data = None
        self.symbols = None

        self.ro_start = None
        self.ro_size = None
        self.rw_start = None
        self.rw_size = None
        self.zi_start = None
        self.zi_size = None

        self.flash_start = self.flash_info.start
        self.flash_size = self.flash_info.size
        self.page_size = self.flash_info.page_size
        self.sector_sizes = self.flash_info.sector_info_list

        ro_section = None
        rw_section = None
        zi_section = None

        symbols = {}
        for symbol in self.REQUIRED_SYMBOLS:
            symbols[symbol] = elf_simple.symbols[symbol].value
        self.symbols = symbols

        # Find requried sections
        for section in elf_simple.elf.iter_sections():
            if bytes2str(section.name) == "PrgCode":
                if section['sh_type'] == "SHT_PROGBITS":
                    if ro_section is None:
                        ro_section = section
                    else:
                        print("Extra ro section")
                else:
                    print("Unexpected section type in PrgCode")
            if bytes2str(section.name) == "PrgData":
                if section['sh_type'] == "SHT_PROGBITS":
                    if rw_section is None:
                        rw_section = section
                    else:
                        print("Extra rw section")
                elif section['sh_type'] == "SHT_NOBITS":
                    if zi_section is None:
                        zi_section = section
                    else:
                        print("Extra zi section")
                else:
                    print("Unexpected section type in PrgData")

        # Make sure all required sections are present
        if ro_section is None:
            print("Missing ro section")
            return None
        if rw_section is None:
            print("Missing rw section")
            return None
        if zi_section is None:
            print("Missing zi section")
            return None

        # Build the algo
        self.ro_start = ro_section['sh_addr']
        self.ro_size = ro_section['sh_size']
        self.rw_start = rw_section['sh_addr']
        self.rw_size = rw_section['sh_size']
        self.zi_start = zi_section['sh_addr']
        self.zi_size = zi_section['sh_size']

        # Check section ordering
        if self.ro_start != 0:
            print("RO section does not start at address 0")
            return None
        if self.ro_start + self.ro_size != self.rw_start:
            print("RW section does not follow RO section")
            return None
        if self.rw_start + self.rw_size != self.zi_start:
            print("ZI section does not follow RW section")
            return None

        # Attach data to the flash algo
        algo_size = self.ro_size + self.rw_size + self.zi_size
        algo_data = bytearray(algo_size)
        ro_data = ro_section.data()
        algo_data[self.ro_start:self.ro_start + self.ro_size] = ro_data
        rw_data = rw_section.data()
        algo_data[self.rw_start:self.rw_start + self.rw_size] = rw_data
        # ZI is already zeroed
        self.algo_data = algo_data

    def gen_string(self, spaces, group_size):
        blob = binascii.b2a_hex(self.algo_data)
        line_list = []
        padding = ' ' * spaces
        for i in xrange(0, len(blob), group_size):
            line_list.append(padding + '"' + blob[i:i + group_size] + '"')
        return "\n".join(line_list)


class PackFlashInfo(object):
    """Wrapper class for the non-executable information in an FLM file"""

    FLASH_DEVICE_STRUCT = "<H128sHLLLLBxxxLL"
    FLASH_SECTORS_STRUCT = "<LL"
    SECTOR_END = 0xFFFFFFFF

    def __init__(self, elf_simple):
        dev_info = elf_simple.symbols["FlashDevice"]
        info_start = dev_info.value
        info_size = struct.calcsize(self.FLASH_DEVICE_STRUCT)
        data = elf_simple.read(info_start, info_size)
        values = struct.unpack(self.FLASH_DEVICE_STRUCT, data)

        self.version = values[0]
        self.name = values[1].strip("\x00")
        self.type = values[2]
        self.start = values[3]
        self.size = values[4]
        self.page_size = values[5]
        self.value_empty = values[7]
        self.prog_timeout_ms = values[8]
        self.erase_timeout_ms = values[9]

        sector_entry_size = struct.calcsize(self.FLASH_SECTORS_STRUCT)
        index = 0
        sector_size, sector_start = 0, 0
        sector_info_list = []
        while True:
            sector_info_start = info_start + info_size + index * sector_entry_size
            data = elf_simple.read(sector_info_start, sector_entry_size)
            sector_size, sector_start = struct.unpack(self.FLASH_SECTORS_STRUCT, data)
            if (sector_size == self.SECTOR_END and
               sector_start == self.SECTOR_END):
                break
            sector_info_list.append((sector_start, sector_size))
            index += 1
        self.sector_info_list = sector_info_list

    def __str__(self):
        desc = ""
        desc += "Flash Device:" + os.linesep
        desc += "  name=%s" % self.name + os.linesep
        desc += "  version=%i" % self.version + os.linesep
        desc += "  type=%i" % self.type + os.linesep
        desc += "  start=0x%x" % self.start + os.linesep
        desc += "  size=0x%x" % self.size + os.linesep
        desc += "  page_size=0x%x" % self.page_size + os.linesep
        desc += "  value_empty=0x%x" % self.value_empty + os.linesep
        desc += "  prog_timeout_ms=%i" % self.prog_timeout_ms + os.linesep
        desc += "  erase_timeout_ms=%i" % self.erase_timeout_ms + os.linesep
        desc += "  sectors:" + os.linesep
        for sector_start, sector_size in self.sector_info_list:
            desc += ("    start=0x%x, size=0x%x" %
                     (sector_start, sector_size) + os.linesep)
        return desc


class SymbolSimple(object):
    """Wrapper for symbol object"""

    def __init__(self, name, value, size):
        self.name = name
        self.value = value
        self.size = size


class ElfFileSimple(object):
    """Wrapper for elf object which allows easy access to symbols and rom"""

    def __init__(self, file_name):
        self.symbols = None
        with open(file_name, 'rb') as file_handle:
            data = file_handle.read()
        self.elf = ELFFile(StringIO.StringIO(data))
        self._read_symbol_table()

    def _read_symbol_table(self):
        section = self.elf.get_section_by_name(b'.symtab')
        if not section:
            print("Missing symbol table")
            return

        if not isinstance(section, SymbolTableSection):
            print("Invalid symbol table section")
            return

        symbols = {}
        for symbol in section.iter_symbols():
            name_str = bytes2str(symbol.name)
            symbols[name_str] = SymbolSimple(name_str, symbol['st_value'],
                                             symbol['st_size'])
        self.symbols = symbols

    def read(self, addr, size):
        for segment in self.elf.iter_segments():
            seg_addr = segment['p_paddr']
            seg_size = segment['p_memsz']
            if addr >= seg_addr + seg_size:
                continue
            if addr + size <= seg_addr:
                continue
            # There is at least some overlap

            if addr >= seg_addr and addr + size <= seg_addr + seg_size:
                # Region is fully contained
                data = segment.data()
                start = addr - seg_addr
                return data[start:start + size]


if __name__ == '__main__':
    main()
