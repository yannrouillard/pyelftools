#-------------------------------------------------------------------------------
# elftools: elf/sections.py
#
# ELF sections
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from ..construct import CString
from ..common.utils import struct_parse, elf_assert, parse_cstring_from_stream


class Section(object):
    """ Base class for ELF sections. Also used for all sections types that have
        no special functionality.

        Allows dictionary-like access to the section header. For example:
         > sec = Section(...)
         > sec['sh_type']  # section type
    """
    def __init__(self, header, name, stream):
        self.header = header
        self.name = name
        self.stream = stream

    def data(self):
        """ The section data from the file.
        """
        self.stream.seek(self['sh_offset'])
        return self.stream.read(self['sh_size'])

    def is_null(self):
        """ Is this a null section?
        """
        return False

    def __getitem__(self, name):
        """ Implement dict-like access to header entries
        """
        return self.header[name]

    def __eq__(self, other):
        return self.header == other.header


class NullSection(Section):
    """ ELF NULL section
    """
    def __init__(self, header, name, stream):
        super(NullSection, self).__init__(header, name, stream)

    def is_null(self):
        return True


class StringTableSection(Section):
    """ ELF string table section.
    """
    def __init__(self, header, name, stream):
        super(StringTableSection, self).__init__(header, name, stream)

    def get_string(self, offset):
        """ Get the string stored at the given offset in this string table.
        """
        table_offset = self['sh_offset']
        s = parse_cstring_from_stream(self.stream, table_offset + offset)
        return s


class SymbolTableSection(Section):
    """ ELF symbol table section. Has an associated StringTableSection that's
        passed in the constructor.
    """
    def __init__(self, header, name, stream, elffile, stringtable):
        super(SymbolTableSection, self).__init__(header, name, stream)
        self.elffile = elffile
        self.elfstructs = self.elffile.structs
        self.stringtable = stringtable
        elf_assert(self['sh_entsize'] > 0,
                'Expected entry size of section %s to be > 0' % name)
        elf_assert(self['sh_size'] % self['sh_entsize'] == 0,
                'Expected section size to be a multiple of entry size in section %s' % name)

    def num_symbols(self):
        """ Number of symbols in the table
        """
        return self['sh_size'] // self['sh_entsize']

    def get_symbol(self, n):
        """ Get the symbol at index #n from the table (Symbol object)
        """
        # Grab the symbol's entry from the stream
        entry_offset = self['sh_offset'] + n * self['sh_entsize']
        entry = struct_parse(
            self.elfstructs.Elf_Sym,
            self.stream,
            stream_pos=entry_offset)
        # Find the symbol name in the associated string table
        name = self.stringtable.get_string(entry['st_name'])
        return Symbol(entry, name)

    def iter_symbols(self):
        """ Yield all the symbols in the table
        """
        for i in range(self.num_symbols()):
            yield self.get_symbol(i)


class Symbol(object):
    """ Symbol object - representing a single symbol entry from a symbol table
        section.

        Similarly to Section objects, allows dictionary-like access to the
        symbol entry.
    """
    def __init__(self, entry, name):
        self.entry = entry
        self.name = name

    def __getitem__(self, name):
        """ Implement dict-like access to entries
        """
        return self.entry[name]


class SUNWSyminfoTableSection(Section):
    """ ELF .SUNW Syminfo table section.
        Has an associated SymbolTableSection that's passed in the constructor.
    """
    def __init__(self, header, name, stream, elffile, symboltable):
        super(SUNWSyminfoTableSection, self).__init__(header, name, stream)
        self.elffile = elffile
        self.elfstructs = self.elffile.structs
        self.symboltable = symboltable

    def num_symbols(self):
        """ Number of symbols in the table
        """
        return self['sh_size'] // self['sh_entsize'] - 1

    def get_symbol(self, n):
        """ Get the symbol at index #n from the table (Symbol object).
            It begins at 1 and not 0 since the first entry is used to
            store the current version of the syminfo table.
        """
        # Grab the symbol's entry from the stream
        entry_offset = self['sh_offset'] + n * self['sh_entsize']
        entry = struct_parse(
            self.elfstructs.Elf_Sunw_Syminfo,
            self.stream,
            stream_pos=entry_offset)
        # Find the symbol name in the associated symbol table
        name = self.symboltable.get_symbol(n).name
        return Symbol(entry, name)

    def iter_symbols(self):
        """ Yield all the symbols in the table
        """
        for i in range(1, self.num_symbols() + 1):
            yield self.get_symbol(i)


class SUNWSymbolSortSection(Section):
    """ ELF .SUNW_dynsymsort or .SUNW_dyntlssort section
        Has an associated StringTableSection that's passed in the constructor.
    """
    def __init__(self, header, name, stream, elffile, stringtable):
        super(SUNWSymbolSortSection, self).__init__(header, name, stream)
        self.elffile = elffile
        self.elfstructs = self.elffile.structs
        self.stringtable = stringtable
        self._dynsym_section = elffile.get_section_by_name('.dynsym')
        self._ldynsym_section = elffile.get_section_by_name('.SUNW_ldynsym')
        self._num_local_symbols = self._ldynsym_section.num_symbols()

    def num_symbols(self):
        """ Number of symbols in the table
        """
        return self['sh_size'] // self['sh_entsize']

    def get_symbol_index(self, n):
        """ Get the index of the symbol located at position #n in the sorted
            index section.
            The index returned is an index in the symbols table composed by the
            concatenation of the .SUNW_ldynsym and the .dynsym symbol tables
        """
        # Grab the symbol's entry from the stream
        entry_offset = self['sh_offset'] + n * self['sh_entsize']
        entry = struct_parse(
            self.elfstructs.Elf_Sunw_SortIndex,
            self.stream,
            stream_pos=entry_offset)

        return entry['ndx']

    def get_symbol(self, n):
        """ Get the symbol located at position #n in the sorted index section
        """
        index = self.get_symbol_index(n)

        if index < self._num_local_symbols:
            symbol = self._ldynsym_section.get_symbol(index)
        else:
            symbol = self._dynsym_section.get_symbol(
                index - self._num_local_symbols)

        return symbol

    def find_symbol(self, addr):
        """ Get the symbol located at address addr using a binary search
            algorithm
        """
        low = 0
        high = self.num_symbols()
        while low < high:
            middle = (low + high) // 2
            symbol = self.get_symbol(middle)
            if symbol['st_value'] < addr:
                low = middle + 1
            elif symbol['st_value'] > addr:
                high = middle
            else:
                return symbol

        return None

    def iter_symbols(self):
        """ Yield all the symbols referenced in the sort section
        """
        for i in range(self.num_symbols()):
            yield self.get_symbol(i)
