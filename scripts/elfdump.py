#!/opt/csw/bin/python
#------------------------------------------------------------------------------
# scripts/elfdump.py
#
# A clone of 'elfdump' in Python, based on the pyelftools library
#
# Eli Bendersky (eliben@gmail.com)
# Yann Rouillard (yann@pleiades.fr.eu.org)
# This code is in the public domain
#------------------------------------------------------------------------------
import os
import sys
from optparse import OptionParser
import string

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')


from elftools import __version__
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SUNW_SYMINFO_FLAGS
from elftools.elf.sections import (
    SymbolTableSection, SUNWSyminfoTableSection, SUNWSymbolSortSection)
from elftools.elf.gnuversions import (
    GNUVerNeedSection, GNUVerDefSection, GNUVerSymSection)
from elftools.elf.descriptions import (
    describe_syminfo_flags, describe_symbol_boundto, describe_ver_flags)


# We define our own description functions as elfdump doesn't
# display the symbol informations like readelf does

_DESCR_ST_INFO_TYPE = dict(
    STT_NOTYPE='NOTY',
    STT_OBJECT='OBJT',
    STT_FUNC='FUNC',
    STT_SECTION='SECT',
    STT_FILE='FILE',
    STT_COMMON='COMMON',
    STT_TLS='TLS',
)

_DESCR_ST_INFO_BIND = dict(
    STB_LOCAL='LOCL',
    STB_GLOBAL='GLOB',
    STB_WEAK='WEAK',
)

_DESCR_ST_VISIBILITY = dict(
    STV_DEFAULT='D',
    STV_INTERNAL='I',
    STV_HIDDEN='H',
    STV_PROTECTED='P',
)

_DESCR_ST_SHNDX = dict(
    SHN_UNDEF='UNDEF',
    SHN_ABS='ABS',
    SHN_COMMON='COMMON',
)


def _describe_symbol_type(x):
    return _DESCR_ST_INFO_TYPE.get(x, "")


def _describe_symbol_bind(x):
    return _DESCR_ST_INFO_BIND.get(x, "")


def _describe_symbol_visibility(x):
    return _DESCR_ST_VISIBILITY.get(x, "")


def _describe_symbol_shndx(x):
    return _DESCR_ST_SHNDX.get(x, x)


class Elfdump(object):
    """ display_* methods are used to emit output into the output stream
    """
    def __init__(self, file, output):
        """ file:
                stream object with the ELF file to read

            output:
                output stream to write to
        """
        self.elffile = ELFFile(file)
        self.output = output

    def _find_section(self, section_type):
        """ Find the first section of the given class in the elf file
        """
        for section in self.elffile.iter_sections():
            if isinstance(section, section_type):
                return section
        return None

    def _find_sections(self, section_type):
        """ Find all the section of the given class in the elf file
        """
        sections = []
        for section in self.elffile.iter_sections():
            if isinstance(section, section_type):
                sections.append(section)
        return sections

    def display_version_tables(self):
        """ Display the SUNW verneed and verdef tables contained in the file
        """
        verneed_section = self._find_section(GNUVerNeedSection)
        verdef_section = self._find_section(GNUVerDefSection)

        # Version definition section
        if verdef_section:

            self._emitline("\nVersion Definition Section:  %s" %
                           bytes2str(verdef_section.name))
            self._emitline(
                '     index  version                     dependency')

            for verdef, verdaux_iter in verdef_section.iter_versions():

                # The first verdaux entry is mandatory, it contains the version
                # name of the current version definition
                verdaux = next(verdaux_iter)

                if verdef['vd_cnt'] > 1:
                    # Additional verdaux entries are dependencies of the
                    # current version the first one is displayed on the
                    # same line
                    dependency = next(verdaux_iter)
                    dependency_name = dependency.name
                else:
                    dependency_name = ''

                flags_desc = describe_ver_flags(verdef['vd_flags'])
                if flags_desc:
                    flags_desc = '[ %s ]' % flags_desc

                self._emitline('%10.10s  %-26.26s  %-20s %s' % (
                    '[%i]' % verdef['vd_ndx'], bytes2str(verdaux.name),
                    bytes2str(dependency_name), flags_desc))

                for verdaux in verdaux_iter:
                    # additional dependencies are displayed one by line
                    self._emitline('%47s  %s' % ('', bytes2str(verdaux.name)))

        # Version dependency section
        if verneed_section:

            self._emitline("\nVersion Needed Section:  %s" %
                           bytes2str(verneed_section.name))

            if verneed_section.has_indexes():
                self._emitline(
                    '     index  file                        version')
            else:
                self._emitline(
                    '            file                        version')

            for verneed, vernaux_iter in verneed_section.iter_versions():

                filename = verneed.name

                for vernaux in vernaux_iter:

                    flags_desc = describe_ver_flags(vernaux['vna_flags'])
                    if flags_desc:
                        flags_desc = '[ %s ]' % flags_desc

                    if vernaux['vna_other']:
                        index = '[%s]' % vernaux['vna_other']
                    else:
                        index = ''

                    self._emitline('%10.10s  %-26.26s  %-20s %s' % (
                        index, bytes2str(filename), bytes2str(vernaux.name),
                        flags_desc))

                    # we only display the filename for the first version name
                    # related to this file
                    filename = b''

    def display_syminfo_table(self):
        """ Display the SUNW syminfo tables contained in the file
        """
        syminfo_section = self._find_section(SUNWSyminfoTableSection)

        if syminfo_section:
            # The symbol table section pointed to in sh_link
            dyntable = self.elffile.get_section_by_name(b'.dynamic')

            if syminfo_section['sh_entsize'] == 0:
                self._emitline(
                    "\nSymbol table '%s' has a sh_entsize of zero!" %
                    (bytes2str(syminfo_section.name)))
                return

            # The symbol table section pointed to in sh_link
            symtable = self.elffile.get_section(syminfo_section['sh_link'])

            self._emitline("\nSyminfo Section:  %s" %
                           bytes2str(syminfo_section.name))
            self._emitline(
                '     index  flags            bound to                 symbol')

            for nsym, syminfo in enumerate(syminfo_section.iter_symbols(),
                                           start=1):
                if not (syminfo['si_flags'] or syminfo['si_boundto']):
                    continue

                index = ''
                if syminfo['si_flags'] & SUNW_SYMINFO_FLAGS.SYMINFO_FLG_CAP:
                    boundto = '<symbol capabilities>'
                elif not isinstance(syminfo['si_boundto'], int):
                    boundto = describe_symbol_boundto(syminfo['si_boundto'])
                else:
                    dyn_tag = dyntable.get_tag(syminfo['si_boundto'])
                    if (syminfo['si_flags'] &
                            SUNW_SYMINFO_FLAGS.SYMINFO_FLG_FILTER):
                        boundto = bytes2str(dyn_tag.sunw_filter)
                    else:
                        boundto = bytes2str(dyn_tag.needed)
                    index = '[%d]' % syminfo['si_boundto']

                # symbol names are truncated to 24 chars, similarly to elfdump
                self._emitline('%10s  %-5s %10s %-24s %s' % (
                    '[%d]' % (int(nsym)),
                    describe_syminfo_flags(syminfo['si_flags']),
                    index,
                    boundto,
                    bytes2str(syminfo.name)))

    def _emit_symbol(self, index, symbol, version_index):
        """
        """
        if self.elffile.elfclass == 32:
            symbol_entry_format = ('%10.10s  0x%8.8x 0x%8.8x'
                                   '  %4s %4s %2s %4s %-14.14s %s')
        else:
            symbol_entry_format = ('%10.10s  0x%16.16x 0x%16.16x'
                                   '  %4s %4s %2s %4s %-14.14s %s')

        index_str = '[%i]' % index

        shndx = symbol['st_shndx']
        if isinstance(shndx, str):
            shndx = _describe_symbol_shndx(shndx)
        else:
            shndx = bytes2str(self.elffile.get_section(shndx).name)

        if version_index == 'VER_NDX_LOCAL':
            version_index = 0
        elif version_index == 'VER_NDX_GLOBAL':
            version_index = 1

        self._emitline(symbol_entry_format % (
            index_str, symbol['st_value'], symbol['st_size'],
            _describe_symbol_type(symbol['st_info']['type']),
            _describe_symbol_bind(symbol['st_info']['bind']),
            _describe_symbol_visibility(symbol['st_other']['visibility']),
            version_index, shndx, bytes2str(symbol.name)))

    def display_symbol_tables(self):
        """ Display the symbol tables contained in the file
        """
        symbol_tables = self._find_sections(SymbolTableSection)

        if not symbol_tables:
            return

        # we first look for the versym section to be able to display
        # version index for the associated symbol table
        versym_section = self._find_section(GNUVerSymSection)
        if versym_section:
            linked_section = self.elffile.get_section(
                versym_section['sh_link'])

        for section in symbol_tables:

            if section['sh_entsize'] == 0:
                self._emitline(
                    "\nSymbol table '%s' has a sh_entsize of zero!" % (
                    bytes2str(section.name)))
                return

            # we only print symbol version index if the versym section
            # exists and if it refers to the current section
            versioning = (versym_section and section == linked_section)

            self._emitline(
                "\nSymbol Table Section:  %s" % bytes2str(section.name))
            self._emitline(
                'index    value      size      type bind oth ver shndx'
                '          name')

            for nsym, symbol in enumerate(section.iter_symbols()):
                if versioning:
                    version_index = versym_section.get_symbol(nsym)['ndx']
                else:
                    version_index = 0

                self._emit_symbol(nsym, symbol, version_index)

    def display_sort_index_sections(self):

        symbol_sort_sections = self._find_sections(SUNWSymbolSortSection)
        if not symbol_sort_sections:
            return

        for section in symbol_sort_sections:

            if section['sh_entsize'] == 0:
                self._emitline(
                    "\nSymbol sort index section '%s' "
                    "has a sh_entsize of zero!" % (bytes2str(section.name)))
                return

            # we first look for the versym section and the SUNW_ldynsym section
            # to be able to correctly display the version index of each symbol
            versym_section = self._find_section(GNUVerSymSection)
            ldynsym_section = self.elffile.get_section_by_name('.SUNW_ldynsym')
            if ldynsym_section:
                num_local_symbols = ldynsym_section.num_symbols()
            else:
                num_local_symbols = 0

            self._emitline(
                "\nSymbol Sort Section:  %s (.SUNW_ldynsym / .dynsym)" %
                bytes2str(section.name))
            self._emitline(
                '     index    value              size              type'
                ' bind oth ver shndx          name')

            for index in range(section.num_symbols()):
                real_index = section.get_symbol_index(index)
                symbol = section.get_symbol(index)

                if versym_section and real_index > num_local_symbols:
                    nsym = real_index - num_local_symbols
                    version_index = versym_section.get_symbol(nsym)['ndx']
                else:
                    version_index = 0

                self._emit_symbol(real_index, symbol, version_index)

    def _emit(self, s=''):
        """ Emit an object to output
        """
        self.output.write(str(s))

    def _emitline(self, s=''):
        """ Emit an object to output, followed by a newline
        """
        self.output.write(str(s) + '\n')


SCRIPT_DESCRIPTION = 'Dumps selected parts of an object file'
VERSION_STRING = '%%prog: based on pyelftools %s' % __version__


def main(stream=None):
    # parse the command-line arguments and invoke ReadElf
    optparser = OptionParser(
        usage='usage: %prog [options] <elf-file>',
        description=SCRIPT_DESCRIPTION,
        add_help_option=False,  # -h is a real option of elfdump
        prog='elfdump.py',
        version=VERSION_STRING)
    optparser.add_option('--help',
                         action='store_true', dest='help',
                         help='Display this information')
    optparser.add_option('-s',
                         action='store_true', dest='show_symbols',
                         help='dump the contents of the  .SUNW_ldynsym,'
                              ' .dynsym and .symtab symbol table sections.')
    optparser.add_option('-S',
                         action='store_true', dest='show_sortedsymbols',
                         help='dump the contents of the sort index sections')
    optparser.add_option('-y',
                         action='store_true', dest='show_syminfo',
                         help='dump the contents of the .SUNW_syminfo section')
    optparser.add_option('-v',
                         action='store_true', dest='show_version',
                         help='dump the contents of the version sections')

    options, args = optparser.parse_args()

    if options.help or len(args) == 0:
        optparser.print_help()
        sys.exit(0)

    with open(args[0], 'rb') as file:
        try:
            elfdump = Elfdump(file, stream or sys.stdout)
            if options.show_version:
                elfdump.display_version_tables()
            if options.show_symbols:
                elfdump.display_symbol_tables()
            if options.show_syminfo:
                elfdump.display_syminfo_table()
            if options.show_sortedsymbols:
                elfdump.display_sort_index_sections()
        except ELFError as ex:
            sys.stderr.write('ELF error: %s\n' % ex)
            sys.exit(1)


def profile_main():
    # Run 'main' redirecting its output to elfdumpout.txt
    # Saves profiling information in elfdump.profile
    PROFFILE = 'elfdump.profile'
    import cProfile
    cProfile.run('main(open("elfdumpout.txt", "w"))', PROFFILE)

    # Dig in some profiling stats
    import pstats
    p = pstats.Stats(PROFFILE)
    p.sort_stats('cumulative').print_stats(25)


#------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
    #profile_main()
