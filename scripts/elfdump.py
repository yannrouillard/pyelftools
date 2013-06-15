#!/opt/csw/bin/python
#-------------------------------------------------------------------------------
# scripts/elfdump.py
#
# A clone of 'elfdump' in Python, based on the pyelftools library
#
# Eli Bendersky (eliben@gmail.com)
# Yann Rouillard (yann@pleiades.fr.eu.org)
# This code is in the public domain
#-------------------------------------------------------------------------------
import os, sys
from optparse import OptionParser
import string

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')


from elftools import __version__
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import (
        ifilter, byte2int, bytes2str, itervalues, str2bytes)
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.constants import SUNW_SYMINFO_FLAGS
from elftools.elf.segments import InterpSegment
from elftools.elf.sections import SUNWSyminfoTableSection
from elftools.elf.gnuversions import (
        GNUVerNeedSection, GNUVerDefSection)
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_syminfo_flags, describe_symbol_boundto, describe_ver_flags,
    )
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.descriptions import (
    describe_reg_name, describe_attr_value, set_global_machine_arch,
    describe_CFI_instructions, describe_CFI_register_rule,
    describe_CFI_CFA_rule,
    )
from elftools.dwarf.constants import (
    DW_LNS_copy, DW_LNS_set_file, DW_LNE_define_file)
from elftools.dwarf.callframe import CIE, FDE


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

    def display_version_tables(self):
        """ Display the SUNW verneed and verdef tables contained in the file
        """
        verneed_section = None
        verdef_section = None
        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerNeedSection):
                verneed_section = section
            elif isinstance(section, GNUVerDefSection):
                verdef_section = section

        # Version definition section
        if verdef_section:

            self._emitline("\nVersion Definition Section:  %s" % verdef_section.name)
            self._emitline('     index  version                     dependency')

            for verdef, verdaux_iter in verdef_section.iter_versions():

                # The first verdaux entry is mandatory, it contains the version name
                # of the current version definition
                verdaux = next(verdaux_iter)
    
                if verdef['vd_cnt'] > 1:
                    # Additional verdaux entries are dependencies of the current version
                    # the first one is displayed on the same line
                    dependency = next(verdaux_iter)
                    dependency_name = dependency.name
                else:
                    dependency_name = ''

                flags_desc = describe_ver_flags(verdef['vd_flags'])
                if flags_desc:
                    flags_desc = '[ %s ]' % flags_desc

                self._emitline('%10.10s  %-26.26s  %-20s %s' % (
                    '[%i]' % verdef['vd_ndx'], verdaux.name, 
                    dependency_name, flags_desc))

                for verdaux in verdaux_iter:
                    # additional dependencies are displayed one by line
                    self._emitline('%47s  %s' % ('', verdaux.name))

        # Version dependency section
        if verneed_section:

            self._emitline("\nVersion Needed Section:  %s" % verneed_section.name)

            if verneed_section.has_indexes():
                self._emitline('     index  file                        version')
            else:
                self._emitline('            file                        version')

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
                        index, filename, vernaux.name, flags_desc))

                    # we only display the filename for the first version name
                    # related to this file
                    filename = ''


    def display_syminfo_table(self):
        """ Display the SUNW syminfo tables contained in the file
        """
        syminfo_section = None
        for section in self.elffile.iter_sections():
            if isinstance(section, SUNWSyminfoTableSection):
               syminfo_section = section
               break

        if syminfo_section:
            # The symbol table section pointed to in sh_link
            dyntable = self.elffile.get_section_by_name('.dynamic')

            if section['sh_entsize'] == 0:
                self._emitline("\nSymbol table '%s' has a sh_entsize of zero!" % (
                    bytes2str(section.name)))
                return

            # The symbol table section pointed to in sh_link
            symtable = self.elffile.get_section(section['sh_link'])

            self._emitline("\nSyminfo Section:  %s" % bytes2str(section.name))
            self._emitline('     index  flags            bound to                 symbol')

            for nsym, syminfo in enumerate(section.iter_symbols(), start=1):

                if not (syminfo['si_flags'] or syminfo['si_boundto']):
                    continue

                index = ''
                if syminfo['si_flags'] & SUNW_SYMINFO_FLAGS.SYMINFO_FLG_CAP:
                    boundto = '<symbol capabilities>'
                elif not isinstance(syminfo['si_boundto'], int):
                    boundto = describe_symbol_boundto(syminfo['si_boundto'])
                else:
                    dyn_tag = dyntable.get_tag(syminfo['si_boundto'])
                    if syminfo['si_flags'] & SUNW_SYMINFO_FLAGS.SYMINFO_FLG_FILTER:
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
            add_help_option=False,  # -h is a real option of readelf
            prog='elfdump.py',
            version=VERSION_STRING)
    optparser.add_option('--help',
            action='store_true', dest='help',
            help='Display this information')
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
            readelf = Elfdump(file, stream or sys.stdout)
            if options.show_version:
                readelf.display_version_tables()
            if options.show_syminfo:
                readelf.display_syminfo_table()
        except ELFError as ex:
            sys.stderr.write('ELF error: %s\n' % ex)
            sys.exit(1)


def profile_main():
    # Run 'main' redirecting its output to readelfout.txt
    # Saves profiling information in readelf.profile
    PROFFILE = 'elfdump.profile'
    import cProfile
    cProfile.run('main(open("elfdumpout.txt", "w"))', PROFFILE)

    # Dig in some profiling stats
    import pstats
    p = pstats.Stats(PROFFILE)
    p.sort_stats('cumulative').print_stats(25)


#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
    #profile_main()
