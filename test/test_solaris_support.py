#-------------------------------------------------------------------------------
# elftools tests
#
# Yann Rouillard (yann@pleiades.fr.eu.org)
# This code is in the public domain
#-------------------------------------------------------------------------------
try:
    import unittest2 as unittest
except ImportError:
    import unittest
import os
import copy

from utils import setup_syspath; setup_syspath()
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SUNW_SYMINFO_FLAGS


class TestSolarisSupport(unittest.TestCase):

    def _test_SUNW_syminfo_section_generic(self, testfile):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               testfile), 'rb') as f:
            elf = ELFFile(f)
            syminfo_section = elf.get_section_by_name(b'.SUNW_syminfo')
            self.assertIsNotNone(syminfo_section)

            # The test files were compiled against libc.so.1 with
            # direct binding, hence the libc symbols used
            # (exit, atexit and _exit) have the direct binding flags
            # in the syminfo table.
            # We check that this is properly detected.
            exit_symbols = [s for s in syminfo_section.iter_symbols()
                            if b'exit' in s.name]
            self.assertNotEqual(len(exit_symbols), 0)

            for symbol in exit_symbols:
                # libc.so.1 has the index 0 in the dynamic table
                self.assertEqual(symbol['si_boundto'], 0)
                self.assertEqual(symbol['si_flags'],
                                 SUNW_SYMINFO_FLAGS.SYMINFO_FLG_DIRECT |
                                 SUNW_SYMINFO_FLAGS.SYMINFO_FLG_DIRECTBIND)

    def test_SUNW_syminfo_section_x86(self):
        self._test_SUNW_syminfo_section_generic('exe_solaris32_cc.elf')

    def test_SUNW_syminfo_section_x64(self):
        self._test_SUNW_syminfo_section_generic('exe_solaris64_cc.elf')

    def test_SUNW_syminfo_section_sparc32(self):
        self._test_SUNW_syminfo_section_generic('exe_solaris32_cc.elf.sparc')

    def test_SUNW_syminfo_section_sparc64(self):
        self._test_SUNW_syminfo_section_generic('exe_solaris64_cc.elf.sparc')

    ldsynsym_reference_data = ['', 'exe_solaris32.elf', 'crti.s', 'crt1.o',
                               'crt1.s', 'fsr.s', 'values-Xa.c',
                               'exe_solaris64.elf.c', 'crtn.s']

    def _test_SUNW_ldynsym_section_generic(self, testfile, reference_data):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               testfile), 'rb') as f:
            elf = ELFFile(f)
            ldynsym_section = elf.get_section_by_name(b'.SUNW_ldynsym')
            self.assertIsNotNone(ldynsym_section)

            for symbol, ref_symbol_name in zip(
                    ldynsym_section.iter_symbols(), reference_data):

                self.assertEqual(symbol.name, ref_symbol_name)

    def test_SUNW_ldynsym_section_x86(self):
        reference_data = TestSolarisSupport.ldsynsym_reference_data
        self._test_SUNW_ldynsym_section_generic('exe_solaris32_cc.elf',
                                                reference_data)

    def test_SUNW_ldynsym_section_x64(self):
        reference_data = copy.deepcopy(
            TestSolarisSupport.ldsynsym_reference_data)
        reference_data[1] = 'exe_solaris64.elf'
        reference_data[3] = 'crt1x.o'
        reference_data[5] = 'fsrx.s'
        self._test_SUNW_ldynsym_section_generic('exe_solaris64_cc.elf',
                                                reference_data)

    dynsymsort_reference_data_32 = (
        (12, 0x0805087c, '_PROCEDURE_LINKAGE_TABLE_'),
        (29, 0x080508d0, '_start'),
        (27, 0x08050948, '__fsr'),
        (19, 0x080509e0, 'main'),
        (17, 0x08050a00, '_init'),
        (31, 0x08050a1c, '_fini'),
        (23, 0x08050a38, '_lib_version'),
        (21, 0x08060a3c, '_GLOBAL_OFFSET_TABLE_'),
        (13, 0x08060a58, '_DYNAMIC'),
        (11, 0x08060bb0, 'environ'),
        (32, 0x08060bb4, '__environ_lock'),
        (14, 0x08060bcc, '___Argv'),
        (10, 0x08060bd0, '__xargc'),
        (22, 0x08060bd4, '__xargv'),
        (33, 0x08060bd8, '__longdouble_used'),
        (30, 0x08060bfc, '_end'))

    dynsymsort_reference_data_64 = (
        (12, 0x0000000000400a80, '_PROCEDURE_LINKAGE_TABLE_'),
        (26, 0x0000000000400ac0, '_start'),
        (23, 0x0000000000400b4d, '__fsr'),
        (31, 0x0000000000400cb0, 'main'),
        (24, 0x0000000000400ce0, '_init'),
        (25, 0x0000000000400d08, '_fini'),
        (29, 0x0000000000400d2c, '_lib_version'),
        (15, 0x0000000000410d60, '_DYNAMIC'),
        (17, 0x0000000000411010, 'environ'),
        (28, 0x0000000000411018, '__environ_lock'),
        (30, 0x0000000000411030, '___Argv'),
        (19, 0x0000000000411038, '__xargv'),
        (18, 0x0000000000411040, '__xargc'),
        (16, 0x0000000000411044, '__longdouble_used'),
        (14, 0x0000000000411068, '_end'))

    def _test_SymbolSort_section_generic(self, testfile, reference_data):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               testfile), 'rb') as f:
            elf = ELFFile(f)
            dynsymsort_section = elf.get_section_by_name(b'.SUNW_dynsymsort')
            self.assertIsNotNone(dynsymsort_section)

            for index, ref_data in enumerate(reference_data):
                self.assertEqual(dynsymsort_section.get_symbol_index(index),
                                 ref_data[0])
                self.assertEqual(dynsymsort_section.get_symbol(index).name,
                                 ref_data[2])
                symbol = dynsymsort_section.find_symbol(ref_data[1])
                self.assertEqual(symbol.name, ref_data[2])

    def test_SymbolSort_section_x86(self):
        self._test_SymbolSort_section_generic(
            'exe_solaris32_cc.elf',
            TestSolarisSupport.dynsymsort_reference_data_32)

    def test_SymbolSort_section_x64(self):
        self._test_SymbolSort_section_generic(
            'exe_solaris64_cc.elf',
            TestSolarisSupport.dynsymsort_reference_data_64)

if __name__ == '__main__':
    unittest.main()
