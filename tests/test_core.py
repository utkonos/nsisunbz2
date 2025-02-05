"""NSIS Bzip2 decompression core module unit tests."""
import hashlib
import importlib.resources
import json
import unittest

import nsisunbz2.core


class TestBz2Decompress(unittest.TestCase):
    """Check decompression class for problems at each stage."""

    def setUp(self):
        self.d = importlib.resources.files('tests.data')
        data = self.d.joinpath('setup1.bz2').read_bytes()
        self.bzd = nsisunbz2.core.Bz2Decompress(data, 0x1728)

    def test_get_bits(self):
        """Test that the get bits function can pull bits from the compressed stream."""
        uc = self.bzd._get_bits(8, 'BZ_X_BLKHDR_1')
        self.assertEqual(uc, 0x31)

        uc = self.bzd._get_bits(8, 'BZ_X_ORIGPTR_1')
        self.assertEqual(uc, 0x0)

        uc = self.bzd._get_bits(8, 'BZ_X_ORIGPTR_2')
        self.assertEqual(uc, 0xd)

        uc = self.bzd._get_bits(8, 'BZ_X_ORIGPTR_3')
        self.assertEqual(uc, 0xb)

    def test_origptr(self):
        """Test that the origin pointer is read properly from the compressed stream."""
        self.bzd.run('origptr')

        self.assertEqual(self.bzd.origptr, 0xd0b)

    def test_mapping_table(self):
        """Test that the mapping table is received properly from the compressed stream."""
        self.bzd.run('mapping_table')

        self.assertEqual(self.bzd.ninuse, 158)

        e = self.d.joinpath('mapping_table_seqtounseq.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.seqtounseq, expected)

        self.assertEqual(self.bzd.alphasize, 160)

    def test_selectors(self):
        """Test that the selectors received properly from the compressed stream."""
        self.bzd.run('selectors')

        self.assertEqual(self.bzd.ngroups, 5)

        self.assertEqual(self.bzd.nselectors, 37)

        expected = [0, 0, 1, 4, 2, 2, 2, 0, 1, 1, 1, 2, 1, 1, 4, 1, 4, 1, 2, 4, 2, 4,
                    1, 1, 1, 1, 4, 1, 0, 0, 2, 2, 2, 2, 2, 0, 0] + [0] * 17965
        self.assertListEqual(self.bzd.selector, expected)

    def test_coding_tables(self):
        """Test that the coding tables are received properly from the compressed stream."""
        self.bzd.run('coding_tables')

        e = self.d.joinpath('coding_table_len.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.len, expected)

    def test_huffman_tables(self):
        """Test that the huffman tables are created properly from the compressed stream."""
        self.bzd.run('huffman_tables')

        e = self.d.joinpath('huffman_tables_perm.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.perm, expected)

        e = self.d.joinpath('huffman_tables_base.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.base, expected)

        e = self.d.joinpath('huffman_tables_limit.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.limit, expected)

        expected = [3, 3, 2, 7, 2, 0]
        self.assertListEqual(self.bzd.minlens, expected)

    def test_mtf_init(self):
        """Test that the move to front lists are initialized properly."""
        self.bzd.run('mtf_init')

        e = self.d.joinpath('mtf_base_mtfa.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.mtfa, expected)

        expected = [3840, 3856, 3872, 3888, 3904, 3920, 3936, 3952, 3968, 3984, 4000, 4016, 4032, 4048, 4064, 4080]
        self.assertListEqual(self.bzd.mtfbase, expected)

    def test_first_mtf(self):
        """Test that the first move to front cycle completed properly."""
        self.bzd.run('first_mtf')

        self.assertEqual(self.bzd.grouppos, 49)
        self.assertEqual(self.bzd.groupno, 0)
        self.assertEqual(self.bzd.gsel, 0)
        self.assertEqual(self.bzd.gminlen, 3)

        e = self.d.joinpath('first_mtf_glimit.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.glimit, expected)

        e = self.d.joinpath('first_mtf_gperm.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.gperm, expected)

        e = self.d.joinpath('first_mtf_gbase.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.gbase, expected)

        self.assertEqual(self.bzd.nextsym, 157)

    def test_decompress(self):
        """Test that the main decompression function is working properly."""
        self.bzd.run('decompress')

        self.assertEqual(self.bzd.nblock, 3592)

        e = self.d.joinpath('decompress_unzftab.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.unzftab, expected)

        e = self.d.joinpath('decompress_tt.json').read_text()
        expected = json.loads(e)
        tt = [z for z in self.bzd.tt if z]
        self.assertListEqual(tt, expected)

    def test_cftable(self):
        """Test that the cumulative frequency table was applied correctly."""
        self.bzd.run('cftable')

        e = self.d.joinpath('cftable_tt.json').read_text()
        expected = json.loads(e)
        tt = [z for z in self.bzd.tt if z]
        self.assertListEqual(tt, expected)

    def test_tpos(self):
        """Test that the starting position for the inverse Burrows-Wheeler Transform is calculated properly."""
        self.bzd.run('tpos')

        self.assertEqual(self.bzd.k0, 128)
        self.assertEqual(self.bzd.tpos, 268)
        self.assertEqual(self.bzd.nblock_used, 1)

    def test_unrle(self):
        """Test that the run-length encoding is reversed properly."""
        self.bzd.run('unrle')

        sha256 = hashlib.sha256(self.bzd.out).hexdigest()
        self.assertEqual(sha256, 'eeaefe8c8a5d42855d886e5368d5c752a03d821681c7b2ceb5d900aa6cf70e18')

    def test_end_header(self):
        """Test that the correct end header is present after decompression is complete."""
        self.bzd.run('end_header')
        uc = self.bzd._get_bits(8, 'BZ_X_ENDHDR_1')
        self.assertEqual(uc, 0x17)

    def test_run(self):
        """Test that the full run of the decompression class completes correctly."""
        self.bzd.run()

        sha256 = hashlib.sha256(self.bzd.out).hexdigest()
        self.assertEqual(sha256, 'eeaefe8c8a5d42855d886e5368d5c752a03d821681c7b2ceb5d900aa6cf70e18')


if __name__ == '__main__':
    unittest.main()
