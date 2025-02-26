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
        self.bzd = nsisunbz2.core.Bz2Decompress(data)

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
        self.bzd._run_block('origptr')

        self.assertEqual(self.bzd.origptr, 0xd0b)

    def test_mapping_table(self):
        """Test that the mapping table is received properly from the compressed stream."""
        self.bzd._run_block('mapping_table')

        self.assertEqual(self.bzd.ninuse, 158)

        e = self.d.joinpath('mapping_table_seqtounseq.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.seqtounseq, expected)

        self.assertEqual(self.bzd.alphasize, 160)

    def test_selectors(self):
        """Test that the selectors received properly from the compressed stream."""
        self.bzd._run_block('selectors')

        self.assertEqual(self.bzd.ngroups, 5)

        self.assertEqual(self.bzd.nselectors, 37)

        expected = [0, 0, 1, 4, 2, 2, 2, 0, 1, 1, 1, 2, 1, 1, 4, 1, 4, 1, 2, 4, 2, 4,
                    1, 1, 1, 1, 4, 1, 0, 0, 2, 2, 2, 2, 2, 0, 0] + [0] * 17965
        self.assertListEqual(self.bzd.selector, expected)

    def test_coding_tables(self):
        """Test that the coding tables are received properly from the compressed stream."""
        self.bzd._run_block('coding_tables')

        e = self.d.joinpath('coding_table_len.json').read_text()
        expected = json.loads(e)
        self.assertListEqual(self.bzd.len, expected)

    def test_huffman_tables(self):
        """Test that the huffman tables are created properly from the compressed stream."""
        self.bzd._run_block('huffman_tables')

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

    def test_mtf(self):
        """Test that the move-to-front function is working properly."""
        self.bzd._run_block('mtf')

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
        self.bzd._run_block('cftable')

        e = self.d.joinpath('cftable_tt.json').read_text()
        expected = json.loads(e)
        tt = [z for z in self.bzd.tt if z]
        self.assertListEqual(tt, expected)

    def test_end_header(self):
        """Test that the correct end header is present after decompression is complete."""
        self.bzd._run_block()
        uc = self.bzd._get_bits(8, 'BZ_X_ENDHDR_1')
        self.assertEqual(uc, 0x17)

    def test_decompress(self):
        """Test that the full run of the decompression class completes correctly."""
        output_data = self.bzd.decompress()

        sha256 = hashlib.sha256(output_data).hexdigest()
        self.assertEqual(sha256, 'eeaefe8c8a5d42855d886e5368d5c752a03d821681c7b2ceb5d900aa6cf70e18')


class TestBz2DecompressSolid(unittest.TestCase):
    """Check decompression class for solid archives."""

    def setUp(self):
        self.d = importlib.resources.files('tests.data')
        full_data = bytes()
        for i in range(1, 5):
            full_data += self.d.joinpath(f'compressed.bin.part{i}').read_bytes()
        self.bzd = nsisunbz2.core.Bz2Decompress(full_data)

    def test_decompress(self):
        """Test that the full run of the decompression class completes correctly."""
        output_data = self.bzd.decompress(0x128db6)

        sha256 = hashlib.sha256(output_data).hexdigest()
        self.assertEqual(sha256, '779eaf9696a6edffd5aadf9b9e01b8550bbbaf55c84890dbb060606819fa6d17')


if __name__ == '__main__':
    unittest.main()
