"""A pure Python implementation of Bzip2 decompression based on the NSIS source fork.

/*
 * Copyright and license information can be found below.
 * Modifications Copyright (C) 1999-2025 Nullsoft and Contributors
 *
 * The original zlib source code is available at
 * http://www.bzip.org/
 *
 * This modification is not compatible with the original bzip2.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.
 *
 * Reviewed for Unicode support by Jim Park -- 08/23/2007
 */

/*--
  This file is a part of bzip2 and/or libbzip2, a program and
  library for lossless, block-sorting data compression.

  Copyright (C) 1996-2000 Julian R Seward.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. The origin of this software must not be misrepresented; you must
     not claim that you wrote the original software.  If you use this
     software in a product, an acknowledgment in the product
     documentation would be appreciated but is not required.

  3. Altered source versions must be plainly marked as such, and must
     not be misrepresented as being the original software.

  4. The name of the author may not be used to endorse or promote
     products derived from this software without specific prior written
     permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Julian Seward, Cambridge, UK.
  jseward@acm.org
  bzip2/libbzip2 version 1.0 of 21 March 2000

  This program is based on (at least) the work of:
     Mike Burrows
     David Wheeler
     Peter Fenwick
     Alistair Moffat
     Radford Neal
     Ian H. Witten
     Robert Sedgewick
     Jon L. Bentley

  For more information on these sources, see the manual.
--*/
"""
import io

# Constants from NSIS header files
NSIS_COMPRESS_BZIP2_LEVEL = 9
BZ_G_SIZE = 50
BZ_MAX_SELECTORS = int(2 + (900000 / BZ_G_SIZE))
BZ_N_GROUPS = 6
BZ_MAX_ALPHA_SIZE = 258
BZ_MAX_CODE_LEN = 23
MTFA_SIZE = 4096
MTFL_SIZE = 16
BZ_RUNA = 0
BZ_RUNB = 1


class UnRLE:
    """Remove run length encoding from compressed data."""

    def __init__(self, avail_out, tt, nblock, nblock_used, k0, tpos):
        self.out_ch = 0
        self.out_len = 0

        self.nblock_used = nblock_used
        self.k0 = k0
        self.tpos = tpos
        self.tt = tt
        self.nblockpp = nblock + 1

        self.avail_out = avail_out
        self.next_out = bytearray()

        self.k1 = None

    def _op1(self):
        if self.avail_out == 0:
            return True
        if self.out_len == 1:
            return False
        self.next_out.append(self.out_ch)
        self.out_len -= 1
        self.avail_out -= 1

    def _op2(self):
        if self.avail_out == 0:
            self.out_len = 1
            return True
        self.next_out.append(self.out_ch)
        self.avail_out -= 1

    def _op3(self):
        if self.nblock_used == self.nblockpp:
            self.out_len = 0
            return True
        self.out_ch = self.k0
        self.tpos = self.tt[self.tpos]
        self.k1 = self.tpos & 0xff
        self.tpos >>= 8
        self.nblock_used += 1

    def _op4(self):
        if self._op2():
            return True
        if self._op3():
            return True
        if self.k1 != self.k0:
            self.k0 = self.k1
            if self._op4():
                return True
            return False
        if self.nblock_used == self.nblockpp:
            if self._op4():
                return True
            return False

        self._op5()

    def _op5(self):
        self.out_len = 2
        self.tpos = self.tt[self.tpos]
        self.k1 = self.tpos & 0xff
        self.tpos >>= 8
        self.nblock_used += 1
        if self.nblock_used == self.nblockpp:
            return
        if self.k1 != self.k0:
            self.k0 = self.k1
            return

        self.out_len = 3
        self.tpos = self.tt[self.tpos]
        self.k1 = self.tpos & 0xff
        self.tpos >>= 8
        self.nblock_used += 1
        if self.nblock_used == self.nblockpp:
            return
        if self.k1 != self.k0:
            self.k0 = self.k1
            return

        self.tpos = self.tt[self.tpos]
        self.k1 = self.tpos & 0xff
        self.tpos >>= 8
        self.nblock_used += 1
        self.out_len = self.k1 + 4
        self.tpos = self.tt[self.tpos]
        self.k0 = self.tpos & 0xff
        self.tpos >>= 8
        self.nblock_used += 1

    def run(self):
        """Remove run-length encoding and return fully decompressed data."""
        while True:
            if self.out_len > 0:
                while True:
                    match self._op1():
                        case False:
                            break
                        case True:
                            return self.next_out
                if self._op2():
                    return self.next_out
            if self._op3():
                return self.next_out
            if self.k1 != self.k0:
                self.k0 = self.k1
                if self._op4():
                    return self.next_out
                continue
            if self.nblock_used == self.nblockpp:
                if self._op4():
                    return self.next_out
                continue

            self._op5()

        return self.next_out


class Bz2Decompress:
    """Core decompression class containing all the steps for Bzip2."""

    def __init__(self, data, avail_out):
        if not isinstance(data, bytes):
            raise TypeError('Input must be bytes')
        self.f = io.BytesIO(data)
        self.avail_out = avail_out

        self.bslive = 0
        self.bsbuff = 0

        self.origptr = None

        self.ninuse = None
        self.seqtounseq = None
        self.alphasize = None

        self.ngroups = None
        self.nselectors = None
        self.selector = None

        self.len = None

        self.perm = None
        self.base = None
        self.limit = None
        self.minlens = None

        self.mtfa = None
        self.mtfbase = None

        self.grouppos = None
        self.groupno = None
        self.gsel = None
        self.gminlen = None
        self.glimit = None
        self.gperm = None
        self.gbase = None
        self.nextsym = None

        self.nblock = None
        self.unzftab = None
        self.tt = None

        self.k0 = None
        self.tpos = None
        self.nblock_used = None

        self.out = None

    def _get_bits(self, n, err=None):
        """Read n bits from the compressed data."""
        while True:
            if self.bslive >= n:
                v = (self.bsbuff >> (self.bslive - n)) & ((1 << n) - 1)
                self.bslive -= n

                return v

            next_in = self.f.read(1)
            if not len(next_in):
                raise RuntimeError(f'BZ_DATA_ERROR: {err} not found')

            self.bsbuff = (self.bsbuff << 8) | int.from_bytes(next_in)
            self.bslive += 8

    def _block_header(self):
        """Check that the compressed stream starts with the correct abbreviated NSIS Bzip2 block header."""
        uc = self._get_bits(8, 'BZ_X_BLKHDR_1')

        if uc != 0x31:
            raise RuntimeError('BZ_DATA_ERROR: Block header BZ_X_BLKHDR_1 not found')

    def _origptr(self):
        """Construct the origin pointer."""
        origptr = 0
        uc = self._get_bits(8, 'BZ_X_ORIGPTR_1')
        origptr = (origptr << 8) | uc
        uc = self._get_bits(8, 'BZ_X_ORIGPTR_2')
        origptr = (origptr << 8) | uc
        uc = self._get_bits(8, 'BZ_X_ORIGPTR_3')
        origptr = (origptr << 8) | uc

        if origptr < 0:
            raise RuntimeError('BZ_DATA_ERROR: Origin pointer is negative')
        if origptr > 10 + NSIS_COMPRESS_BZIP2_LEVEL * 100000:
            raise RuntimeError('BZ_DATA_ERROR: Origin pointer is too large')

        self.origptr = origptr

    def _mapping_table(self):
        """Receive the mapping table."""
        inuse16 = list()
        for i in range(16):
            uc = self._get_bits(1, 'BZ_X_MAPPING_1')
            if uc == 1:
                inuse16.append(True)
            else:
                inuse16.append(False)

        inuse = [False] * 256
        for i in range(16):
            if inuse16[i]:
                for j in range(16):
                    uc = self._get_bits(1, 'BZ_X_MAPPING_2')
                    if uc == 1:
                        inuse[i * 16 + j] = True

        ninuse = 0
        seqtounseq = [0] * 256
        for qi in range(256):
            if inuse[qi]:
                seqtounseq[ninuse] = qi
                ninuse += 1

        if ninuse == 0:
            raise RuntimeError('BZ_DATA_ERROR: ninuse is zero')

        self.ninuse = ninuse
        self.seqtounseq = seqtounseq
        self.alphasize = ninuse + 2

    def _selectors(self):
        """Get the selectors."""
        ngroups = self._get_bits(3, 'BZ_X_SELECTOR_1')
        if ngroups < 2 or ngroups > 6:
            raise RuntimeError('BZ_DATA_ERROR: Invalid number of groups')

        nselectors = self._get_bits(15, 'BZ_X_SELECTOR_2')
        if nselectors < 1:  # Maybe this can be nselectors == 0 ?
            raise RuntimeError('BZ_DATA_ERROR: Invalid number of selectors')

        selectormtf = [0] * BZ_MAX_SELECTORS
        for i in range(nselectors):
            j = 0
            while True:
                uc = self._get_bits(1, 'BZ_X_SELECTOR_3')
                if uc == 0:  # Why not store this value as 3 bits rather than a set of bits?
                    break    # It can only be the number of groups which is already stored as 3 bits above.
                j += 1
                if j >= ngroups:
                    raise RuntimeError('BZ_DATA_ERROR: Invalid selectorMtf value')
            selectormtf[i] = j

        # Undo the MTF values for the selectors.
        pos = [0] * BZ_N_GROUPS

        for i in range(ngroups):
            pos[i] = i

        selector = [0] * BZ_MAX_SELECTORS

        for i in range(nselectors):
            v = selectormtf[i]
            tmp = pos[v]
            while v > 0:
                pos[v] = pos[v-1]
                v -= 1
            pos[0] = tmp
            selector[i] = tmp

        self.ngroups = ngroups
        self.nselectors = nselectors
        self.selector = selector

    def _coding_tables(self):
        """Get the coding tables."""
        lenn = [[0 for _ in range(BZ_MAX_ALPHA_SIZE)] for _ in range(BZ_N_GROUPS)]
        for i in range(self.ngroups):
            curr = self._get_bits(5, 'BZ_X_CODING_1')
            for j in range(self.alphasize):
                while True:
                    if curr < 1 or curr > 20:
                        raise RuntimeError('BZ_DATA_ERROR: Value curr outside of acceptable range')
                    uc = self._get_bits(1, 'BZ_X_CODING_2')
                    if uc == 0:
                        break
                    uc = self._get_bits(1, 'BZ_X_CODING_3')
                    if uc == 0:
                        curr += 1
                    else:
                        curr -= 1
                lenn[i][j] = curr

        self.len = lenn

    def _huffman_tables(self):
        """Create the Huffman decoding tables."""
        ln = [[0 for _ in range(BZ_MAX_ALPHA_SIZE)] for _ in range(BZ_N_GROUPS)]
        b = [[0 for _ in range(BZ_MAX_ALPHA_SIZE)] for _ in range(BZ_N_GROUPS)]
        p = [[0 for _ in range(BZ_MAX_ALPHA_SIZE)] for _ in range(BZ_N_GROUPS)]

        minlens = [0] * BZ_N_GROUPS

        for t in range(self.ngroups):
            minlen = 32
            maxlen = 8
            for i in range(self.alphasize):
                if self.len[t][i] > maxlen:
                    maxlen = self.len[t][i]
                if self.len[t][i] < minlen:
                    minlen = self.len[t][i]

            limit = ln[t]
            base = b[t]
            perm = p[t]
            length = self.len[t]

            pp = 0
            for i in range(minlen, maxlen + 1):
                for j in range(self.alphasize):
                    if length[j] == i:
                        perm[pp] = j
                        pp += 1

            for i in range(BZ_MAX_CODE_LEN):
                base[i] = 0

            for i in range(self.alphasize):
                base[length[i] + 1] += 1

            for i in range(BZ_MAX_CODE_LEN):
                base[i] += base[i - 1]

            for i in range(BZ_MAX_CODE_LEN):
                limit[i] = 0

            vec = 0
            for i in range(minlen, maxlen + 1):
                vec += base[i + 1] - base[i]
                limit[i] = vec - 1
                vec <<= 1

            for i in range(minlen + 1, maxlen + 1):
                base[i] = ((limit[i - 1] + 1) << 1) - base[i]

            minlens[t] = minlen

        self.limit = ln
        self.base = b
        self.perm = p

        self.minlens = minlens

    def _mtf_init(self):
        """Initialize the move to front lists."""
        mtfa = [0] * MTFA_SIZE
        mtfbase = [0] * int(256 / MTFL_SIZE)

        k = MTFA_SIZE - 1

        for i in reversed(range(int(256 / MTFL_SIZE))):
            for j in reversed(range(MTFL_SIZE)):
                mtfa[k] = i * MTFL_SIZE + j
                k -= 1
            mtfbase[i] = k + 1

        self.mtfa = mtfa
        self.mtfbase = mtfbase

    def _first_mtf(self):
        """Perform first move to front cycle."""
        grouppos = 0
        groupno = -1
        gsel = 0
        gminlen = 0
        glimit = 0
        gperm = 0
        gbase = 0

        if grouppos == 0:
            groupno += 1
            if groupno >= self.nselectors:
                raise RuntimeError('BZ_DATA_ERROR: Number of groups larger than number of selectors')
            grouppos = BZ_G_SIZE
            gsel = self.selector[groupno]
            gminlen = self.minlens[gsel]
            glimit = self.limit[gsel]
            gperm = self.perm[gsel]
            gbase = self.base[gsel]
        grouppos -= 1
        zn = gminlen

        zvec = self._get_bits(zn, 'BZ_X_MTF_1')

        while True:
            if zn > 20:
                raise RuntimeError('BZ_DATA_ERROR: Value zv too large')
            if zvec <= glimit[zn]:
                break
            zn += 1
            zj = self._get_bits(1, 'BZ_X_MTF_2')
            zvec = (zvec << 1) | zj

        if zvec - gbase[zn] < 0 or zvec - gbase[zn] >= BZ_MAX_ALPHA_SIZE:
            raise RuntimeError('BZ_DATA_ERROR: Value zvec outside of acceptable range')

        nextsym = gperm[zvec - gbase[zn]]

        self.grouppos = grouppos
        self.groupno = groupno
        self.gsel = gsel
        self.gminlen = gminlen
        self.glimit = glimit
        self.gperm = gperm
        self.gbase = gbase
        self.nextsym = nextsym

    def _decompress(self):
        """Perform the remaining decompression phases."""
        unzftab = [0] * 256
        tt = [0] * NSIS_COMPRESS_BZIP2_LEVEL * 100000
        eob = self.ninuse + 1
        nblock = 0
        nblockmax = NSIS_COMPRESS_BZIP2_LEVEL * 100_000

        while True:
            if self.nextsym == eob:
                break

            if self.nextsym == BZ_RUNA or self.nextsym == BZ_RUNB:
                es = -1
                n = 1

                while self.nextsym == BZ_RUNA or self.nextsym == BZ_RUNB:
                    if self.nextsym == BZ_RUNA:
                        es += n
                    n = n << 1
                    if self.nextsym == BZ_RUNB:
                        es += n

                    if self.grouppos == 0:
                        self.groupno += 1
                        if self.groupno >= self.nselectors:
                            raise RuntimeError('BZ_DATA_ERROR: Number of groups larger than number of selectors')
                        self.grouppos = BZ_G_SIZE
                        self.gsel = self.selector[self.groupno]
                        self.gminlen = self.minlens[self.gsel]
                        self.glimit = self.limit[self.gsel]
                        self.gperm = self.perm[self.gsel]
                        self.gbase = self.base[self.gsel]
                    self.grouppos -= 1
                    zn = self.gminlen

                    zvec = self._get_bits(zn, 'BZ_X_MTF_3')

                    while True:
                        if zn > 20:
                            raise RuntimeError('BZ_DATA_ERROR: Value zv too large')
                        if zvec <= self.glimit[zn]:
                            break
                        zn += 1
                        zj = self._get_bits(1, 'BZ_X_MTF_4')
                        zvec = (zvec << 1) | zj

                    if zvec - self.gbase[zn] < 0 or zvec - self.gbase[zn] >= BZ_MAX_ALPHA_SIZE:
                        raise RuntimeError('BZ_DATA_ERROR: Value zvec outside of acceptable range')
                    self.nextsym = self.gperm[zvec - self.gbase[zn]]

                es += 1
                uc = self.seqtounseq[self.mtfa[self.mtfbase[0]]]
                unzftab[uc] += es

                while es > 0:
                    if nblock >= nblockmax:
                        raise RuntimeError('BZ_DATA_ERROR: Value nblock too large')
                    tt[nblock] = uc
                    nblock += 1
                    es -= 1

            else:
                if nblock >= nblockmax:
                    raise RuntimeError('BZ_DATA_ERROR: Value nblock higher than maximum')

                pp = 0
                nn = self.nextsym - 1

                if nn < MTFL_SIZE:
                    pp = self.mtfbase[0]
                    uc = self.mtfa[pp + nn]
                    while nn > 0:
                        self.mtfa[pp + nn] = self.mtfa[pp + nn - 1]
                        nn -= 1
                    self.mtfa[pp] = uc
                else:
                    lno = int(nn / MTFL_SIZE)
                    off = nn % MTFL_SIZE
                    pp = self.mtfbase[lno] + off
                    uc = self.mtfa[pp]

                    while pp > self.mtfbase[lno]:
                        self.mtfa[pp] = self.mtfa[pp - 1]
                        pp -= 1

                    self.mtfbase[lno] += 1

                    while lno > 0:
                        self.mtfbase[lno] -= 1
                        self.mtfa[self.mtfbase[lno]] = self.mtfa[self.mtfbase[lno - 1] + MTFL_SIZE - 1]
                        lno -= 1

                    self.mtfbase[0] -= 1

                    self.mtfa[self.mtfbase[0]] = uc

                    if self.mtfbase[0] == 0:
                        k = MTFA_SIZE - 1
                        for i in reversed(range(int(256 / MTFL_SIZE))):
                            for j in reversed(range(MTFL_SIZE)):
                                self.mtfa[k] = self.mtfa[self.mtfbase[i] + j]
                                k -= 1
                            self.mtfbase[i] = k + 1

                unzftab[self.seqtounseq[uc]] += 1
                tt[nblock] = self.seqtounseq[uc]
                nblock += 1

                if self.grouppos == 0:
                    self.groupno += 1
                    if self.groupno >= self.nselectors:
                        raise RuntimeError('BZ_DATA_ERROR: Number of groups too large')
                    self.grouppos = BZ_G_SIZE
                    self.gsel = self.selector[self.groupno]
                    self.gminlen = self.minlens[self.gsel]
                    self.glimit = self.limit[self.gsel]
                    self.gperm = self.perm[self.gsel]
                    self.gbase = self.base[self.gsel]
                self.grouppos -= 1
                zn = self.gminlen

                zvec = self._get_bits(zn, 'BZ_X_MTF_5')

                while True:
                    if zn > 20:
                        raise RuntimeError('BZ_DATA_ERROR: Value zv too large')
                    if zvec <= self.glimit[zn]:
                        break
                    zn += 1
                    zj = self._get_bits(1, 'BZ_X_MTF_6')
                    zvec = (zvec << 1) | zj

                if zvec - self.gbase[zn] < 0 or zvec - self.gbase[zn] >= BZ_MAX_ALPHA_SIZE:
                    raise RuntimeError('BZ_DATA_ERROR: Value zvec outside of acceptable range')

                self.nextsym = self.gperm[zvec - self.gbase[zn]]

        self.nblock = nblock
        self.unzftab = unzftab
        self.tt = tt

    def _cftable(self):
        """Apply the cumulative frequency table."""
        # These two origin pointer checks need to move to the function where
        # the origin pointer is used. Also, the first check is redundant.
        if self.origptr < 0:
            raise RuntimeError('BZ_DATA_ERROR: Orig ptr is negative')
        if self.origptr > 10 + NSIS_COMPRESS_BZIP2_LEVEL * 100000:
            raise RuntimeError('BZ_DATA_ERROR: Orig ptr is too large')

        cftab = [0] * 257

        for i in range(1, 257):
            cftab[i] = self.unzftab[i - 1] + cftab[i - 1]

        for i in range(self.nblock):
            uc = self.tt[i] & 0xff
            self.tt[cftab[uc]] |= (i << 8)
            cftab[uc] += 1

    def _tpos(self):
        """Calculate the starting position for the inverse Burrows-Wheeler Transform from the origin pointer."""
        nblock_used = 0
        tpos = self.tt[self.origptr] >> 8
        tpos = self.tt[tpos]
        k0 = tpos & 0xff
        tpos >>= 8
        nblock_used += 1

        self.k0 = k0
        self.tpos = tpos
        self.nblock_used = nblock_used

    def _unrle(self):
        """Reverse the run-length encoding."""
        ur = UnRLE(self.avail_out, self.tt, self.nblock, self.nblock_used, self.k0, self.tpos)
        self.out = ur.run()

    def _end_header(self):
        """Check the end header."""
        uc = self._get_bits(8, 'BZ_X_ENDHDR_1')
        if uc != 0x17:
            raise RuntimeError('BZ_DATA_ERROR: Incorrect BZ_X_ENDHDR_1')

    def run(self, stop=None):
        """Run the decompression process."""
        self._block_header()
        self._origptr()
        if stop == 'origptr':
            return
        self._mapping_table()
        if stop == 'mapping_table':
            return
        self._selectors()
        if stop == 'selectors':
            return
        self._coding_tables()
        if stop == 'coding_tables':
            return
        self._huffman_tables()
        if stop == 'huffman_tables':
            return
        self._mtf_init()
        if stop == 'mtf_init':
            return
        self._first_mtf()
        if stop == 'first_mtf':
            return
        self._decompress()
        if stop == 'decompress':
            return
        self._cftable()
        if stop == 'cftable':
            return
        self._tpos()
        if stop == 'tpos':
            return
        self._unrle()
        if stop in ['unrle', 'end_header']:
            return
        self._end_header()
