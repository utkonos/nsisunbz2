#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define NSIS_COMPRESS_BZIP2_LEVEL 9
#define NSIS_MAX_STRLEN 1024

#define BZ_OK                0
#define BZ_STREAM_END        4
#define BZ_DATA_ERROR        (-4)
#define BZ_SEQUENCE_ERROR    (-1)

#define BZ_MAX_ALPHA_SIZE 258
#define BZ_MAX_CODE_LEN    23

#define BZ_RUNA 0
#define BZ_RUNB 1

#define BZ_N_GROUPS 6
#define BZ_G_SIZE   50
#define BZ_MAX_SELECTORS (2 + (900000 / BZ_G_SIZE))

typedef unsigned char   Bool;

#define True  ((Bool)1)
#define False ((Bool)0)

#define BZ_X_IDLE        1
#define BZ_X_OUTPUT      2

#define BZ_X_BLKHDR_1    11
#define BZ_X_RANDBIT     12
#define BZ_X_ORIGPTR_1   13
#define BZ_X_ORIGPTR_2   14
#define BZ_X_ORIGPTR_3   15
#define BZ_X_MAPPING_1   16
#define BZ_X_MAPPING_2   17
#define BZ_X_SELECTOR_1  18
#define BZ_X_SELECTOR_2  19
#define BZ_X_SELECTOR_3  20
#define BZ_X_CODING_1    21
#define BZ_X_CODING_2    22
#define BZ_X_CODING_3    23
#define BZ_X_MTF_1       24
#define BZ_X_MTF_2       25
#define BZ_X_MTF_3       26
#define BZ_X_MTF_4       27
#define BZ_X_MTF_5       28
#define BZ_X_MTF_6       29

#define MTFA_SIZE 4096
#define MTFL_SIZE 16

typedef struct {
   int i;
    int j;
    int t;
    int alphaSize;
    int nGroups;
    int nSelectors;
    int EOB;
    int groupNo;
    int groupPos;
    int nextSym;
    int nblockMAX;
    int nblock;
    int es;
    int N;
    int curr;
    int zt;
    int zn;
    int zvec;
    int zj;
    int gSel;
    int gMinlen;
    int *gLimit;
    int *gBase;
    int *gPerm;
} DState_save;

typedef struct {
    unsigned char *next_in;
    unsigned int avail_in;

    unsigned char *next_out;
    unsigned int avail_out;

    char state;

    unsigned char    state_out_ch;
    int state_out_len;
    int nblock_used;
    int k0;
    unsigned int tPos;

    unsigned int bsBuff;
    int bsLive;

    int origPtr;
    int unzftab[256];
    int cftab[257];
    int cftabCopy[257];

    unsigned int tt[NSIS_COMPRESS_BZIP2_LEVEL * 100000];

    int nInUse;
    Bool     inUse[256];
    Bool     inUse16[16];
    unsigned char    seqToUnseq[256];

    unsigned char    mtfa   [MTFA_SIZE];
    int mtfbase[256 / MTFL_SIZE];
    unsigned char    selector   [BZ_MAX_SELECTORS];
    unsigned char    selectorMtf[BZ_MAX_SELECTORS];
    unsigned char    len  [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];

    int limit[BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];
    int base[BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];
    int perm[BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE];
    int minLens[BZ_N_GROUPS];

    DState_save save;
} DState;

#define BZ_GET_FAST(cccc)                     \
    s->tPos = s->tt[s->tPos];                 \
    cccc = (unsigned char)(s->tPos & 0xff);           \
    s->tPos >>= 8;

#define BZ_GET_FAST_C(cccc)                   \
    c_tPos = c_tt[c_tPos];                    \
    cccc = (unsigned char)(c_tPos & 0xff);            \
    c_tPos >>= 8;

#define BZ2_bzDecompressInit(s) { (s)->state = BZ_X_BLKHDR_1; (s)->bsLive = 0; }

void print_array(const char *name, const int *array, const int size) {
    printf("  %s: [", name);
    for (int i = 0; i < size; i++) {
        printf("%d", array[i]);
        if (i < size - 1) printf(", ");
    }
    printf("]\n");
}

void print_array_uchar(const char *name, const unsigned char *array, const int size) {
    printf("  %s: [", name);
    for (int i = 0; i < size; i++) {
        printf("%d", array[i]);
        if (i < size - 1) printf(", ");
    }
    printf("]\n");
}

void print_array_bool(const char *name, const Bool *array, const int size) {
    printf("  %s: [", name);
    for (int i = 0; i < size; i++) {
        printf("%s", array[i] ? "true" : "false");
        if (i < size - 1) printf(", ");
    }
    printf("]\n");
}

void print_dstate_save(const DState_save *save) {
    printf("\nDState_save:\n");
    printf("  i: %d\n", save->i);
    printf("  j: %d\n", save->j);
    printf("  t: %d\n", save->t);
    printf("  alphaSize: %d\n", save->alphaSize);
    printf("  nGroups: %d\n", save->nGroups);
    printf("  nSelectors: %d\n", save->nSelectors);
    printf("  EOB: %d\n", save->EOB);
    printf("  groupNo: %d\n", save->groupNo);
    printf("  groupPos: %d\n", save->groupPos);
    printf("  nextSym: %d\n", save->nextSym);
    printf("  nblockMAX: %d\n", save->nblockMAX);
    printf("  nblock: %d\n", save->nblock);
    printf("  es: %d\n", save->es);
    printf("  N: %d\n", save->N);
    printf("  curr: %d\n", save->curr);
    printf("  zt: %d\n", save->zt);
    printf("  zn: %d\n", save->zn);
    printf("  zvec: %d\n", save->zvec);
    printf("  zj: %d\n", save->zj);
    printf("  gSel: %d\n", save->gSel);
    printf("  gMinlen: %d\n", save->gMinlen);
    printf("  gLimit: pointer to array\n");
    printf("  gBase: pointer to array\n");
    printf("  gPerm: pointer to array\n");
}

void print_dstate(const DState *state, const int verbose) {
    printf("DState:\n");
    printf("  next_in: %p\n", (void *)state->next_in);
    printf("  avail_in: %u\n", state->avail_in);
    printf("  next_out: %p\n", (void *)state->next_out);
    printf("  avail_out: %u\n", state->avail_out);
    printf("  state: %d\n", state->state);
    printf("  state_out_ch: %d\n", state->state_out_ch);
    printf("  state_out_len: %d\n", state->state_out_len);
    printf("  nblock_used: %d\n", state->nblock_used);
    printf("  k0: %d\n", state->k0);
    printf("  tPos: %u\n", state->tPos);
    printf("  bsBuff: %u\n", state->bsBuff);
    printf("  bsLive: %d\n", state->bsLive);
    printf("  origPtr: %d\n", state->origPtr);

   if (verbose) {
      print_array("unzftab", state->unzftab, 256);
      print_array("cftab", state->cftab, 257);
      print_array("cftabCopy", state->cftabCopy, 257);
      print_array("tt", (int *)state->tt, NSIS_COMPRESS_BZIP2_LEVEL * 100000);

   }
    printf("  nInUse: %d\n", state->nInUse);

   if (verbose) {
      print_array_bool("inUse", state->inUse, 256);
      print_array_bool("inUse16", state->inUse16, 16);
      print_array_uchar("seqToUnseq", state->seqToUnseq, 256);
      print_array_uchar("mtfa", state->mtfa, MTFA_SIZE);
      print_array("mtfbase", state->mtfbase, 256 / MTFL_SIZE);
      print_array_uchar("selector", state->selector, BZ_MAX_SELECTORS);
      print_array_uchar("selectorMtf", state->selectorMtf, BZ_MAX_SELECTORS);

      for (int i = 0; i < BZ_N_GROUPS; i++) {
         char name[64];

         sprintf(name, "len[%d]", i);
         print_array_uchar(name, state->len[i], BZ_MAX_ALPHA_SIZE);

         sprintf(name, "limit[%d]", i);
         print_array(name, state->limit[i], BZ_MAX_ALPHA_SIZE);

         sprintf(name, "base[%d]", i);
         print_array(name, state->base[i], BZ_MAX_ALPHA_SIZE);

         sprintf(name, "perm[%d]", i);
         print_array(name, state->perm[i], BZ_MAX_ALPHA_SIZE);
      }

      print_array("minLens", state->minLens, BZ_N_GROUPS);
   }

    print_dstate_save(&state->save);
}

void hexdump(const void *buffer, const unsigned int n) {
   const unsigned char *byte_buffer = buffer;

   for (unsigned int line = 0; line < n; line++) {
      // ReSharper disable once CppVariableCanBeMadeConstexpr
      const unsigned int bytes_per_line = 16;
      const unsigned int offset = line * bytes_per_line;
      printf("%08X  ", offset);

      unsigned int j;
      for (j = 0; j < bytes_per_line; j++) {
         printf("%02X ", byte_buffer[offset + j]);
      }

      printf(" ");

      for (j = 0; j < bytes_per_line; j++) {
         const unsigned char c = byte_buffer[offset + j];
         printf("%c", isprint(c) ? c : '.');
      }

      printf("\n");
   }
}

void BZ2_hbCreateDecodeTables (
   int *limit,
   int *base,
   int *perm,
   const unsigned char *length,
   const int minLen,
   const int maxLen,
   const int alphaSize)
{
   int i;

   int pp = 0;
   for (i = minLen; i <= maxLen; i++)
      for (int j = 0; j < alphaSize; j++)
         if (length[j] == i) { perm[pp] = j; pp++; };

   for (i = 0; i < BZ_MAX_CODE_LEN; i++) base[i] = 0;
   for (i = 0; i < alphaSize; i++) base[length[i]+1]++;

   for (i = 1; i < BZ_MAX_CODE_LEN; i++) base[i] += base[i-1];

   for (i = 0; i < BZ_MAX_CODE_LEN; i++) limit[i] = 0;
   int vec = 0;

   for (i = minLen; i <= maxLen; i++) {
      vec += (base[i+1] - base[i]);
      limit[i] = vec-1;
      vec <<= 1;
   }
   for (i = minLen + 1; i <= maxLen; i++)
      base[i] = ((limit[i-1] + 1) << 1) - base[i];
}

#define RETURN(rrr)                               \
   { retVal = rrr; goto save_state_and_return; };

static int __mygetbits(int *vtmp, const int nnn, DState* s)
{
   for (;;) {
      if (s->bsLive >= nnn) {
         const unsigned int v = (s->bsBuff >>
                           (s->bsLive - nnn)) & ((1 << nnn) - 1);
         s->bsLive -= nnn;
         *vtmp = v; // NOLINT(*-narrowing-conversions)
        return 0;
      }
      if (s->avail_in == 0) return 1;
      s->bsBuff = (s->bsBuff << 8) | ((unsigned int) (*s->next_in));
      s->bsLive += 8;
      s->next_in++;
      s->avail_in--;
   }
}

#define GET_BITS(lll,vvv,nnn)                     \
   case lll: s->state = lll; \
    if (__mygetbits(&vvv,nnn,s)) RETURN(BZ_OK)

#define GET_UCHAR(lll,uuu)                        \
   GET_BITS(lll,uuu,8)

#define GET_BIT(lll,uuu)                          \
   GET_BITS(lll,uuu,1)

static int getmtf1(DState_save *sv,DState* s)
{
   if (sv->groupPos == 0) {
      sv->groupNo++;
      if (sv->groupNo >= sv->nSelectors) return 1;
      sv->groupPos = BZ_G_SIZE;
      sv->gSel = s->selector[sv->groupNo];
      sv->gMinlen = s->minLens[sv->gSel];
      sv->gLimit = &(s->limit[sv->gSel][0]);
      sv->gPerm = &(s->perm[sv->gSel][0]);
      sv->gBase = &(s->base[sv->gSel][0]);
   }
   sv->groupPos--;
   sv->zn = sv->gMinlen;
   return 0;
}

#define GET_MTF_VAL(label1,label2,lval)           \
{                                                 \
   if (getmtf1(&sv,s)) RETURN(BZ_DATA_ERROR);     \
   GET_BITS(label1, zvec, zn);                    \
   for (;;)  {                                    \
      if (zn > 20) RETURN(BZ_DATA_ERROR);         \
      if (zvec <= gLimit[zn]) break;              \
      zn++;                                       \
      GET_BIT(label2, zj);                        \
      zvec = (zvec << 1) | zj;                    \
   };                                             \
   if (zvec - gBase[zn] < 0                       \
       || zvec - gBase[zn] >= BZ_MAX_ALPHA_SIZE)  \
      RETURN(BZ_DATA_ERROR);                      \
   lval = gPerm[zvec - gBase[zn]];                \
}

int BZ2_decompress(DState *s) {
   int uc;
   int retVal;
   int minLen, maxLen;

   DState_save sv;

   sv=s->save;

   #define i (sv.i)
   #define j (sv.j)
   #define t (sv.t)
   #define alphaSize (sv.alphaSize)
   #define nGroups (sv.nGroups)
   #define nSelectors (sv.nSelectors)
   #define EOB (sv.EOB)
   #define groupNo (sv.groupNo)
   #define groupPos (sv.groupPos)
   #define nextSym (sv.nextSym)
   #define nblockMAX (sv.nblockMAX)
   #define nblock (sv.nblock)
   #define es (sv.es)
   #define N (sv.N)
   #define curr (sv.curr)
   #define zt (sv.zt)
   #define zn (sv.zn)
   #define zvec (sv.zvec)
   #define zj (sv.zj)
   #define gSel (sv.gSel)
   #define gMinlen (sv.gMinlen)
   #define gLimit (sv.gLimit)
   #define gBase (sv.gBase)
   #define gPerm (sv.gPerm)

   retVal = BZ_OK;

   switch (s->state) {

      case BZ_X_BLKHDR_1:
         s->state = BZ_X_BLKHDR_1;
         if (__mygetbits(&uc, 8, s)) {
            retVal = BZ_OK;
            goto save_state_and_return;
         }

      if (uc == 0x17) {
         s->state = BZ_X_IDLE;
         retVal = BZ_STREAM_END;
         goto save_state_and_return;
      }
      if (uc != 0x31) {
         retVal = BZ_DATA_ERROR;
         goto save_state_and_return;
      }

      s->origPtr = 0;
      GET_UCHAR(BZ_X_ORIGPTR_1, uc);
      s->origPtr = (s->origPtr << 8) | uc;
      GET_UCHAR(BZ_X_ORIGPTR_2, uc);
      s->origPtr = (s->origPtr << 8) | uc;
      GET_UCHAR(BZ_X_ORIGPTR_3, uc);
      s->origPtr = (s->origPtr << 8) | uc;

      if (s->origPtr < 0)
         RETURN(BZ_DATA_ERROR);
      if (s->origPtr > 10 + NSIS_COMPRESS_BZIP2_LEVEL*100000)
         RETURN(BZ_DATA_ERROR);

      for (i = 0; i < 16; i++) {
         GET_BIT(BZ_X_MAPPING_1, uc);
         if (uc == 1)
            s->inUse16[i] = True; else
            s->inUse16[i] = False;
      }

      for (i = 0; i < 256; i++) s->inUse[i] = False;

      for (i = 0; i < 16; i++)
         if (s->inUse16[i])
            for (j = 0; j < 16; j++) {
               GET_BIT(BZ_X_MAPPING_2, uc);
               if (uc == 1) s->inUse[i * 16 + j] = True;
            }
      {
         int qi;
         s->nInUse = 0;
         for (qi = 0; qi < 256; qi++)
            if (s->inUse[qi])
               s->seqToUnseq[s->nInUse++] = qi;
      }

      if (s->nInUse == 0) RETURN(BZ_DATA_ERROR);
      alphaSize = s->nInUse+2;

      GET_BITS(BZ_X_SELECTOR_1, nGroups, 3);
      if (nGroups < 2 || nGroups > 6) RETURN(BZ_DATA_ERROR);
      GET_BITS(BZ_X_SELECTOR_2, nSelectors, 15);
      if (nSelectors < 1) RETURN(BZ_DATA_ERROR);
      for (i = 0; i < nSelectors; i++) {
         j = 0;
         while (True) {
            GET_BIT(BZ_X_SELECTOR_3, uc);
            if (uc == 0) break;
            j++;
            if (j >= nGroups) RETURN(BZ_DATA_ERROR);
         }
         s->selectorMtf[i] = j;
      }

      {
         unsigned char pos[BZ_N_GROUPS], tmp, v;
         for (v = 0; v < nGroups; v++) pos[v] = v; // NOLINT(*-too-small-loop-variable)

         for (i = 0; i < nSelectors; i++) {
            v = s->selectorMtf[i];
            tmp = pos[v];
            while (v > 0) { pos[v] = pos[v-1]; v--; }
            pos[0] = tmp;
            s->selector[i] = tmp;
         }
      }

      for (t = 0; t < nGroups; t++) {
         GET_BITS(BZ_X_CODING_1, curr, 5);
         for (i = 0; i < alphaSize; i++) {
            while (True) {
               if (curr < 1 || curr > 20) RETURN(BZ_DATA_ERROR);
               GET_BIT(BZ_X_CODING_2, uc);
               if (uc == 0) break;
               GET_BIT(BZ_X_CODING_3, uc);
               if (uc == 0) curr++; else curr--;
            }
            s->len[t][i] = curr;
         }
      }

      for (t = 0; t < nGroups; t++) {
         minLen = 32;
         maxLen = 0;
         for (i = 0; i < alphaSize; i++) {
            if (s->len[t][i] > maxLen) maxLen = s->len[t][i];
            if (s->len[t][i] < minLen) minLen = s->len[t][i];
         }
         BZ2_hbCreateDecodeTables (
            &(s->limit[t][0]),
            &(s->base[t][0]),
            &(s->perm[t][0]),
            &(s->len[t][0]),
            minLen, maxLen, alphaSize
         );
         s->minLens[t] = minLen;
      }

      EOB      = s->nInUse+1;
      nblockMAX = NSIS_COMPRESS_BZIP2_LEVEL*100000;
      groupNo  = -1;
      groupPos = 0;

      for (i = 0; i <= 255; i++) s->unzftab[i] = 0;

      {
         int ii, jj, kk = MTFA_SIZE - 1;
         for (ii = 256 / MTFL_SIZE - 1; ii >= 0; ii--) {
            for (jj = MTFL_SIZE-1; jj >= 0; jj--) {
               s->mtfa[kk] = (unsigned char)(ii * MTFL_SIZE + jj);
               kk--;
            }
            s->mtfbase[ii] = kk + 1;
         }
      }

      nblock = 0;
      GET_MTF_VAL(BZ_X_MTF_1, BZ_X_MTF_2, nextSym);

      while (True) {

         if (nextSym == EOB) break;

         if (nextSym == BZ_RUNA || nextSym == BZ_RUNB) {

            es = -1;
            N = 1;
            while (nextSym == BZ_RUNA || nextSym == BZ_RUNB)
            {
               if (nextSym == BZ_RUNA) es += N;
               N = N << 1;
               if (nextSym == BZ_RUNB) es += N;
               GET_MTF_VAL(BZ_X_MTF_3, BZ_X_MTF_4, nextSym);
            }

            es++;
            uc = s->seqToUnseq[ s->mtfa[s->mtfbase[0]] ];
            s->unzftab[uc] += es;

             while (es > 0) {
                if (nblock >= nblockMAX) RETURN(BZ_DATA_ERROR);
                s->tt[nblock] = (unsigned int)uc;
                nblock++;
                es--;
             }
         } else {
            if (nblock >= nblockMAX) RETURN(BZ_DATA_ERROR);
            {
               int pp;
               unsigned int nn;
               nn = (unsigned int)(nextSym - 1);

               if (nn < MTFL_SIZE) {
                  pp = s->mtfbase[0];
                  uc = s->mtfa[pp+nn];
                  while (nn > 0) {
                     s->mtfa[(pp+nn)] = s->mtfa[(pp+nn)-1]; nn--;
                  };
                  s->mtfa[pp] = uc;
               } else {
                  int off;
                  int lno;
                  lno = nn / MTFL_SIZE; // NOLINT(*-narrowing-conversions)
                  off = nn % MTFL_SIZE; // NOLINT(*-narrowing-conversions)
                  pp = s->mtfbase[lno] + off;
                  uc = s->mtfa[pp];
                  while (pp > s->mtfbase[lno]) {
                     s->mtfa[pp] = s->mtfa[pp-1]; pp--;
                  };
                  s->mtfbase[lno]++;
                  while (lno > 0) {
                     s->mtfbase[lno]--;
                     s->mtfa[s->mtfbase[lno]]
                        = s->mtfa[s->mtfbase[lno-1] + MTFL_SIZE - 1];
                     lno--;
                  }
                  s->mtfbase[0]--;
                  s->mtfa[s->mtfbase[0]] = uc;
                  if (s->mtfbase[0] == 0) {
                     int kk;
                     int jj;
                     int ii;
                     kk = MTFA_SIZE-1;
                     for (ii = 256 / MTFL_SIZE-1; ii >= 0; ii--) {
                        for (jj = MTFL_SIZE-1; jj >= 0; jj--) {
                           s->mtfa[kk] = s->mtfa[s->mtfbase[ii] + jj];
                           kk--;
                        }
                        s->mtfbase[ii] = kk + 1;
                     }
                  }
               }
            }

            s->unzftab[s->seqToUnseq[uc]]++;
            s->tt[nblock]   = (unsigned int)(s->seqToUnseq[uc]);
            nblock++;

            GET_MTF_VAL(BZ_X_MTF_5, BZ_X_MTF_6, nextSym);
         }
      }

      if (s->origPtr < 0 || s->origPtr >= nblock)
         RETURN(BZ_DATA_ERROR);

      s->state_out_len = 0;
      s->state_out_ch  = 0;
      s->state = BZ_X_OUTPUT;

      s->cftab[0] = 0;
      for (i = 1; i <= 256; i++) s->cftab[i] = s->unzftab[i-1]+s->cftab[i-1];
      for (i = 0; i < nblock; i++) {
         uc = (unsigned char)(s->tt[i] & 0xff);
         s->tt[s->cftab[uc]] |= (i << 8);
         s->cftab[uc]++;
      }

      s->tPos = s->tt[s->origPtr] >> 8;
      s->nblock_used = 0;
      BZ_GET_FAST(s->k0); s->nblock_used++;

      RETURN(BZ_OK);
   default: RETURN(BZ_DATA_ERROR);
   }

   save_state_and_return:

   s->save=sv;

   #undef i
   #undef j
   #undef t
   #undef alphaSize
   #undef nGroups
   #undef nSelectors
   #undef EOB
   #undef groupNo
   #undef groupPos
   #undef nextSym
   #undef nblockMAX
   #undef nblock
   #undef es
   #undef N
   #undef curr
   #undef zt
   #undef zn
   #undef zvec
   #undef zj
   #undef gSel
   #undef gMinlen
   #undef gLimit
   #undef gBase
   #undef gPerm

   return retVal;
}

static void unRLE_obuf_to_output_FAST ( DState* s )
{
   unsigned char k1;
   unsigned char         c_state_out_ch       = s->state_out_ch;
   int c_state_out_len = s->state_out_len;
   int c_nblock_used = s->nblock_used;
   int c_k0 = s->k0;
   unsigned int c_tPos = s->tPos;

   // ReSharper disable once CppUseAuto
   char*         cs_next_out          = (char*) s->next_out;
      unsigned int  cs_avail_out         = s->avail_out;

   const unsigned int *c_tt = s->tt;
   const int s_save_nblockPP = s->save.nblock + 1;

      while (True) {
         if (c_state_out_len > 0) {
            while (True) {
               if (cs_avail_out == 0) goto return_notr;
               if (c_state_out_len == 1) break;
               *( (unsigned char*)(cs_next_out) ) = c_state_out_ch;
               c_state_out_len--;
               cs_next_out++;
               cs_avail_out--;
            }
            s_state_out_len_eq_one:
            {
               if (cs_avail_out == 0) {
                  c_state_out_len = 1; goto return_notr;
               };
               *( (unsigned char*)(cs_next_out) ) = c_state_out_ch;
               cs_next_out++;
               cs_avail_out--;
            }
         }
         if (c_nblock_used == s_save_nblockPP) {
            c_state_out_len = 0; goto return_notr;
         };
         c_state_out_ch = c_k0;
         BZ_GET_FAST_C(k1); c_nblock_used++;
         if (k1 != c_k0) {
            c_k0 = k1; goto s_state_out_len_eq_one;
         };
         if (c_nblock_used == s_save_nblockPP)
            goto s_state_out_len_eq_one;

         c_state_out_len = 2;
         BZ_GET_FAST_C(k1); c_nblock_used++;
         if (c_nblock_used == s_save_nblockPP) continue;
         if (k1 != c_k0) { c_k0 = k1; continue; };

         c_state_out_len = 3;
         BZ_GET_FAST_C(k1); c_nblock_used++;
         if (c_nblock_used == s_save_nblockPP) continue;
         if (k1 != c_k0) { c_k0 = k1; continue; };

         BZ_GET_FAST_C(k1); c_nblock_used++;
         c_state_out_len = ((int)k1) + 4;
         BZ_GET_FAST_C(c_k0); c_nblock_used++;
      }

      return_notr:
      s->state_out_ch       = c_state_out_ch;
      s->state_out_len      = c_state_out_len;
      s->nblock_used        = c_nblock_used;
      s->k0                 = c_k0;
      s->tPos               = c_tPos;
      s->next_out     = (unsigned char*) cs_next_out;
      s->avail_out    = cs_avail_out;
}

int BZ2_bzDecompress( DState *s )
{
   while (True) {
      if (s->state == BZ_X_IDLE) return BZ_SEQUENCE_ERROR;
      if (s->state == BZ_X_OUTPUT) {
         unRLE_obuf_to_output_FAST ( s );
         if (s->nblock_used == s->save.nblock+1 && s->state_out_len == 0) {
            s->state = BZ_X_BLKHDR_1;
         } else {
            return BZ_OK;
         }
      }
      if (s->state >= BZ_X_BLKHDR_1) {
         const int r = BZ2_decompress(s);
         if (r == BZ_STREAM_END) {
            return r;
         }
         if (s->state != BZ_X_OUTPUT) return r;
      }
   }
}

void write_to_file(const char *filename, const unsigned char *data, const unsigned int size) {
   FILE *outfile = fopen(filename, "wb");
   if (outfile == NULL) {
      perror("Error opening output file");
      return;
   }

   if (fwrite(data, 1, size, outfile) != size) {
      perror("Error writing to output file");
   }

   fclose(outfile);
}

int main(const int argc, char *argv[]) {
   int verbose = 0;

   if (argc < 2 || argc > 3) {
      fprintf(stderr, "Usage: %s [-v] <outbuffer_size_in_hex>\n", argv[0]);
      return 1;
   }

   if (argc == 3 && strcmp(argv[1], "-v") == 0) {
      verbose = 1;
      argv++;
   } else if (argc == 3 && strcmp(argv[1], "-vv") == 0) {
      verbose = 2;
      argv++;
   }

   char *endptr;
   const unsigned int outbuffer_size = strtoul(argv[1], &endptr, 16);
   if (errno != 0 || *endptr != '\0') {
      fprintf(stderr, "Invalid hex number: %s\n", argv[1]);
      return 1;
   }

   unsigned char *outbuffer = calloc(outbuffer_size, sizeof(unsigned char));
   if (outbuffer == NULL) {
      printf("Memory allocation failed\n");
      return 1;
   }

   FILE *file = fopen("data", "rb");
   if (file == NULL) {
      perror("Error opening file");
      return 1;
   }

   fseek(file, 0, SEEK_END);
   const unsigned int filesize = ftell(file);
   rewind(file);

   unsigned char *inbuffer = malloc(filesize + 1);
   if (inbuffer == NULL) {
      perror("Memory allocation failed");
      fclose(file);
      return 1;
   }

   if (fread(inbuffer, 1, filesize, file) != filesize) {
      perror("Error reading file");
      free(inbuffer);
      fclose(file);
      return 1;
   }

   inbuffer[filesize] = '\0';
   fclose(file);

   if (verbose > 1) hexdump(inbuffer, 5);

   DState s;
   memset(&s, 0, sizeof(DState));
   BZ2_bzDecompressInit(&s)

   s.next_in = inbuffer;
   s.avail_in = filesize;
   s.next_out = outbuffer;
   s.avail_out = outbuffer_size;

   if (verbose > 1) print_dstate(&s, 0);

   const int result = BZ2_bzDecompress(&s);
   if (result != BZ_OK && result != BZ_STREAM_END) {
      fprintf(stderr, "Decompression failed with error: %d\n", result);
      free(inbuffer);
      free(outbuffer);
      return 1;
   }

   if (verbose > 1) print_dstate(&s, 0);

   if (verbose > 1) hexdump(outbuffer, 20);

   write_to_file("out", outbuffer, outbuffer_size);

   free(inbuffer);
   free(outbuffer);

   if (verbose) {
      FILE *cmd1 = popen("shasum -a 256 out", "r");
      if (cmd1 == NULL) {
         fprintf(stderr, "Failed to execute shasum command.\n");
         return 1;
      }

      char shasum_output1[70];
      while (fgets(shasum_output1, sizeof(shasum_output1), cmd1) != NULL) {
         printf("%s", shasum_output1);
      }

      const char* in = "echo 'eeaefe8c8a5d42855d886e5368d5c752a03d821681c7b2ceb5d900aa6cf70e18  out' | shasum -c -";
      FILE *cmd2 = popen(in, "r");
      if (cmd2 == NULL) {
         fprintf(stderr, "Failed to execute shasum command.\n");
         return 1;
      }

      char shasum_output2[70];
      while (fgets(shasum_output2, sizeof(shasum_output2), cmd2) != NULL) {
         printf("%s", shasum_output2);
      }

      if (pclose(cmd1) == -1) {
         fprintf(stderr, "Error closing command stream.\n");
      }
      if (pclose(cmd2) == -1) {
         fprintf(stderr, "Error closing command stream.\n");
      }
   }

   return 0;
}
