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

static int getbits(int *vtmp, const int nnn, DState* s)
{
   while (True) {
      if (s->bsLive >= nnn) {
         const unsigned int v = (s->bsBuff >> (s->bsLive - nnn)) & ((1 << nnn) - 1);
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
   // printf("Fun Begins\n");

   switch (s->state) {

      case BZ_X_BLKHDR_1:
         s->state = BZ_X_BLKHDR_1;
         // printf("BZ_X_BLKHDR_1\n");
         if (getbits(&uc, 8, s)) return BZ_OK;
         // printf("%02X\n", uc & 0xFF);
         // printf("%02X\n", s->avail_in);

      if (uc == 0x17) {
         s->state = BZ_X_IDLE;
         // printf("BZ_X_IDLE\n");
         retVal = BZ_STREAM_END;
         goto save_state_and_return;
      }
      if (uc != 0x31) return BZ_DATA_ERROR;

      s->origPtr = 0;
      case BZ_X_ORIGPTR_1:
         s->state = BZ_X_ORIGPTR_1;
         // printf("BZ_X_ORIGPTR_1\n");
         if (getbits(&uc, 8, s)) return BZ_OK;
      // printf("%02X\n", uc & 0xFF);
      // printf("%02X\n", s->avail_in);
      s->origPtr = (s->origPtr << 8) | uc;
      case BZ_X_ORIGPTR_2:
         s->state = BZ_X_ORIGPTR_2;
         // printf("BZ_X_ORIGPTR_2\n");
         if (getbits(&uc, 8, s)) return BZ_OK;
      // printf("%02X\n", uc & 0xFF);
      // printf("%02X\n", s->avail_in);
      s->origPtr = (s->origPtr << 8) | uc;
      case BZ_X_ORIGPTR_3:
         s->state = BZ_X_ORIGPTR_3;
         // printf("BZ_X_ORIGPTR_3\n");
         if (getbits(&uc, 8, s)) return BZ_OK;
      // printf("%02X\n", uc & 0xFF);
      // printf("%02X\n", s->avail_in);
      s->origPtr = (s->origPtr << 8) | uc;
      // printf("%02X\n", s->origPtr);

      if (s->origPtr < 0) return BZ_DATA_ERROR;
      if (s->origPtr > 10 + NSIS_COMPRESS_BZIP2_LEVEL*100000) return BZ_DATA_ERROR;

      for (i = 0; i < 16; i++) {
         case BZ_X_MAPPING_1:
            s->state = BZ_X_MAPPING_1;
            // printf("BZ_X_MAPPING_1\n");
            if (getbits(&uc, 1, s)) return BZ_OK;
         // printf("%02X\n", uc & 0xFF);
         // printf("%02X\n", s->avail_in);
         if (uc == 1)
            s->inUse16[i] = True; else
            s->inUse16[i] = False;
      }

      for (i = 0; i < 256; i++) s->inUse[i] = False;

      for (i = 0; i < 16; i++)
         if (s->inUse16[i])
            for (j = 0; j < 16; j++) {
               case BZ_X_MAPPING_2:
                  s->state = BZ_X_MAPPING_2;
                  // printf("BZ_X_MAPPING_2\n");
                  if (getbits(&uc, 1, s)) return BZ_OK;
                  // printf(uc ? "True\n" : "False\n");
               // printf("%02X\n", s->avail_in);
               if (uc == 1) s->inUse[i * 16 + j] = True;
            }
      int qi;
      s->nInUse = 0;
      for (qi = 0; qi < 256; qi++)
         if (s->inUse[qi])
            s->seqToUnseq[s->nInUse++] = qi;
      // print_array_uchar("seqToUnseq", s->seqToUnseq, 256);

      if (s->nInUse == 0) return BZ_DATA_ERROR;
      alphaSize = s->nInUse+2;

      case BZ_X_SELECTOR_1:
         s->state = BZ_X_SELECTOR_1;
         // printf("BZ_X_SELECTOR_1\n");
         if (getbits(&nGroups, 3, s)) return BZ_OK;
         // printf("%02X\n", nGroups & 0xFF);
      // printf("%02X\n", s->avail_in);
      if (nGroups < 2 || nGroups > 6) return BZ_DATA_ERROR;
      case BZ_X_SELECTOR_2:
         s->state = BZ_X_SELECTOR_2;
         // printf("BZ_X_SELECTOR_2\n");
         if (getbits(&nSelectors, 15, s)) return BZ_OK;
      // nSelectors = 0b111111111111111;
      // printf("%02X\n", nSelectors & 0xFFFF);
      // printf("%02X\n", s->avail_in);
      if (nSelectors < 1) {
         printf("nSelectors < 1\n");
         return BZ_DATA_ERROR;
      }
      for (i = 0; i < nSelectors; i++) {
         j = 0;
         while (True) {
            case BZ_X_SELECTOR_3:
               s->state = BZ_X_SELECTOR_3;
               // printf("BZ_X_SELECTOR_3\n");
               if (getbits(&uc, 1, s)) return BZ_OK;
            // printf("%02X\n", uc & 0xFF);
            // printf("%02X\n", s->avail_in);
            if (uc == 0) break;
            j++;
            if (j >= nGroups) return BZ_DATA_ERROR;
         }
         s->selectorMtf[i] = j;
      }
      // print_array_uchar("selectorMtf", s->selectorMtf, BZ_MAX_SELECTORS);

      unsigned char pos[BZ_N_GROUPS], tmp, v;
      // print_array_uchar("pos", pos, BZ_N_GROUPS);
      for (v = 0; v < nGroups; v++) pos[v] = v; // NOLINT(*-too-small-loop-variable)
      // print_array_uchar("pos", pos, BZ_N_GROUPS);

      for (i = 0; i < nSelectors; i++) {
         v = s->selectorMtf[i];
         tmp = pos[v];
         while (v > 0) { pos[v] = pos[v-1]; v--; }
         pos[0] = tmp;
         s->selector[i] = tmp;
      }
      // print_array_uchar("selector", s->selector, 37);

      for (t = 0; t < nGroups; t++) {
         case BZ_X_CODING_1:
            s->state = BZ_X_CODING_1;
            // printf("BZ_X_CODING_1\n");
            if (getbits(&curr, 5, s)) return BZ_OK;
         // printf("%02X\n", curr & 0xFF);
         // printf("%02X\n", s->avail_in);
         for (i = 0; i < alphaSize; i++) {
            while (True) {
               if (curr < 1 || curr > 20) return BZ_DATA_ERROR;
               case BZ_X_CODING_2:
                  s->state = BZ_X_CODING_2;
                  // printf("BZ_X_CODING_2\n");
                  if (getbits(&uc, 1, s)) return BZ_OK;
               // printf("%02X\n", uc & 0xFF);
               // printf("%02X\n", s->avail_in);
               if (uc == 0) break;
               case BZ_X_CODING_3:
                  s->state = BZ_X_CODING_3;
                  // printf("BZ_X_CODING_3\n");
                  if (getbits(&uc, 1, s)) return BZ_OK;
               // printf("%02X\n", uc & 0xFF);
               // printf("%02X\n", s->avail_in);
               if (uc == 0) curr++; else curr--;
            }
            s->len[t][i] = curr;
         }
      }
      // for (i = 0; i < BZ_N_GROUPS; i++) {
         // print_array_uchar("len", s->len[i], BZ_MAX_ALPHA_SIZE);
      // }

      for (t = 0; t < nGroups; t++) {
         minLen = 32;
         maxLen = 0;
         for (i = 0; i < alphaSize; i++) {
            if (s->len[t][i] > maxLen) maxLen = s->len[t][i];
            if (s->len[t][i] < minLen) minLen = s->len[t][i];
         }
         // printf("%02X\n", minLen);
         // printf("%02X\n", maxLen);

         int *limit = s->limit[t];
         int *base = s->base[t];
         int *perm = s->perm[t];
         const unsigned char *length = s->len[t];
         int pp = 0;
         for (i = minLen; i <= maxLen; i++)
            for (j = 0; j < alphaSize; j++)
               if (length[j] == i) { perm[pp] = j; pp++; };

         // print_array("perm", perm, BZ_MAX_ALPHA_SIZE);
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
         // print_array("base", base, BZ_MAX_ALPHA_SIZE);
         // print_array("limit", limit, BZ_MAX_ALPHA_SIZE);

         // printf("%02X\n", minLen);
         s->minLens[t] = minLen;
      }
      // print_array("minLens", s->minLens, BZ_N_GROUPS);
      // for (i = 0; i < BZ_N_GROUPS; i++) {
      //    print_array_uchar("limit", s->limit[i], BZ_MAX_ALPHA_SIZE);
      // }

      EOB      = s->nInUse+1;
      nblockMAX = NSIS_COMPRESS_BZIP2_LEVEL*100000;
      groupNo  = -1;
      groupPos = 0;

      for (i = 0; i <= 255; i++) s->unzftab[i] = 0;

      int ii, jj, kk = MTFA_SIZE - 1;
      for (ii = 256 / MTFL_SIZE - 1; ii >= 0; ii--) {
         for (jj = MTFL_SIZE-1; jj >= 0; jj--) {
            s->mtfa[kk] = (unsigned char)(ii * MTFL_SIZE + jj);
            kk--;
         }
         s->mtfbase[ii] = kk + 1;
      }
      // print_array_uchar("mtfa", s->mtfa, MTFA_SIZE);
      // print_array("mtfbase", s->mtfbase, 256 / MTFL_SIZE);

      nblock = 0;
      if (groupPos == 0) {
         groupNo++;
         if (groupNo >= nSelectors) return BZ_DATA_ERROR;
         groupPos = BZ_G_SIZE;
         gSel = s->selector[groupNo];
         gMinlen = s->minLens[gSel];
         gLimit = &(s->limit[gSel][0]);
         gPerm = &(s->perm[gSel][0]);
         gBase = &(s->base[gSel][0]);
      }
      groupPos--;
      zn = gMinlen;
      // print_array("gLimit", gLimit, BZ_MAX_ALPHA_SIZE);
      // print_array("gPerm", gPerm, BZ_MAX_ALPHA_SIZE);
      // print_array("gBase", gBase, BZ_MAX_ALPHA_SIZE);
      case BZ_X_MTF_1:
         s->state = BZ_X_MTF_1;
         // printf("BZ_X_MTF_1\n");
         // printf("%02X\n", zn);
         if (getbits(&zvec, zn, s)) return BZ_OK;
      // printf("%02X\n", zvec);
      while (True) {
         if (zn > 20) return BZ_DATA_ERROR;
         if (zvec <= gLimit[zn]) break;
         zn++;
         case BZ_X_MTF_2:
            s->state = BZ_X_MTF_2;
            // printf("BZ_X_MTF_2\n");
            if (getbits(&zj, 1, s)) return BZ_OK;
         zvec = (zvec << 1) | zj;
      }
      // printf("%02X\n", zn);
      // printf("%02X\n", zj);
      // printf("%02X\n", zvec);
      if (zvec - gBase[zn] < 0 || zvec - gBase[zn] >= BZ_MAX_ALPHA_SIZE) return BZ_DATA_ERROR;
      nextSym = gPerm[zvec - gBase[zn]];
      // printf("%d\n", nextSym);
      // int counter = 0;
      while (True) {

         if (nextSym == EOB) break;

         if (nextSym == BZ_RUNA || nextSym == BZ_RUNB) {

            // printf("First\n");
            es = -1;
            N = 1;
            while (nextSym == BZ_RUNA || nextSym == BZ_RUNB)
            {
               // printf("Second\n");
               if (nextSym == BZ_RUNA) es += N;
               N = N << 1;
               if (nextSym == BZ_RUNB) es += N;
               if (groupPos == 0) {
                  groupNo++;
                  if (groupNo >= nSelectors) return BZ_DATA_ERROR;
                  groupPos = BZ_G_SIZE;
                  gSel = s->selector[groupNo];
                  gMinlen = s->minLens[gSel];
                  gLimit = &(s->limit[gSel][0]);
                  gPerm = &(s->perm[gSel][0]);
                  gBase = &(s->base[gSel][0]);
               }
               groupPos--;
               zn = gMinlen;
               // if (!counter) {
               //    printf("%d\n", groupPos);
               //    counter++;
               // }
               case BZ_X_MTF_3:
                  s->state = BZ_X_MTF_3;
                  if (getbits(&zvec, zn, s)) return BZ_OK;
               // if (!counter) {
               //    printf("%d\n", zvec);
               //    counter++;
               // }
               while (True) {
                  if (zn > 20) return BZ_DATA_ERROR;
                  if (zvec <= gLimit[zn]) break;
                  zn++;
                  case BZ_X_MTF_4:
                     s->state = BZ_X_MTF_4;
                     if (getbits(&zj, 1, s)) return BZ_OK;
                  zvec = (zvec << 1) | zj;
               }
               // if (!counter) {
               //    printf("%d\n", zn);
               //    counter++;
               // }
               // if (!counter) {
               //    printf("%d\n", zj);
               //    counter++;
               // }
               // if (!counter) {
               //    printf("%d\n", zvec);
               //    counter++;
               // }
               if (zvec - gBase[zn] < 0 || zvec - gBase[zn] >= BZ_MAX_ALPHA_SIZE) return BZ_DATA_ERROR;
               nextSym = gPerm[zvec - gBase[zn]];
               // if (!counter) {
               //    printf("%d\n", nextSym);
               //    counter++;
               // }
            }

            // printf("Third\n");
            es++;
            // if (!counter) {
            //    printf("%d\n", es);
            //    counter++;
            // }
            uc = s->seqToUnseq[ s->mtfa[s->mtfbase[0]] ];
            // if (!counter) {
            //    printf("%d\n", uc);
            //    counter++;
            // }
            s->unzftab[uc] += es;
            // if (!counter) {
            //    print_array("unzftab", s->unzftab, 256);
            //    counter++;
            // }
            // if (!counter) {
            //    printf("%d\n", nblock);
            // }
            while (es > 0) {
                if (nblock >= nblockMAX) return BZ_DATA_ERROR;
                s->tt[nblock] = (unsigned int)uc;
                // if (!counter) {
                //    printf("%d\n", s->tt[nblock]);
                //    counter++;
                // }
                nblock++;
                // if (!counter) {
                //    printf("%d\n", nblock);
                //    counter++;
                // }
                es--;
             }
            // if (!counter) {
            //    printf("Condensed array: [");
            //    int first = 1;
            //    for (i = 0; i < NSIS_COMPRESS_BZIP2_LEVEL * 100000; i++) {
            //       if (s->tt[i] != 0) {
            //          if (!first) {
            //             printf(", ");
            //          }
            //          printf("%d", s->tt[i]);
            //          first = 0;
            //       }
            //    }
            //    printf("]\n");
            //    counter++;
            // }
         } else {
            // printf("Fourth\n");
            if (nblock >= nblockMAX) return BZ_DATA_ERROR;

            int pp;
            unsigned int nn;
            nn = (unsigned int)(nextSym - 1);
            // if (!counter) {
            //    printf("%d\n", nn);
            //    counter++;
            // }

            if (nn < MTFL_SIZE) {
               // printf("Fifth\n");
               // if (!counter) {
               //    printf("%d\n", nn);
               //    counter++;
               // }
               pp = s->mtfbase[0];
               // if (!counter) {
               //    printf("%d\n", pp);
               //    counter++;
               // }
               uc = s->mtfa[pp+nn];
               // if (!counter) {
               //    printf("%d\n", uc);
               //    counter++;
               // }
               while (nn > 0) {
                  s->mtfa[pp+nn] = s->mtfa[pp+nn-1]; nn--;
               }
               // if (!counter) {
               //    print_array_uchar("mtfa", s->mtfa, MTFA_SIZE);
               //    counter++;
               // }
               s->mtfa[pp] = uc;
               // if (!counter) {
               //    print_array_uchar("mtfa", s->mtfa, MTFA_SIZE);
               //    counter++;
               // }
            } else {
               // printf("Sixth\n");
               int off;
               int lno;
               lno = nn / MTFL_SIZE; // NOLINT(*-narrowing-conversions)
               // printf("%d\n", lno);
               off = nn % MTFL_SIZE; // NOLINT(*-narrowing-conversions)
               // printf("%d\n", off);
               pp = s->mtfbase[lno] + off;
               // printf("%d\n", pp);
               uc = s->mtfa[pp];
               // printf("%d\n", uc);
               while (pp > s->mtfbase[lno]) {
                  s->mtfa[pp] = s->mtfa[pp-1]; pp--;
               }
               // if (!counter) {
               //    print_array_uchar("mtfa", s->mtfa, MTFA_SIZE);
               //    counter++;
               // }
               s->mtfbase[lno]++;
               // if (!counter) {
               //    printf("%d\n", s->mtfbase[lno]);
               //    counter++;
               // }
               while (lno > 0) {
                  s->mtfbase[lno]--;
                  s->mtfa[s->mtfbase[lno]] = s->mtfa[s->mtfbase[lno-1] + MTFL_SIZE - 1];
                  lno--;
               }
               // if (!counter) {
               //    print_array("mtfbase", s->mtfbase, 256 / MTFL_SIZE);
               //    counter++;
               // }
               // if (!counter) {
               //    print_array_uchar("mtfa", s->mtfa, MTFA_SIZE);
               //    counter++;
               // }
               s->mtfbase[0]--;
               // if (!counter) {
               //    print_array("mtfbase", s->mtfbase, 256 / MTFL_SIZE);
               //    counter++;
               // }
               s->mtfa[s->mtfbase[0]] = uc;
               // if (!counter) {
               //    print_array_uchar("mtfa", s->mtfa, MTFA_SIZE);
               //    counter++;
               // }
               if (s->mtfbase[0] == 0) {
                  kk = MTFA_SIZE-1;
                  for (ii = 256 / MTFL_SIZE-1; ii >= 0; ii--) {
                     for (jj = MTFL_SIZE-1; jj >= 0; jj--) {
                        s->mtfa[kk] = s->mtfa[s->mtfbase[ii] + jj];
                        kk--;
                     }
                     s->mtfbase[ii] = kk + 1;
                  }
               }
               // if (!counter) {
               //    print_array_uchar("mtfa", s->mtfa, MTFA_SIZE);
               //    counter++;
               // }
               // if (!counter) {
               //    print_array("mtfbase", s->mtfbase, 256 / MTFL_SIZE);
               //    counter++;
               // }
            }

            // printf("Seventh\n");
            s->unzftab[s->seqToUnseq[uc]]++;
            // if (!counter) {
            //    print_array("unzftab", s->unzftab, 256);
            //    counter++;
            // }
            s->tt[nblock]   = (unsigned int)(s->seqToUnseq[uc]);
            // if (!counter) {
            //    printf("%d\n", s->tt[nblock]);
            //    counter++;
            // }
            nblock++;
            // if (!counter) {
            //    printf("%d\n", nblock);
            //    counter++;
            // }

            if (groupPos == 0) {
               groupNo++;
               if (groupNo >= nSelectors) return BZ_DATA_ERROR;
               groupPos = BZ_G_SIZE;
               gSel = s->selector[groupNo];
               gMinlen = s->minLens[gSel];
               gLimit = &(s->limit[gSel][0]);
               gPerm = &(s->perm[gSel][0]);
               gBase = &(s->base[gSel][0]);
            }
            groupPos--;
            zn = gMinlen;
            case BZ_X_MTF_5:
               s->state = BZ_X_MTF_5;
               // printf("BZ_X_MTF_5\n");
               if (getbits(&zvec, zn, s)) return BZ_OK;
            // if (!counter) {
            //    printf("%d\n", zvec);
            //    counter++;
            // }
            while (True) {
               if (zn > 20) return BZ_DATA_ERROR;
               if (zvec <= gLimit[zn]) break;
               zn++;
               case BZ_X_MTF_6:
                  s->state = BZ_X_MTF_6;
                  // printf("BZ_X_MTF_6\n");
                  if (getbits(&zj, 1, s)) return BZ_OK;
               zvec = (zvec << 1) | zj;
            }
            // if (!counter) {
            //    printf("%d\n", zn);
            //    counter++;
            // }
            // if (!counter) {
            //    printf("%d\n", zj);
            //    counter++;
            // }
            // if (!counter) {
            //    printf("%d\n", zvec);
            //    counter++;
            // }
            if (zvec - gBase[zn] < 0 || zvec - gBase[zn] >= BZ_MAX_ALPHA_SIZE) return BZ_DATA_ERROR;
            nextSym = gPerm[zvec - gBase[zn]];
            // if (!counter) {
            //    printf("%d\n", nextSym);
            //    counter++;
            // }
         }
      }
      // const unsigned int array_size = NSIS_COMPRESS_BZIP2_LEVEL * 100000;
      // int count = 0;
      // for (i = 0; i < array_size; i++) {
      //    if (s->tt[i]) {
      //       count++;
      //    }
      // }
      // printf("Number of non-zero elements: %d\n", count);

      // printf("Condensed array: [");
      // int first = 1;
      // for (i = 0; i < NSIS_COMPRESS_BZIP2_LEVEL * 100000; i++) {
      //    if (s->tt[i] != 0) {
      //       if (!first) {
      //          printf(", ");
      //       }
      //       printf("%d", s->tt[i]);
      //       first = 0;
      //    }
      // }
      // printf("]\n");

      if (s->origPtr < 0 || s->origPtr >= nblock) return BZ_DATA_ERROR;

      s->state_out_len = 0;
      s->state_out_ch  = 0;
      s->state = BZ_X_OUTPUT;
      // printf("BZ_X_OUTPUT\n");
      // printf("%02X\n", *s->next_in);
      // printf("%02X\n", s->avail_in);

      s->cftab[0] = 0;
      for (i = 1; i <= 256; i++) s->cftab[i] = s->unzftab[i-1]+s->cftab[i-1];
      // print_array("cftab", s->cftab, 257);
      for (i = 0; i < nblock; i++) {
         uc = (unsigned char)(s->tt[i] & 0xff);
         s->tt[s->cftab[uc]] |= (i << 8);
         s->cftab[uc]++;
      }
      // printf("%d\n", nblock);
      // const unsigned int array_size = NSIS_COMPRESS_BZIP2_LEVEL * 100000;
      // int count = 0;
      // for (i = 0; i < array_size; i++) {
      //    if (s->tt[i]) {
      //       count++;
      //    }
      // }
      // printf("Number of non-zero elements: %d\n", count);
      // printf("Condensed array: [");
      // int first = 1;
      // for (i = 0; i < NSIS_COMPRESS_BZIP2_LEVEL * 100000; i++) {
      //    if (s->tt[i] != 0) {
      //       if (!first) {
      //          printf(", ");
      //       }
      //       printf("%d", s->tt[i]);
      //       first = 0;
      //    }
      // }
      // printf("]\n");

      s->tPos = s->tt[s->origPtr] >> 8;
      // printf("%d\n", s->tPos);
      s->nblock_used = 0;
      s->tPos = s->tt[s->tPos];
      // printf("%d\n", s->tPos);
      s->k0 = (unsigned char)(s->tPos & 0xff);
      // printf("%d\n", s->k0);
      s->tPos >>= 8;
      // printf("%d\n", s->tPos);
      s->nblock_used++;
      // printf("%d\n", s->nblock_used);

      retVal = BZ_OK;
      // printf("BZ_OK\n");
      goto save_state_and_return;
      
   default:
      retVal = BZ_DATA_ERROR;
      printf("BZ_DATA_ERROR\n");
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
         // printf("First\n");
         if (c_state_out_len > 0) {
            // printf("Second\n");
            while (True) {
               // printf("Third\n");
               if (cs_avail_out == 0) goto return_notr;
               if (c_state_out_len == 1) break;
               *( (unsigned char*)(cs_next_out) ) = c_state_out_ch;
               c_state_out_len--;
               cs_next_out++;
               cs_avail_out--;
            }
            s_state_out_len_eq_one:
            // printf("Fourth\n");
            {
               if (cs_avail_out == 0) {
                  // printf("Fifth\n");
                  c_state_out_len = 1; goto return_notr;
               };
               // printf("Sixth\n");
               *( (unsigned char*)(cs_next_out) ) = c_state_out_ch;
               cs_next_out++;
               cs_avail_out--;
            }
         }
         // printf("Seventh\n");
         if (c_nblock_used == s_save_nblockPP) {
            // printf("Eighth\n");
            c_state_out_len = 0; goto return_notr;
         };
         // printf("Ninth\n");
         c_state_out_ch = c_k0;
         c_tPos = c_tt[c_tPos];
         unsigned char k1 = c_tPos & 0xff;
         c_tPos >>= 8;
         c_nblock_used++;
         if (k1 != c_k0) {
            // printf("Tenth\n");
            c_k0 = k1; goto s_state_out_len_eq_one;
         };
         // printf("Eleventh\n");
         if (c_nblock_used == s_save_nblockPP) {
            // printf("Twelfth\n");
            goto s_state_out_len_eq_one;
         }

         // printf("Thirteenth\n");
         c_state_out_len = 2;
         c_tPos = c_tt[c_tPos];
         k1 = (unsigned char)(c_tPos & 0xff);
         c_tPos >>= 8;
         c_nblock_used++;
         if (c_nblock_used == s_save_nblockPP) continue;
         if (k1 != c_k0) { c_k0 = k1; continue; };

         c_state_out_len = 3;
         c_tPos = c_tt[c_tPos];
         k1 = (unsigned char)(c_tPos & 0xff);
         c_tPos >>= 8;
         c_nblock_used++;
         if (c_nblock_used == s_save_nblockPP) continue;
         if (k1 != c_k0) { c_k0 = k1; continue; };

         c_tPos = c_tt[c_tPos];
         k1 = (unsigned char)(c_tPos & 0xff);
         c_tPos >>= 8;
         c_nblock_used++;
         c_state_out_len = ((int)k1) + 4;
         c_tPos = c_tt[c_tPos];
         c_k0 = (unsigned char)(c_tPos & 0xff);
         c_tPos >>= 8;
         c_nblock_used++;
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
