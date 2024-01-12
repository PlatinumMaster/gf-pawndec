#ifndef AMX_UTIL
#define AMX_UTIL

#include <assert.h>
#include <cstdint>
#include "amx_constants.h"
#include "xy_hashtable.h"

namespace pawn {
    class AMXUtil {
        public:
            static std::string FNVLookup(uint32_t Hash) {
                for (std::string Name : HASHTABLE) {
                    if (CalculateFNV(Name) == Hash) {
                        return Name;
                    }
                }
                return "";
            }

            static uint32_t CalculateFNV(std::string str) {
                constexpr int FNV_PRIME = 0x83;
                uint32_t hash = 0;
                for (int i = 0; i < str.length(); ++i) {
                    hash *= FNV_PRIME; // hash * prime
                    hash ^= str.at(i); // hash ^ data
                }
                return hash;
            }

            static void DecompressInPlace(uint8_t* code, uint64_t codesize, uint64_t memsize) {
                uint32_t c;
                struct {
                    long memloc;
                    uint32_t c;
                } spare[AMX_COMPACTMARGIN];
                int sh = 0, st = 0, sc = 0;
                int shift;

                /* for in-place expansion, move from the end backward */
                assert(memsize % sizeof(int32_t) == 0);
                while (codesize > 0) {
                    c = 0;
                    shift = 0;
                    do {
                        codesize--;
                        /* no input byte should be shifted out completely */
                        assert(shift < 8 * sizeof(int32_t));
                        /* we work from the end of a sequence backwards; the final code in
                        * a sequence may not have the continuation bit set */
                        assert(shift > 0 || (code[(size_t)codesize] & 0x80) == 0);
                        c |= (uint32_t)(code[(size_t)codesize] & 0x7f) << shift;
                        shift += 7;
                    } while (codesize > 0 && (code[(size_t)codesize - 1] & 0x80) != 0);
                    /* sign expand */
                    if ((code[(size_t)codesize] & 0x40) != 0) {
                        while (shift < (int)(8 * sizeof(int32_t))) {
                            c |= (uint32_t)0xff << shift;
                            shift += 8;
                        } /* while */
                    } /* if */

                    /* store */
                    while (sc && (spare[sh].memloc > codesize)) {
                        *(uint32_t*)(code + (int)spare[sh].memloc) = spare[sh].c;
                        sh = (sh + 1) % AMX_COMPACTMARGIN;
                        sc--;
                    } /* while */

                    memsize -= sizeof(int32_t);
                    assert(memsize >= 0);

                    if ((memsize > codesize) || ((memsize == codesize) && (memsize == 0))) {
                        *(uint32_t*)(code + (size_t)memsize) = c;
                    } else {
                        assert(sc < AMX_COMPACTMARGIN);
                        spare[st].memloc = memsize;
                        spare[st].c = c;
                        st = (st + 1) % AMX_COMPACTMARGIN;
                        sc++;
                    } /* if */
                } /* while */
                /* when all bytes have been expanded, the complete memory block should be done */
                assert(memsize == 0);
            }

            struct TableDef {
                const std::string Name;
                uint32_t Size;
            };

            struct TableEntry {
                uint32_t Address;
                uint32_t Hash;
            };
    };
}

#endif