#ifndef GF_AMX 
#define GF_AMX

#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>

#include "amx_commands.h"
#include "amx_opcodes.h"
#include "amx_constants.h"
#include "amx_util.h"

namespace pawn {
    class AMX {
        public:
            AMX() {

            }

            AMX(std::ifstream & input) {
                // Read header.
                m_Header = (AMXHeader *)malloc(sizeof(AMXHeader));
                memset(m_Header, 0, sizeof(AMXHeader));
                input.read((char *)m_Header, sizeof(AMXHeader));

                std::cout << "Checking if valid GF_AMX script..." << std::endl;

                // Before we do anything, check if the file has the right magic.
                if (m_Header->Magic != AMX_MAGIC) {
                    std::cout << "Invalid magic; expected = " << AMX_MAGIC << ", got " << m_Header->Magic << std::endl;
                    exit(1);
                }

                std::cout << "Valid GF_AMX script found!" << std::endl;
                std::cout << "Script Container Information:" << std::endl;

                // Header stuff.
                printf("- Definition size:  %i\n", m_Header->DefinitionSize);
                printf("- Code Start Address:   0x%08X\n", m_Header->Code);
                printf("- Data Start Address:   0x%08X\n", m_Header->Data);
                printf("- Heap Start Address:   0x%08X\n", m_Header->Heap);
                printf("- Stack End Address:    0x%08X\n", m_Header->stp);
                printf("- Program Main: 0x%08X\n", m_Header->cip);

                // Functions and whatnot.
                pawn::AMXUtil::TableDef Properties[] = {
                    {"Public Functions", (m_Header->Natives - m_Header->Publics) / m_Header->DefinitionSize},
                    {"Native Functions", (m_Header->Libraries - m_Header->Natives) / m_Header->DefinitionSize},
                    {"Libraries", (m_Header->PublicVariables - m_Header->Libraries) / m_Header->DefinitionSize},
                    {"Public Variables", (m_Header->Tags - m_Header->PublicVariables) / m_Header->DefinitionSize},
                    {"Public Tag Names", (m_Header->NameTable - m_Header->Tags) / m_Header->DefinitionSize},
                    {"Name Table", (m_Header->Overlays  - m_Header->NameTable) / m_Header->DefinitionSize},
                    {"Overlays", (m_Header->Code - m_Header->Overlays) / m_Header->DefinitionSize},
                };

                // Just so I don't have to do a switch case somewhere...
                std::vector<std::string> SymbolVectors[] = {
                    m_PublicSymbols, 
                    m_NativeSymbols, 
                    m_LibSymbols, 
                    m_PubVarSymbols, 
                    m_TagNameSymbols, 
                    m_NameTableSymbols, 
                    m_OverlaySymbols
                };

                for (int i = 0; i < 0x7; ++i) {
                    std::cout << "- " << Properties[i].Name << ": " << Properties[i].Size << std::endl;
                    for (int cell = 0; cell < Properties[i].Size; ++cell) {
                        // Read table entry.
                        pawn::AMXUtil::TableEntry Entry;
                        input.read((char *)&Entry, sizeof(pawn::AMXUtil::TableEntry));

                        // Bruteforce hashes to find the name corresponding to the hash.
                        std::string Name = pawn::AMXUtil::FNVLookup(Entry.Hash);
                        if (Name == "") {
                            printf("\tCould not find a name that corresponds to hash %x; skipping...\n", Entry.Hash); 
                        } else {
                            std::cout << "\t- " << Name << std::endl;
                            SymbolVectors[i].push_back(Name);
                        }
                    }
                }

                // Allocate bufers for code and data.
                m_CodeSize = (m_Header->Data - m_Header->Code);
                m_DataSize = (m_Header->Heap - m_Header->Data);

                m_Code = (uint8_t *)malloc(m_CodeSize * sizeof(uint8_t));
                m_Data = (uint8_t *)malloc(m_DataSize * sizeof(uint8_t));

                // Check if compressed.
                if (m_Header->Flags & AMXFlags::AMX_FLAG_COMPACT) {
                    // Compressed; time to decompress.
                    std::cout << "File is compressed! Decompressing..." << std::endl;
                    
                    // Calculate new sizes.
                    uint32_t CompressedSize = m_Header->Size - m_Header->Code;
                    uint32_t DecompressedSize = m_Header->Heap - m_Header->Code;
                    
                    // Allocate enough space to do decompression of code and data at once.
                    uint8_t *Data = (uint8_t *)malloc(DecompressedSize);
                    memset(Data, 0, DecompressedSize);
                    
                    // Read data and perform decompression.
                    input.seekg(m_Header->Code);
                    input.read((char *)Data, CompressedSize);
                    pawn::AMXUtil::DecompressInPlace(Data, CompressedSize, DecompressedSize);

                    // Copy decompressed data to the respective locations.
                    memcpy(m_Code, Data, m_CodeSize);
                    memcpy(m_Data, Data, m_DataSize);

                    free(Data);
                } else {
                    // Not compressed; fill up m_Code/m_Data normally.
                    input.seekg(m_Header->Code);
                    input.read((char *)m_Code, m_CodeSize);
                    input.seekg(m_Header->Data);
                    input.read((char *)m_Data, m_DataSize);
                }

                // Cleanup.
                input.close();
            }

            void Decode() {
                uint32_t OpcodeCount = m_CodeSize >> 2;
                uint32_t *CodePtr = (uint32_t *)m_Code;
                for (uint32_t Index = 0; Index < OpcodeCount; ++Index) {
                    Command* cmd = CommandList[*CodePtr++ & 0xFF];
                    std::cout << cmd->GetLabel() << " ";
                    for (uint32_t ParamIndex = 0; ParamIndex < cmd->GetParameterCount(); ++ParamIndex) {
                        std::cout << *CodePtr++;;
                    }
                    std::cout << std::endl;
                }
            }

        private:
            struct AMXHeader {
                uint32_t Size;
                uint16_t Magic;
                uint8_t FileVersion;
                uint8_t AMXVersion;
                uint16_t Flags;
                uint16_t DefinitionSize;
                uint32_t Code;
                uint32_t Data;
                uint32_t Heap;
                uint32_t stp;
                uint32_t cip;
                uint32_t Publics;
                uint32_t Natives;
                uint32_t Libraries;
                uint32_t PublicVariables;
                uint32_t Tags;
                uint32_t NameTable;
                uint32_t Overlays;
            };

            enum AMXFlags {
                AMX_FLAG_OVERLAY = 0x0001, /* all function calls use overlays */
                AMX_FLAG_DEBUG = 0x0002,   /* symbolic info. available */
                AMX_FLAG_COMPACT = 0x0004, /* compact encoding */
                AMX_FLAG_SLEEP = 0x0008,   /* script uses the sleep instruction (possible re-entry or power-down mode) */

                AMX_FLAG_NOCHECKS = 0x0010,  /* no array bounds checking; no BREAK opcodes */
                AMX_FLAG_DSEG_INIT = 0x0020, /* data section is explicitly initialized */
                AMX_FLAG_RESERVED_1 = 0x0040,
                AMX_FLAG_RESERVED_2 = 0x0080,

                AMX_FLAG_RESERVED_3 = 0x0100,
                AMX_FLAG_RESERVED_4 = 0x0200,
                AMX_FLAG_RESERVED_5 = 0x0400,
                AMX_FLAG_SYSREQN = 0x0800, /* script uses new (optimized) version of SYSREQ opcode */

                AMX_FLAG_NTVREG = 0x1000, /* all native functions are registered */
                AMX_FLAG_JITC = 0x2000,   /* abstract machine is JIT compiled */
                AMX_FLAG_VERIFY = 0x4000, /* busy verifying P-code */
                AMX_FLAG_INIT = 0x8000,   /* AMX has been initialized */
            };

            AMXHeader *m_Header;
            uint8_t *m_Code;
            uint32_t m_CodeSize;
            uint8_t *m_Data;
            uint32_t m_DataSize;

            // Symbol stuff.
            std::vector<std::string> m_PublicSymbols; 
            std::vector<std::string> m_NativeSymbols; 
            std::vector<std::string> m_LibSymbols; 
            std::vector<std::string> m_PubVarSymbols; 
            std::vector<std::string> m_TagNameSymbols; 
            std::vector<std::string> m_NameTableSymbols; 
            std::vector<std::string> m_OverlaySymbols;
    };
}

#endif