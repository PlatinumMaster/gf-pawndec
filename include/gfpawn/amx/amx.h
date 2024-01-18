#ifndef GF_AMX 
#define GF_AMX

#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <format>
#include <map>
#include <stack>
#include <cmath>

#include "amx_commands.h"
#include "amx_opcodes.h"
#include "amx_constants.h"
#include "amx_util.h"
#include "../ir/ir.h"

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
                std::cout << std::format("- Definition size:  {}", m_Header->DefinitionSize) << std::endl;
                std::cout << std::format("- Code Start Address:   0x{:X}", m_Header->Code) << std::endl;
                std::cout << std::format("- Data Start Address:   0x{:X}", m_Header->Data) << std::endl;
                std::cout << std::format("- Heap Start Address:   0x{:X}", m_Header->Heap) << std::endl;
                std::cout << std::format("- Stack End Address:    0x{:X}", m_Header->StackPointer) << std::endl;
                std::cout << std::format("- Program Main: 0x{:X}", m_Header->InstructionPointer) << std::endl;

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
                std::vector<std::string> *SymbolVectors[] = {
                    &m_PublicSymbols, 
                    &m_NativeSymbols, 
                    &m_LibSymbols, 
                    &m_PubVarSymbols, 
                    &m_TagNameSymbols, 
                    &m_NameTableSymbols, 
                    &m_OverlaySymbols
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
                            Name = std::format("HASH_{}", Entry.Hash);
                        }
                        std::cout << "\t- " << Name << std::endl;
                        SymbolVectors[i]->push_back(Name);
                    }
                }

                // Allocate bufers for code and data.
                m_CodeSize = (m_Header->Data - m_Header->Code);
                m_DataSize = (m_Header->Heap - m_Header->Data);

                m_Code = (uint8_t *)malloc(m_CodeSize * sizeof(uint8_t));
                m_Data = (uint8_t *)malloc(m_DataSize * sizeof(uint8_t));
                memset(m_Code, 0, m_CodeSize * sizeof(uint8_t));
                memset(m_Data, 0, m_DataSize * sizeof(uint8_t));

                // Check if compressed.
                if (m_Header->Flags & Flags::AMX_FLAG_COMPACT) {
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
                    input.read((char *)Data, DecompressedSize);
                    pawn::AMXUtil::DecompressInPlace(Data, CompressedSize, DecompressedSize);

                    // Copy decompressed data to the respective locations.
                    memcpy(m_Code, Data, m_CodeSize);
                    memcpy(m_Data, Data + m_CodeSize, m_DataSize);
                    std::fstream dump("data.bin", std::ios::out | std::ios::binary);
                    dump.write((char *)m_Data, m_DataSize);
                    dump.close();
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

            void Disassemble(std::string path) {
                Decode();
                ConstructFlow();
                WriteAssembly(path);
            }


            void Decompile(std::string path) {
                Decode();
                ConstructFlow();
                CallAnalysis();
                WriteLiftedRepresentation(path);
            }
            
            void WriteLiftedRepresentation(std::string path) {
                std::fstream ir_output(path, std::ios::out);
                for (std::pair<uint32_t, Node *> function : m_Functions) {
                    Node *operation = function.second;
                    uint32_t Address = function.first;
                    std::vector<uint32_t> m_ClosedList;
                    m_ClosedList.push_back(Address);
                    while (operation) {
                        if (operation->m_Command) {
                            Command *cmd = operation->m_Command;
                            switch (cmd->GetOpcode()) {
                                case CMD_PROC: {
                                    if (Address == m_Header->InstructionPointer) {
                                        ir_output << std::format("main(", Address);
                                    } else {
                                        ir_output << std::format("fn_{}(", Address);
                                    }
                                    uint32_t parameter_max = m_FuncParameters.at(Address);
                                    for (int i = 0; i < parameter_max; ++i) {
                                        ir_output << std::format("p{}", i);
                                        if (i != parameter_max - 1) {
                                            ir_output << std::format(", ", i);
                                        }
                                    }
                                    ir_output << std::format(") {{") << std::endl;
                                    break;
                                }
                                case CMD_RETN: {
                                    ir_output << std::format("}}") << std::endl;
                                    break;
                                }
                                case CMD_JUMP: {
                                    uint32_t jump_address = ((Jump *)cmd->GetParameters()->at(0))->GetValue();
                                    if (std::find(m_ClosedList.begin(), m_ClosedList.end(), jump_address) != m_ClosedList.end()) {
                                        continue;
                                    }
                                    if (function.first == jump_address) {
                                        continue;
                                    }
                                    m_ClosedList.push_back(jump_address);
                                    break;
                                }
                                default: {
                                    ir_output << std::format("\t#emit {} {}", cmd->GetLabel(), cmd->GetParametersToString()) << std::endl;
                                    break;
                                }
                            }
                            Address += cmd->GetSize();
                        }
                        operation = operation->m_Next;
                    } 
                }
                ir_output.close(); 
            }

            void CallAnalysis() {
                std::cout << "Doing call analysis..." << std::endl;
                for (std::pair<uint32_t, Node*> block_pair : m_Functions) {
                    std::stack<uint32_t> Stack;
                    CallAnalysisFromNode(block_pair.second, Stack);
                }

                for (std::pair<uint32_t, std::vector<uint32_t>> p : m_FuncEstimates) {
                    if (std::adjacent_find(p.second.begin(), p.second.end(), std::not_equal_to<>()) == p.second.end()) {
                        std::cout << std::format("Parameters are in agreement! function {} has {} parameters...", p.first, p.second.at(0)) << std::endl;
                    } else {
                        std::sort(p.second.begin(), p.second.end());
                        std::cout << std::format("Parameters are NOT in agreement! function {} Maybe varadic function. Will assume largest param cnt ({})", p.first, p.second.at(0)) << std::endl;
                    }
                    m_FuncParameters.insert(std::make_pair(p.first, p.second.at(0)));
                }

                for (std::pair<std::string, std::vector<uint32_t>> p : m_NativeEstimates) {
                    if (std::adjacent_find(p.second.begin(), p.second.end(), std::not_equal_to<>()) == p.second.end()) {
                        std::cout << std::format("Parameters are in agreement! function {} has {} parameters...", p.first, p.second.at(0)) << std::endl;
                    } else {
                        std::sort(p.second.begin(), p.second.end());
                        std::cout << std::format("Parameters are NOT in agreement! function {} Maybe varadic function. Will assume largest param cnt ({})", p.first, p.second.at(0)) << std::endl;
                    }
                    m_NativeParameters.insert(std::make_pair(p.first, p.second.at(0)));
                }
            }

            void Decode() {
                uint32_t *CodePtr = (uint32_t*)(m_Code);
                uint32_t CurrentAddress = 0x0;
                uint32_t CodeSize = m_Header->Data - m_Header->Code;

                while (CurrentAddress < CodeSize) {
                    uint32_t CommandIndex = *CodePtr++;
                    Command* cmd = new Command(CommandList[CommandIndex & 0xFFFF]);
                    std::cout << (cmd->GetLabel()) << std::endl << "Params: " << cmd->GetParameterCount() << std::endl;
                    bool IsPacked = false;
                    for (ParameterTypes t : cmd->GetParameterTypes()) {
                        switch (t) {
                            case JUMP: {
                                cmd->AddParameter(new Jump(CurrentAddress + (int32_t)*CodePtr++));
                                Jump* Target = (Jump *)cmd->GetParameters()->at(0);
                                if (std::find(m_JumpAddresses.begin(), m_JumpAddresses.end(), Target->GetValue()) == m_JumpAddresses.end()) {
                                    m_JumpAddresses.push_back(Target->GetValue());
                                }
                                break;
                            }
                            case SWITCH: {
                                cmd->AddParameter(new Switch(CurrentAddress + (int32_t)*CodePtr++));
                                Switch* Target = (Switch *)cmd->GetParameters()->at(0);
                                if (std::find(m_CaseTables.begin(), m_CaseTables.end(), Target->GetValue()) == m_CaseTables.end()) {
                                    m_CaseTables.push_back(Target->GetValue());
                                }
                                break;
                            }
                            case CALL: {
                                cmd->AddParameter(new Call(CurrentAddress + (int32_t)*CodePtr++));
                                Call* Target = (Call *)cmd->GetParameters()->at(0);
                                if (std::find(m_FunctionAddresses.begin(), m_FunctionAddresses.end(), Target->GetValue()) == m_FunctionAddresses.end()) {
                                    m_FunctionAddresses.push_back(Target->GetValue());
                                }
                                break;
                            }
                            case NATIVE: {
                                cmd->AddParameter(new Native(m_NativeSymbols[*CodePtr++]));
                                break;
                            }
                            case VALUE: {
                                cmd->AddParameter(new Value(*CodePtr++));
                                break;
                            }
                            case PACKED: {
                                cmd->AddParameter(new Value((int16_t)(CommandIndex >> 0x10)));
                                IsPacked = true;
                                break;
                            }
                            case CASETBL: {
                                Cases *cases = new Cases();
                                int32_t Skip = 0x2;

                                // Default case is also a case...
                                int32_t cases_count = *CodePtr++;
                                Jump *default_address = new Jump(CurrentAddress + sizeof(int32_t) + *CodePtr++);
                                cases->AddEntry({
                                    cases_count, 
                                    default_address
                                });
                                if (std::find(m_JumpAddresses.begin(), m_JumpAddresses.end(), default_address->GetValue()) == m_JumpAddresses.end()) {
                                    m_JumpAddresses.push_back(default_address->GetValue());
                                }

                                // Parse the rest of the actual cases.
                                for (int i = 0; i < cases_count; ++i) {
                                    int32_t case_value = *CodePtr++;
                                    Jump *jump_address = new Jump(CurrentAddress + (Skip + 1) * sizeof(uint32_t) + *CodePtr++);
                                    cases->AddEntry({
                                        case_value, 
                                        jump_address
                                    });
                                    if (std::find(m_JumpAddresses.begin(), m_JumpAddresses.end(), jump_address->GetValue()) == m_JumpAddresses.end()) {
                                        m_JumpAddresses.push_back(jump_address->GetValue());
                                    }
                                    Skip += 0x2;
                                }
                                cmd->AddParameter(cases);
                                break;
                            }
                        }
                    }
                    std::cout << std::format("Size: {}", IsPacked ? sizeof(uint32_t) : cmd->GetSize()) << std::endl;
                    m_Commands.insert(std::pair<uint32_t, Command *>(CurrentAddress, cmd));
                    CurrentAddress += cmd->GetSize();
                }
                std::cout << std::format("Calls = {}, Jumps = {}", m_FunctionAddresses.size(), m_JumpAddresses.size()) << std::endl;
            }

            void ConstructFlow() {
                // Init; setup blocks for all calls and jumps.
                for (uint32_t Address : m_FunctionAddresses) {
                    this->m_Functions.insert(std::make_pair(Address, new Node(NULL, NULL)));
                }
                for (uint32_t Address : m_JumpAddresses) {
                    this->m_Jumps.insert(std::make_pair(Address, new Node(NULL, NULL)));
                }

                // Now build the lists with commands.
                for (uint32_t Address : m_FunctionAddresses) {
                    PopulateBlocks(Address);
                }
                
                for (uint32_t Address : m_JumpAddresses) {
                    PopulateBlocks(Address);
                }
            }

            void PopulateBlocks(uint32_t Address) {
                Node *Head, *Current;
                uint32_t CurrentAddress = Address;

                // Find a block
                if (m_Jumps.find(Address) != m_Jumps.end()) {
                    Head = m_Jumps.at(Address);
                } else if (m_Functions.find(Address) != m_Functions.end()) {
                    Head = m_Functions.at(Address);
                }
                Current = Head;

                while (true) {                    
                    // Get the command corresponding to the address.
                    Command *command = this->m_Commands.at(CurrentAddress);

                    // Update the current node's command.
                    Current->m_Command = command;
                    Current->Address = CurrentAddress;

                    Node *NewNode = new Node(Current, nullptr);

                    // Handle the next node
                    switch (command->GetOpcode()) {
                        case CMD_JUMP: 
                        case CMD_JREL: {  
                            // Link to absolute jump.
                            uint32_t JumpAddress = ((Jump *)command->GetParameters()->at(0))->GetValue();
                            Current->m_Next = m_Jumps.at(JumpAddress);
                            break;
                        }     
                        case CMD_JZER:      
                        case CMD_JNZ:       
                        case CMD_JEQ:       
                        case CMD_JNEQ:      
                        case CMD_JLESS:     
                        case CMD_JLEQ:      
                        case CMD_JGRTR:     
                        case CMD_JGEQ:      
                        case CMD_JSLESS:    
                        case CMD_JSLEQ:     
                        case CMD_JSGRTR:    
                        case CMD_JSGEQ: {
                            // Link to conditional jump.
                            uint32_t JumpAddress = ((Jump *)command->GetParameters()->at(0))->GetValue();
                            // Create new node, link it to our current one.
                            // Set up conditional jump.
                            Current->m_NextConditionalOrCall = m_Jumps.at(JumpAddress);
                            Current->m_Next = NewNode;
                            break;
                        }
                        case CMD_CALL: {
                            // Link to call.
                            uint32_t CallAddress = ((Call *)command->GetParameters()->at(0))->GetValue();
                            // Set up conditional jump.
                            Current->m_NextConditionalOrCall = m_Functions.at(CallAddress);
                            Current->m_Next = NewNode;
                            break;
                        }
                        case CMD_RETN: {
                            break;
                        }
                        default: {
                            // Link to instruction.
                            Current->m_Next = NewNode;
                            break;
                        }
                    }

                    if (command->GetOpcode() == CMD_JUMP || command->GetOpcode() == CMD_RETN) {
                        break;
                    }
                    
                    Current = Current->m_Next;
                    CurrentAddress += command->GetSize();
                }
            }

            void CallAnalysisFromNode(Node *head, std::stack<uint32_t> Stack) {    
                Node *current = head;
                while (current) {
                    if (std::find(m_CallAnalysisClosedList.begin(), m_CallAnalysisClosedList.end(), current->Address) != m_CallAnalysisClosedList.end()) {
                        // Already processed this...
                        return;
                    }
                    m_CallAnalysisClosedList.push_back(current->Address);
                    Command *command = current->m_Command;
                    std::cout << command->GetLabel() << std::endl;
                    std::cout << current->m_Next << std::endl;
                    std::cout << current->m_NextConditionalOrCall << std::endl;
                    std::cout << "Old Stack Size: " << Stack.size() << std::endl;

                    switch (command->GetOpcode()) {
                        case CMD_PUSH_PRI:  
                        case CMD_PUSH_ALT:
                        case CMD_PUSH_P_C:  
                        case CMD_PUSH_P:  
                        case CMD_PUSH_C:  
                        case CMD_PUSH_P_S:
                        case CMD_PUSHR_PRI: 
                        case CMD_PUSHR_C:   
                        case CMD_PUSHR_S:   
                        case CMD_PUSHR_ADR: 
                        case CMD_PUSH_ADR:      
                        case CMD_PUSH2_C:   
                        case CMD_PUSH2:     
                        case CMD_PUSH2_S:   
                        case CMD_PUSH2_ADR: 
                        case CMD_PUSH3_C:   
                        case CMD_PUSH3:     
                        case CMD_PUSH3_S:   
                        case CMD_PUSH3_ADR: 
                        case CMD_PUSH4_C:   
                        case CMD_PUSH4:     
                        case CMD_PUSH4_S:   
                        case CMD_PUSH4_ADR: 
                        case CMD_PUSH5_C:   
                        case CMD_PUSH5:     
                        case CMD_PUSH5_S:   
                        case CMD_PUSH5_ADR:
                        case CMD_PUSH_P_ADR:
                        case CMD_PUSHR_P_C: 
                        case CMD_PUSHR_P_S: 
                        case CMD_PUSHR_P_ADR: {
                            if (!command->GetParameterCount()) {
                                // Shim
                                Stack.push(0);
                            } else {
                                for (int j = 0; j < command->GetParameterCount(); ++j) {
                                    uint32_t Data = ((Value*)command->GetParameters()->at(j))->GetValue();
                                    std::cout << Data << std::endl;
                                    Stack.push(Data);
                                }
                            }
                            break;
                        }
                        case CMD_POP_PRI:
                        case CMD_POP_ALT: {              
                            Stack.pop();
                            break;
                        }
                        case CMD_CALL: {
                            // Most recent element on the stack should be byte count for parameter...
                            uint32_t parameter_count = Stack.top();
                            parameter_count >>= 0x2;
                            Stack.pop();
                            uint32_t TargetFunction = ((Call *)command->GetParameters()->at(0))->GetValue();
                            m_FuncEstimates[TargetFunction].push_back(parameter_count);
                            for (int j = 0; j < parameter_count; ++j) {
                                Stack.pop();
                            }
                            break;
                        }
                        case CMD_SYSREQ_N: {
                            uint32_t parameter_count = ((Value *)command->GetParameters()->at(1))->GetValue() >> 0x2;
                            std::string TargetFunction = ((Native *)command->GetParameters()->at(0))->ToString();
                            m_NativeEstimates[TargetFunction].push_back(parameter_count);
                            for (int j = 0; j < parameter_count; ++j) {
                                Stack.pop();
                            }
                            break;
                        }
                        case CMD_JZER:      
                        case CMD_JNZ:       
                        case CMD_JEQ:       
                        case CMD_JNEQ:      
                        case CMD_JLESS:     
                        case CMD_JLEQ:      
                        case CMD_JGRTR:     
                        case CMD_JGEQ:      
                        case CMD_JSLESS:    
                        case CMD_JSLEQ:     
                        case CMD_JSGRTR:    
                        case CMD_JSGEQ: {
                            if (current->m_NextConditionalOrCall) {
                                CallAnalysisFromNode(current->m_NextConditionalOrCall, Stack);
                            }
                            break;
                        }
                    }

                    std::cout << "New Stack Size: " << Stack.size() << std::endl;
                    current = current->m_Next;
                }
            }

            void WriteAssembly(std::string path) {
                uint32_t CurrentAddress = 0;
                std::fstream amx_output(path, std::ios::out);
                for (std::pair<uint32_t, Command *> cmd_pair : m_Commands) {
                    bool IsJump = std::find(m_JumpAddresses.begin(), m_JumpAddresses.end(), CurrentAddress) != m_JumpAddresses.end();
                    bool IsCall = std::find(m_FunctionAddresses.begin(), m_FunctionAddresses.end(), CurrentAddress) != m_FunctionAddresses.end();
                    bool IsCaseTable = std::find(m_CaseTables.begin(), m_CaseTables.end(), CurrentAddress) != m_CaseTables.end();
                    
                    if (IsJump) {
                        amx_output << std::format("jump_{}:", CurrentAddress) << std::endl;
                    } else if (CurrentAddress == m_Header->InstructionPointer) {
                        amx_output << std::format("main:", CurrentAddress) << std::endl;
                    } else if (IsCall) {
                        amx_output << std::format("fn_{}:", CurrentAddress) << std::endl;
                    } else if (IsCaseTable) {
                        amx_output << std::format("casetbl_{}:", CurrentAddress) << std::endl;
                    }
                    amx_output << std::format("\t{} {}", cmd_pair.second->GetLabel(), cmd_pair.second->GetParametersToString(), CurrentAddress) << std::endl;

                    CurrentAddress += cmd_pair.second->GetSize();
                }
                amx_output.close();
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
                uint32_t StackPointer;
                uint32_t InstructionPointer;
                uint32_t Publics;
                uint32_t Natives;
                uint32_t Libraries;
                uint32_t PublicVariables;
                uint32_t Tags;
                uint32_t NameTable;
                uint32_t Overlays;
            };

            enum Flags {
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

            // Disassembly stuff. Will likely be deleted...
            std::vector<uint32_t> m_FunctionAddresses, m_JumpAddresses;
            std::vector<uint32_t> m_CaseTables;
            std::map<uint32_t, Command *> m_Commands;
            std::map<uint32_t, Node*> m_Functions, m_Jumps;
            std::map<uint32_t, std::vector<uint32_t>> m_FuncEstimates;
            std::map<std::string, std::vector<uint32_t>> m_NativeEstimates;
            std::vector<uint32_t> m_CallAnalysisClosedList;
            std::map<std::string, std::vector<uint32_t>> m_NativeParameters;
            std::map<uint32_t, uint32_t> m_FuncParameters;

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