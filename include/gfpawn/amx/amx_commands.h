#ifndef GF_AMX_CMD
#define GF_AMX_CMD

#include <string>
#include <cstdint>
#include <sstream>
#include "amx_opcodes.h"

namespace pawn { 
    class Parameter {
        public:
            virtual std::string ToString();
            virtual int GetSize();
    };

    class Value : public Parameter {
        public:
            Value(uint32_t Data = 0) {
                this->m_Data = Data;
            }

            std::string ToString() {
                return std::format("{}", m_Data);
            } 

            int GetSize() {
                return sizeof(uint32_t);
            }
        private:
            uint32_t m_Data;
    };

    class Native : public Parameter {
        public:
            Native(std::string Label) {
                this->m_Data = Label;
            }

            std::string ToString() {
                return std::format("{}", m_Data);
            } 

            int GetSize() {
                return sizeof(uint32_t);
            }
        private:
            std::string m_Data;
    };

    // class Comma {
    //     public:
    //         Packed(uint32_t Data = 0) {
    //             this->m_Index = Data & 0xFFFF;
    //             this->m_Parameter = (Data & 0xFFFF0000) >> 0x8;
    //         }

    //         std::string ToString() {

    //         } 
    //     private:
    //         uint32_t m_Index;
    //         uint32_t m_Parameter;
    // };

    class Jump : public Parameter {
        public:
            Jump(uint32_t Address) {
                this->m_Address = Address;
            }

            std::string ToString() {
                return std::format("jump_{}", m_Address);
            } 

            int GetSize() {
                return sizeof(uint32_t);
            }

            uint32_t GetValue(){
                return this->m_Address;
            }
        private:
            uint32_t m_Address;
    };

    class Call : public Parameter {
        public:
            Call(uint32_t Address) {
                this->m_Address = Address;
            }

            std::string ToString() {
                return std::format("jump_{}", m_Address);
            } 

            int GetSize() {
                return sizeof(uint32_t);
            }

            uint32_t GetValue(){
                return this->m_Address;
            }
        private:
            uint32_t m_Address;
    };

    class Cases : public Parameter {
        public:
            struct CaseTableEntry {
                uint32_t Value;
                Jump Target;
            };

            void AddEntry(CaseTableEntry e) {
                this->m_CaseTableEntries.push_back(e);
            }

            std::string ToString() {
                std::stringstream string;
                for (CaseTableEntry entry : m_CaseTableEntries) {
                    string << std::format("case {}, {}", entry.Value, entry.Target.GetValue()) << std::endl;
                }
                return string.str();
            } 

            int GetSize() {
                return sizeof(uint32_t) * (m_CaseTableEntries.size() << 0x1);
            }
        private:
            std::vector<CaseTableEntry> m_CaseTableEntries;
    };

    
    class Switch : public Parameter {
        public:
            Switch(Cases case_table) {
                this->m_CaseTable = case_table;
            }
            
            Cases GetCaseTable() {
                return this->m_CaseTable;
            }
            
            std::string ToString() {
                return "0"; // I dunno what to do here lol
            }             
            
            int GetSize() {
                return sizeof(uint32_t);
            }
        private:
            Cases m_CaseTable;
    };

    class Command {
        public:
            Command(pawn::Opcode opcode, std::string label, std::vector<ParameterTypes> types, std::vector<Parameter*> *parameters = NULL) {
                this->m_Label = label;
                this->m_Opcode = opcode;
                this->m_Type = types;
                this->m_Parameters = parameters;
            }

            Command(Command *t) {
                this->m_Label = t->m_Label;
                this->m_Opcode = t->m_Opcode;
                this->m_Type = t->m_Type;
                this->m_Parameters = t->m_Parameters;
            }

            std::string GetLabel() {
                return this->m_Label;
            }

            pawn::Opcode GetOpcode() {
                return this->m_Opcode;
            }

            std::vector<ParameterTypes> GetParameterTypes() {
                return this->m_Type;
            }

            uint32_t GetSize() {
                uint32_t Base = sizeof(uint32_t);
                if (std::vector<Parameter *> *Parameters = this->GetParameters()) {
                    for (Parameter *p : *Parameters) {
                        Base += p->GetSize();
                    }    
                }
                return Base;
            }

            uint32_t GetParameterCount() {
                return m_Type.size();
            }

            std::vector<Parameter *> *GetParameters() {
                return this->m_Parameters;
            }

            std::string GetParametersToString() {
                std::stringstream param_string;
                if (!this->m_Parameters) {
                    return "";
                }
                for (Parameter *parameter : *this->m_Parameters) {
                    param_string << parameter->ToString() << " ";
                }
                return param_string.str();
            }


            void AddParameter(Parameter *parameter) {
                if (!this->m_Parameters) {
                    this->m_Parameters = new std::vector<Parameter*>();
                }
                m_Parameters->push_back(parameter);
            }

        private:                
            std::string m_Label;
            pawn::Opcode m_Opcode;
            uint32_t m_ParameterCount;
            std::vector<ParameterTypes> m_Type;
            std::vector<Parameter*> *m_Parameters;
    };

    // TODO: Dynamically build from YML or something smarter.
    static Command* CommandList[] = {
        new Command(CMD_NOOP, "noop", {}), // CMD_UNKNOWN
        new Command(CMD_LOAD_PRI, "load.pri", {VALUE}), // CMD_LOAD_PRI
        new Command(CMD_LOAD_ALT, "load.alt", {VALUE}), // CMD_LOAD_ALT
        new Command(CMD_LOAD_S_PRI, "load.s.pri", {VALUE}), // CMD_LOAD_S_PRI
        new Command(CMD_LOAD_S_ALT, "load.s.alt", {VALUE}), // CMD_LOAD_S_ALT
        new Command(CMD_LREF_PRI, "lref.pri", {VALUE}), // CMD_LREF_PRI
        new Command(CMD_LREF_ALT, "lref.alt", {VALUE}), // CMD_LREF_ALT
        new Command(CMD_LREF_S_PRI, "lref.s.pri", {VALUE}), // CMD_LREF_S_PRI
        new Command(CMD_LREF_S_ALT, "lref.s.alt", {VALUE}), // CMD_LREF_S_ALT
        new Command(CMD_LOAD_I, "load.i", {}), // CMD_LOAD_I
        new Command(CMD_LODB_I, "lodb.i", {VALUE}), // CMD_LODB_I
        new Command(CMD_CONST_PRI, "const.pri", {VALUE}), // CMD_CONST_PRI
        new Command(CMD_CONST_ALT, "const.alt", {VALUE}), // CMD_CONST_ALT
        new Command(CMD_ADDR_PRI, "addr.pri", {VALUE}), // CMD_ADDR_PRI
        new Command(CMD_ADDR_ALT, "addr.alt", {VALUE}), // CMD_ADDR_ALT
        new Command(CMD_STOR_PRI, "stor.pri", {VALUE}), // CMD_STOR_PRI
        new Command(CMD_STOR_ALT, "stor.alt", {VALUE}), // CMD_STOR_ALT
        new Command(CMD_STOR_S_PRI, "stor.s.pri", {VALUE}), // CMD_STOR_S_PRI
        new Command(CMD_STOR_S_ALT, "stor.s.alt", {VALUE}), // CMD_STOR_S_ALT
        new Command(CMD_SREF_PRI, "sref.pri", {VALUE}), // CMD_SREF_PRI
        new Command(CMD_SREF_ALT, "sref.alt", {VALUE}), // CMD_SREF_ALT
        new Command(CMD_SREF_S_PRI, "sref.s.pri", {VALUE}), // CMD_SREF_S_PRI
        new Command(CMD_SREF_S_ALT, "sref.s.alt", {VALUE}), // CMD_SREF_S_ALT
        new Command(CMD_STOR_I, "stor.i", {}), // CMD_STOR_I
        new Command(CMD_STRB_I, "strb.i", {VALUE}), // CMD_STRB_I
        new Command(CMD_LIDX, "lidx", {}), // CMD_LIDX
        new Command(CMD_LIDX_B, "lidx.b", {VALUE}), // CMD_LIDX_B
        new Command(CMD_IDXADDR, "idxaddr", {}), // CMD_IDXADDR
        new Command(CMD_IDXADDR_B, "idxaddr.b", {VALUE}), // CMD_IDXADDR_B
        new Command(CMD_ALIGN_PRI, "align.pri", {VALUE}), // CMD_ALIGN_PRI
        new Command(CMD_ALIGN_ALT, "align.alt", {VALUE}), // CMD_ALIGN_ALT
        new Command(CMD_LCTRL, "lctrl", {VALUE}), // CMD_LCTRL
        new Command(CMD_SCTRL, "sctrl", {VALUE}), // CMD_SCTRL
        new Command(CMD_MOVE_PRI, "move.pri", {}), // CMD_MOVE_PRI
        new Command(CMD_MOVE_ALT, "move.alt", {}), // CMD_MOVE_ALT
        new Command(CMD_XCHG, "xchg", {}), // CMD_XCHG
        new Command(CMD_PUSH_PRI, "push.pri", {}), // CMD_PUSH_PRI
        new Command(CMD_PUSH_ALT, "push.alt", {}), // CMD_PUSH_ALT
        new Command(CMD_PICK, "pick", {VALUE}), // CMD_PICK
        new Command(CMD_PUSH_C, "push.c", {VALUE}), // CMD_PUSH_C
        new Command(CMD_PUSH, "push", {VALUE}), // CMD_PUSH
        new Command(CMD_PUSH_S, "push.s", {VALUE}), // CMD_PUSH_S
        new Command(CMD_POP_PRI, "pop.pri", {}), // CMD_POP_PRI
        new Command(CMD_POP_ALT, "pop.alt", {}), // CMD_POP_ALT
        new Command(CMD_STACK, "stack", {VALUE}), // CMD_STACK
        new Command(CMD_HEAP, "heap", {VALUE}), // CMD_HEAP
        new Command(CMD_PROC, "proc", {}), // CMD_PROC
        new Command(CMD_RET, "ret", {}), // CMD_RET
        new Command(CMD_RETN, "retn", {}), // CMD_RETN
        new Command(CMD_CALL, "call", {CALL}), // CMD_CALL
        new Command(CMD_CALL_PRI, "call.pri", {}), // CMD_CALL_PRI
        new Command(CMD_JUMP, "jump", {JUMP}), // CMD_JUMP
        new Command(CMD_JREL, "jrel", {VALUE}), // CMD_JREL
        new Command(CMD_JZER, "jzer", {JUMP}), // CMD_JZER
        new Command(CMD_JNZ, "jnz", {JUMP}), // CMD_JNZ
        new Command(CMD_JEQ, "jeq", {JUMP}), // CMD_JEQ
        new Command(CMD_JNEQ, "jneq", {JUMP}), // CMD_JNEQ
        new Command(CMD_JLESS, "jless", {JUMP}), // CMD_JLESS
        new Command(CMD_JLEQ, "jleq", {JUMP}), // CMD_JLEQ
        new Command(CMD_JGRTR, "jgrtr", {JUMP}), // CMD_JGRTR
        new Command(CMD_JGEQ, "jgeq", {JUMP}), // CMD_JGEQ
        new Command(CMD_JSLESS, "jsless", {JUMP}), // CMD_JSLESS
        new Command(CMD_JSLEQ, "jsleq", {JUMP}), // CMD_JSLEQ
        new Command(CMD_JSGRTR, "jsgrtr", {JUMP}), // CMD_JSGRTR
        new Command(CMD_JSGEQ, "jsgeq", {JUMP}), // CMD_JSGEQ
        new Command(CMD_SHL, "shl", {}), // CMD_SHL
        new Command(CMD_SHR, "shr", {}), // CMD_SHR
        new Command(CMD_SSHR, "sshr", {}), // CMD_SSHR
        new Command(CMD_SHL_C_PRI, "shl.c.pri", {VALUE}), // CMD_SHL_C_PRI
        new Command(CMD_SHL_C_ALT, "shl.c.alt", {VALUE}), // CMD_SHL_C_ALT
        new Command(CMD_SHR_C_PRI, "shr.c.pri", {VALUE}), // CMD_SHR_C_PRI
        new Command(CMD_SHR_C_ALT, "shr.c.alt", {VALUE}), // CMD_SHR_C_ALT
        new Command(CMD_SMUL, "smul", {}), // CMD_SMUL
        new Command(CMD_SDIV, "sdiv", {}), // CMD_SDIV
        new Command(CMD_SDIV_ALT, "sdiv.alt", {}), // CMD_SDIV_ALT
        new Command(CMD_UMUL, "umul", {}), // CMD_UMUL
        new Command(CMD_UDIV, "udiv", {}), // CMD_UDIV
        new Command(CMD_UDIV_ALT, "udiv.alt", {}), // CMD_UDIV_ALT
        new Command(CMD_ADD, "add", {}), // CMD_ADD
        new Command(CMD_SUB, "sub", {}), // CMD_SUB
        new Command(CMD_SUB_ALT, "sub.alt", {}), // CMD_SUB_ALT
        new Command(CMD_AND, "and", {}), // CMD_AND
        new Command(CMD_OR, "or", {}), // CMD_OR
        new Command(CMD_XOR, "xor", {}), // CMD_XOR
        new Command(CMD_NOT, "not", {}), // CMD_NOT
        new Command(CMD_NEG, "neg", {}), // CMD_NEG
        new Command(CMD_INVERT, "invert", {}), // CMD_INVERT
        new Command(CMD_ADD_C, "add.c", {VALUE}), // CMD_ADD_C
        new Command(CMD_SMUL_C, "smul.c", {VALUE}), // CMD_SMUL_C
        new Command(CMD_ZERO_PRI, "zero.pri", {}), // CMD_ZERO_PRI
        new Command(CMD_ZERO_ALT, "zero.alt", {}), // CMD_ZERO_ALT
        new Command(CMD_ZERO, "zero", {VALUE}), // CMD_ZERO
        new Command(CMD_ZERO_S, "zero.s", {VALUE}), // CMD_ZERO_S
        new Command(CMD_SIGN_PRI, "sign.pri", {}), // CMD_SIGN_PRI
        new Command(CMD_SIGN_ALT, "sign.alt", {}), // CMD_SIGN_ALT
        new Command(CMD_EQ, "eq", {}), // CMD_EQ
        new Command(CMD_NEQ, "neq", {}), // CMD_NEQ
        new Command(CMD_LESS, "less", {}), // CMD_LESS
        new Command(CMD_LEQ, "leq", {}), // CMD_LEQ
        new Command(CMD_GRTR, "grtr", {}), // CMD_GRTR
        new Command(CMD_GEQ, "geq", {}), // CMD_GEQ
        new Command(CMD_SLESS, "sless", {}), // CMD_SLESS
        new Command(CMD_SLEQ, "sleq", {}), // CMD_SLEQ
        new Command(CMD_SGRTR, "sgrtr", {}), // CMD_SGRTR
        new Command(CMD_SGEQ, "sgeq", {}), // CMD_SGEQ
        new Command(CMD_EQ_C_PRI, "eq.c.pri", {VALUE}), // CMD_EQ_C_PRI
        new Command(CMD_EQ_C_ALT, "eq.c.alt", {VALUE}), // CMD_EQ_C_ALT
        new Command(CMD_INC_PRI, "inc.pri", {}), // CMD_INC_PRI
        new Command(CMD_INC_ALT, "inc.alt", {}), // CMD_INC_ALT
        new Command(CMD_INC, "inc", {VALUE}), // CMD_INC
        new Command(CMD_INC_S, "inc.s", {VALUE}), // CMD_INC_S
        new Command(CMD_INC_I, "inc.i", {}), // CMD_INC_I
        new Command(CMD_DEC_PRI, "dec.pri", {}), // CMD_DEC_PRI
        new Command(CMD_DEC_ALT, "dec.alt", {}), // CMD_DEC_ALT
        new Command(CMD_DEC, "dec", {VALUE}), // CMD_DEC
        new Command(CMD_DEC_S, "dec.s", {VALUE}), // CMD_DEC_S
        new Command(CMD_DEC_I, "dec.i", {}), // CMD_DEC_I
        new Command(CMD_MOVS, "movs", {VALUE}), // CMD_MOVS
        new Command(CMD_CMPS, "cmps", {VALUE}), // CMD_CMPS
        new Command(CMD_FILL, "fill", {VALUE}), // CMD_FILL
        new Command(CMD_HALT, "halt", {VALUE}), // CMD_HALT
        new Command(CMD_BOUNDS, "bounds", {VALUE}), // CMD_BOUNDS
        new Command(CMD_SYSREQ_PRI, "sysreq.pri", {}), // CMD_SYSREQ_PRI
        new Command(CMD_SYSREQ_C, "sysreq.c", {VALUE}), // CMD_SYSREQ_C
        new Command(CMD_PUSHR_PRI, "pushr.pri", {}), // CMD_PUSHR_PRI
        new Command(CMD_PUSHR_C, "pushr.c", {VALUE}), // CMD_PUSHR_C
        new Command(CMD_PUSHR_S, "pushr.s", {VALUE}), // CMD_PUSHR_S
        new Command(CMD_PUSHR_ADR, "pushr.adr", {VALUE}), // CMD_PUSHR_ADR
        new Command(CMD_JUMP_PRI, "jump.pri", {}), // CMD_JUMP_PRI
        new Command(CMD_SWITCH, "switch", {SWITCH}), // CMD_SWITCH
        new Command(CMD_CASETBL, "casetbl", {CASETBL}), // CMD_CASETBL
        new Command(CMD_SWAP_PRI, "swap.pri", {}), // CMD_SWAP_PRI
        new Command(CMD_SWAP_ALT, "swap.alt", {}), // CMD_SWAP_ALT
        new Command(CMD_PUSH_ADR, "push.adr", {VALUE}), // CMD_PUSH_ADR
        new Command(CMD_NOP, "nop", {}), // CMD_NOP
        new Command(CMD_SYSREQ_N, "sysreq.n", {NATIVE, VALUE}), // CMD_SYSREQ_N
        new Command(CMD_SYMTAG, "symtag", {VALUE}), // CMD_SYMTAG
        new Command(CMD_BREAK, "break", {}), // CMD_BREAK
        new Command(CMD_PUSH2_C, "push2.c", {VALUE, VALUE}), // CMD_PUSH2_C
        new Command(CMD_PUSH2, "push2", {VALUE, VALUE}), // CMD_PUSH2
        new Command(CMD_PUSH2_S, "push2.s", {VALUE, VALUE}), // CMD_PUSH2_S
        new Command(CMD_PUSH2_ADR, "push2.adr", {VALUE, VALUE}), // CMD_PUSH2_ADR
        new Command(CMD_PUSH3_C, "push3.c", {VALUE, VALUE, VALUE}), // CMD_PUSH3_C
        new Command(CMD_PUSH3, "push3", {VALUE, VALUE, VALUE}), // CMD_PUSH3
        new Command(CMD_PUSH3_S, "push3.s", {VALUE, VALUE, VALUE}), // CMD_PUSH3_S
        new Command(CMD_PUSH3_ADR, "push3.adr", {VALUE, VALUE, VALUE}), // CMD_PUSH3_ADR
        new Command(CMD_PUSH4_C, "push4.c", {VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH4_C
        new Command(CMD_PUSH4, "push4", {VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH4
        new Command(CMD_PUSH4_S, "push4.s", {VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH4_S
        new Command(CMD_PUSH4_ADR, "push4.adr", {VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH4_ADR
        new Command(CMD_PUSH5_C, "push5.c", {VALUE, VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH5_C
        new Command(CMD_PUSH5, "push5", {VALUE, VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH5
        new Command(CMD_PUSH5_S, "push5.s", {VALUE, VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH5_S
        new Command(CMD_PUSH5_ADR, "push5.adr", {VALUE, VALUE, VALUE, VALUE, VALUE}), // CMD_PUSH5_ADR
        new Command(CMD_LOAD_BOTH, "load.both", {VALUE, VALUE}), // CMD_LOAD_BOTH
        new Command(CMD_LOAD_S_BOTH, "load.s.both", {VALUE, VALUE}), // CMD_LOAD_S_BOTH
        new Command(CMD_CONST, "const", {VALUE, VALUE}), // CMD_CONST
        new Command(CMD_CONST_S, "const.s", {VALUE, VALUE}), // CMD_CONST_S
        new Command(CMD_ICALL, "icall", {VALUE}), // CMD_ICALL
        new Command(CMD_IRETN, "iretn", {}), // CMD_IRETN
        new Command(CMD_ISWITCH, "iswitch", {SWITCH}), // CMD_ISWITCH
        new Command(CMD_ICASETBL, "icasetbl", {ICASETBL}), // CMD_ICASETBL
        new Command(CMD_LOAD_P_PRI, "load.p.pri", {PACKED}), // CMD_LOAD_P_PRI
        new Command(CMD_LOAD_P_ALT, "load.p.alt", {PACKED}), // CMD_LOAD_P_ALT
        new Command(CMD_LOAD_P_S_PRI, "load.p.s.pri", {PACKED}), // CMD_LOAD_P_S_PRI
        new Command(CMD_LOAD_P_S_ALT, "load.p.s.alt", {PACKED}), // CMD_LOAD_P_S_ALT
        new Command(CMD_LREF_P_PRI, "lref.p.pri", {PACKED}), // CMD_LREF_P_PRI
        new Command(CMD_LREF_P_ALT, "lref.p.alt", {PACKED}), // CMD_LREF_P_ALT
        new Command(CMD_LREF_P_S_PRI, "lref.p.s.pri", {PACKED}), // CMD_LREF_P_S_PRI
        new Command(CMD_LREF_P_S_ALT, "lref.p.s.alt", {PACKED}), // CMD_LREF_P_S_ALT
        new Command(CMD_LODB_P_I, "lodb.p.i", {PACKED}), // CMD_LODB_P_I
        new Command(CMD_CONST_P_PRI, "const.p.pri", {PACKED}), // CMD_CONST_P_PRI
        new Command(CMD_CONST_P_ALT, "const.p.alt", {PACKED}), // CMD_CONST_P_ALT
        new Command(CMD_ADDR_P_PRI, "addr.p.pri", {PACKED}), // CMD_ADDR_P_PRI
        new Command(CMD_ADDR_P_ALT, "addr.p.alt", {PACKED}), // CMD_ADDR_P_ALT
        new Command(CMD_STOR_P_PRI, "stor.p.pri", {PACKED}), // CMD_STOR_P_PRI
        new Command(CMD_STOR_P_ALT, "stor.p.alt", {PACKED}), // CMD_STOR_P_ALT
        new Command(CMD_STOR_P_S_PRI, "stor.p.s.pri", {PACKED}), // CMD_STOR_P_S_PRI
        new Command(CMD_STOR_P_S_ALT, "stor.p.s.alt", {PACKED}), // CMD_STOR_P_S_ALT
        new Command(CMD_SREF_P_PRI, "sref.p.pri", {PACKED}), // CMD_SREF_P_PRI
        new Command(CMD_SREF_P_ALT, "sref.p.alt", {PACKED}), // CMD_SREF_P_ALT
        new Command(CMD_SREF_P_S_PRI, "sref.p.s.pri", {PACKED}), // CMD_SREF_P_S_PRI
        new Command(CMD_SREF_P_S_ALT, "sref.p.s.alt", {PACKED}), // CMD_SREF_P_S_ALT
        new Command(CMD_STRB_P_I, "strb.p.i", {PACKED}), // CMD_STRB_P_I
        new Command(CMD_LIDX_P_B, "lidx.p.b", {PACKED}), // CMD_LIDX_P_B
        new Command(CMD_IDXADDR_P_B, "idxaddr.p.b", {PACKED}), // CMD_IDXADDR_P_B
        new Command(CMD_ALIGN_P_PRI, "align.p.pri", {PACKED}), // CMD_ALIGN_P_PRI
        new Command(CMD_ALIGN_P_ALT, "align.p.alt", {PACKED}), // CMD_ALIGN_P_ALT
        new Command(CMD_PUSH_P_C, "push.p.c", {PACKED}), // CMD_PUSH_P_C
        new Command(CMD_PUSH_P, "push.p", {PACKED}), // CMD_PUSH_P
        new Command(CMD_PUSH_P_S, "push.p.s", {PACKED}), // CMD_PUSH_P_S
        new Command(CMD_STACK_P, "stack.p", {PACKED}), // CMD_STACK_P
        new Command(CMD_HEAP_P, "heap.p", {PACKED}), // CMD_HEAP_P
        new Command(CMD_SHL_P_C_PRI, "shl.p.c.pri", {PACKED}), // CMD_SHL_P_C_PRI
        new Command(CMD_SHL_P_C_ALT, "shl.p.c.alt", {PACKED}), // CMD_SHL_P_C_ALT
        new Command(CMD_SHR_P_C_PRI, "shr.p.c.pri", {PACKED}), // CMD_SHR_P_C_PRI
        new Command(CMD_SHR_P_C_ALT, "shr.p.c.alt", {PACKED}), // CMD_SHR_P_C_ALT
        new Command(CMD_ADD_P_C, "add.p.c", {PACKED}), // CMD_ADD_P_C
        new Command(CMD_SMUL_P_C, "smul.p.c", {PACKED}), // CMD_SMUL_P_C
        new Command(CMD_ZERO_P, "zero.p", {PACKED}), // CMD_ZERO_P
        new Command(CMD_ZERO_P_S, "zero.p.s", {PACKED}), // CMD_ZERO_P_S
        new Command(CMD_EQ_P_C_PRI, "eq.p.c.pri", {PACKED}), // CMD_EQ_P_C_PRI
        new Command(CMD_EQ_P_C_ALT, "eq.p.c.alt", {PACKED}), // CMD_EQ_P_C_ALT
        new Command(CMD_INC_P, "inc.p", {PACKED}), // CMD_INC_P
        new Command(CMD_INC_P_S, "inc.p.s", {PACKED}), // CMD_INC_P_S
        new Command(CMD_DEC_P, "dec.p", {PACKED}), // CMD_DEC_P
        new Command(CMD_DEC_P_S, "dec.p.s", {PACKED}), // CMD_DEC_P_S
        new Command(CMD_MOVS_P, "movs.p", {PACKED}), // CMD_MOVS_P
        new Command(CMD_CMPS_P, "cmps.p", {PACKED}), // CMD_CMPS_P
        new Command(CMD_FILL_P, "fill.p", {PACKED}), // CMD_FILL_P
        new Command(CMD_HALT_P, "halt.p", {PACKED}), // CMD_HALT_P
        new Command(CMD_BOUNDS_P, "bounds.p", {PACKED}), // CMD_BOUNDS_P
        new Command(CMD_PUSH_P_ADR, "push.p.adr", {PACKED}), // CMD_PUSH_P_ADR
        new Command(CMD_PUSHR_P_C, "pushr.p.c", {PACKED}), // CMD_PUSHR_P_C
        new Command(CMD_PUSHR_P_S, "pushr.p.s", {PACKED}), // CMD_PUSHR_P_S
        new Command(CMD_PUSHR_P_ADR, "pushr.p.adr", {PACKED}), // CMD_PUSHR_P_ADR
    };
};

#endif