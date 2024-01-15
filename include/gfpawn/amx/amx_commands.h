#ifndef GF_AMX_CMD
#define GF_AMX_CMD

#include <string>
#include <cstdint>
#include <sstream>
#include "amx_opcodes.h"

namespace pawn {
    class Command {
        public:
            Command(pawn::Opcode opcode, std::string label, ParameterTypes type, uint32_t parameter_count, std::vector<uint32_t> *parameters = NULL) {
                this->m_Label = label;
                this->m_Opcode = opcode;
                this->m_Type = type;
                this->m_ParameterCount = parameter_count;
                this->m_Parameters = parameters;
            }

            Command(Command *t) {
                this->m_Label = t->m_Label;
                this->m_Opcode = t->m_Opcode;
                this->m_Type = t->m_Type;
                this->m_ParameterCount = t->m_ParameterCount;
                this->m_Parameters = t->m_Parameters;
            }

            std::string GetLabel() {
                return this->m_Label;
            }

            pawn::Opcode GetOpcode() {
                return this->m_Opcode;
            }

            ParameterTypes GetParameterType() {
                return this->m_Type;
            }

            uint32_t GetSize() {
                if (this->GetParameterType() == PACKED || !this->m_Parameters) {
                    return sizeof(uint32_t);
                } 
                return sizeof(uint32_t) * (1 + GetParameters()->size());
            }

            uint32_t GetParameterCount() {
                return this->m_ParameterCount;
            }

            std::vector<uint32_t> *GetParameters() {
                return this->m_Parameters;
            }

            std::string GetParametersToString() {
                std::stringstream param_string;
                if (!this->m_Parameters) {
                    return "";
                }
                for (uint32_t parameter : *this->m_Parameters) {
                    param_string << parameter << " ";
                }
                return param_string.str();
            }


            void AddParameter(uint32_t Parameter) {
                if (!this->m_Parameters) {
                    this->m_Parameters = new std::vector<uint32_t>();
                }
                m_Parameters->push_back(Parameter);
            }

        private:                
            std::string m_Label;
            pawn::Opcode m_Opcode;
            ParameterTypes m_Type;
            uint32_t m_ParameterCount;
            std::vector<uint32_t> *m_Parameters;
    };

    // TODO: Dynamically build from YML or something smarter.
    static Command* CommandList[] = {
        new Command(CMD_NOOP, "noop", VALUE, 0), // CMD_NOOP
        new Command(CMD_LOAD_PRI, "load.pri", ADDRESS, 1), // CMD_LOAD_PRI
        new Command(CMD_LOAD_ALT, "load.alt", VALUE, 1), // CMD_LOAD_ALT
        new Command(CMD_LOAD_S_PRI, "load.s.pri", VALUE, 1), // CMD_LOAD_S_PRI
        new Command(CMD_LOAD_S_ALT, "load.s.alt", VALUE, 1), // CMD_LOAD_S_ALT
        new Command(CMD_LREF_PRI, "lref.pri", VALUE, 1), // CMD_LREF_PRI
        new Command(CMD_LREF_ALT, "lref.alt", VALUE, 1), // CMD_LREF_ALT
        new Command(CMD_LREF_S_PRI, "lref.s.pri", VALUE, 1), // CMD_LREF_S_PRI
        new Command(CMD_LREF_S_ALT, "lref.s.alt", VALUE, 1), // CMD_LREF_S_ALT
        new Command(CMD_LOAD_I, "load.i", VALUE, 0), // CMD_LOAD_I
        new Command(CMD_LODB_I, "lodb.i", VALUE, 1), // CMD_LODB_I
        new Command(CMD_CONST_PRI, "const.pri", VALUE, 1), // CMD_CONST_PRI
        new Command(CMD_CONST_ALT, "const.alt", VALUE, 1), // CMD_CONST_ALT
        new Command(CMD_ADDR_PRI, "addr.pri", VALUE, 1), // CMD_ADDR_PRI
        new Command(CMD_ADDR_ALT, "addr.alt", VALUE, 1), // CMD_ADDR_ALT
        new Command(CMD_STOR_PRI, "stor.pri", VALUE, 1), // CMD_STOR_PRI
        new Command(CMD_STOR_ALT, "stor.alt", VALUE, 1), // CMD_STOR_ALT
        new Command(CMD_STOR_S_PRI, "stor.s.pri", VALUE, 1), // CMD_STOR_S_PRI
        new Command(CMD_STOR_S_ALT, "stor.s.alt", VALUE, 1), // CMD_STOR_S_ALT
        new Command(CMD_SREF_PRI, "sref.pri", VALUE, 1), // CMD_SREF_PRI
        new Command(CMD_SREF_ALT, "sref.alt", VALUE, 1), // CMD_SREF_ALT
        new Command(CMD_SREF_S_PRI, "sref.s.pri", VALUE, 1), // CMD_SREF_S_PRI
        new Command(CMD_SREF_S_ALT, "sref.s.alt", VALUE, 1), // CMD_SREF_S_ALT
        new Command(CMD_STOR_I, "stor.i", VALUE, 0), // CMD_STOR_I
        new Command(CMD_STRB_I, "strb.i", VALUE, 1), // CMD_STRB_I
        new Command(CMD_LIDX, "lidx", VALUE, 0), // CMD_LIDX
        new Command(CMD_LIDX_B, "lidx.b", VALUE, 1), // CMD_LIDX_B
        new Command(CMD_IDXADDR, "idxaddr", VALUE, 0), // CMD_IDXADDR
        new Command(CMD_IDXADDR_B, "idxaddr.b", VALUE, 1), // CMD_IDXADDR_B
        new Command(CMD_ALIGN_PRI, "align.pri", VALUE, 1), // CMD_ALIGN_PRI
        new Command(CMD_ALIGN_ALT, "align.alt", VALUE, 1), // CMD_ALIGN_ALT
        new Command(CMD_LCTRL, "lctrl", VALUE, 1), // CMD_LCTRL
        new Command(CMD_SCTRL, "sctrl", VALUE, 1), // CMD_SCTRL
        new Command(CMD_MOVE_PRI, "move.pri", VALUE, 0), // CMD_MOVE_PRI
        new Command(CMD_MOVE_ALT, "move.alt", VALUE, 0), // CMD_MOVE_ALT
        new Command(CMD_XCHG, "xchg", VALUE, 0), // CMD_XCHG
        new Command(CMD_PUSH_PRI, "push.pri", VALUE, 0), // CMD_PUSH_PRI
        new Command(CMD_PUSH_ALT, "push.alt", VALUE, 0), // CMD_PUSH_ALT
        new Command(CMD_PICK, "pick", VALUE, 1), // CMD_PICK
        new Command(CMD_PUSH_C, "push.c", VALUE, 1), // CMD_PUSH_C
        new Command(CMD_PUSH, "push", VALUE, 1), // CMD_PUSH
        new Command(CMD_PUSH_S, "push.s", VALUE, 1), // CMD_PUSH_S
        new Command(CMD_POP_PRI, "pop.pri", VALUE, 0), // CMD_POP_PRI
        new Command(CMD_POP_ALT, "pop.alt", VALUE, 0), // CMD_POP_ALT
        new Command(CMD_STACK, "stack", VALUE, 1), // CMD_STACK
        new Command(CMD_HEAP, "heap", VALUE, 1), // CMD_HEAP
        new Command(CMD_PROC, "proc", VALUE, 0), // CMD_PROC
        new Command(CMD_RET, "ret", VALUE, 0), // CMD_RET
        new Command(CMD_RETN, "retn", VALUE, 0), // CMD_RETN
        new Command(CMD_CALL, "call", CALL, 1), // CMD_CALL
        new Command(CMD_CALL_PRI, "call.pri", VALUE, 0), // CMD_CALL_PRI
        new Command(CMD_JUMP, "jump", JUMP, 1), // CMD_JUMP
        new Command(CMD_JREL, "jrel", VALUE, 1), // CMD_JREL
        new Command(CMD_JZER, "jzer", JUMP, 1), // CMD_JZER
        new Command(CMD_JNZ, "jnz", JUMP, 1), // CMD_JNZ
        new Command(CMD_JEQ, "jeq", JUMP, 1), // CMD_JEQ
        new Command(CMD_JNEQ, "jneq", JUMP, 1), // CMD_JNEQ
        new Command(CMD_JLESS, "jless", JUMP, 1), // CMD_JLESS
        new Command(CMD_JLEQ, "jleq", JUMP, 1), // CMD_JLEQ
        new Command(CMD_JGRTR, "jgrtr", JUMP, 1), // CMD_JGRTR
        new Command(CMD_JGEQ, "jgeq", JUMP, 1), // CMD_JGEQ
        new Command(CMD_JSLESS, "jsless", JUMP, 1), // CMD_JSLESS
        new Command(CMD_JSLEQ, "jsleq", JUMP, 1), // CMD_JSLEQ
        new Command(CMD_JSGRTR, "jsgrtr", JUMP, 1), // CMD_JSGRTR
        new Command(CMD_JSGEQ, "jsgeq", JUMP, 1), // CMD_JSGEQ
        new Command(CMD_SHL, "shl", VALUE, 0), // CMD_SHL
        new Command(CMD_SHR, "shr", VALUE, 0), // CMD_SHR
        new Command(CMD_SSHR, "sshr", VALUE, 0), // CMD_SSHR
        new Command(CMD_SHL_C_PRI, "shl.c.pri", VALUE, 1), // CMD_SHL_C_PRI
        new Command(CMD_SHL_C_ALT, "shl.c.alt", VALUE, 1), // CMD_SHL_C_ALT
        new Command(CMD_SHR_C_PRI, "shr.c.pri", VALUE, 1), // CMD_SHR_C_PRI
        new Command(CMD_SHR_C_ALT, "shr.c.alt", VALUE, 1), // CMD_SHR_C_ALT
        new Command(CMD_SMUL, "smul", VALUE, 0), // CMD_SMUL
        new Command(CMD_SDIV, "sdiv", VALUE, 0), // CMD_SDIV
        new Command(CMD_SDIV_ALT, "sdiv.alt", VALUE, 0), // CMD_SDIV_ALT
        new Command(CMD_UMUL, "umul", VALUE, 0), // CMD_UMUL
        new Command(CMD_UDIV, "udiv", VALUE, 0), // CMD_UDIV
        new Command(CMD_UDIV_ALT, "udiv.alt", VALUE, 0), // CMD_UDIV_ALT
        new Command(CMD_ADD, "add", VALUE, 0), // CMD_ADD
        new Command(CMD_SUB, "sub", VALUE, 0), // CMD_SUB
        new Command(CMD_SUB_ALT, "sub.alt", VALUE, 0), // CMD_SUB_ALT
        new Command(CMD_AND, "and", VALUE, 0), // CMD_AND
        new Command(CMD_OR, "or", VALUE, 0), // CMD_OR
        new Command(CMD_XOR, "xor", VALUE, 0), // CMD_XOR
        new Command(CMD_NOT, "not", VALUE, 0), // CMD_NOT
        new Command(CMD_NEG, "neg", VALUE, 0), // CMD_NEG
        new Command(CMD_INVERT, "invert", VALUE, 0), // CMD_INVERT
        new Command(CMD_ADD_C, "add.c", VALUE, 1), // CMD_ADD_C
        new Command(CMD_SMUL_C, "smul.c", VALUE, 1), // CMD_SMUL_C
        new Command(CMD_ZERO_PRI, "zero.pri", VALUE, 0), // CMD_ZERO_PRI
        new Command(CMD_ZERO_ALT, "zero.alt", VALUE, 0), // CMD_ZERO_ALT
        new Command(CMD_ZERO, "zero", VALUE, 1), // CMD_ZERO
        new Command(CMD_ZERO_S, "zero.s", VALUE, 1), // CMD_ZERO_S
        new Command(CMD_SIGN_PRI, "sign.pri", VALUE, 0), // CMD_SIGN_PRI
        new Command(CMD_SIGN_ALT, "sign.alt", VALUE, 0), // CMD_SIGN_ALT
        new Command(CMD_EQ, "eq", VALUE, 0), // CMD_EQ
        new Command(CMD_NEQ, "neq", VALUE, 0), // CMD_NEQ
        new Command(CMD_LESS, "less", VALUE, 0), // CMD_LESS
        new Command(CMD_LEQ, "leq", VALUE, 0), // CMD_LEQ
        new Command(CMD_GRTR, "grtr", VALUE, 0), // CMD_GRTR
        new Command(CMD_GEQ, "geq", VALUE, 0), // CMD_GEQ
        new Command(CMD_SLESS, "sless", VALUE, 0), // CMD_SLESS
        new Command(CMD_SLEQ, "sleq", VALUE, 0), // CMD_SLEQ
        new Command(CMD_SGRTR, "sgrtr", VALUE, 0), // CMD_SGRTR
        new Command(CMD_SGEQ, "sgeq", VALUE, 0), // CMD_SGEQ
        new Command(CMD_EQ_C_PRI, "eq.c.pri", VALUE, 1), // CMD_EQ_C_PRI
        new Command(CMD_EQ_C_ALT, "eq.c.alt", VALUE, 1), // CMD_EQ_C_ALT
        new Command(CMD_INC_PRI, "inc.pri", VALUE, 0), // CMD_INC_PRI
        new Command(CMD_INC_ALT, "inc.alt", VALUE, 0), // CMD_INC_ALT
        new Command(CMD_INC, "inc", VALUE, 1), // CMD_INC
        new Command(CMD_INC_S, "inc.s", VALUE, 1), // CMD_INC_S
        new Command(CMD_INC_I, "inc.i", VALUE, 0), // CMD_INC_I
        new Command(CMD_DEC_PRI, "dec.pri", VALUE, 0), // CMD_DEC_PRI
        new Command(CMD_DEC_ALT, "dec.alt", VALUE, 0), // CMD_DEC_ALT
        new Command(CMD_DEC, "dec", VALUE, 1), // CMD_DEC
        new Command(CMD_DEC_S, "dec.s", VALUE, 1), // CMD_DEC_S
        new Command(CMD_DEC_I, "dec.i", VALUE, 0), // CMD_DEC_I
        new Command(CMD_MOVS, "movs", VALUE, 1), // CMD_MOVS
        new Command(CMD_CMPS, "cmps", VALUE, 1), // CMD_CMPS
        new Command(CMD_FILL, "fill", VALUE, 1), // CMD_FILL
        new Command(CMD_HALT, "halt", VALUE, 1), // CMD_HALT
        new Command(CMD_BOUNDS, "bounds", VALUE, 1), // CMD_BOUNDS
        new Command(CMD_SYSREQ_PRI, "sysreq.pri", VALUE, 0), // CMD_SYSREQ_PRI
        new Command(CMD_SYSREQ_C, "sysreq.c", VALUE, 1), // CMD_SYSREQ_C
        new Command(CMD_PUSHR_PRI, "pushr.pri", VALUE, 0), // CMD_PUSHR_PRI
        new Command(CMD_PUSHR_C, "pushr.c", VALUE, 1), // CMD_PUSHR_C
        new Command(CMD_PUSHR_S, "pushr.s", VALUE, 1), // CMD_PUSHR_S
        new Command(CMD_PUSHR_ADR, "pushr.adr", VALUE, 1), // CMD_PUSHR_ADR
        new Command(CMD_JUMP_PRI, "jump.pri", VALUE, 0), // CMD_JUMP_PRI
        new Command(CMD_SWITCH, "switch", SWITCH, 1), // CMD_SWITCH
        new Command(CMD_CASETBL, "casetbl", CASETBL, 1), // CMD_CASETBL
        new Command(CMD_SWAP_PRI, "swap.pri", VALUE, 0), // CMD_SWAP_PRI
        new Command(CMD_SWAP_ALT, "swap.alt", VALUE, 0), // CMD_SWAP_ALT
        new Command(CMD_PUSH_ADR, "push.adr", VALUE, 1), // CMD_PUSH_ADR
        new Command(CMD_NOP, "nop", VALUE, 0), // CMD_NOP
        new Command(CMD_SYSREQ_N, "sysreq.n", VALUE, 2), // CMD_SYSREQ_N
        new Command(CMD_SYMTAG, "symtag", VALUE, 1), // CMD_SYMTAG
        new Command(CMD_BREAK, "break", VALUE, 0), // CMD_BREAK
        new Command(CMD_PUSH2_C, "push2.c", VALUE, 2), // CMD_PUSH2_C
        new Command(CMD_PUSH2, "push2", VALUE, 2), // CMD_PUSH2
        new Command(CMD_PUSH2_S, "push2.s", VALUE, 2), // CMD_PUSH2_S
        new Command(CMD_PUSH2_ADR, "push2.adr", VALUE, 2), // CMD_PUSH2_ADR
        new Command(CMD_PUSH3_C, "push3.c", VALUE, 3), // CMD_PUSH3_C
        new Command(CMD_PUSH3, "push3", VALUE, 3), // CMD_PUSH3
        new Command(CMD_PUSH3_S, "push3.s", VALUE, 3), // CMD_PUSH3_S
        new Command(CMD_PUSH3_ADR, "push3.adr", VALUE, 3), // CMD_PUSH3_ADR
        new Command(CMD_PUSH4_C, "push4.c", VALUE, 4), // CMD_PUSH4_C
        new Command(CMD_PUSH4, "push4", VALUE, 4), // CMD_PUSH4
        new Command(CMD_PUSH4_S, "push4.s", VALUE, 4), // CMD_PUSH4_S
        new Command(CMD_PUSH4_ADR, "push4.adr", VALUE, 4), // CMD_PUSH4_ADR
        new Command(CMD_PUSH5_C, "push5.c", VALUE, 5), // CMD_PUSH5_C
        new Command(CMD_PUSH5, "push5", VALUE, 5), // CMD_PUSH5
        new Command(CMD_PUSH5_S, "push5.s", VALUE, 5), // CMD_PUSH5_S
        new Command(CMD_PUSH5_ADR, "push5.adr", VALUE, 5), // CMD_PUSH5_ADR
        new Command(CMD_LOAD_BOTH, "load.both", VALUE, 2), // CMD_LOAD_BOTH
        new Command(CMD_LOAD_S_BOTH, "load.s.both", VALUE, 2), // CMD_LOAD_S_BOTH
        new Command(CMD_CONST, "const", VALUE, 2), // CMD_CONST
        new Command(CMD_CONST_S, "const.s", VALUE, 2), // CMD_CONST_S
        new Command(CMD_ICALL, "icall", VALUE, 1), // CMD_ICALL
        new Command(CMD_IRETN, "iretn", VALUE, 0), // CMD_IRETN
        new Command(CMD_ISWITCH, "iswitch", SWITCH, 1), // CMD_ISWITCH
        new Command(CMD_ICASETBL, "icasetbl", ICASETBL, 1), // CMD_ICASETBL
        new Command(CMD_LOAD_P_PRI, "load.p.pri", PACKED, 1), // CMD_LOAD_P_PRI
        new Command(CMD_LOAD_P_ALT, "load.p.alt", PACKED, 1), // CMD_LOAD_P_ALT
        new Command(CMD_LOAD_P_S_PRI, "load.p.s.pri", PACKED, 1), // CMD_LOAD_P_S_PRI
        new Command(CMD_LOAD_P_S_ALT, "load.p.s.alt", PACKED, 1), // CMD_LOAD_P_S_ALT
        new Command(CMD_LREF_P_PRI, "lref.p.pri", PACKED, 1), // CMD_LREF_P_PRI
        new Command(CMD_LREF_P_ALT, "lref.p.alt", PACKED, 1), // CMD_LREF_P_ALT
        new Command(CMD_LREF_P_S_PRI, "lref.p.s.pri", PACKED, 1), // CMD_LREF_P_S_PRI
        new Command(CMD_LREF_P_S_ALT, "lref.p.s.alt", PACKED, 1), // CMD_LREF_P_S_ALT
        new Command(CMD_LODB_P_I, "lodb.p.i", PACKED, 1), // CMD_LODB_P_I
        new Command(CMD_CONST_P_PRI, "const.p.pri", PACKED, 1), // CMD_CONST_P_PRI
        new Command(CMD_CONST_P_ALT, "const.p.alt", PACKED, 1), // CMD_CONST_P_ALT
        new Command(CMD_ADDR_P_PRI, "addr.p.pri", PACKED, 1), // CMD_ADDR_P_PRI
        new Command(CMD_ADDR_P_ALT, "addr.p.alt", PACKED, 1), // CMD_ADDR_P_ALT
        new Command(CMD_STOR_P_PRI, "stor.p.pri", PACKED, 1), // CMD_STOR_P_PRI
        new Command(CMD_STOR_P_ALT, "stor.p.alt", PACKED, 1), // CMD_STOR_P_ALT
        new Command(CMD_STOR_P_S_PRI, "stor.p.s.pri", PACKED, 1), // CMD_STOR_P_S_PRI
        new Command(CMD_STOR_P_S_ALT, "stor.p.s.alt", PACKED, 1), // CMD_STOR_P_S_ALT
        new Command(CMD_SREF_P_PRI, "sref.p.pri", PACKED, 1), // CMD_SREF_P_PRI
        new Command(CMD_SREF_P_ALT, "sref.p.alt", PACKED, 1), // CMD_SREF_P_ALT
        new Command(CMD_SREF_P_S_PRI, "sref.p.s.pri", PACKED, 1), // CMD_SREF_P_S_PRI
        new Command(CMD_SREF_P_S_ALT, "sref.p.s.alt", PACKED, 1), // CMD_SREF_P_S_ALT
        new Command(CMD_STRB_P_I, "strb.p.i", PACKED, 1), // CMD_STRB_P_I
        new Command(CMD_LIDX_P_B, "lidx.p.b", PACKED, 1), // CMD_LIDX_P_B
        new Command(CMD_IDXADDR_P_B, "idxaddr.p.b", PACKED, 1), // CMD_IDXADDR_P_B
        new Command(CMD_ALIGN_P_PRI, "align.p.pri", PACKED, 1), // CMD_ALIGN_P_PRI
        new Command(CMD_ALIGN_P_ALT, "align.p.alt", PACKED, 1), // CMD_ALIGN_P_ALT
        new Command(CMD_PUSH_P_C, "push.p.c", PACKED, 1), // CMD_PUSH_P_C
        new Command(CMD_PUSH_P, "push.p", PACKED, 1), // CMD_PUSH_P
        new Command(CMD_PUSH_P_S, "push.p.s", PACKED, 1), // CMD_PUSH_P_S
        new Command(CMD_STACK_P, "stack.p", PACKED, 1), // CMD_STACK_P
        new Command(CMD_HEAP_P, "heap.p", PACKED, 1), // CMD_HEAP_P
        new Command(CMD_SHL_P_C_PRI, "shl.p.c.pri", PACKED, 1), // CMD_SHL_P_C_PRI
        new Command(CMD_SHL_P_C_ALT, "shl.p.c.alt", PACKED, 1), // CMD_SHL_P_C_ALT
        new Command(CMD_SHR_P_C_PRI, "shr.p.c.pri", PACKED, 1), // CMD_SHR_P_C_PRI
        new Command(CMD_SHR_P_C_ALT, "shr.p.c.alt", PACKED, 1), // CMD_SHR_P_C_ALT
        new Command(CMD_ADD_P_C, "add.p.c", PACKED, 1), // CMD_ADD_P_C
        new Command(CMD_SMUL_P_C, "smul.p.c", PACKED, 1), // CMD_SMUL_P_C
        new Command(CMD_ZERO_P, "zero.p", PACKED, 1), // CMD_ZERO_P
        new Command(CMD_ZERO_P_S, "zero.p.s", PACKED, 1), // CMD_ZERO_P_S
        new Command(CMD_EQ_P_C_PRI, "eq.p.c.pri", PACKED, 1), // CMD_EQ_P_C_PRI
        new Command(CMD_EQ_P_C_ALT, "eq.p.c.alt", PACKED, 1), // CMD_EQ_P_C_ALT
        new Command(CMD_INC_P, "inc.p", PACKED, 1), // CMD_INC_P
        new Command(CMD_INC_P_S, "inc.p.s", PACKED, 1), // CMD_INC_P_S
        new Command(CMD_DEC_P, "dec.p", PACKED, 1), // CMD_DEC_P
        new Command(CMD_DEC_P_S, "dec.p.s", PACKED, 1), // CMD_DEC_P_S
        new Command(CMD_MOVS_P, "movs.p", PACKED, 1), // CMD_MOVS_P
        new Command(CMD_CMPS_P, "cmps.p", PACKED, 1), // CMD_CMPS_P
        new Command(CMD_FILL_P, "fill.p", PACKED, 1), // CMD_FILL_P
        new Command(CMD_HALT_P, "halt.p", PACKED, 1), // CMD_HALT_P
        new Command(CMD_BOUNDS_P, "bounds.p", PACKED, 1), // CMD_BOUNDS_P
        new Command(CMD_PUSH_P_ADR, "push.p.adr", PACKED, 1), // CMD_PUSH_P_ADR
        new Command(CMD_PUSHR_P_C, "pushr.p.c", PACKED, 1), // CMD_PUSHR_P_C
        new Command(CMD_PUSHR_P_S, "pushr.p.s", PACKED, 1), // CMD_PUSHR_P_S
        new Command(CMD_PUSHR_P_ADR, "pushr.p.adr", PACKED, 1), // CMD_PUSHR_P_ADR
    };
};

#endif