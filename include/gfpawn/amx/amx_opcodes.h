#ifndef GF_AMX_OPCODES
#define GF_AMX_OPCODES  

namespace pawn {
    enum Opcode {
        CMD_NOOP,
        CMD_LOAD_PRI,  
        CMD_LOAD_ALT,  
        CMD_LOAD_S_PRI,
        CMD_LOAD_S_ALT,
        CMD_LREF_PRI,  
        CMD_LREF_ALT,  
        CMD_LREF_S_PRI,
        CMD_LREF_S_ALT,
        CMD_LOAD_I,    
        CMD_LODB_I,    
        CMD_CONST_PRI, 
        CMD_CONST_ALT, 
        CMD_ADDR_PRI,  
        CMD_ADDR_ALT,  
        CMD_STOR_PRI,  
        CMD_STOR_ALT,  
        CMD_STOR_S_PRI,
        CMD_STOR_S_ALT,
        CMD_SREF_PRI,  
        CMD_SREF_ALT,  
        CMD_SREF_S_PRI,
        CMD_SREF_S_ALT,
        CMD_STOR_I,    
        CMD_STRB_I,    
        CMD_LIDX,      
        CMD_LIDX_B,    
        CMD_IDXADDR,   
        CMD_IDXADDR_B, 
        CMD_ALIGN_PRI, 
        CMD_ALIGN_ALT, 
        CMD_LCTRL,     
        CMD_SCTRL,     
        CMD_MOVE_PRI,  
        CMD_MOVE_ALT,  
        CMD_XCHG,      
        CMD_PUSH_PRI,  
        CMD_PUSH_ALT,  
        CMD_PICK,      
        CMD_PUSH_C,    
        CMD_PUSH,      
        CMD_PUSH_S,    
        CMD_POP_PRI,   
        CMD_POP_ALT,   
        CMD_STACK,     
        CMD_HEAP,      
        CMD_PROC,
        CMD_RET,       
        CMD_RETN,      
        CMD_CALL,      
        CMD_CALL_PRI,  
        CMD_JUMP,      
        CMD_JREL,      
        CMD_JZER,      
        CMD_JNZ,       
        CMD_JEQ,       
        CMD_JNEQ,      
        CMD_JLESS,     
        CMD_JLEQ,      
        CMD_JGRTR,     
        CMD_JGEQ,      
        CMD_JSLESS,    
        CMD_JSLEQ,     
        CMD_JSGRTR,    
        CMD_JSGEQ,     
        CMD_SHL,       
        CMD_SHR,       
        CMD_SSHR,      
        CMD_SHL_C_PRI, 
        CMD_SHL_C_ALT, 
        CMD_SHR_C_PRI, 
        CMD_SHR_C_ALT, 
        CMD_SMUL,      
        CMD_SDIV,      
        CMD_SDIV_ALT,  
        CMD_UMUL,      
        CMD_UDIV,      
        CMD_UDIV_ALT,  
        CMD_ADD,       
        CMD_SUB,       
        CMD_SUB_ALT,   
        CMD_AND,       
        CMD_OR,        
        CMD_XOR,       
        CMD_NOT,       
        CMD_NEG,       
        CMD_INVERT,    
        CMD_ADD_C,     
        CMD_SMUL_C,    
        CMD_ZERO_PRI,  
        CMD_ZERO_ALT,  
        CMD_ZERO,      
        CMD_ZERO_S,    
        CMD_SIGN_PRI,  
        CMD_SIGN_ALT,  
        CMD_EQ,        
        CMD_NEQ,       
        CMD_LESS,      
        CMD_LEQ,       
        CMD_GRTR,      
        CMD_GEQ,       
        CMD_SLESS,     
        CMD_SLEQ,      
        CMD_SGRTR,     
        CMD_SGEQ,      
        CMD_EQ_C_PRI,  
        CMD_EQ_C_ALT,  
        CMD_INC_PRI,   
        CMD_INC_ALT,   
        CMD_INC,       
        CMD_INC_S,     
        CMD_INC_I,     
        CMD_DEC_PRI,   
        CMD_DEC_ALT,   
        CMD_DEC,       
        CMD_DEC_S,     
        CMD_DEC_I,     
        CMD_MOVS,      
        CMD_CMPS,      
        CMD_FILL,      
        CMD_HALT,      
        CMD_BOUNDS,    
        CMD_SYSREQ_PRI,
        CMD_SYSREQ_C,  
        CMD_PUSHR_PRI, 
        CMD_PUSHR_C,   
        CMD_PUSHR_S,   
        CMD_PUSHR_ADR, 
        CMD_JUMP_PRI,  
        CMD_SWITCH,    
        CMD_CASETBL,
        CMD_SWAP_PRI,  
        CMD_SWAP_ALT,  
        CMD_PUSH_ADR,  
        CMD_NOP,       
        CMD_SYSREQ_N,  
        CMD_SYMTAG,    
        CMD_BREAK,     
        CMD_PUSH2_C,   
        CMD_PUSH2,     
        CMD_PUSH2_S,   
        CMD_PUSH2_ADR, 
        CMD_PUSH3_C,   
        CMD_PUSH3,     
        CMD_PUSH3_S,   
        CMD_PUSH3_ADR, 
        CMD_PUSH4_C,   
        CMD_PUSH4,     
        CMD_PUSH4_S,   
        CMD_PUSH4_ADR, 
        CMD_PUSH5_C,   
        CMD_PUSH5,     
        CMD_PUSH5_S,   
        CMD_PUSH5_ADR, 
        CMD_LOAD_BOTH, 
        CMD_LOAD_S_BOTH,
        CMD_CONST,     
        CMD_CONST_S,   
        CMD_ICALL,     
        CMD_IRETN,     
        CMD_ISWITCH,   
        CMD_ICASETBL, 
        CMD_LOAD_P_PRI,
        CMD_LOAD_P_ALT,
        CMD_LOAD_P_S_PRI,
        CMD_LOAD_P_S_ALT,
        CMD_LREF_P_PRI,
        CMD_LREF_P_ALT,
        CMD_LREF_P_S_PRI,
        CMD_LREF_P_S_ALT,
        CMD_LODB_P_I,  
        CMD_CONST_P_PRI,
        CMD_CONST_P_ALT,
        CMD_ADDR_P_PRI,
        CMD_ADDR_P_ALT,
        CMD_STOR_P_PRI,
        CMD_STOR_P_ALT,
        CMD_STOR_P_S_PRI,
        CMD_STOR_P_S_ALT,
        CMD_SREF_P_PRI,
        CMD_SREF_P_ALT,
        CMD_SREF_P_S_PRI,
        CMD_SREF_P_S_ALT,
        CMD_STRB_P_I,  
        CMD_LIDX_P_B,  
        CMD_IDXADDR_P_B,
        CMD_ALIGN_P_PRI,
        CMD_ALIGN_P_ALT,
        CMD_PUSH_P_C,  
        CMD_PUSH_P,    
        CMD_PUSH_P_S,  
        CMD_STACK_P,   
        CMD_HEAP_P,    
        CMD_SHL_P_C_PRI,
        CMD_SHL_P_C_ALT,
        CMD_SHR_P_C_PRI,
        CMD_SHR_P_C_ALT,
        CMD_ADD_P_C,   
        CMD_SMUL_P_C,  
        CMD_ZERO_P,    
        CMD_ZERO_P_S,  
        CMD_EQ_P_C_PRI,
        CMD_EQ_P_C_ALT,
        CMD_INC_P,     
        CMD_INC_P_S,   
        CMD_DEC_P,     
        CMD_DEC_P_S,   
        CMD_MOVS_P,    
        CMD_CMPS_P,    
        CMD_FILL_P,    
        CMD_HALT_P,    
        CMD_BOUNDS_P,  
        CMD_PUSH_P_ADR,
        CMD_PUSHR_P_C, 
        CMD_PUSHR_P_S, 
        CMD_PUSHR_P_ADR
    };


    enum ParameterTypes {
        VALUE,    // Cell containing a number | TODO: float, etc.
        CALL,     // Address
        JUMP,     // Address
        SWITCH,   // Address
        CASETBL,  // (casenum|ADDRESS) followed by casenum times (SIMPLE|ADDRESS) pairs
        ICASETBL,  // (casenum|ADDRESS) followed by casenum times (SIMPLE|ADDRESS) pairs
        PACKED,    // Packed inside the opcode itself, no additional field
        NATIVE
    };
}

#endif