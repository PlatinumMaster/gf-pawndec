#ifndef IR_H
#define IR_H

#include "../amx/amx_commands.h"

namespace pawn {
    enum NodeType {
        NODE_INSTRUCTION,
        NODE_JUMP,
        NODE_CALL
    };

    // IR stuff. Let's keep it simple...
    class Node {
        public:
            Node(Node *prev, Node *next) {
                m_Prev = prev;
                m_Next = next;
            }

            Node *m_Prev;
            Node *m_Next;
            Node *m_NextConditionalOrCall;
            Command *m_Command;
            uint32_t Address;
    };
};

#endif 