#include <cstring>
#include <iostream>
#include <fstream>
#include "gfpawn/gfpawn.h"

using namespace pawn;

int main(int argc, char* argv[]) {
  std::cout << "GF_PAWN_DEC ~ (c) 2024 PlatinumMaster" << std::endl;
  // Check if we have parameters.
  if (argc <= 1 || argc > 3) {
    return 1;
  }

  // TODO: Positional parameters... maybe.
  std::ifstream ifs(argv[1], std::ios::in | std::ios::binary);

  if (!ifs.is_open()) {
    std::cout << "Could not open file. Exiting." << std::endl;
    return 1;
  }
  
  printf("Opened file \"%s\" successfully.\n", argv[1]);

  // Open Pawn container.
  pawn::AMX *pAMXContainer = new pawn::AMX(ifs);
  pAMXContainer->Decompile(std::string(argv[2]));
  // pAMXContainer->WriteAssembly(std::string(argv[2]));
  // pAMXContainer->WriteLiftedPawn("test.p");
  return 0;
}