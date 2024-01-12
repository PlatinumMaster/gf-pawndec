cmake_minimum_required(VERSION 3.26)
project(gfpawndec VERSION 0.1.0)
project(gfpawndec LANGUAGES C CXX ASM)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(gfpawndec main.cpp ${INCLUDES})
target_include_directories(gfpawndec PUBLIC include)