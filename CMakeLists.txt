cmake_minimum_required(VERSION 3.17)
project(MVHSS)

set(CMAKE_CXX_STANDARD 14)

add_executable(MVHSS main.c split.h split.c compute.h compute.c BV11.h BV11.c tool.h tool.c compute.h MVHSS.c MVHSS.h)

target_link_libraries(MVHSS libgmp.so /usr/local/lib/libflint.so libm.so)