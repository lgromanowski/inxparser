project(inxdumper)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

add_definitions(-O0 -g -march=native -mtune=native -Wall -Wextra -Werror -std=c++11 -pedantic -pipe)

