cmake_minimum_required(VERSION 2.6)
project(osocks C)

add_definitions(-Os -ggdb -Wall --std=gnu99 -Wmissing-declarations)

option(DEBUG "Compile for debugging purposes." OFF)
if(DEBUG)
  add_definitions(-DDEBUG -g3)
endif()

find_library(UBOX NAMES ubox)

add_executable(osocks main.c)
target_link_libraries(osocks ${UBOX})
install(TARGETS osocks
	RUNTIME DESTINATION sbin
)

add_custom_target(run ./osocks -p 7001
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
