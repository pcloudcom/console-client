cmake_minimum_required(VERSION 2.8)
project(pcloudcc)

#INCLUDE(CPack)

set(CMAKE_BUILD_TYPE Release)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
unset(Boost_INCLUDE_DIR CACHE)
unset(Boost_LIBRARY_DIRS CACHE)

find_package(Boost COMPONENTS system program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
#set (CMAKE_CXX_FLAGS "-static -Wl,-Bstatic")
#set (CMAKE_CXX_FLAGS "-Wl,-Bstatic")
#set (CMAKE_CXX_FLAGS "-DP_CONSOLE_CLIENT")
set (CMAKE_C_FLAGS "-fPIC")
set (PCLSYNC_PATH ${CMAKE_SOURCE_DIR}/lib/pclsync)
set (MBEDTLS_PATH ${CMAKE_SOURCE_DIR}/lib/mbedtls)
set (SQLITE3_PATH ${CMAKE_SOURCE_DIR}/lib/sqlite)
set (PRJF_PATH ${CMAKE_SOURCE_DIR}/lib/prjf)

#add_subdirectory(${MBEDTLS_PATH})

include_directories(${SQLITE3_PATH})
# add_custom_target(
#   sqlite3_lib
#   COMMAND ./configure && make
#   WORKING_DIRECTORY ${SQLITE3_PATH}
# )

include_directories(${PCLSYNC_PATH})
# add_custom_target(
#   pclsync_clean
#   COMMAND make clean
#   WORKING_DIRECTORY ${PCLSYNC_PATH}
# )

add_custom_target(
  pclsync
  COMMAND make fs
  WORKING_DIRECTORY ${PCLSYNC_PATH}
)

add_custom_target(
  mbedtls
  COMMAND cmake . && make
  WORKING_DIRECTORY ${MBEDTLS_PATH}
)

set(OVERLAY_CLENT_PATH ${CMAKE_SOURCE_DIR}/lib/poverlay_linux)
include_directories(${OVERLAY_CLENT_PATH})

add_library(sqlite3 STATIC ${SQLITE3_PATH}/sqlite3.c)
target_link_libraries(sqlite3 z dl)

add_library(pcloudcc_lib SHARED pclsync_lib_c.cpp pclsync_lib.cpp control_tools.cpp ${OVERLAY_CLENT_PATH}/overlay_client.c ${OVERLAY_CLENT_PATH}/debug.c ${PRJF_PATH}/pRJF.c)
target_link_libraries(pcloudcc_lib ${PCLSYNC_PATH}/psynclib.a  ${MBEDTLS_PATH}/library/libmbedtls.a fuse pthread sqlite3 udev)

file(GLOB_RECURSE INC_ALL "*.h" "*.hpp")
add_executable(pcloudcc main.cpp ${INC_ALL})

target_link_libraries(pcloudcc pcloudcc_lib)
target_link_libraries(pcloudcc ${Boost_LIBRARIES})
link_directories(${PCLSYNC_PATH} ${MBEDTLS_PATH}/library ${SQLITE3_PATH} ${OVERLAY_CLENT_PATH})

#add_dependencies(pclsync sqlite3_lib)
#add_dependencies(pcloudcc sqlite3_lib mbedtls pclsync )
#add_dependencies(pcloudcc pcloudcc_lib)
#EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )
#message( STATUS "Architecture: ${ARCHITECTURE}" )
#if(${ARCHITECTURE} STREQUAL "x86_64")
#    	set(LIB_DIR "/usr/lib64")
#else()
#	set(LIB_DIR "/usr/lib")
#endif()

message(STATUS "System CPU: " ${CMAKE_SYSTEM_PROCESSOR})
install(TARGETS pcloudcc DESTINATION /usr/bin)
install(TARGETS pcloudcc_lib LIBRARY DESTINATION /usr/lib)
