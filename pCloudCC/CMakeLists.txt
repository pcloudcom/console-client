cmake_minimum_required(VERSION 2.6)
project(pcl_client)

find_package(Boost COMPONENTS system program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

#set (CMAKE_CXX_FLAGS "-fsanitize=address")
set (PCLSYNC_PATH ${CMAKE_SOURCE_DIR}/lib/pclsync)
set (MBEDTLS_PATH ${CMAKE_SOURCE_DIR}/lib/mbedtls)
set (SQLITE3_PATH ${CMAKE_SOURCE_DIR}/lib/sqlite)

add_subdirectory(${MBEDTLS_PATH})

include_directories(${SQLITE3_PATH})
add_custom_target(
  sqlite3_lib
  COMMAND ./configure && make
  WORKING_DIRECTORY ${SQLITE3_PATH}
)

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

set (OVERLAY_CLENT_PATH ${CMAKE_SOURCE_DIR}/lib/poverlay_linux)
include_directories(${OVERLAY_CLENT_PATH})

link_directories(${PCLSYNC_PATH} ${MBEDTLS_PATH}/library ${SQLITE3_PATH} ${OVERLAY_CLENT_PATH})


add_executable(pcl_client main.cpp pclsync_lib.cpp control_tools.cpp ${OVERLAY_CLENT_PATH}/overlay_client.c ${OVERLAY_CLENT_PATH}/debug.c ${SQLITE3_PATH}/sqlite3.c)


target_link_libraries(pcl_client psynclib mbedtls fuse pthread z dl
)

target_link_libraries(pcl_client ${Boost_LIBRARIES})

add_dependencies(pclsync sqlite3_lib)

add_dependencies(pcl_client sqlite3_lib pclsync )

install(TARGETS pcl_client RUNTIME DESTINATION bin)