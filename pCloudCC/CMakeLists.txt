cmake_minimum_required(VERSION 2.6)
project(pcl_client)

find_package(Boost COMPONENTS system program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

#set (CMAKE_CXX_FLAGS "-fsanitize=address")

set (PCLSYNC_PATH ../pclsync)
include_directories(${PCLSYNC_PATH})
# add_custom_target(
#    pclsync_clean
#    COMMAND make clean
#    WORKING_DIRECTORY ${PCLSYNC_PATH}
# )

# add_custom_target(
#    pclsync
#    COMMAND make fs
#    WORKING_DIRECTORY ${PCLSYNC_PATH}
# )

set (OVERLAY_CLENT_PATH ${PCLSYNC_PATH}/lib/poverlay_linux)
include_directories(${OVERLAY_CLENT_PATH})

link_directories(${PCLSYNC_PATH} ${PCLSYNC_PATH}/lib/mbedtls/library ${PCLSYNC_PATH}/lib/sqlite/inst/lib ${OVERLAY_CLENT_PATH})


add_executable(pcl_client main.cpp pclsync_lib.cpp control_tools.cpp ${OVERLAY_CLENT_PATH}/overlay_client.c ${OVERLAY_CLENT_PATH}/debug.c)


target_link_libraries(pcl_client psynclib mbedtls sqlite3 fuse pthread z
)

target_link_libraries(pcl_client ${Boost_LIBRARIES})

add_dependencies(pcl_client pclsync_clean pclsync)

install(TARGETS pcl_client RUNTIME DESTINATION bin)
