cmake_minimum_required(VERSION 2.6)
project(pcloudcc)

# Set version for packaging
set(VERSION "2.0.1")

#INCLUDE(CPack)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
unset(Boost_INCLUDE_DIR CACHE)
unset(Boost_LIBRARY_DIRS CACHE)

find_package(Boost COMPONENTS system program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
#set (CMAKE_CXX_FLAGS "-static -Wl,-Bstatic")
#set (CMAKE_CXX_FLAGS "-Wl,-Bstatic")
set (CMAKE_C_FLAGS "-fPIC")
set (PCLSYNC_PATH ${CMAKE_SOURCE_DIR}/lib/pclsync)
set (MBEDTLS_PATH ${CMAKE_SOURCE_DIR}/lib/mbedtls)
set (SQLITE3_PATH ${CMAKE_SOURCE_DIR}/lib/sqlite)

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

set (OVERLAY_CLENT_PATH ${CMAKE_SOURCE_DIR}/lib/poverlay_linux)
include_directories(${OVERLAY_CLENT_PATH})

add_library(sqlite3 STATIC ${SQLITE3_PATH}/sqlite3.c)
target_link_libraries(sqlite3 z dl)

add_library(pcloudcc_lib SHARED pclsync_lib_c.cpp pclsync_lib.cpp control_tools.cpp ${OVERLAY_CLENT_PATH}/overlay_client.c ${OVERLAY_CLENT_PATH}/debug.c )

target_link_libraries(pcloudcc_lib ${PCLSYNC_PATH}/psynclib.a  ${MBEDTLS_PATH}/library/libmbedtls.a fuse pthread sqlite3 udev
)

add_executable(pcloudcc main.cpp)

target_link_libraries(pcloudcc pcloudcc_lib)

target_link_libraries(pcloudcc ${Boost_LIBRARIES})

link_directories(${PCLSYNC_PATH} ${MBEDTLS_PATH}/library ${SQLITE3_PATH} ${OVERLAY_CLENT_PATH})

#add_dependencies(pclsync sqlite3_lib)

#add_dependencies(pcloudcc sqlite3_lib mbedtls pclsync )

install(TARGETS pcloudcc RUNTIME DESTINATION bin)
install(TARGETS pcloudcc_lib LIBRARY DESTINATION lib)

# RPM parmeters
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "pcloudcc")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "pCloud.com")
set(CPACK_PACKAGE_VENDOR "pCloud.com")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RPM_PACKAGE_AUTOREQ 1)
set(CPACK_RPM_PACKAGE_GROUP "System")
set(CPACK_RPM_PACKAGE_DESCRIPTION "pCloud.com command line client")
set(CPACK_RPM_PACKAGE_GROUP "system")
include(CPack)

