cmake_minimum_required(VERSION 2.8.12)
project(sysrepo-tsn C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-format-truncation")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include(GNUInstallDirs)

include_directories("${PROJECT_SOURCE_DIR}/inc")

# set default build type if not specified by user and normalize it
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)

if("${BUILD_TYPE_UPPER}" STREQUAL "RELEASE")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-DNDEBUG -O2 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-g -O0 ${CMAKE_C_FLAGS}")
endif()

set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/sysrepo-tsn" CACHE STRING "Directory where to copy the YANG modules to.")

# dependencies - libtsn
find_package(TSN REQUIRED)
include_directories(${TSN_INCLUDE_DIRS})
set(LIBS ${LIBS} ${TSN_LIBRARIES})

# dependencies - cjson
find_package(CJSON REQUIRED)
include_directories(${CJSON_INCLUDE_DIRS})
set(LIBS ${LIBS} ${CJSON_LIBRARIES})

# dependencies - nl
find_package(NL REQUIRED)
include_directories(${NL_INCLUDE_DIRS})
set(LIBS ${LIBS} ${NL_LIBRARIES})

# dependencies - gen-nl
find_package(NLGEN REQUIRED)
include_directories(${NLGEN_INCLUDE_DIRS})
set(LIBS ${LIBS} ${NLGEN_LIBRARIES})

# dependencies - sysrepo
find_package(Sysrepo REQUIRED)
include_directories(${SYSREPO_INCLUDE_DIRS})
set(LIBS ${LIBS} ${SYSREPO_LIBRARIES})

# dependencies - libyang
find_package(LibYANG REQUIRED)
include_directories(${LIBYANG_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBYANG_LIBRARIES})

# dependencies - pthread
find_package(Threads)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

find_package(LibSystemd)
if(LIBSYSTEMD_FOUND)
    set(RT_HAVE_SYSTEMD 1)
    include_directories(${LIBSYSTEMD_INCLUDE_DIRS})
    set(LIBS ${LIBS} ${LIBSYSTEMD_LIBRARIES})
    message(STATUS "systemd system service unit path: ${SYSTEMD_UNIT_DIR}")
else()
    message(WARNING "Disabling sysrepo-plugind systemd support because libsystemd was not found.")
endif()

set(SOURCES
		src/main.c
		src/common.c
		src/qbv.c
		src/qbu.c
		src/cb_streamid.c
		src/qci.c
		src/qci_sf.c
		src/qci_sg.c
		src/qci_fm.c
		src/brtc_cfg.c
		src/ip_cfg.c
		src/mac_cfg.c
		src/cb.c
		src/vlan_cfg.c
		src/file_mon.c)

find_package(PkgConfig)

if (CONF_SYSREPO_TSN_TC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSYSREPO_TSN_TC")
endif()

if(RT_HAVE_SYSTEMD)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DRT_HAVE_SYSTEMD")
endif()

# Command line options to be passed to `sysrepoctl` when working with modules
# which should only be accessible by an administrator
if (NOT SYSREPOCTL_ROOT_PERMS)
    set(SYSREPOCTL_ROOT_PERMS "-o root:root -p 600")
endif()

configure_file("${PROJECT_SOURCE_DIR}/sysrepo-tsn.service.in" "${PROJECT_BINARY_DIR}/sysrepo-tsn.service" @ONLY)

if(RT_HAVE_SYSTEMD)
    install(FILES ${PROJECT_BINARY_DIR}/sysrepo-tsn.service DESTINATION ${SYSTEMD_UNIT_DIR})
endif()

# install YANG modules
file(GLOB yangs "${PROJECT_SOURCE_DIR}/modules/*.yang")
install(FILES ${yangs} DESTINATION ${YANG_MODULE_DIR})

install(FILES ${PROJECT_SOURCE_DIR}/scripts/install-tsn-yang.sh DESTINATION /etc/sysrepo-tsn/)

add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBS})

install(TARGETS ${CMAKE_PROJECT_NAME} RUNTIME DESTINATION bin)
