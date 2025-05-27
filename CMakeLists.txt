cmake_minimum_required(VERSION 2.8.12)
project(sysrepo-tsn C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-format-truncation -Wno-unused-result")

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

set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/sysrepo-tsn"
    CACHE STRING "Directory where to copy the YANG modules to.")

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

find_package(PkgConfig REQUIRED)

set(LLDP_PLUGIN_NAME "lldp-plugin")
set(LLDP_SRC
		src/common.c
		src/lldp-plugin.c)

set(PTP_PLUGIN_NAME "ptp-plugin")
set(PTP_SRC
		src/common.c
		src/ptp-plugin.c)

set(TSN_PLUGIN_NAME "tsn-plugin")
set(TSN_SRC
		src/common.c
        src/tsn-plugin.c
		src/ip_cfg.c
		src/qbv.c
	    src/qbu.c
		src/brtc_cfg.c
		src/mac_cfg.c
		src/vlan_cfg.c
		src/qci.c
		src/qci_sf.c
		src/qci_sg.c
		src/qci_fm.c
		src/qci.c
		src/cb.c
		src/cb_streamid.c)

if (CONF_SYSREPO_TSN_TC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSYSREPO_TSN_TC")
endif()

# install YANG modules
file(GLOB yang_modules "${PROJECT_SOURCE_DIR}/modules/*.yang")
install(FILES ${yang_modules} DESTINATION ${YANG_MODULE_DIR})

install(FILES ${PROJECT_SOURCE_DIR}/scripts/install-tsn-yang.sh DESTINATION /etc/sysrepo-tsn/)

pkg_get_variable(PLUGINS_PATH sysrepo SRPD_PLUGINS_PATH)

add_library(${LLDP_PLUGIN_NAME} MODULE ${LLDP_SRC})
target_link_libraries(${LLDP_PLUGIN_NAME} ${LIBS})
set_target_properties(${LLDP_PLUGIN_NAME} PROPERTIES PREFIX "")
install(TARGETS ${LLDP_PLUGIN_NAME} DESTINATION ${PLUGINS_PATH})

add_library(${PTP_PLUGIN_NAME} MODULE ${PTP_SRC})
target_link_libraries(${PTP_PLUGIN_NAME} ${LIBS})
set_target_properties(${PTP_PLUGIN_NAME} PROPERTIES PREFIX "")
install(TARGETS ${PTP_PLUGIN_NAME} DESTINATION ${PLUGINS_PATH})

add_library(${TSN_PLUGIN_NAME} MODULE ${TSN_SRC})
target_link_libraries(${TSN_PLUGIN_NAME} ${LIBS})
set_target_properties(${TSN_PLUGIN_NAME} PROPERTIES PREFIX "")
install(TARGETS ${TSN_PLUGIN_NAME} DESTINATION ${PLUGINS_PATH})

