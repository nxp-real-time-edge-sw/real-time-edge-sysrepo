cmake_minimum_required(VERSION 2.8.12)
project(sysrepo-tsn)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-format-truncation")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories("${PROJECT_SOURCE_DIR}/inc")

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

# find programs
find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
if (NOT SYSREPOCTL_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
endif()

find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
if (NOT SYSREPOCFG_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
endif()

find_program(CHMOD_EXECUTABLE chmod)
if (NOT CHMOD_EXECUTABLE)
    message(FATAL_ERROR "Unable to find chmod, set CHMOD_EXECUTABLE manually.")
endif()

if (CONF_SYSREPO_TSN_TC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSYSREPO_TSN_TC")
endif()

# Command line options to be passed to `sysrepoctl` when working with modules
# which should only be accessible by an administrator
if (NOT SYSREPOCTL_ROOT_PERMS)
    set(SYSREPOCTL_ROOT_PERMS "-o root:root -p 600")
endif()

install(CODE "
	set(ENV{SYSREPOCTL} ${SYSREPOCTL_EXECUTABLE})
	set(ENV{SYSREPOCTL_ROOT_PERMS} SYSREPOCTL_ROOT_PERMS)
	execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/model-install.sh)")

add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBS})

install(TARGETS ${CMAKE_PROJECT_NAME} RUNTIME DESTINATION bin)
