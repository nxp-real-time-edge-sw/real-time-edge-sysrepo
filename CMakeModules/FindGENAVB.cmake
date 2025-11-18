#  GENAVB_FOUND - System has libgenavb
#  GENAVB_INCLUDE_DIRS - The libgenavb include directories
#  GENAVB_LIBRARIES - The libraries needed to use libgenavb
#  GENAVB_DEFINITIONS - Compiler switches required for using libgenavb

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_GENAVB libgenavb)
endif()

find_path(GENAVB_INCLUDE_DIR genavb/genavb.h
          HINTS ${PC_GENAVB_INCLUDEDIR} ${PC_GENAVB_INCLUDE_DIRS}
          PATH_SUFFIXES genavb)

find_library(GENAVB_LIBRARY NAMES genavb
             HINTS ${PC_GENAVB_LIBDIR} ${PC_GENAVB_LIBRARY_DIRS})

set(GENAVB_LIBRARIES ${GENAVB_LIBRARY} )
set(GENAVB_INCLUDE_DIRS ${GENAVB_INCLUDE_DIR})
set(GENAVB_DEFINITIONS ${PC_GENAVB_CFLAGS_OTHER})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GENAVB  DEFAULT_MSG
                                  GENAVB_LIBRARY GENAVB_INCLUDE_DIR)

mark_as_advanced(GENAVB_INCLUDE_DIR GENAVB_LIBRARY)
