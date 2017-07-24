cmake_minimum_required(VERSION 2.6)
project(ScvpScriptGenerator)

SET (ScvpScriptGenerator_exe_SRCS
	ScvpScriptGenerator.cpp
	pkits.cpp
)

SET (ScvpScriptGenerator_exe_HEADERS
	ScvpScriptGenerator.h
)
if(APPLE)
   MESSAGE(STATUS "Setting -std=c++11 -stdlib=libc++ for Mac OS X")
   set(CMAKE_CXX_FLAGS "-stdlib=libc++ -std=c++11 ${CMAKE_CXX_FLAGS}")
   set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")
   ADD_DEFINITIONS("-DBOOST_NO_CXX11_SCOPED_ENUMS")
endif()

source_group("Headers" FILES ${ScvpScriptGenerator_exe_HEADERS})

if (WIN32)
    ADD_DEFINITIONS("-DBOOST_ALL_NO_LIB")
  set(BOOST_INCLUDEDIR ${RHS_INSTALL_STAGE}/boost/include/boost-1_47)
endif (WIN32)

include_directories(
    .
)

ADD_EXECUTABLE(ScvpScriptGenerator ${ScvpScriptGenerator_exe_SRCS} ${ScvpScriptGenerator_exe_HEADERS})

# These path manipulations are intended to make it easy to install product-specific
# versions of dependencies that may differ from system-wide installed versions.
# (because, e.g. we can't uninstall the wx that ships with Snow Leopard but may have
# a good reason to use a different one)
set(OLD_CMAKE_PREFIX_PATH  ${CMAKE_PREFIX_PATH})
MESSAGE(STATUS "OLD_CMAKE_PREFIX_PATH: \"${OLD_CMAKE_PREFIX_PATH}\"")

#include stuff is above add_executable
target_link_libraries(ScvpScriptGenerator ${openssl1fips_LIBRARIES})

MESSAGE(STATUS "CMAKE_PREFIX_PATH: \"${CMAKE_PREFIX_PATH}\"")
set(Boost_USE_STATIC_LIBS ON)
set(CMAKE_PREFIX_PATH ${RHS_INSTALL_STAGE}/boost ${OLD_CMAKE_PREFIX_PATH} )
set(BOOST_ROOT ${RHS_INSTALL_STAGE}/boost )
set(Boost_NO_SYSTEM_PATHS true)
set(Boost_ADDITIONAL_VERSIONS "1.58" "1.58.0" "1.59" "1.59.0")
find_package( Boost 1.46.1 COMPONENTS chrono serialization filesystem system thread date_time regex program_options REQUIRED )
include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(ScvpScriptGenerator ${Boost_LIBRARIES})
MESSAGE(STATUS "CMAKE_PREFIX_PATH: \"${CMAKE_PREFIX_PATH}\"")
MESSAGE(STATUS "Boost_LIB_PREFIX: \"${Boost_LIB_PREFIX}\"")
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    # boost::thread uses GetTickCount64 as of some recent version, and we still need to
    # run on server 2003, where that's not available.
    add_definitions(-D_WIN32_WINNT=0x0501)
endif(CMAKE_SYSTEM_NAME MATCHES "Windows")

if( "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftemplate-depth=256" )
endif( "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" )

if(WIN32)
	# This is required for the exe to run on server 2k3.
	SET_TARGET_PROPERTIES(ScvpScriptGenerator PROPERTIES LINK_FLAGS "/DELAYLOAD:ncrypt.dll")
endif(WIN32)

SET(APPS "\${CMAKE_INSTALL_PREFIX}/ScvpScriptGenerator")

install( TARGETS ScvpScriptGenerator
    BUNDLE DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT Runtime
    RUNTIME DESTINATION bin COMPONENT Runtime
    )



