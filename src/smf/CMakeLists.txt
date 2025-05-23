# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
#
# NOTE:  Windows uses this for FILEVERSION in plugin.rc and so
# may not contains useful strings like "rc" or "dev" or "<branchname>"
#
if (NOT DEFINED SMF_PLUGIN_MAJOR_VERSION)
   set(SMF_PLUGIN_MAJOR_VERSION ${PROJECT_MAJOR_VERSION})
endif()
if (NOT DEFINED SMF_PLUGIN_MINOR_VERSION)
   set(SMF_PLUGIN_MINOR_VERSION ${PROJECT_MINOR_VERSION})
endif()
if (NOT DEFINED SMF_PLUGIN_PATCH_VERSION)
   set(SMF_PLUGIN_PATCH_VERSION 0)
endif()
if (NOT DEFINED SMF_PLUGIN_COMMIT_HASH)
   set(SMF_PLUGIN_COMMIT_HASH 0)
endif()

set_module_info(smf ${SMF_PLUGIN_MAJOR_VERSION} ${SMF_PLUGIN_MINOR_VERSION} ${SMF_PLUGIN_PATCH_VERSION} ${SMF_PLUGIN_COMMIT_HASH})

set(DISSECTOR_SRC
	packet-assuredctrl.c
	packet-clientctrl.c
	packet-pubctrl.c
	packet-smf.c
	packet-smf-binarymeta.c
	packet-smf-compress.c
	packet-matelink.c
	packet-smf-openmama-payload.c
	packet-smp.c
	packet-smrp.c
	packet-subctrl.c
	packet-xmllink.c
	sdt-decoder.c
	smf-analysis.c
	perftool-decoder.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(smf epan)
target_include_directories(smf SYSTEM PRIVATE ${ZLIB_INCLUDE_DIRS})
target_link_libraries(smf epan ${ZLIB_LIBRARIES})

install_plugin(smf epan)

#[[
install(TARGETS smf
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
)
]]
file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  smf
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)
