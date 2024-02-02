# Makefile.am
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

include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = smf

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-assuredctrl.c \
	packet-clientctrl.c \
	packet-pubctrl.c \
	packet-smf.c \
	packet-smf-binarymeta.c \
	packet-smf-compress.c \
	packet-matelink.c \
	packet-smf-openmama-payload.c \
	packet-smp.c \
	packet-smrp.c \
	packet-subctrl.c \
	packet-xmllink.c \
	sdt-decoder.c \
	smf-analysis.c \
	perftool-decoder.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES = \
	packet-smf.h \
	sdt-decoder.h \
	smf-analysis.c \
	perftool-decoder.h

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = smf.la

smf_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

smf_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

smf_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

smf_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	smf \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c

EXTRA_DIST = \
	plugin.rc.in		\
	CMakeLists.txt
