/* perftool-decoder.c
 * Structured Data Type Dissector
 * Copyright 2007, Solace Corporation
 *
 * $Id: $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

# include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include "perftool-decoder.h"


void
add_tooldata_block(proto_tree *bm_tree, int headerFieldIndex, tvbuff_t *tvb, int start_offset, int* length)
{
	int pos;			/* position in payload */
	char *buffer;       /* temp buffer to hold our decode string */
    char *pad_buf;		/* buffer to use for left-padding our decode string */
	uint32_t field_bitmap;

    /* Generate a padding leader */
    pad_buf = (char*)malloc(2);
    memset( pad_buf, ' ', 1);
    pad_buf[1] = '\0';

    pos = start_offset + 4;
	length += 4;
    
	field_bitmap = tvb_get_ntohl(tvb, pos);

	pos += 4;
	length += 4;

	buffer = (char*)malloc(300);

	if (field_bitmap & 0x8000)
	{
		pos += 4;
		length += 4;
	}

	if (field_bitmap & 0x1)
	{
		g_snprintf(buffer, 300, "%sXML Payload Integrity Hash = %" G_GUINT32_FORMAT "",
                               pad_buf, tvb_get_ntohl(tvb, pos));
		proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, 4, buffer);
		pos += 4;
		length += 4;
	}
	if (field_bitmap & 0x2)
	{
		g_snprintf(buffer, 300, "%sStream Identifier = %" G_GUINT32_FORMAT "",
                               pad_buf, tvb_get_ntohl(tvb, pos));
		proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, 4, buffer);
		pos += 4;
		length += 4;
	}
	if (field_bitmap & 0x8)
	{
		g_snprintf(buffer, 300, "%sBinary Attachment Integrity Hash = %" G_GUINT32_FORMAT "",
                               pad_buf, tvb_get_ntohl(tvb, pos));
		proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, 4, buffer);
		pos += 4;
		length += 4;
	}
	if (field_bitmap & 0x10)
	{
		g_snprintf(buffer, 300, "%sMessage Identifier = %" G_GUINT64_FORMAT "",
                               pad_buf, tvb_get_ntoh64(tvb, pos));
		proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, 8, buffer);
		pos += 8;
		length += 8;
	}
	if (field_bitmap & 0x20)
	{
		g_snprintf(buffer, 300, "%sLatency Timestamp = %" G_GUINT64_FORMAT "",
                               pad_buf, tvb_get_ntoh64(tvb, pos));
		proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, 8, buffer);
		pos += 8;
		length += 8;
	}
	if (field_bitmap & 0x40)
	{
		g_snprintf(buffer, 300, "%sRepublished Flag = true",
                               pad_buf);
		proto_tree_add_string(bm_tree, headerFieldIndex, tvb, start_offset + 7, 1, buffer);
	}
	else
	{
		g_snprintf(buffer, 300, "%sRepublished Flag = false",
                               pad_buf);
		proto_tree_add_string(bm_tree, headerFieldIndex, tvb, start_offset + 7, 1, buffer);
	}

    free(pad_buf);
}
