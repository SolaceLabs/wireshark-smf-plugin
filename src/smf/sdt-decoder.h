/* sdt-decoder.h
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

#ifndef SDT_DECODER_H_
#define SDT_DECODER_H_

#include "epan/proto.h"

extern int ett_trace_span_message_creation_context;

void
add_sdt_block(proto_tree *bm_tree, packet_info* pinfo, int headerFieldIndex, tvbuff_t *tvb, int offset, int length, int indent, bool is_in_map);

void get_embedded_smf_info(tvbuff_t *tvb, int offset, int length, int *embedded_smf_info);

void sdt_decoder_init(void);

#endif /* SDT_DECODER_H_ */
