/* packet-smf.h
 * Defines functions and constants for packet-smf.c, packet-smrp.c, 
 * packet-clientctrl.c, smf-analysis.c, packet-assuredctrl.c, and sdt-decoder.c
 *
 * Copyright 2024, Solace Corporation
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

#ifndef __PACKET_SMF_H__
#define __PACKET_SMF_H__

struct smfdata {
	char *subtype;
};
void call_dissect_smf_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int bdChannel);
void smf_proto_add_trace_span_transport_context_value(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb, int offset, int size);

#define ETHERTYPE_SMF_BACKDOOR 0xbacd

// 0x200 (1023) is max channel #, but..
// ...we use 0x400 as there are two 
// directions (LC->CC and CC->LC)
#define MAX_BD_CHANNEL         0x7ff
#endif
