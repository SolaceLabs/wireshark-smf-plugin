/* packet-smf-binarymeta.c
 * Subscription Management Protocol Dissector
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
#include <epan/wmem_scopes.h>
#include "sdt-decoder.h"

/* Forward declaration we need below */
void proto_reg_handoff_bm(void);

/* Initialize the protocol and registered fields */
static int proto_bm = -1;
static int hf_bm_num_elem = -1;
static int hf_bm_payload = -1;
static int hf_bm_block = -1;
static int hf_bm_sdtitem = -1;

/* Binary Metadata Types */
#define BM_TYPE_SDT 0x00
#define BM_TYPE_JMS 0x01

/* Global sample preference ("controls" display of numbers) */
//static bool gPREF_HEX = false;

/* Initialize the subtree pointers */
static int ett_bm = -1;

typedef struct {
    int type;
    int length;
} indexentry;

/* Code to actually dissect the packets */
static int
dissect_bm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *bm_tree;
	int i;
	int num_blocks;
	indexentry idxblocks[256];
	int data_offset;
	int cumul_offset;
	char *buffer;

/* Make entries in Protocol column and Info column on summary display */
#if 0
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "smf-bm");
#endif
	//if (tree) {

/* NOTE: The offset and length values in the call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   Supplying a length of -1 is the way to highlight all data from the
   offset to the end of the packet. */

/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_bm, tvb, 0, -1, false);

		bm_tree = proto_item_add_subtree(ti, ett_bm);

        /* Dissect header fields */
		proto_tree_add_item(bm_tree,
		    hf_bm_num_elem, tvb, 0, 1, false);

		/* Dissect contents */
		num_blocks = tvb_get_uint8(tvb, 0);
		for(i = 0; i < num_blocks; i++) {
			idxblocks[i].type = tvb_get_uint8(tvb, 1+4*i);
			idxblocks[i].length = tvb_get_ntoh24(tvb, 2+4*i);
		}
		data_offset = num_blocks * 4 + 1;
		cumul_offset = data_offset;
		for(i = 0; i < num_blocks; i++) {
		    
            buffer = (char*)wmem_alloc(wmem_packet_scope(), 300);

			g_snprintf(buffer, 300, "Type %d Length %d", idxblocks[i].type, idxblocks[i].length);
			proto_tree_add_string(bm_tree, hf_bm_block, tvb, cumul_offset, idxblocks[i].length, buffer);
			if (idxblocks[i].type == BM_TYPE_SDT) {
		            add_sdt_block(bm_tree, pinfo, hf_bm_sdtitem, tvb, cumul_offset, idxblocks[i].length, 1, false);
			}
			cumul_offset += idxblocks[i].length;
		}
	//}
	return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_bm(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_bm_num_elem,
			{ "MetadataBlockCount",           "smf-bm.num_elem",
			FT_UINT8, BASE_DEC, NULL, 0xFF,
			"", HFILL }
		},
        { &hf_bm_payload,
            { "Payload",           "smf-bm.payload",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_bm_block,
            { "MetadataBlock",           "smf-bm.metadatablock",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_bm_sdtitem,
            { "SDTItem",           "smf-bm.sdtitem",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
		

	};

/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_bm
	};

/* Register the protocol name and description */
	proto_bm = proto_register_protocol(
		"SMF Binary Metadata",
	    "SMF-BM", "smf-bm");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_bm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.smf-bm", dissect_bm, proto_bm);

#if 0
/* Register preferences module (See Section 2.6 for more on preferences) */
	assuredctrl_module = prefs_register_protocol(proto_assuredctrl,
	    proto_reg_handoff_assuredctrl);

/* Register a sample preference */
	prefs_register_bool_preference(assuredctrl_module, "showHex",
	     "Display numbers in Hex",
	     "Enable to display numerical values in hexadecimal.",
	     &gPREF_HEX);
#endif
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these routines
   and create the code that calls these routines.

   This function is also called by preferences whenever "Apply" is pressed
   (see prefs_register_protocol above) so it should accommodate being called
   more than once.
*/
void
proto_reg_handoff_bm(void)
{
	static bool inited = false;

	if (!inited) {
	    //dissector_handle_t bm_handle;
	    //bm_handle = create_dissector_handle(dissect_bm, proto_bm);
	    (void)create_dissector_handle(dissect_bm, proto_bm);
	    inited = true;
	}

        /*
          If you perform registration functions which are dependant upon
          prefs the you should de-register everything which was associated
          with the previous settings and re-register using the new prefs settings
          here. In general this means you need to keep track of what value the
          preference had at the time you registered using a local static in this
          function. ie.

          static int currentPort = -1;

          if (currentPort != -1) {
              dissector_delete("tcp.port", currentPort, assuredctrl_handle);
          }

          currentPort = gPortPref;

          dissector_add("tcp.port", currentPort, assuredctrl_handle);

        */
}
