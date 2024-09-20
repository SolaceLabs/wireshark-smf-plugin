/* packet-pubctrl.c
 * Routines for Publisher Control dissection
 * Copyright 2007, Solace Corporation
 *
 * $Id: packet-pubctrl.c 318 2007-01-24 16:01:31Z $
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

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
/* #include "packet-pubctrl.h" */

/* Forward declaration we need below */
void proto_reg_handoff_pubctrl(void);

/* Initialize the protocol and registered fields */
static int proto_pubctrl = -1;
static int hf_pubctrl_version = -1;
static int hf_pubctrl_msg_len = -1;
static int hf_pubctrl_unknown_param = -1;
static int hf_pubctrl_pad_byte = -1;
static int hf_pubctrl_udp_port_param = -1;
static int hf_pubctrl_explicit_ack_mode_param = -1;
static int hf_pubctrl_udp_source_addr_param = -1;
static int hf_pubctrl_software_version_param = -1;
static int hf_pubctrl_software_date_param = -1;
static int hf_pubctrl_platform_param = -1;
static int hf_pubctrl_csmp_vrid_param = -1;

/* Global sample preference ("controls" display of numbers) */
//static bool gPREF_HEX = false;

/* Initialize the subtree pointers */
static int ett_pubctrl = -1;

#define PUBCTRL_UDP_PORT_PARAM 0x1
#define PUBCTRL_EXPLICIT_ACK_MODE_PARAM 0x2
#define PUBCTRL_UDP_SOURCE_ADDRESS_PARAM 0x3
#define PUBCTRL_RTR_CAPABILITIES_PARAM 0x4
#define PUBCTRL_SOFTWARE_VERSION_PARAM 0x5
#define PUBCTRL_SOFTWARE_DATE_PARAM 0x6
#define PUBCTRL_PLATFORM_PARAM 0x7
#define PUBCTRL_CSMP_VRID_PARAM 0x8

/* We use the dissector in packet-clientctrl.c
   as teh rtr capabilities parameter is defined
   identically for both pubctrl and clientctrl  */
extern void 
clientctrl_dissect_rtr_capabilities_param(
	tvbuff_t *tvb,
    	proto_tree *tree,
    	int offset,
    	int size,
        bool extended);

static void
add_pubctrl_param(
    tvbuff_t *tvb,
    proto_tree *tree,
    uint8_t param_type,
    int offset,
    int size)
{
    offset += 2;
    size -= 2;

    switch (param_type)
    {
        case PUBCTRL_UDP_PORT_PARAM:
            proto_tree_add_item(tree,
                hf_pubctrl_udp_port_param,
                tvb, offset, size, false);
            break;

        case PUBCTRL_EXPLICIT_ACK_MODE_PARAM:
            proto_tree_add_item(tree,
                hf_pubctrl_explicit_ack_mode_param,
                tvb, offset-2, size+2, false);
            break;

        case PUBCTRL_UDP_SOURCE_ADDRESS_PARAM:
            proto_tree_add_item(tree,
                hf_pubctrl_udp_source_addr_param,
                tvb, offset, size, false);
            break;

        case PUBCTRL_RTR_CAPABILITIES_PARAM:
            clientctrl_dissect_rtr_capabilities_param(tvb, tree, offset, size, false);
            break;

        case PUBCTRL_SOFTWARE_VERSION_PARAM:
            proto_tree_add_item(tree,
                hf_pubctrl_software_version_param,
                tvb, offset, size, false);
            break;

        case PUBCTRL_SOFTWARE_DATE_PARAM:
            proto_tree_add_item(tree,
                hf_pubctrl_software_date_param,
                tvb, offset, size, false);
            break;

        case PUBCTRL_PLATFORM_PARAM:
            proto_tree_add_item(tree,
                hf_pubctrl_platform_param,
                tvb, offset, size, false);
            break;

		case PUBCTRL_CSMP_VRID_PARAM:
            proto_tree_add_item(tree,
                hf_pubctrl_csmp_vrid_param,
                tvb, offset, size, false);
            break;

        default:
            proto_tree_add_item(tree,
                hf_pubctrl_unknown_param,
                tvb, offset-2, size+2, false);
            break;
    }
}

static int
dissect_pubctrl_param(
    tvbuff_t *tvb, 
    int offset, 
    proto_tree *tree)
{
    int param_len;
    uint8_t param_type;

    /* Is it a pad byte? */
    if (tvb_get_uint8(tvb, offset) == 0)
    {
        proto_tree_add_item(tree,
            hf_pubctrl_pad_byte, tvb, offset, 1, false);
        return 1;
    }

    param_type = tvb_get_uint8(tvb, offset) & 0x1f;
    param_len  = tvb_get_uint8(tvb, offset+1);

    add_pubctrl_param(tvb, tree, param_type, offset, param_len);

    return param_len;
}

static void
dissect_pubctrl_params(
    tvbuff_t *tvb, 
    int param_offset_start, 
    int param_offset_end,
    proto_tree *tree)
{
    int offset;

    for (offset=param_offset_start; offset<param_offset_end; )
    {
        int param_len = dissect_pubctrl_param(tvb, offset, tree);
        if (0 == param_len) {
            // A param cannot be 0 length. Something went wrong with the dissection. Just exit
            break;
        }
        offset += param_len;
    }
}

/* Code to actually dissect the packets */
static int
dissect_pubctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *pubctrl_tree;
    int header_len;

/* Make entries in Protocol column and Info column on summary display */
#if 0
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "pubctrl");
#endif 
/* This field shows up as the "Info" column in the display; you should use
   it, if possible, to summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. See section 1.5
   for more information.

   Before changing the contents of a column you should make sure the column is
   active by calling "check_col(pinfo->cinfo, COL_*)". If it is not active 
   don't bother setting it.
   
   If you are setting the column to a constant string, use "col_set_str()", 
   as it's more efficient than the other "col_set_XXX()" calls.

   If you're setting it to a string you've constructed, or will be
   appending to the column later, use "col_add_str()".

   "col_add_fstr()" can be used instead of "col_add_str()"; it takes
   "printf()"-like arguments.  Don't use "col_add_fstr()" with a format
   string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
   more efficient than "col_add_fstr()".

   If you will be fetching any data from the packet before filling in
   the Info column, clear that column first, in case the calls to fetch
   data from the packet throw an exception because they're fetching data
   past the end of the packet, so that the Info column doesn't have data
   left over from the previous dissector; do

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

   */

    /*
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_set_str(pinfo->cinfo, COL_INFO, "XXX Request");
    */
/* A protocol dissector can be called in 2 different ways:

	(a) Operational dissection

		In this mode, Wireshark is only interested in the way protocols
		interact, protocol conversations are created, packets are reassembled
		and handed over to higher-level protocol dissectors.
		In this mode Wireshark does not build a so-called "protocol tree".

	(b) Detailed dissection

		In this mode, Wireshark is also interested in all details of a given
		protocol, so a "protocol tree" is created.

   Wireshark distinguishes between the 2 modes with the proto_tree pointer:
	(a) <=> tree == NULL
	(b) <=> tree != NULL

   In the interest of speed, if "tree" is NULL, avoid building a
   protocol tree and adding stuff to it, or even looking at any packet
   data needed only if you're building the protocol tree, if possible.

   Note, however, that you must fill in column information, create
   conversations, reassemble packets, build any other persistent state
   needed for dissection, and call subdissectors regardless of whether
   "tree" is NULL or not.  This might be inconvenient to do without
   doing most of the dissection work; the routines for adding items to
   the protocol tree can be passed a null protocol tree pointer, in
   which case they'll return a null item pointer, and
   "proto_item_add_subtree()" returns a null tree pointer if passed a
   null item pointer, so, if you're careful not to dereference any null
   tree or item pointers, you can accomplish this by doing all the
   dissection work.  This might not be as efficient as skipping that
   work if you're not building a protocol tree, but if the code would
   have a lot of tests whether "tree" is null if you skipped that work,
   you might still be better off just doing all that work regardless of
   whether "tree" is null or not. */
	//if (tree) {

/* NOTE: The offset and length values in the call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   Supplying a length of -1 is the way to highlight all data from the
   offset to the end of the packet. */

/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_pubctrl, tvb, 0, -1, false);

		pubctrl_tree = proto_item_add_subtree(ti, ett_pubctrl);

        /* Dissect header fields */
		proto_tree_add_item(pubctrl_tree,
		    hf_pubctrl_version, tvb, 0, 1, false);
        proto_tree_add_item(pubctrl_tree,
            hf_pubctrl_msg_len, tvb, 1, 2, false);

        /* Dissect parameters */
        header_len = tvb_get_ntohs(tvb, 1) & 0xfff;
        dissect_pubctrl_params(tvb, 3, 4*header_len, pubctrl_tree);

        /* And that's it! */
	//}
	return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_pubctrl(void)
{                 
	//module_t *pubctrl_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_pubctrl_version,
			{ "Version",           "pubctrl.version",
			FT_UINT8, BASE_DEC, NULL, 0x3f,          
			"", HFILL }
		},
		{ &hf_pubctrl_msg_len,
			{ "Message length",           "pubctrl.msg_len",
			FT_UINT16, BASE_DEC, NULL, 0xfff,          
			"", HFILL }
		},
		{ &hf_pubctrl_unknown_param,
			{ "Unrecognized parameter",           "pubctrl.unknown_param",
			FT_BYTES, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_pubctrl_pad_byte,
			{ "Pad byte",           "pubctrl.pad_byte",
			FT_NONE, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_pubctrl_udp_port_param,
			{ "UDP port",           "pubctrl.udp_port",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_pubctrl_explicit_ack_mode_param,
			{ "Explicit ACK mode",           "pubctrl.explicit_ack_mode",
			FT_NONE, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_pubctrl_udp_source_addr_param,
			{ "UDP source address",           "pubctrl.udp_source_addr",
			FT_IPv4, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
                { &hf_pubctrl_software_version_param,
                    { "Software Version",           "pubctrl.software_version",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_pubctrl_software_date_param,
                    { "Software Date",           "pubctrl.software_date",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_pubctrl_platform_param,
                    { "Platform",           "pubctrl.platform",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_pubctrl_csmp_vrid_param,
                    { "CSMP VRID",           "pubctrl.csmp_vrid",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
        	};

/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_pubctrl
	};

/* Register the protocol name and description */
	proto_pubctrl = proto_register_protocol("Publisher Control",
	    "PubCtrl", "pubctrl");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_pubctrl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.pubctrl", dissect_pubctrl, proto_pubctrl);
        
#if 0
/* Register preferences module (See Section 2.6 for more on preferences) */
	pubctrl_module = prefs_register_protocol(proto_pubctrl, 
	    proto_reg_handoff_pubctrl);
     
/* Register a sample preference */
	prefs_register_bool_preference(pubctrl_module, "showHex", 
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
proto_reg_handoff_pubctrl(void)
{
	static bool inited = false;
        
	if (!inited) {

	    //dissector_handle_t pubctrl_handle;
	    //pubctrl_handle = create_dissector_handle(dissect_pubctrl, proto_pubctrl);
	    (void)create_dissector_handle(dissect_pubctrl, proto_pubctrl);
	    //dissector_add("smf.encap_proto", 0x8, pubctrl_handle);
        
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
              dissector_delete("tcp.port", currentPort, pubctrl_handle);
          }

          currentPort = gPortPref;

          dissector_add("tcp.port", currentPort, pubctrl_handle);
            
        */
}
