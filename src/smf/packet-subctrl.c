/* packet-subctrl.c
 * Routines for Subscriber Control dissection
 * Copyright 2007, Solace Corporation
 *
 * $Id: packet-subctrl.c 318 2007-01-24 16:01:31Z $
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
/* #include "packet-subctrl.h" */

/* Forward declaration we need below */
void proto_reg_handoff_subctrl(void);

/* Initialize the protocol and registered fields */
static int proto_subctrl = -1;
static int hf_subctrl_version = -1;
static int hf_subctrl_msg_len = -1;
static int hf_subctrl_unknown_param = -1;
static int hf_subctrl_pad_byte = -1;
static int hf_subctrl_udp_port_param = -1;
static int hf_subctrl_udp_mcast_param = -1;
static int hf_subctrl_subscription_summary_num_param = -1;
static int hf_subctrl_subscription_summary_isfilter_param = -1;
static int hf_subctrl_subscription_summary_xpelen_param = -1;
static int hf_subctrl_subscription_summary_lastxpe_param = -1;
static int hf_subctrl_subscription_summary_v2_num_param = -1;
static int hf_subctrl_subscription_summary_v2_isfilter_param = -1;
static int hf_subctrl_subscription_summary_v2_cid_param = -1;
static int hf_subctrl_subscription_summary_v2_xpelen_param = -1;
static int hf_subctrl_subscription_summary_v2_lastxpe_param = -1;
static int hf_subctrl_xpe_segment_param = -1;
static int hf_subctrl_udp_mcast_addr_param = -1;
static int hf_subctrl_udp_mcast_port_param = -1;
static int hf_subctrl_udp_mcast_subid_param = -1;
static int hf_subctrl_refresh_required_param = -1;
static int hf_subctrl_udp_unicast_addr_param = -1;
static int hf_subctrl_software_version_param = -1;
static int hf_subctrl_software_date_param = -1;
static int hf_subctrl_platform_param = -1;
static int hf_subctrl_csmp_vrid_param = -1;

#if 0
/* Global sample preference ("controls" display of numbers) */
static bool gPREF_HEX = false;
#endif

/* Initialize the subtree pointers */
static int ett_subctrl = -1;

#define SUBCTRL_UDP_PORT_PARAM 0x1
#define SUBCTRL_UDP_MCAST_PARAM 0x2
#define SUBCTRL_SUBSCRIPTION_SUMMARY_PARAM 0x3
#define SUBCTRL_XPE_SEGMENT_PARAM 0x4
#define SUBCTRL_UDP_MCAST_ADDR_PARAM 0x5
#define SUBCTRL_REFRESH_REQUIRED_PARAM 0x6
#define SUBCTRL_UDP_UNICAST_ADDR_PARAM 0x7
#define SUBCTRL_SUBSCRIPTION_SUMMARY_V2_PARAM 0x8
#define SUBCTRL_RTR_CAPABILITIES_PARAM 0x9
#define SUBCTRL_SOFTWARE_VERSION_PARAM 0xa
#define SUBCTRL_SOFTWARE_DATE_PARAM 0xb
#define SUBCTRL_PLATFORM_PARAM 0xc
#define SUBCTRL_CSMP_VRID_PARAM 0xd

/* We use the dissector in packet-clientctrl.c
   as teh rtr capabilities parameter is defined
   identically for both subctrl and clientctrl  */
extern void 
clientctrl_dissect_rtr_capabilities_param(
	tvbuff_t *tvb,
    	proto_tree *tree,
    	int offset,
    	int size,
        bool extended);

static void
add_subctrl_param(
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
        case SUBCTRL_UDP_PORT_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_udp_port_param,
                tvb, offset, size, false);
            break;

        case SUBCTRL_UDP_MCAST_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_udp_mcast_param,
                tvb, offset-2, size+2, false);
            break;

        case SUBCTRL_SUBSCRIPTION_SUMMARY_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_num_param,
                tvb, offset, 3, false);
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_isfilter_param,
                tvb, offset+3, 1, false);
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_xpelen_param,
                tvb, offset+4, 2, false);
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_lastxpe_param,
                tvb, offset+6, size-6, false);
            break;

        case SUBCTRL_XPE_SEGMENT_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_xpe_segment_param,
                tvb, offset, size, false);
            break;

        case SUBCTRL_UDP_MCAST_ADDR_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_udp_mcast_addr_param,
                tvb, offset, 4, false);
            proto_tree_add_item(tree,
                hf_subctrl_udp_mcast_port_param,
                tvb, offset+4, 2, false);
            proto_tree_add_item(tree,
                hf_subctrl_udp_mcast_subid_param,
                tvb, offset+6, 2, false);
            break;

        case SUBCTRL_REFRESH_REQUIRED_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_refresh_required_param,
                tvb, offset-2, size+2, false);
            break;

        case SUBCTRL_UDP_UNICAST_ADDR_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_udp_unicast_addr_param,
                tvb, offset, size, false);
            break;

        case SUBCTRL_SUBSCRIPTION_SUMMARY_V2_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_v2_num_param,
                tvb, offset, 3, false);
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_v2_isfilter_param,
                tvb, offset+3, 1, false);
			proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_v2_cid_param,
                tvb, offset+4, 4, false);
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_v2_xpelen_param,
                tvb, offset+8, 2, false);
            proto_tree_add_item(tree,
                hf_subctrl_subscription_summary_v2_lastxpe_param,
                tvb, offset+10, size-10, false);
            break;

        case SUBCTRL_RTR_CAPABILITIES_PARAM:
            clientctrl_dissect_rtr_capabilities_param(tvb, tree, offset, size, false);
            break;

        case SUBCTRL_SOFTWARE_VERSION_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_software_version_param,
                tvb, offset, size, false);
            break;

        case SUBCTRL_SOFTWARE_DATE_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_software_date_param,
                tvb, offset, size, false);
            break;

        case SUBCTRL_PLATFORM_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_platform_param,
                tvb, offset, size, false);
            break;

		case SUBCTRL_CSMP_VRID_PARAM:
            proto_tree_add_item(tree,
                hf_subctrl_csmp_vrid_param,
                tvb, offset, size, false);
            break;

        default:
            proto_tree_add_item(tree,
                hf_subctrl_unknown_param,
                tvb, offset-2, size+2, false);
            break;

    }
}


static int
dissect_subctrl_param(
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
            hf_subctrl_pad_byte, tvb, offset, 1, false);
        return 1;
    }

    param_type = tvb_get_uint8(tvb, offset) & 0x1f;
    param_len  = tvb_get_uint8(tvb, offset+1);

    add_subctrl_param(tvb, tree, param_type, offset, param_len);

    return param_len;
}

static void
dissect_subctrl_params(
    tvbuff_t *tvb, 
    int param_offset_start, 
    int param_offset_end,
    proto_tree *tree)
{
    int offset;

    for (offset=param_offset_start; offset<param_offset_end; )
    {
        int param_len = dissect_subctrl_param(tvb, offset, tree);
        if (0 == param_len) {
            // A param cannot be 0 length. Something went wrong with the dissection. Just exit
            break;
        }
        offset += param_len;
    }
}


/* Code to actually dissect the packets */
static int
dissect_subctrl(
	tvbuff_t *tvb, 
	packet_info *pinfo, 
	proto_tree *tree,
	void* data _U_)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *subctrl_tree;
    int header_len;
	
	/* Silence compiler warning */
	(void)&pinfo;
	

/* Make entries in Protocol column and Info column on summary display */
#if 0
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "subctrl");
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
		ti = proto_tree_add_item(tree, proto_subctrl, tvb, 0, -1, false);

		subctrl_tree = proto_item_add_subtree(ti, ett_subctrl);

        /* Dissect header fields */
		proto_tree_add_item(subctrl_tree,
		    hf_subctrl_version, tvb, 0, 1, false);
        proto_tree_add_item(subctrl_tree,
            hf_subctrl_msg_len, tvb, 1, 2, false);

        /* Dissect parameters */
        header_len = tvb_get_ntohs(tvb, 1) & 0xfff;
        dissect_subctrl_params(tvb, 3, 4*header_len, subctrl_tree);

        /* And that's it! */
	//}
	return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_subctrl(void)
{                 
//	module_t *subctrl_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_subctrl_version,
			{ "Version",           "subctrl.version",
			FT_UINT8, BASE_DEC, NULL, 0x3f,          
			"", HFILL }
		},
		{ &hf_subctrl_msg_len,
			{ "Message length",           "subctrl.msg_len",
			FT_UINT16, BASE_DEC, NULL, 0xfff,          
			"", HFILL }
		},
		{ &hf_subctrl_unknown_param,
			{ "Unrecognized parameter",           "subctrl.unknown_param",
			FT_BYTES, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_pad_byte,
			{ "Pad byte",           "subctrl.pad_byte",
			FT_NONE, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_udp_port_param,
			{ "UDP port",           "subctrl.udp_port",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_udp_mcast_param,
			{ "Use UDP multicast",           "subctrl.use_udp_mcast",
			FT_NONE, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_num_param,
			{ "Subscription summary - # subscriptions",   
            "subctrl.subsum_numsubs",
			FT_UINT24, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_isfilter_param,
			{ "Subscription summary - is filter",           
            "subctrl.subsum_isfilter",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_xpelen_param,
			{ "Subscription summary - XPE length",           
            "subctrl.subsum_xpelen",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_lastxpe_param,
			{ "Subscription summary - last XPE",           
            "subctrl.subsum_lastxpe",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_v2_num_param,
			{ "Subscription summary v2 - # subscriptions",   
            "subctrl.subsum_v2_numsubs",
			FT_UINT24, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_v2_isfilter_param,
			{ "Subscription summary v2 - is filter",           
            "subctrl.subsum_v2_isfilter",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_v2_cid_param,
			{ "Subscription summary v2 - consumer id",           
            "subctrl.subsum_v2_cid",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_v2_xpelen_param,
			{ "Subscription summary v2 - XPE length",           
            "subctrl.subsum_v2_xpelen",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_subscription_summary_v2_lastxpe_param,
			{ "Subscription summary v2 - last XPE",           
            "subctrl.subsum_v2_lastxpe",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_xpe_segment_param,
			{ "XPE segment",           "subctrl.xpe_segment",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_udp_mcast_addr_param,
			{ "UDP multicast address",           "subctrl.udp_mcast_addr",
			FT_IPv4, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_udp_mcast_port_param,
			{ "UDP multicast port",           "subctrl.udp_mcast_port",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_udp_mcast_subid_param,
			{ "UDP multicast subscriber id",  "subctrl.udp_mcast_subid",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_refresh_required_param,
			{ "Refresh required",  "subctrl.refresh_required",
			FT_NONE, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_subctrl_udp_unicast_addr_param,
			{ "UDP unicast address",  "subctrl.udp_unicast_addr",
			FT_IPv4, BASE_NONE, NULL, 0x0,          
			"", HFILL }
		},
                { &hf_subctrl_software_version_param,
                    { "Software Version",         "subctrl.software_version",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_subctrl_software_date_param,
                    { "Software Date",            "subctrl.software_date",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_subctrl_platform_param,
                    { "Platform",           "subctrl.platform",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
        { &hf_subctrl_csmp_vrid_param,
            { "CSMP VRID",            "subctrl.csmp_vrid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "", HFILL }
        }
	};

/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_subctrl
	};

/* Register the protocol name and description */
	proto_subctrl = proto_register_protocol("Subscriber Control",
	    "SubCtrl", "subctrl");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_subctrl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.subctrl", dissect_subctrl, proto_subctrl);
        
#if 0
/* Register preferences module (See Section 2.6 for more on preferences) */
	subctrl_module = prefs_register_protocol(proto_subctrl, 
	    proto_reg_handoff_subctrl);
     
/* Register a sample preference */
	prefs_register_bool_preference(subctrl_module, "showHex", 
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
proto_reg_handoff_subctrl(void)
{
	static bool inited = false;
        
	if (!inited) {

	    //dissector_handle_t subctrl_handle;
	    //subctrl_handle = create_dissector_handle(dissect_subctrl, proto_subctrl);
	    (void)create_dissector_handle(dissect_subctrl, proto_subctrl);
	    //dissector_add("smf.encap_proto", 0x8, subctrl_handle);
        
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
              dissector_delete("tcp.port", currentPort, subctrl_handle);
          }

          currentPort = gPortPref;

          dissector_add("tcp.port", currentPort, subctrl_handle);
            
        */
}
