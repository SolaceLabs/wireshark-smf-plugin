/* packet-smp.c
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

#include "packet-smf.h"

/* Forward declaration we need below */
void proto_reg_handoff_smp(void);

/* Initialize the protocol and registered fields */
static int proto_smp = -1;
static int hf_smp_uh = -1;
static int hf_smp_msg_type = -1;
static int hf_smp_msg_len = -1;
static int hf_smp_payload = -1;

/* Add/Remove Subscription */
static int hf_smp_add_da = -1;
static int hf_smp_add_r = -1;
static int hf_smp_add_t = -1;
static int hf_smp_add_p = -1;
static int hf_smp_add_f = -1;
static int hf_smp_add_subscription = -1;

/* For queue subs */
static int hf_smp_add_queuename = -1;
static int hf_smp_add_clientname = -1;

/* Global sample preference ("controls" display of numbers) */
//static bool gPREF_HEX = false;

/* Initialize the subtree pointers */
static int ett_smp = -1;

#define SMP_ADDSUBSCRIPTION 0x00
#define SMP_REMSUBSCRIPTION 0x01
#define SMP_ADDQUEUESUBSCRIPTION	0x02
#define SMP_REMQUEUESUBSCRIPTION	0x03
#define SMP_ADDSUBSCRIPTIONFORCLIENTNAME 0x04
#define SMP_REMSUBSCRIPTIONFORCLIENTNAME 0x05

static const value_string msgtypenames[] = {
    { SMP_ADDSUBSCRIPTION, "AddSubscription" },
    { SMP_REMSUBSCRIPTION, "RemoveSubscription" },
    { SMP_ADDQUEUESUBSCRIPTION, "AddQueueSubscription" },
    { SMP_REMQUEUESUBSCRIPTION, "RemoveQueueSubscription" },
    { SMP_ADDSUBSCRIPTIONFORCLIENTNAME, "AddSubForClientName" },
    { SMP_REMSUBSCRIPTIONFORCLIENTNAME, "RemoveSubForClientName" },
    { 0x00, NULL }
};


static void dissect_smp_flags(
	tvbuff_t *tvb,
	int offset,
	proto_tree *tree)
{
	proto_tree_add_item(tree,
	    hf_smp_add_da, tvb, offset, 1, false);
	proto_tree_add_item(tree,
	    hf_smp_add_r, tvb, offset, 1, false);
	proto_tree_add_item(tree,
	    hf_smp_add_t, tvb, offset, 1, false);
	proto_tree_add_item(tree,
	    hf_smp_add_p, tvb, offset, 1, false);
	proto_tree_add_item(tree,
	    hf_smp_add_f, tvb, offset, 1, false);

}

static void dissect_smp_add_remove(
								   tvbuff_t *tvb,
								   int offset_start,
								   int offset_end,
								   proto_tree *tree)
{
	int offset = offset_start;
	dissect_smp_flags(tvb, offset, tree);
	offset++;
	proto_tree_add_item(tree,
	    hf_smp_add_subscription, tvb, offset, offset_end - offset, false);
}

static void dissect_smp_add_remove_queue_sub(
								   tvbuff_t *tvb,
								   int offset_start,
								   int offset_end _U_,
								   proto_tree *tree)
{
	int offset = offset_start;
	int qn_len = 0;
	int sn_len = 0;
	dissect_smp_flags(tvb, offset, tree);
	offset++;

	qn_len = tvb_get_uint8(tvb, offset);
	offset++;
	proto_tree_add_item(tree,
	    hf_smp_add_queuename, tvb, offset, qn_len, false);
	offset += qn_len;
	sn_len = tvb_get_uint8(tvb, offset);
	offset++;
	proto_tree_add_item(tree,
	    hf_smp_add_subscription, tvb, offset, sn_len, false);
	

}

static void dissect_smp_add_remove_clientname(
								   tvbuff_t *tvb,
								   int offset_start,
								   int offset_end _U_,
								   proto_tree *tree)
{
	int offset = offset_start;
	int cn_len = 0;
	int sn_len = 0;
	dissect_smp_flags(tvb, offset, tree);
	offset++;

	cn_len = tvb_get_uint8(tvb, offset);
	offset++;
	proto_tree_add_item(tree,
	    hf_smp_add_clientname, tvb, offset, cn_len, false);
	offset += cn_len;
	sn_len = tvb_get_uint8(tvb, offset);
	offset++;
	proto_tree_add_item(tree,
	    hf_smp_add_subscription, tvb, offset, sn_len, false);
	

}


/* Code to actually dissect the packets */
static int
dissect_smp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *smp_tree;
	int msg_len;
	int msg_type;
    //int header_len;
	int msgtype;
	const char *str_msgtype;
	char* str_buffer = (char*)data;

/* Make entries in Protocol column and Info column on summary display */
#if 0
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "smp");
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
		ti = proto_tree_add_item(tree, proto_smp, tvb, 0, -1, false);

		smp_tree = proto_item_add_subtree(ti, ett_smp);

        /* Dissect header fields */
		proto_tree_add_item(smp_tree,
		    hf_smp_uh, tvb, 0, 1, false);
        proto_tree_add_item(smp_tree,
            hf_smp_msg_type, tvb, 0, 1, false);
        proto_tree_add_item(smp_tree,
            hf_smp_msg_len, tvb, 1, 4, false);

		/* Dissect contents */
		msg_len = tvb_get_ntohl(tvb, 1);
		msg_type = tvb_get_uint8(tvb, 0) & 0x7f;
		switch(msg_type)
		{
		case SMP_ADDSUBSCRIPTION:
		case SMP_REMSUBSCRIPTION:
			dissect_smp_add_remove(tvb, 5, msg_len, smp_tree);
			break;
		case SMP_ADDQUEUESUBSCRIPTION:
		case SMP_REMQUEUESUBSCRIPTION:
			dissect_smp_add_remove_queue_sub(tvb, 5, msg_len, smp_tree);
			break;
		case SMP_ADDSUBSCRIPTIONFORCLIENTNAME:
		case SMP_REMSUBSCRIPTIONFORCLIENTNAME:
			dissect_smp_add_remove_clientname(tvb, 5, msg_len, smp_tree);
			break;
		default:
			proto_tree_add_item(smp_tree,
				hf_smp_payload, tvb, 5, msg_len-5, false);
			break;
		}

        /* Dissect parameters */
//        header_len = tvb_get_ntohs(tvb, 1) & 0xfff;
//        dissect_assuredctrl_params(tvb, 3, 4*header_len, assuredctrl_tree);

		/* Figure out type of message and put it on the shared parent info */
		msgtype = (tvb_get_uint8(tvb, 0) & 0x7f);
		str_msgtype = try_val_to_str(msgtype, msgtypenames);

		if (str_msgtype) {
			g_snprintf(str_buffer, 30, " (%s)", str_msgtype);
		} else {
			g_snprintf(str_buffer, 30, " (%s)", "unknown");
		}

        /* And that's it! */
	//}
	return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_smp(void)
{                 
	//module_t *assuredctrl_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_smp_uh,
			{ "UH",           "smp.uh",
			FT_UINT8, BASE_DEC, NULL, 0x80,          
			"", HFILL }
		},
		{ &hf_smp_msg_type,
			{ "Message type",           "smp.msg_type",
			FT_UINT8, BASE_HEX, VALS(msgtypenames), 0x7f,          
			"", HFILL }
		},
		{ &hf_smp_msg_len,
			{ "Message length",           "smp.msg_len",
			FT_UINT32, BASE_DEC, NULL, 0x00,          
			"", HFILL }
		},
        { &hf_smp_payload,
            { "Payload",           "smp.payload",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },

		{ &hf_smp_add_da,
			{ "DeliverAlways",           "smp.da",
			FT_BOOLEAN, 8, NULL, 0x10,          
			"", HFILL }
		},
		{ &hf_smp_add_r,
			{ "ResponseRequired",           "smp.r",
			FT_BOOLEAN, 8, NULL, 0x08,          
			"", HFILL }
		},
		{ &hf_smp_add_t,
			{ "Topic",           "smp.t",
			FT_BOOLEAN, 8, NULL, 0x04,          
			"", HFILL }
		},
		{ &hf_smp_add_p,
			{ "Persist",           "smp.p",
			FT_BOOLEAN, 8, NULL, 0x02,          
			"", HFILL }
		},
		{ &hf_smp_add_f,
			{ "Filter",           "smp.f",
			FT_BOOLEAN, 8, NULL, 0x01,          
			"", HFILL }
		},
        { &hf_smp_add_subscription,
            { "SubscriptionString", "smp.subscription",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_smp_add_queuename,
            { "Queue", "smp.queue",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_smp_add_clientname,
            { "ClientName", "smp.clientname",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
	};

/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_smp
	};

/* Register the protocol name and description */
	proto_smp = proto_register_protocol(
		"Subscription Management Protocol",
	    "SOL-SMP", "sol-smp");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_smp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.smp", dissect_smp, proto_smp);
        
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
proto_reg_handoff_smp(void)
{
	static bool inited = false;
        
	if (!inited) {
	    //dissector_handle_t smp_handle;
	    //smp_handle = create_dissector_handle(dissect_smp, proto_smp);        
	    (void)create_dissector_handle(dissect_smp, proto_smp);
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
