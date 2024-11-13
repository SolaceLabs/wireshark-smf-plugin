/* packet-smrp.c
 * Subscription Management Routing Protocol Dissector
 * Copyright 2009, Solace Corporation
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
void proto_reg_handoff_smrp(void);

/* Initialize the protocol and registered fields */
static int proto_smrp = -1;
static int hf_smrp_ver = -1;
static int hf_smrp_msg_len = -1;
static int hf_smrp_min_compat_ver = -1;
static int hf_smrp_msg_type = -1;
static int hf_smrp_rfu0 = -1;
static int hf_smrp_rfu1 = -1;
static int hf_smrp_router_name_hash = -1;
static int hf_smrp_db_summary_cs_flag = -1;
static int hf_smrp_db_summary_rfu = -1;
static int hf_smrp_db_summary_rq_flag = -1;
static int hf_smrp_db_summary_num_blocks_in_db = -1;
static int hf_smrp_db_summary_block_summary_cs = -1;
static int hf_smrp_db_summary_num_subs_in_db = -1;
static int hf_smrp_block_summary_rfu = -1;
static int hf_smrp_block_contents_req_block_id = -1;
static int hf_smrp_block_contents_req_rfu0 = -1;
static int hf_smrp_block_contents_req_rfu1 = -1;
static int hf_smrp_block_contents_req_rfu2 = -1;
static int hf_smrp_block_contents_flags = -1;
static int hf_smrp_block_contents_flags_cs = -1;
static int hf_smrp_block_contents_flags_rfu0 = -1;
static int hf_smrp_block_contents_flags_p = -1;
static int hf_smrp_block_contents_flags_rfu1 = -1;
static int hf_smrp_block_contents_flags_u = -1;
static int hf_smrp_block_contents_flags_rfu2 = -1;
static int hf_smrp_block_contents_num_subs_in_block = -1;
static int hf_smrp_block_contents_block_id = -1;
static int hf_smrp_block_contents_block_key = -1;
static int hf_smrp_block_contents_seq_num = -1;
static int hf_smrp_block_contents_msg_vpn_hash = -1;
static int hf_smrp_block_contents_block_cs = -1;
static int hf_smrp_block_contents_rfu = -1;
static int hf_smrp_block_update_pu = -1;
static int hf_smrp_block_update_rfu0 = -1;
static int hf_smrp_block_update_num_adds_in_update = -1;
static int hf_smrp_block_update_num_removes_in_update = -1;
static int hf_smrp_block_update_rfu1 = -1;
static int hf_smrp_parm_bad_format = -1;
static int hf_smrp_parm_router_name = -1;
static int hf_smrp_parm_vpn_name = -1;
static int hf_smrp_parm_block_info = -1;
static int hf_smrp_parm_block_info_block_id = -1;
static int hf_smrp_parm_block_info_block_key = -1;
static int hf_smrp_parm_block_info_seq_num = -1;
static int hf_smrp_parm_block_info_flags_cs = -1;
static int hf_smrp_parm_block_info_flags_rfu0 = -1;
static int hf_smrp_parm_block_info_flags_p = -1;
static int hf_smrp_parm_block_info_flags_rfu1 = -1;
static int hf_smrp_parm_block_info_flags_u = -1;
static int hf_smrp_parm_block_info_num_subs = -1;
static int hf_smrp_parm_block_info_block_cs = -1;
static int hf_smrp_parm_subs_info = -1;
static int hf_smrp_parm_subs_info_flags_r = -1;
static int hf_smrp_parm_subs_info_flags_da = -1;
static int hf_smrp_parm_subs_info_flags_rfu = -1;
static int hf_smrp_parm_subs_info_subs_index = -1;
static int hf_smrp_parm_subs_info_dto_weight = -1;
static int hf_smrp_parm_subs_info_rfu = -1;
static int hf_smrp_parm_subs_info_dto_pri = -1;
static int hf_smrp_parm_subs_info_topic_size = -1;
static int hf_smrp_parm_subs_info_topic_string = -1;
static int hf_smrp_parm_unknown = -1;
     
/* Global sample preference ("controls" display of numbers) */
//static bool gPREF_HEX = false;

/* Initialize the subtree pointers */
static int ett_smrp = -1;

#define SMRP_MSG_HEADER_LEN          36
#define SMRP_DB_SUMMARY_MSG          0x00
#define SMRP_BLOCK_SUMMARY_MSG       0x01
#define SMRP_BLOCK_CONTENTS_MSG      0x02
#define SMRP_BLOCK_UPDATE_MSG        0x03
#define SMRP_BLOCK_CONTENTS_REQ_MSG  0x04
#define SMRP_ROUTER_NAME_PARM        0x00
#define SMRP_VPN_NAME_PARM           0x01
#define SMRP_BLOCK_INFO_PARM         0x02
#define SMRP_SUBS_INFO_PARM          0x03

static const value_string msgtypenames[] = {
    { SMRP_DB_SUMMARY_MSG,         "DB Summary" },
    { SMRP_BLOCK_SUMMARY_MSG,      "Block Summary" },
    { SMRP_BLOCK_CONTENTS_MSG,     "Block Contents" },
    { SMRP_BLOCK_UPDATE_MSG,       "Block Update" },
    { SMRP_BLOCK_CONTENTS_REQ_MSG, "Block Contents Request" },
    { 0x00, NULL }
};

/* Disset a DB Summary message */
static int
dissect_db_summary(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *smrp_tree, int *offset_ptr)
{
  int offset = *offset_ptr;

  if (tvb_captured_length_remaining(tvb, offset) < 12) return -1;

  proto_tree_add_item(smrp_tree, hf_smrp_db_summary_cs_flag, tvb, offset, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_db_summary_rfu, tvb, offset, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_db_summary_rq_flag, tvb, offset, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_db_summary_num_blocks_in_db, tvb, offset+2, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_db_summary_block_summary_cs, tvb, offset+4, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_db_summary_num_subs_in_db, tvb, offset+8, 4, false);
  *offset_ptr = offset+12;

  return 0;
}

/* Disset a Block Summary message */
static int
dissect_block_summary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *smrp_tree, int *offset_ptr)
{
  
  // First part is a db_summary
  if (dissect_db_summary(tvb, pinfo, smrp_tree, offset_ptr) < 0) return -1;

  // offset_ptr is changed by dissect_db_summary
  int offset = *offset_ptr;
  if (tvb_captured_length_remaining(tvb, offset) < 8) return -1;

  proto_tree_add_item(smrp_tree, hf_smrp_block_summary_rfu, tvb, offset, 8, false);
  *offset_ptr = offset+8;

  return 0;
}


/* Disset a Block Contents message */
static int
dissect_block_contents(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *smrp_tree, int *offset_ptr)
{
  int offset = *offset_ptr;

  if (tvb_captured_length_remaining(tvb, offset) < 48) return -1;

  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_block_id, tvb, offset, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_seq_num, tvb, offset+4, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_block_key, tvb, offset+8, 8, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_block_cs, tvb, offset+16, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_flags, tvb, offset+20, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_flags_cs, tvb, offset+20, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_flags_rfu0, tvb, offset+20, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_flags_p, tvb, offset+20, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_flags_rfu1, tvb, offset+20, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_flags_u, tvb, offset+20, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_flags_rfu2, tvb, offset+20, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_num_subs_in_block, tvb, offset+22, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_msg_vpn_hash, tvb, offset+24, 8, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_rfu, tvb, offset+32, 16, false);
  *offset_ptr = offset+48;

  return 0;
}


/* Disset a Block Update message */
static int
dissect_block_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *smrp_tree, int *offset_ptr)
{
  int offset = *offset_ptr;

  // First component is the Block Contents Header. Note that the value of offset gets changed here
  if (dissect_block_contents(tvb, pinfo, smrp_tree, &offset) < 0) return -1;

  // Next dissect the  Block Update Header
  if (tvb_captured_length_remaining(tvb, offset) < 24) return -1;

  proto_tree_add_item(smrp_tree, hf_smrp_block_update_pu, tvb, offset, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_update_rfu0, tvb, offset, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_update_num_adds_in_update, tvb, offset+4, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_update_num_removes_in_update, tvb, offset+6, 2, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_update_rfu1, tvb, offset+8, 16, false);
  *offset_ptr = offset+24;

  return 0;
}


/* Disset a Block Contents Request message */
static int
dissect_block_contents_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *smrp_tree, int *offset_ptr)
{
  int offset = *offset_ptr;

  if (tvb_captured_length_remaining(tvb, offset) < 16) return -1;

  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_req_block_id, tvb, offset, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_req_rfu0, tvb, offset+4, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_req_rfu1, tvb, offset+8, 4, false);
  proto_tree_add_item(smrp_tree, hf_smrp_block_contents_req_rfu2, tvb, offset+12, 4, false);
  *offset_ptr = offset+16;
  return 0;
}

/* Disset the parameters */ 
static int
dissect_smrp_parms(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *smrp_tree, int *offset_ptr)
{
  int offset = *offset_ptr;
  int numParms = -1;
  int parm_len;
  int parm;

  while (tvb_captured_length_remaining(tvb, offset) > 0) {
     // Check whether we can extract the tag and length
     if (tvb_captured_length_remaining(tvb, offset) < 2) return numParms;

     parm = tvb_get_uint8(tvb, offset);
     parm_len = tvb_get_uint8(tvb, offset+1);
     // Check for 
     if (parm_len == 0) {
        if (tvb_captured_length_remaining(tvb, offset) < 6) return numParms;
        parm_len = tvb_get_ntohl(tvb, offset+2);
        parm_len -= 6;
		if (parm_len <= 0) {
			// invalid length
			proto_tree_add_item(smrp_tree, hf_smrp_parm_bad_format, tvb, offset, -1, false);
			return numParms;
		}
        offset += 6;
     } else {
        parm_len -= 2;
        offset += 2;
     }

     // Make sure there is actually enough data
     if (tvb_captured_length_remaining(tvb, offset) < parm_len) {
         proto_tree_add_item(smrp_tree, hf_smrp_parm_bad_format, tvb, offset, -1, false);
         return numParms;
     }

     switch(parm)
     {
     case SMRP_ROUTER_NAME_PARM:
         proto_tree_add_item(smrp_tree, hf_smrp_parm_router_name, tvb, offset, parm_len, false);
         break;

     case SMRP_VPN_NAME_PARM:
         proto_tree_add_item(smrp_tree, hf_smrp_parm_vpn_name, tvb, offset, parm_len, false);
         break;

     case SMRP_BLOCK_INFO_PARM:
         // Min size of the Block Info structure is 24 bytes
         if (parm_len < 24) {
            proto_tree_add_item(smrp_tree, hf_smrp_parm_bad_format, tvb, offset, -1, false);
            break;
         }
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info, tvb, offset, parm_len, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_block_id, tvb, offset, 4, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_seq_num, tvb, offset+4, 4, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_block_key, tvb, offset+8, 8, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_block_cs, tvb, offset+16, 4, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_flags_cs, tvb, offset+20, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_flags_rfu0, tvb, offset+20, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_flags_p, tvb, offset+20, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_flags_rfu1, tvb, offset+20, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_flags_u, tvb, offset+20, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_block_info_num_subs, tvb, offset+22, 2, false);
         break;

     case SMRP_SUBS_INFO_PARM:
         // Min size of the Subscription Info structure is 20 bytes
         if (parm_len < 20) {
            proto_tree_add_item(smrp_tree, hf_smrp_parm_bad_format, tvb, offset, -1, false);
            break;
         }
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info, tvb, offset, parm_len, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_flags_r, tvb, offset, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_flags_da, tvb, offset, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_flags_rfu, tvb, offset, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_subs_index, tvb, offset+2, 2, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_dto_weight, tvb, offset+4, 4, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_rfu, tvb, offset+8, 8, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_dto_pri, tvb, offset+16, 1, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_topic_size, tvb, offset+17, 1, false);
         proto_tree_add_item(smrp_tree, hf_smrp_parm_subs_info_topic_string, tvb, offset+18, parm_len-18, false);
         break;

     default:
         proto_tree_add_item(smrp_tree, hf_smrp_parm_unknown, tvb, offset, parm_len, false);
         break;
     }
     offset += parm_len;
     numParms++;
  }

  return 0;
}

/* Code to actually dissect the SMRP packets */
static int
dissect_smrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *smrp_tree;
    //int msg_len;
    int msg_type;
    int offset;

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

   /* Make entries in Protocol column and Info column on summary display */
    col_append_fstr(pinfo->cinfo, COL_PROTOCOL, " SMRP");

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
        ti = proto_tree_add_item(tree, proto_smrp, tvb, 0, -1, false);

        smrp_tree = proto_item_add_subtree(ti, ett_smrp);

        /* Dissect header fields */
        proto_tree_add_item(smrp_tree, hf_smrp_ver, tvb, 0, 2, false);
        proto_tree_add_item(smrp_tree, hf_smrp_min_compat_ver, tvb, 2, 2, false);
        proto_tree_add_item(smrp_tree, hf_smrp_msg_len, tvb, 4, 4, false);
        proto_tree_add_item(smrp_tree, hf_smrp_rfu0, tvb, 8, 4, false);
        proto_tree_add_item(smrp_tree, hf_smrp_msg_type, tvb, 11, 1, false);
        proto_tree_add_item(smrp_tree, hf_smrp_router_name_hash, tvb, 12, 8, false);
        proto_tree_add_item(smrp_tree, hf_smrp_rfu1, tvb, 20, 16, false);

        /* Dissect contents */
        //msg_len = tvb_get_ntohl(tvb, 4); Commented out on July 24, 2019, since it is not being used. Seemed useful though, so I didn't delete it.
        msg_type = tvb_get_uint8(tvb, 11) & 0x0f;
        offset = SMRP_MSG_HEADER_LEN;

        switch(msg_type)
        {
        case SMRP_DB_SUMMARY_MSG:
            if (dissect_db_summary(tvb, pinfo, smrp_tree, &offset) < 0) return tvb_captured_length(tvb);
            break;

        case SMRP_BLOCK_SUMMARY_MSG:
            if (dissect_block_summary(tvb, pinfo, smrp_tree, &offset) < 0) return tvb_captured_length(tvb);
            break;

        case SMRP_BLOCK_CONTENTS_MSG:
            if (dissect_block_contents(tvb, pinfo, smrp_tree, &offset) < 0) return tvb_captured_length(tvb);
            break;

        case SMRP_BLOCK_UPDATE_MSG:
            if (dissect_block_update(tvb, pinfo, smrp_tree, &offset) < 0) return tvb_captured_length(tvb);
            break;

        case SMRP_BLOCK_CONTENTS_REQ_MSG:
            if (dissect_block_contents_req(tvb, pinfo, smrp_tree, &offset) < 0) return tvb_captured_length(tvb);
            break;

        default:
            break;
        }

        // After the message header will be a number of TLV parameters
        dissect_smrp_parms(tvb, pinfo, smrp_tree, &offset);
    //}
    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_smrp(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_smrp_ver,
            { "Version",           "smrp.ver",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_min_compat_ver,
            { "Min Compatible Version",           "smrp.min_compat_ver",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_msg_len,
            { "Message Length",           "smrp.msg_len",
            FT_UINT32, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_rfu0,
            { "RFU",           "smrp.rfu0",
            FT_UINT32, BASE_HEX, NULL, 0xfff0,          
            "", HFILL }
        },
        { &hf_smrp_msg_type,
            { "Msg Type",           "smrp.msg_types",
            FT_UINT8, BASE_HEX, VALS(msgtypenames), 0x0f,          
            "", HFILL }
        },
        { &hf_smrp_router_name_hash,
            { "Router Name Hash",           "smrp.router_name_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_rfu1,
            { "RFU",           "smrp.rfu1",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_db_summary_cs_flag,
            { "CS Flag",           "smrp.db_summary_cs_flag",
            FT_BOOLEAN, 16, NULL, 0x8000,          
            "", HFILL }
        },
        { &hf_smrp_db_summary_rfu,
            { "RFU",           "smrp.db_summary_rfu",
            FT_UINT16, BASE_HEX, NULL, 0x7ffe,          
            "", HFILL }
        },
        { &hf_smrp_db_summary_rq_flag,
            { "RQ Flag",           "smrp.db_summary_rq_flag",
            FT_BOOLEAN, 16, NULL, 0x0001,          
            "", HFILL }
        },
        { &hf_smrp_db_summary_num_blocks_in_db,
            { "NumBlocksInDb",           "smrp.db_summary_num_blocks_in_db",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_db_summary_block_summary_cs,
            { "BlockSummaryCheckSum",   "smrp.db_summary_block_summary_cs",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_db_summary_num_subs_in_db,
            { "NumSubscriptionsInDb",   "smrp.db_summary_num_subs_in_db",
            FT_UINT32, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_summary_rfu,
            { "RFU",           "smrp.block_summary_rfu",
            FT_UINT64, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_req_block_id,
            { "Block Id",   "smrp.block_contents_req_block_id",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_req_rfu0,
            { "RFU",   "smrp.block_contents_req_rfu0",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_req_rfu1,
            { "RFU",   "smrp.block_contents_req_rfu1",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_req_rfu2,
            { "RFU",   "smrp.block_contents_req_rfu2",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_flags,
            { "Flags",   "smrp.block_contents_flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_flags_cs,
            { "Checksum Present",   "smrp.block_contents_flags_cs",
            FT_BOOLEAN, 16, NULL, 0x8000,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_flags_rfu0,
            { "RFU",   "smrp.block_contents_flags_rfu0",
            FT_BOOLEAN, 16, NULL, 0x6000,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_flags_p,
            { "Persistent Subscriptions",   "smrp.block_contents_flags_p",
            FT_BOOLEAN, 16, NULL, 0x1000,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_flags_rfu1,
            { "RFU",   "smrp.block_contents_flags_rfu1",
            FT_BOOLEAN, 16, NULL, 0x0e00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_flags_u,
            { "Updated by Primary",   "smrp.block_contents_flags_u",
            FT_BOOLEAN, 16, NULL, 0x0100,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_flags_rfu2,
            { "RFU",   "smrp.block_contents_flags_rfu2",
            FT_BOOLEAN, 16, NULL, 0x00ff,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_num_subs_in_block,
            { "NumSubscriptionsInBlock",   "smrp.block_contents_num_subs_in_block",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_block_id,
            { "BlockId",   "smrp.block_contents_block_id",
            FT_UINT16, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_block_key,
            { "BlockKey",   "smrp.block_contents_block_key",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_seq_num,
            { "SeqNum",   "smrp.block_contents_seq_num",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_msg_vpn_hash,
            { "MsgVpnHash",   "smrp.block_contents_msg_vpn_hash",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_block_cs,
            { "BlockChecksum",   "smrp.block_contents_block_cs",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_contents_rfu ,
            { "RFU",   "smrp.block_contents_rfu",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_update_pu ,
            { "Updated by Primary",   "smrp.block_update_pu",
            FT_BOOLEAN, 32, NULL, 0x8000,          
            "", HFILL }
        },
        { &hf_smrp_block_update_rfu0 ,
            { "RFU",   "smrp.block_update_rfu0",
            FT_BOOLEAN, 32, NULL, 0x7fff,          
            "", HFILL }
        },
        { &hf_smrp_block_update_num_adds_in_update ,
            { "NumAddsInUpdate",   "smrp.block_update_num_adds_in_update",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_update_num_removes_in_update ,
            { "NumRemovesInUpdate",   "smrp.block_update_num_removes_in_update",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_block_update_rfu1 ,
            { "RFU",   "smrp.block_update_rfu1",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_bad_format ,
            { "Badly Formated Parameter",   "smrp.parm_bad_format",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_router_name ,
            { "Router Name",   "smrp.parm_router_name",
            FT_STRING, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_vpn_name ,
            { "VPN Name",   "smrp.parm_vpn_name",
            FT_STRING, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info,
            { "Block Info",   "smrp.parm_block_info",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_block_id ,
            { "BlockId",   "smrp.parm_block_info_block_id",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_block_key ,
            { "BlockKey",   "smrp.parm_block_info_block_key",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_seq_num ,
            { "BlockSeqNum",   "smrp.parm_block_info_seq_num",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_flags_cs,
            { "CS Present",   "smrp.parm_block_info_flags_cs",
            FT_BOOLEAN, 16, NULL, 0x8000,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_flags_rfu0 ,
            { "RFU",   "smrp.parm_block_info_flags_rfu0",
            FT_BOOLEAN, 16, NULL, 0x6000,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_flags_p,
            { "Persistent",   "smrp.parm_block_info_flags_p",
            FT_BOOLEAN, 16, NULL, 0x1000,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_flags_rfu1,
            { "RFU",   "smrp.parm_block_info_flags_rfu1",
            FT_BOOLEAN, 16, NULL, 0x0e00,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_flags_u,
            { "Updated by Primary",   "smrp.parm_block_info_flags_u",
            FT_BOOLEAN, 16, NULL, 0x0100,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_num_subs,
            { "NumSubscriptions",   "smrp.parm_block_info_num_subs",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_block_info_block_cs,
            { "BlockChecksum",   "smrp.parm_block_info_block_cs",
            FT_UINT32, BASE_HEX, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info ,
            { "Subscription Info",   "smrp.parm_subs_info",
            FT_BYTES, BASE_NONE, NULL, 0x00,         
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_flags_r ,
            { "Removal",   "smrp.parm_subs_info_flags_r",
            FT_BOOLEAN, 16, NULL, 0x8000,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_flags_da,
            { "Deliver Always",   "smrp.parm_subs_info_flags_da",
            FT_BOOLEAN, 16, NULL, 0x4000,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_flags_rfu ,
            { "RFU",   "smrp.parm_subs_info_flags_rfu",
            FT_BOOLEAN, 16, NULL, 0x3fff,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_subs_index ,
            { "SubscriptionIndex",   "smrp.parm_subs_info_subs_index",
            FT_UINT16, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_dto_weight ,
            { "DTOweight",   "smrp.parm_subs_info_dto_weight",
            FT_UINT32, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_rfu ,
            { "RFU",   "smrp.parm_subs_info_rfu",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_dto_pri ,
            { "DTOpriority",   "smrp.parm_subs_info_dto_pri",
            FT_UINT8, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_topic_size,
            { "TopicSize",   "smrp.parm_subs_info_topic_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_subs_info_topic_string,
            { "Topic",   "smrp.parm_subs_info_topic_string",
            FT_STRING, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
        { &hf_smrp_parm_unknown ,
            { "Unknown Parameter",   "smrp.parm_unknown",
            FT_BYTES, BASE_NONE, NULL, 0x00,          
            "", HFILL }
        },
    };

/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_smrp
    };

/* Register the protocol name and description */
    proto_smrp = proto_register_protocol(
        "Subscription Management Routing Protocol",
        "SMRP", "smrp");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_smrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.smrp", dissect_smrp, proto_smrp);
        
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
proto_reg_handoff_smrp(void)
{
    static bool inited = false;
        
    if (!inited) {
        //dissector_handle_t smrp_handle;
        //smrp_handle = create_dissector_handle(dissect_smrp, proto_smrp);        
        (void)create_dissector_handle(dissect_smrp, proto_smrp);
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
