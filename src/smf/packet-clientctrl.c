/* packet-assuredctrl.c
 * Routines for Assured Control dissection
 * Copyright 2007, Solace Corporation 
 *
 * $Id: packet-assuredctrl.c 321 2007-01-24 19:42:21Z $
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
#include "packet-smf.h"

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
/* #include "packet-assuredctrl.h" */

/* Forward declaration we need below */
void proto_reg_handoff_clientctrl(void);

/* Initialize the protocol and registered fields */

/* Header fields */
static int proto_clientctrl = -1;
static int hf_clientctrl_uh = -1;
static int hf_clientctrl_rfu = -1;
static int hf_clientctrl_version = -1;
static int hf_clientctrl_msg_type = -1;
static int hf_clientctrl_msg_len = -1;
static int hf_clientctrl_payload = -1;

/* Parameters */
static int hf_clientctrl_unknown_param = -1;
static int hf_clientctrl_software_version_param = -1;
static int hf_clientctrl_software_date_param = -1;
static int hf_clientctrl_platform_param = -1;
static int hf_clientctrl_userid_param = -1;
static int hf_clientctrl_client_description_param = -1;
static int hf_clientctrl_client_name_param = -1;
static int hf_clientctrl_msgvpn_name_param = -1;
static int hf_clientctrl_deliver_to_one_priority_param = -1;
static int hf_clientctrl_p2p_topic_param = -1;
static int hf_clientctrl_version_str = -1;
static int hf_clientctrl_vrid_name_param = -1;
static int hf_clientctrl_transporttype_param = -1;
static int hf_clientctrl_routername_param = -1;
static int hf_clientctrl_rtr_capabilities_param = -1;
static int hf_clientctrl_bridge_msg_vpn_name_param = -1;
static int hf_clientctrl_bridge_router_name_param = -1;
static int hf_clientctrl_no_local_param = -1;
static int hf_clientctrl_bridge_version_param = -1;
static int hf_clientctrl_authentication_scheme_param = -1;
static int hf_clientctrl_connection_type_param = -1;
static int hf_clientctrl_rtr_capabilities_extended_param = -1;
static int hf_clientctrl_requires_release7_0_param = -1;
static int hf_clientctrl_requested_encoding_param = -1;
static int hf_clientctrl_mqtt_clean_session_type_param = -1;
static int hf_clientctrl_client_capabilities_param = -1;
static int hf_clientctrl_keep_alive_interval_param = -1; 

/* Boolean Router Capabilities */
static int hf_clientctrl_rtr_capabilities_param_num_bool = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_jndi = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_compression = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_sub_flow_gtd = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_temp_endpt = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_pub_flow_gtd = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_browser = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_endpoint_management = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_selector = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_endpoint_message_ttl = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_queue_subscriptions = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_flow_recover = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_subscription_manager = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_message_eliding = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_transacted_sessions = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_no_local = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_flow_change_updates = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_sequenced_topics = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_discard_behaviour = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_cut_through = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_openmama = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_replay = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_compressed_ssl = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_long_selectors = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_shared_subs = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_br_replay_errorid = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_ad_appack_failed = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_var_len_ext_param = -1;
static int hf_clientctrl_rtr_capabilities_param_bool_rfu = -1;
static int hf_clientctrl_rtr_capabilities_param_non_bool = -1;

/* Non-Boolean Router Capabilities */
static int hf_clientctrl_rtr_capabilities_param_port_speed = -1;
static int hf_clientctrl_rtr_capabilities_param_port_type = -1;
static int hf_clientctrl_rtr_capabilities_param_max_gtd_msg_sz = -1;
static int hf_clientctrl_rtr_capabilities_param_max_drct_msg_sz = -1;

/* Non-Boolean Router Capabilities Extended */
static int hf_clientctrl_rtr_capabilities_param_supported_adctrl_versions = -1;
static int hf_clientctrl_rtr_capabilities_param_supported_xactrl_versions = -1;
static int hf_clientctrl_rtr_capabilities_param_supported_adctrl_version_string = -1;
static int hf_clientctrl_rtr_capabilities_param_supported_xactrl_version_string = -1;


/* Client Capabilities */
static int hf_clientctrl_client_capabilities_param_num_bool = -1;
//static int hf_clientctrl_client_capabilities_param_non_bool = -1;
static int hf_clientctrl_client_capabilities_param_bool_unbind_ack = -1;
static int hf_clientctrl_client_capabilities_param_bool_bind_ack_errorId = -1;
static int hf_clientctrl_client_capabilities_param_bool_pq = -1;
static int hf_clientctrl_client_capabilities_param_bool_rd_lt = -1;

/* Global sample preference ("controls" display of numbers) */
//static bool gPREF_HEX = false;

/* Initialize the subtree pointers */
static int ett_clientctrl = -1;
static int ett_clientctrl_rtr_capabilities_param = -1;
static int ett_clientctrl_rtr_capabilities_extended_param = -1;
static int ett_clientctrl_client_capabilities_param = -1;

// ClientCtrl Parameters
#define CLIENTCTRL_SOFTWAREVERSION_PARAM	        0x00
#define CLIENTCTRL_SOFTWAREDATE_PARAM		        0x01
#define CLIENTCTRL_PLATFORM_PARAM		        0x02
#define CLIENTCTRL_USERID_PARAM			        0x03
#define CLIENTCTRL_CLIENTDESCRIPTION_PARAM	        0x04
#define CLIENTCTRL_CLIENTNAME_PARAM		        0x05
#define CLIENTCTRL_MSGVPNNAME_PARAM		        0x06
#define CLIENTCTRL_DELIVERTOONEPRIORITY_PARAM	        0x07
#define CLIENTCTRL_P2PTOPIC_PARAM		        0x08
#define CLIENTCTRL_RTR_CAPABILITIES_PARAM	        0x09
#define CLIENTCTRL_VRID_NAME_PARAM		        0x0a
#define CLIENTCTRL_TRANSPORTTYPE_PARAM	                0x0b
#define CLIENTCTRL_ROUTERNAME_PARAM		        0x0c
#define CLIENTCTRL_BRIDGE_MSG_VPN_NAME_PARAM		0x0d
#define CLIENTCTRL_BRIDGE_ROUTER_NAME_PARAM	    	0x0e
#define CLIENTCTRL_NO_LOCAL_PARAM		        0x0f
#define CLIENTCTRL_BRIDGE_VERSION_PARAM                 0x10
#define CLIENTCTRL_AUTHTICATION_SCHEME_PARAM            0x11
#define CLIENTCTRL_CONNECTION_TYPE_PARAM                0x12
#define CLIENTCTRL_RTR_CAPABILITIES_EXTENDED_PARAM      0x13
#define CLIENTCTRL_REQUIRES_RELEASE7_0_PARAM            0x14
#define CLIENTCTRL_REQUESTED_ENCODING_PARAM             0x15
#define CLIENTCTRL_MQTT_CLEAN_SESSION_TYPE_PARAM        0x16
#define CLIENTCTRL_CLIENT_CAPABILITIES_PARAM            0x17
#define CLIENTCTRL_KEEP_ALIVE_INTERVAL_PARAM            0x18

// Must update this when adding a new clientctrl parameter:
#define LAST_CLIENTCTRL_PARAM			CLIENTCTRL_KEEP_ALIVE_INTERVAL_PARAM

// Non-Boolean Router Capabilities
#define CLIENTCTRL_RTR_CAPABILITIES_PARAM_PORT_SPEED			0x00
#define CLIENTCTRL_RTR_CAPABILITIES_PARAM_PORT_TYPE			0x01
#define CLIENTCTRL_RTR_CAPABILITIES_PARAM_MAX_GUARANTEED_MSG_SIZE	0x02
#define CLIENTCTRL_RTR_CAPABILITIES_PARAM_MAX_DIRECT_MSG_SIZE		0x03

// Must update this when adding a new clientctrl paramter:
#define LAST_RTR_CAP_PARAM             CLIENTCTRL_RTR_CAPABILITIES_PARAM_MAX_DIRECT_MSG_SIZE

// Extended Non-Boolean Router Capabilities
#define CLIENTCTRL_RTR_CAPABILITIES_PARAM_SUPPORTED_ADCTRL_VERSIONS     0x04
#define CLIENTCTRL_RTR_CAPABILITIES_PARAM_SUPPORTED_XACTRL_VERSIONS     0x05

// Must update this when adding a new non-boolean router capabilities parameter:
#define LAST_RTR_CAP_EXT_PARAM		CLIENTCTRL_RTR_CAPABILITIES_PARAM_SUPPORTED_XACTRL_VERSIONS

static const value_string msgtypenames[] = {
    { 0x00, "Login" },
    { 0x01, "Update" },
    { 0x00, NULL }
};

static const value_string authschemenames[] = {
    { 0x01, "Client Certificate" },
    { 0x02, "GSSAPI Kerberos v5" },
    { 0x0a, "OAuth 2.0" },
    { 0x00, NULL }
};

static const value_string connectiontypenames[] = {
    { 0x0, "Basic Connection" },
    { 0x01, "XA Connection" },
    { 0x00, NULL }
};

void clientctrl_dissect_client_capabilities_param(
    tvbuff_t* tvb,
    proto_tree* tree,
    int offset,
    int size,
    bool nonBoolean _U_)
{
//This was written in May 2019. In May 2019, there are no non-boolean client capabilities so this section of
//the program will never be used.
//However, because at some point there probably will be, part of the code that you will probably require is
//written in this function but commented out.
    proto_item*   ti;
    proto_tree*   cap_tree;
    // uint8_t        num_bool_cap;
    // Non-boolean Client Capabilities
    // uint8_t        cap_type;
    // int           num_bool_bytes;
    // int           cap_offset, cap_len, cap_offset_end;
    // int           rtrcaps[LAST_CLIENT_CAP_PARAM + 1];

    // num_bool_cap = tvb_get_uint8(tvb, offset);
    // Non-boolean Client Capabilities
    // num_bool_bytes = (num_bool_cap + 7) / 8;

    //if (nonBoolean) {
        //Non-boolean Client Capabilities
        //ti = proto_tree_add_item(tree, hf_clientctrl_client_capabilities_extended_param, tvb, offset, size, false);
    //}
    //else {
        ti = proto_tree_add_item(tree, hf_clientctrl_client_capabilities_param, tvb, offset, size, false);
    //}

    cap_tree = proto_item_add_subtree(ti, ett_clientctrl_client_capabilities_param);

    proto_tree_add_item(cap_tree, hf_clientctrl_client_capabilities_param_num_bool, tvb, offset, 1, false);
    proto_tree_add_item(cap_tree, hf_clientctrl_client_capabilities_param_bool_unbind_ack, tvb, offset + 1, 1, false);
    proto_tree_add_item(cap_tree, hf_clientctrl_client_capabilities_param_bool_bind_ack_errorId, tvb, offset + 1, 1, false);
    proto_tree_add_item(cap_tree, hf_clientctrl_client_capabilities_param_bool_pq, tvb, offset + 1, 1, false);
    proto_tree_add_item(cap_tree, hf_clientctrl_client_capabilities_param_bool_rd_lt, tvb, offset + 1, 1, false);
}

static void 
add_clientctrl_rtr_cap_extended_param(
    proto_tree    *tree,
    uint8_t        cap_type,
    tvbuff_t*     tvb,
    int           offset)
{
    uint8_t versionFrom = 0;
    uint8_t versionTo = 0;
    
    int rtrcapExtended[LAST_RTR_CAP_EXT_PARAM + 1];
    rtrcapExtended[CLIENTCTRL_RTR_CAPABILITIES_PARAM_SUPPORTED_ADCTRL_VERSIONS] = hf_clientctrl_rtr_capabilities_param_supported_adctrl_version_string;
    rtrcapExtended[CLIENTCTRL_RTR_CAPABILITIES_PARAM_SUPPORTED_XACTRL_VERSIONS] = hf_clientctrl_rtr_capabilities_param_supported_xactrl_version_string;

    const char * strings[LAST_RTR_CAP_EXT_PARAM + 1];
    strings[CLIENTCTRL_RTR_CAPABILITIES_PARAM_SUPPORTED_ADCTRL_VERSIONS] = "AdCtrl";
    strings[CLIENTCTRL_RTR_CAPABILITIES_PARAM_SUPPORTED_XACTRL_VERSIONS] = "XaCtrl";

    versionFrom = tvb_get_uint8(tvb, offset);
    versionTo = tvb_get_uint8(tvb, offset + 1);

    proto_tree_add_string_format(
        tree, rtrcapExtended[cap_type], tvb, offset, 2, NULL,
        "Supported %s Versions: %d-%d", strings[cap_type], versionFrom, versionTo);
}


void
clientctrl_dissect_rtr_capabilities_param(
    tvbuff_t *tvb,
    proto_tree *tree,
    int offset,
    int size,
    bool extended)
{
    proto_item   *ti;
    proto_tree   *cap_tree;
    uint8_t num_bool_cap;
    unsigned int non_bool_cap_type;
    int non_bool_cap_length;
    int non_bool_caps_end;
    int non_bool_cap_offset;
    int	num_bool_bytes = 0;
    int rtrcaps[LAST_RTR_CAP_PARAM + 1];

	num_bool_cap = tvb_get_uint8(tvb, offset);
        if (num_bool_cap > 0) {
            num_bool_bytes = (num_bool_cap - 1) / 8 + 1;
        }

        rtrcaps[CLIENTCTRL_RTR_CAPABILITIES_PARAM_PORT_SPEED] = hf_clientctrl_rtr_capabilities_param_port_speed;
        rtrcaps[CLIENTCTRL_RTR_CAPABILITIES_PARAM_PORT_TYPE] = hf_clientctrl_rtr_capabilities_param_port_type;
        rtrcaps[CLIENTCTRL_RTR_CAPABILITIES_PARAM_MAX_GUARANTEED_MSG_SIZE] = hf_clientctrl_rtr_capabilities_param_max_gtd_msg_sz;
        rtrcaps[CLIENTCTRL_RTR_CAPABILITIES_PARAM_MAX_DIRECT_MSG_SIZE] = hf_clientctrl_rtr_capabilities_param_max_drct_msg_sz;
        
    
    if (extended) {
        ti = proto_tree_add_item(tree, hf_clientctrl_rtr_capabilities_extended_param, tvb, offset, size, false);
        cap_tree = proto_item_add_subtree(ti, ett_clientctrl_rtr_capabilities_extended_param);
    } 
    else {
        ti = proto_tree_add_item(tree, hf_clientctrl_rtr_capabilities_param, tvb, offset, size, false);

        cap_tree = proto_item_add_subtree(ti, ett_clientctrl_rtr_capabilities_param);
    }

    proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_num_bool, tvb, offset, 1, false);

        if (num_bool_bytes >= 1) {
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_jndi, tvb, offset + 1, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_compression, tvb, offset + 1, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_sub_flow_gtd, tvb, offset + 1, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_temp_endpt, tvb, offset + 1, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_pub_flow_gtd, tvb, offset + 1, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_browser, tvb, offset + 1, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_endpoint_management, tvb, offset + 1, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_selector, tvb, offset + 1, 1, false);
        }
        if (num_bool_bytes >= 2) {
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_endpoint_message_ttl, tvb, offset + 2, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_queue_subscriptions, tvb, offset + 2, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_flow_recover, tvb, offset + 2, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_subscription_manager, tvb, offset + 2, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_message_eliding, tvb, offset + 2, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_transacted_sessions, tvb, offset + 2, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_no_local, tvb, offset + 2, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_flow_change_updates, tvb, offset + 2, 1, false);
        }
        if (num_bool_bytes >= 3) {
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_sequenced_topics, tvb, offset + 3, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_discard_behaviour, tvb, offset + 3, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_cut_through, tvb, offset + 3, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_openmama, tvb, offset + 3, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_replay, tvb, offset + 3, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_compressed_ssl, tvb, offset + 3, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_long_selectors, tvb, offset + 3, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_shared_subs, tvb, offset + 3, 1, false);
        }
        if (num_bool_bytes >= 4) {
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_br_replay_errorid, tvb, offset + 4, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_ad_appack_failed, tvb, offset + 4, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_var_len_ext_param, tvb, offset + 4, 1, false);
            proto_tree_add_item(cap_tree, hf_clientctrl_rtr_capabilities_param_bool_rfu, tvb, offset + 4, 1, false);
        }

    if (extended) {
        non_bool_caps_end = offset - 5 + size;
        non_bool_cap_offset = offset + 1 + num_bool_bytes;
        for (; non_bool_cap_offset < non_bool_caps_end;) {
            non_bool_cap_type = tvb_get_uint8(tvb, non_bool_cap_offset);
            non_bool_cap_length = tvb_get_ntohl(tvb, non_bool_cap_offset + 1);
            add_clientctrl_rtr_cap_extended_param(cap_tree, non_bool_cap_type, tvb, non_bool_cap_offset + 5);
            non_bool_cap_offset += non_bool_cap_length;
        }
    }
    else {
        non_bool_caps_end = offset - 5 + size;
        non_bool_cap_offset = offset + 1 + num_bool_bytes;
        for (; non_bool_cap_offset < non_bool_caps_end;) {
            non_bool_cap_type = tvb_get_uint8(tvb, non_bool_cap_offset);
            non_bool_cap_length = tvb_get_ntohl(tvb, non_bool_cap_offset + 1);
            proto_tree_add_item(cap_tree, rtrcaps[non_bool_cap_type], tvb, non_bool_cap_offset + 5, non_bool_cap_length - 5, false);
            non_bool_cap_offset += non_bool_cap_length;
        }
    }
 
}

static void
add_clientctrl_param(
    tvbuff_t *tvb,
    proto_tree *tree,
    uint8_t param_type,
    int offset,
    uint32_t size)
{
	int ccparams[LAST_CLIENTCTRL_PARAM+1];
	uint8_t dto_local_pri;
	uint8_t dto_network_pri;
	char* buffer;
    
	size -= 5;

	ccparams[CLIENTCTRL_SOFTWAREVERSION_PARAM] = hf_clientctrl_software_version_param;
	ccparams[CLIENTCTRL_SOFTWAREDATE_PARAM] = hf_clientctrl_software_date_param;
	ccparams[CLIENTCTRL_PLATFORM_PARAM] = hf_clientctrl_platform_param;
	ccparams[CLIENTCTRL_USERID_PARAM] = hf_clientctrl_userid_param;
	ccparams[CLIENTCTRL_CLIENTDESCRIPTION_PARAM] = hf_clientctrl_client_description_param;
	ccparams[CLIENTCTRL_CLIENTNAME_PARAM] = hf_clientctrl_client_name_param;
	ccparams[CLIENTCTRL_MSGVPNNAME_PARAM] = hf_clientctrl_msgvpn_name_param;
	ccparams[CLIENTCTRL_DELIVERTOONEPRIORITY_PARAM] = hf_clientctrl_deliver_to_one_priority_param;
	ccparams[CLIENTCTRL_P2PTOPIC_PARAM] = hf_clientctrl_p2p_topic_param;
	ccparams[CLIENTCTRL_RTR_CAPABILITIES_PARAM] = hf_clientctrl_rtr_capabilities_param;
	ccparams[CLIENTCTRL_VRID_NAME_PARAM] = hf_clientctrl_vrid_name_param;
	ccparams[CLIENTCTRL_TRANSPORTTYPE_PARAM] = hf_clientctrl_transporttype_param;
	ccparams[CLIENTCTRL_ROUTERNAME_PARAM] = hf_clientctrl_routername_param;
        ccparams[CLIENTCTRL_BRIDGE_MSG_VPN_NAME_PARAM] = hf_clientctrl_bridge_msg_vpn_name_param;
        ccparams[CLIENTCTRL_BRIDGE_ROUTER_NAME_PARAM] = hf_clientctrl_bridge_router_name_param;
        ccparams[CLIENTCTRL_NO_LOCAL_PARAM] = hf_clientctrl_no_local_param;
        ccparams[CLIENTCTRL_BRIDGE_VERSION_PARAM] = hf_clientctrl_bridge_version_param;
        ccparams[CLIENTCTRL_AUTHTICATION_SCHEME_PARAM] = hf_clientctrl_authentication_scheme_param;
	ccparams[CLIENTCTRL_CONNECTION_TYPE_PARAM] = hf_clientctrl_connection_type_param;
        ccparams[CLIENTCTRL_RTR_CAPABILITIES_EXTENDED_PARAM] = hf_clientctrl_rtr_capabilities_extended_param;
        ccparams[CLIENTCTRL_REQUIRES_RELEASE7_0_PARAM] = hf_clientctrl_requires_release7_0_param;
        ccparams[CLIENTCTRL_REQUESTED_ENCODING_PARAM] = hf_clientctrl_requested_encoding_param;
        ccparams[CLIENTCTRL_MQTT_CLEAN_SESSION_TYPE_PARAM] = hf_clientctrl_mqtt_clean_session_type_param;
        ccparams[CLIENTCTRL_CLIENT_CAPABILITIES_PARAM] = hf_clientctrl_client_capabilities_param;
    ccparams[CLIENTCTRL_KEEP_ALIVE_INTERVAL_PARAM] = hf_clientctrl_keep_alive_interval_param;

    switch (param_type)
    {
        case CLIENTCTRL_SOFTWAREVERSION_PARAM:
	case CLIENTCTRL_SOFTWAREDATE_PARAM:
	case CLIENTCTRL_PLATFORM_PARAM:
	case CLIENTCTRL_USERID_PARAM:
	case CLIENTCTRL_CLIENTDESCRIPTION_PARAM:
	case CLIENTCTRL_CLIENTNAME_PARAM:
	case CLIENTCTRL_MSGVPNNAME_PARAM:
	case CLIENTCTRL_P2PTOPIC_PARAM:
	case CLIENTCTRL_VRID_NAME_PARAM:
	case CLIENTCTRL_TRANSPORTTYPE_PARAM:
	case CLIENTCTRL_ROUTERNAME_PARAM:
        case CLIENTCTRL_BRIDGE_MSG_VPN_NAME_PARAM:
        case CLIENTCTRL_BRIDGE_ROUTER_NAME_PARAM:
        case CLIENTCTRL_NO_LOCAL_PARAM:
        case CLIENTCTRL_BRIDGE_VERSION_PARAM:
        case CLIENTCTRL_AUTHTICATION_SCHEME_PARAM:
        case CLIENTCTRL_CONNECTION_TYPE_PARAM:
        case CLIENTCTRL_REQUIRES_RELEASE7_0_PARAM:
        case CLIENTCTRL_REQUESTED_ENCODING_PARAM:
        case CLIENTCTRL_MQTT_CLEAN_SESSION_TYPE_PARAM:
		proto_tree_add_item(tree,
		                    ccparams[param_type],
				    tvb, offset, size, false);
		break;

    	case CLIENTCTRL_RTR_CAPABILITIES_PARAM:
        	clientctrl_dissect_rtr_capabilities_param(tvb, tree, offset, size, false);
        	break;
        case CLIENTCTRL_RTR_CAPABILITIES_EXTENDED_PARAM:
        	clientctrl_dissect_rtr_capabilities_param(tvb, tree, offset, size, true);
        	break;

	case CLIENTCTRL_DELIVERTOONEPRIORITY_PARAM:
		dto_local_pri = tvb_get_uint8(tvb, offset);
		dto_network_pri = tvb_get_uint8(tvb, offset+1);
                buffer = (char*)wmem_alloc(wmem_packet_scope(), 100);
		g_snprintf(buffer, 100, "Local=%d Network=%d", dto_local_pri, dto_network_pri);
		proto_tree_add_string(tree, ccparams[CLIENTCTRL_DELIVERTOONEPRIORITY_PARAM],
                                      tvb, offset, size, buffer);
		break;
        case CLIENTCTRL_CLIENT_CAPABILITIES_PARAM:
                clientctrl_dissect_client_capabilities_param(tvb, tree, offset, size, false);
                break;
    case CLIENTCTRL_KEEP_ALIVE_INTERVAL_PARAM:
        proto_tree_add_item(tree, ccparams[param_type], tvb, offset, size, false);
        break;
    default:
                proto_tree_add_item(tree,
                hf_clientctrl_unknown_param,
                tvb, offset-5, size+5, false);
                break;
    }
}

static int
dissect_clientctrl_param(
    tvbuff_t *tvb, 
    int offset, 
    proto_tree *tree)
{
    uint32_t param_len;
    uint8_t param_type;

    param_type = tvb_get_uint8(tvb, offset) & 0x7f;

	offset++;
    param_len  = tvb_get_ntohl(tvb, offset);
	offset += 4;



    add_clientctrl_param(tvb, tree, param_type, offset, param_len);

    // Checks if param_len less than by how much the offset moves so that it doesn't get stuck in a loop 
    if (param_len < 5){
        param_len = 5;
    }
    return param_len;
}

static void
dissect_clientctrl_params(
    tvbuff_t *tvb, 
    int param_offset_start, 
    int param_offset_end,
    proto_tree *tree)
{
    int offset;

    for (offset=param_offset_start; offset<param_offset_end; )
    {
        int param_len = dissect_clientctrl_param(tvb, offset, tree);
        if (0 == param_len) {
            // A param cannot be 0 length. Something went wrong with the dissection. Just exit
            break;
        }
        offset += param_len;
    }
}

/* Code to actually dissect the packets */
static int
dissect_clientctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data)
{
/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *clientctrl_tree;
	int header_len;
	int msgtype;
	const char *str_msgtype;
	char* str_buffer = (char*)data; /* This is done so that the prototype for dissect_clientctrl 
					 * can match the dissect_t prototype, which will resolve some 
					 * compiler errors. the data passed to dissect_clientctrl from 
					 * packet-smf.c is a char*, so we typecast the void* data back 
					 * to char*. 
					 */

/* Make entries in Protocol column and Info column on summary display */
#if 0
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "assuredctrl");
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
		ti = proto_tree_add_item(tree, proto_clientctrl, tvb, 0, -1, false);

		clientctrl_tree = proto_item_add_subtree(ti, ett_clientctrl);

        /* Dissect header fields */
		proto_tree_add_item(clientctrl_tree,
			hf_clientctrl_uh, tvb, 0, 1, false);
		proto_tree_add_item(clientctrl_tree,
			hf_clientctrl_rfu, tvb, 0, 1, false);
		proto_tree_add_item(clientctrl_tree,
			hf_clientctrl_version, tvb, 0, 1, false);

		proto_tree_add_item(clientctrl_tree,
			hf_clientctrl_msg_type, tvb, 1, 1, false);
		proto_tree_add_item(clientctrl_tree,
			hf_clientctrl_msg_len, tvb, 2, 4, false);

        /* Dissect parameters */
		header_len = tvb_get_ntohl(tvb, 2);

        dissect_clientctrl_params(tvb, 6, header_len, clientctrl_tree);

		/* Figure out type of message and put it on the shared parent info */
		msgtype = tvb_get_uint8(tvb, 1) ;
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
proto_register_clientctrl(void)
{                 
	//module_t *assuredctrl_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {

		{ &hf_clientctrl_uh,
			{ "UH",           "clientctrl.uh",
			FT_UINT8, BASE_DEC, NULL, 0x80,
			"", HFILL }
		},
		{ &hf_clientctrl_rfu,
			{ "RFU",           "clientctrl.rfu",
			FT_UINT8, BASE_DEC, NULL, 0x78,
			"", HFILL }
		},
		{ &hf_clientctrl_version,
			{ "Version",           "clientctrl.version",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			"", HFILL }
		},
		{ &hf_clientctrl_msg_type,
			{ "Message Type",           "clientctrl.msg_type",
			FT_UINT8, BASE_DEC, VALS(msgtypenames), 0xFF,
			"", HFILL }
		},
		{ &hf_clientctrl_msg_len,
			{ "Message length",           "clientctrl.msg_len",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
                { &hf_clientctrl_payload,
                    { "Payload",           "clientctrl.payload",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_software_version_param,
                    { "Software Version",           "clientctrl.software_version",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_software_date_param,
                    { "Software Date",           "clientctrl.software_date",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_platform_param,
                    { "Platform",           "clientctrl.platform",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_userid_param,
                    { "UserId",           "clientctrl.userid",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_client_description_param,
                    { "Client Description",           "clientctrl.client_description",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_client_name_param,
                    { "Client Name",           "clientctrl.client_name",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_msgvpn_name_param,
                    { "MsgVpn",           "clientctrl.msgvpn",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_deliver_to_one_priority_param,
                    { "DTO Priority",           "clientctrl.dto_priority",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_p2p_topic_param,
                    { "P2P Topic",           "clientctrl.p2p_topic",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param,
                    { "Router Capabilities",           "clientctrl.rtr_capabilities",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_vrid_name_param,
                    { "VRID ",           "clientctrl.vrid",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_transporttype_param,
                    { "Transport Type",           "clientctrl.transport_type",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_routername_param,
                    { "Router Name",           "clientctrl.router_name",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_bridge_msg_vpn_name_param,
                    { "BridgeMsgVpnName",           "clientctrl.bridge_msg_vpn_name",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_bridge_router_name_param,
                    { "BridgeRouterName",           "clientctrl.bridge_router_name",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_no_local_param,
                    { "NoLocal",           "clientctrl.nolocal",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_unknown_param,
                    { "Param",           "clientctrl.unknown_param",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_version_str,
                    { "Version",           "clientctrl.version_str",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_bridge_version_param,
                    { "Bridge Version",         "clientctrl.bridge_version",
                    FT_UINT8, BASE_HEX, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_authentication_scheme_param,
                    { "Authentication Scheme",  "clientctrl.authscheme",
                    FT_UINT8, BASE_HEX, VALS(authschemenames), 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_connection_type_param,
                    { "Connection Type",  "clientctrl.connectiontype",
                    FT_UINT8, BASE_HEX, VALS(connectiontypenames), 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_requires_release7_0_param,
                    { "Requires Release 7.0",       "clientctrl.requires_release7_0",
                    FT_NONE, BASE_NONE, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_requested_encoding_param,
                    { "Requested Encoding",         "clientctrl.requested_encoding",
                    FT_UINT8, BASE_HEX, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_mqtt_clean_session_type_param,
                    { "MQTT Clean Session",         "clientctrl.mqtt_clean_session",
                    FT_UINT8, BASE_HEX, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_client_capabilities_param,
                    { "Client Capabilities",        "clientctrl.client_capabilities",
                    FT_UINT8, BASE_HEX, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_client_capabilities_param_num_bool,
                    { "Client Capabilities Num Bools",      "clientctrl.client_capabilities.num_bool",
                    FT_UINT8, BASE_DEC, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_extended_param,
                    { "Router Capabilities (extended)",           "clientctrl.rtr_capabilities",
                    FT_BYTES, BASE_NONE, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_keep_alive_interval_param,
                    { "Keep Alive Interval",        "clientctrl.keep_alive_interval",
                    FT_UINT32, BASE_DEC, NULL, 0x00,
                    "", HFILL}
                },



			        /* CAPABILITIES FOLLOW */

                { &hf_clientctrl_rtr_capabilities_param_num_bool,
                    { "Num Booleans",           "clientctrl.rtr_capabilities.num_bool",
                    FT_UINT8, BASE_DEC, NULL, 0x00,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_jndi,
                    { "JNDI ",  "clientctrl.rtr_capabilities.bool_jndi",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_compression,
                    { "Compression ",  "clientctrl.rtr_capabilities.bool_compression",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_sub_flow_gtd,
                    { "Sub Flow Gtd ",  "clientctrl.rtr_capabilities.bool_sub_flow_gtd",
                    FT_BOOLEAN, 8, NULL, 0x20,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_temp_endpt,
                    { "Temp Endpt ",  "clientctrl.rtr_capabilities.bool_temp_endpt",
                    FT_BOOLEAN, 8, NULL, 0x10,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_pub_flow_gtd,
                    { "Pub Flow Gtd ",  "clientctrl.rtr_capabilities.bool_pub_flow_gtd",
                    FT_BOOLEAN, 8, NULL, 0x08,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_browser,
                    { "Browser ",  "clientctrl.rtr_capabilities.bool_browser",
                    FT_BOOLEAN, 8, NULL, 0x04,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_endpoint_management,
                    { "Endpt Mgmt",  "clientctrl.rtr_capabilities.bool_endpoint_management",
                    FT_BOOLEAN, 8, NULL, 0x02,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_selector,
                    { "Selector ",  "clientctrl.rtr_capabilities.bool_selector",
                    FT_BOOLEAN, 8, NULL, 0x01,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_endpoint_message_ttl,
                    { "Endpoint Message TTL ",  "clientctrl.rtr_capabilities.bool_endpoint_message_ttl",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_queue_subscriptions,
                    { "Queue Subscriptions ",  "clientctrl.rtr_capabilities.bool_queue_subscriptions",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_flow_recover,
                    { "Flow Recover ",  "clientctrl.rtr_capabilities.bool_flow_recover",
                    FT_BOOLEAN, 8, NULL, 0x20,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_subscription_manager,
                    { "Subscription Manager ",  "clientctrl.rtr_capabilities.bool_subscription_manager",
                    FT_BOOLEAN, 8, NULL, 0x10,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_message_eliding,
                    { "Message Eliding ",  "clientctrl.rtr_capabilities.bool_message_eliding",
                    FT_BOOLEAN, 8, NULL, 0x08,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_transacted_sessions,
                    { "Transacted Sessions ",  "clientctrl.rtr_capabilities.bool_transacted_sessions",
                    FT_BOOLEAN, 8, NULL, 0x04,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_no_local,
                    { "NoLocal ",  "clientctrl.rtr_capabilities.bool_no_local",
                    FT_BOOLEAN, 8, NULL, 0x02,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_flow_change_updates,
                    { "Flow Change Updates ",  "clientctrl.rtr_capabilities.bool_flow_change_updates",
                    FT_BOOLEAN, 8, NULL, 0x01,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_sequenced_topics,
                    { "Sequenced Topics ",  "clientctrl.rtr_capabilities.bool_sequenced_topics",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_discard_behaviour,
                    { "Discard Behaviour ",  "clientctrl.rtr_capabilities.bool_discard_behaviour",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_cut_through,
                    { "Cut Through ",  "clientctrl.rtr_capabilities.bool_cut_through",
                    FT_BOOLEAN, 8, NULL, 0x20,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_openmama,
                    { "OpenMAMA ",  "clientctrl.rtr_capabilities.bool_openmama",
                    FT_BOOLEAN, 8, NULL, 0x10,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_replay,
                    { "Replay", "clientctrl.rtr_capabilities.bool_replay",
                    FT_BOOLEAN, 8, NULL, 0x08,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_compressed_ssl,
                    { "Compressed SSL",      "clientctrl.rtr_capabilities.bool_compressed_ssl",
                    FT_BOOLEAN, 8, NULL, 0x04,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_long_selectors,
                    { "Long Selectors",     "clientctrl.rtr_capabilities.bool_long_selectors",
                    FT_BOOLEAN, 8, NULL, 0x02,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_shared_subs,
                    { "Shared Subs",        "clientctrl.rtr_capabilities.bool_shared_subs",
                    FT_BOOLEAN, 8, NULL, 0x01,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_br_replay_errorid,
                    { "BR Replay Error ID", "clientctrl.rtr_capabilities.bool_br_replay_errorid",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_ad_appack_failed,
                    { "Assured Delivery Application ACK Failed", "clientctrl.rtr_capabilities.bool_ad_appack_failed",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_var_len_ext_param,
                    { "Variable Length Extended Parameter", "clientctrl.rtr_capabilities.bool_var_len_ext_param",
                    FT_BOOLEAN, 8, NULL, 0x20,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_bool_rfu,
                    { "Reserved for Future", "clientctrl.rtr_capabilities.rfu",
                    FT_UINT8, BASE_HEX, NULL, 0x1f,
                    "", HFILL}
                },
	        { &hf_clientctrl_rtr_capabilities_param_non_bool,
	            { "Router capability",           "clientctrl.rtr_capabilities",
                    FT_BYTES, BASE_NONE, NULL, 0x0,          
	            "", HFILL }
	        },
                { &hf_clientctrl_rtr_capabilities_param_port_speed,
                    { "Port Speed ",  "clientctrl.rtr_capabilities.port_speed",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_port_type,
                    { "Port Type ",  "clientctrl.rtr_capabilities.port_type",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_max_gtd_msg_sz,
                    { "Max Message Size (Guaranteed) ",  "clientctrl.rtr_capabilities.max_gtd_msg",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_rtr_capabilities_param_max_drct_msg_sz,
                    { "Max Message Size (Direct) ",  "clientctrl.rtr_capabilities.max_drct_msg",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL }
                },
                { &hf_clientctrl_client_capabilities_param_bool_unbind_ack,
                    { "Unbind Ack",                     "clientctrl.client_capabilities.bool_unbind_ack",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL}
                },
                { &hf_clientctrl_client_capabilities_param_bool_bind_ack_errorId,
                    { "Bind Ack Endpoint Error Id",    "clientctrl.client_capabilities.bool_unbind_ack",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL}
                },
                { &hf_clientctrl_client_capabilities_param_bool_pq,
                    { "Partitioned Queue", "clientctrl.client_capabilities.bool_pq",
                    FT_BOOLEAN, 8, NULL, 0x20,
                    "", HFILL}
                },
                { &hf_clientctrl_client_capabilities_param_bool_rd_lt,
                    { "Delayed Redelivery with Local Transactions", "clientctrl.client_capabilities.bool_rd_lt",
                    FT_BOOLEAN, 8, NULL, 0x10,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_supported_adctrl_versions,
                    { "ADCTRL Version",         "clientctrl.rtr_capabilities_extended.adctrl",
                    FT_UINT16, BASE_DEC, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_supported_xactrl_versions,
                    { "XACTRL Version",         "clientctrl.rtr_capabilities_extended.xactrl",
                    FT_UINT16, BASE_DEC, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_supported_xactrl_version_string,
                    { "XACTRL Supported Versions",      "clientctrl.rtr_capabilities_extended.xactrl",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "", HFILL}
                },
                { &hf_clientctrl_rtr_capabilities_param_supported_adctrl_version_string,
                    { "ADCTRL Supported Versions",      "clientctrl.rtr_capabilities_extended.adctrl",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "", HFILL}
                }
	};

/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_clientctrl,
		&ett_clientctrl_rtr_capabilities_param,
                &ett_clientctrl_rtr_capabilities_extended_param,
                &ett_clientctrl_client_capabilities_param
	};

/* Register the protocol name and description */
	proto_clientctrl = proto_register_protocol("ClientCtrl",
	    "ClientCtrl", "clientctrl");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_clientctrl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.clientctrl", dissect_clientctrl, proto_clientctrl);
        
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
proto_reg_handoff_clientctrl(void)
{
	static bool inited = false;
        
	if (!inited) {

	    //dissector_handle_t clientctrl_handle;
	    //clientctrl_handle = create_dissector_handle(dissect_clientctrl, proto_clientctrl);
            (void)create_dissector_handle(dissect_clientctrl, proto_clientctrl);
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
