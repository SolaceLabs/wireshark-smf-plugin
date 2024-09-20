/* packet-smf.c
 * Routines for Solace Message Format dissection
 * Copyright 2007, Solace Corporation
 *
 * $Id: packet-smf.c 657 2007-07-31 20:42:07Z $
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

// NOTE:  See the README.developer file for instructions on modifying the 
// dissector code.

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <wsutil/pint.h>

#include "packet-smf.h"
#include "smf-analysis.h"
#include "sdt-decoder.h"
#include <epan/column-info.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <stdbool.h>
#include <epan/uat-int.h> 
//#include <epan/uat_load.l>

/*
IF PROTO exposes code to other dissectors, then it must be exported
 in a header file. If not, a header file is not needed at all. */
/* #include "packet-smf.h" */

/* Forward declaration we need below */
void proto_reg_handoff_smf(void);
static void smf_proto_init(void);
static void try_load_smf_subdissection_uat(void);

/* Initialize the protocol and registered fields */
static int proto_smf = -1;
static int global_smf_port = 55555;
static int global_smf_rtg_port = 55556;
static bool scan_smf_in_stream = true;

/* Header v3 */

static int hf_smf_di = -1;
static int hf_smf_ee = -1;
static int hf_smf_dto = -1;
static int hf_smf_adf = -1;
static int hf_smf_dmqe = -1;
static int hf_smf_version = -1;
static int hf_smf_uh = -1;
static int hf_smf_encap_protocol = -1;
static int hf_smf_priority = -1;
static int hf_smf_retain = -1;
static int hf_smf_acf = -1;
static int hf_smf_sni = -1;
static int hf_smf_ttl = -1;
static int hf_smf_header_len_v3 = -1;
static int hf_smf_msg_len_v3 = -1;


/* Header v2 */

static int hf_smf_rfu = -1;
static int hf_smf_header_len = -1;
static int hf_smf_msg_len = -1;


/* Standard Parameters */

static int hf_smf_publisherid_param = -1;
static int hf_smf_publisher_msgid_param = -1;
static int hf_smf_message_prio_param = -1;
static int hf_smf_userdata_param = -1;
static int hf_smf_message_id_param = -1;
static int hf_smf_username_param = -1;
static int hf_smf_password_param = -1;
static int hf_smf_response_param = -1;
static int hf_smf_entitlements_param = -1;
static int hf_smf_subscriber_ids_param = -1;
static int hf_smf_generic_attachment_param = -1;
static int hf_smf_binary_attachment_param = -1;
static int hf_smf_originator_address_param = -1;
static int hf_smf_delivery_mode_param = -1;
static int hf_smf_ad_msg_id_param = -1;
static int hf_smf_ad_prev_msg_id_param = -1;
static int hf_smf_ad_redelivered_param = -1;
static int hf_smf_ad_ttl_deprecated_param = -1;
static int hf_smf_ad_ttl_param = -1;
static int hf_smf_retryable_error = -1;
static int hf_smf_message_contents_summary_param = -1;
static int hf_smf_ad_flow_id_param = -1;
static int hf_assuredctrl_flow_id_hidden_param = -1;
static int hf_smf_topic_name_param = -1;
static int hf_smf_ad_flow_redelivered_flag = -1;
static int hf_smf_point_of_entry_unique_id_client_id = -1;
static int hf_smf_point_of_entry_unique_id_ingress_vrid_hash = -1;
static int hf_smf_point_of_entry_unique_id_vpn_name_hash = -1;
static int hf_smf_deliver_always_only = -1;
static int hf_smf_sequence_number_param = -1;


/* Lightweight Parameters */
static int hf_smf_correlation_tag_param = -1;
static int hf_smf_topic_name_offset_param = -1;
static int hf_smf_queue_name_offset_param = -1;
static int hf_smf_ack_immediately_tag_param = -1;
static int hf_smf_header_extension_param = -1;
static int hf_smf_header_extension_param_odf = -1;
static int hf_smf_header_extension_param_fac = -1;
static int hf_smf_header_extension_param_rffu = -1;


/* Extended Parameters */
static int hf_smf_gss_api_token_param = -1;
static int hf_smf_assured_delivery_ack_message_id_param = -1;
static int hf_smf_assured_delivery_trans_id_param = -1;
static int hf_smf_assured_delivery_trans_sr_flag = -1;
static int hf_smf_assured_delivery_trans_pr_flag = -1;

static int hf_smf_assured_delivery_spooler_unique_id = -1;
static int hf_smf_assured_delivery_rep_mate_ack_id = -1;
static int hf_smf_assured_delivery_redelivery_count = -1;
static int hf_smf_assured_delivery_eligible_time = -1;
static int hf_smf_assured_delivery_queued_for_redelivery = -1;

static int hf_smf_oauth_issuer_identifier = -1;
static int hf_smf_openid_connect_id_token = -1;
static int hf_smf_oauth_access_token = -1;

static int hf_smf_trace_span_transport_context_param = -1;

/* Trace Span Context Internal Structure */
static int hf_smf_trace_span_context_struct_version = -1;
static int hf_smf_trace_span_context_struct_sampled_flag = -1;
static int hf_smf_trace_span_context_struct_rfu_flag = -1;
static int hf_smf_trace_span_context_struct_trace_id = -1;
static int hf_smf_trace_span_context_struct_span_id = -1;
static int hf_smf_trace_span_context_struct_injection_standard = -1;
static int hf_smf_trace_span_context_struct_rfu = -1;
static int hf_smf_trace_span_context_struct_trace_state_length = -1;
static int hf_smf_trace_span_context_struct_trace_state = -1;

/* Message Contents Summary Elements */
static int hf_smf_binary_metadata_param = -1;


/* Fragments, Reassembly, Perf Tool */
static int hf_smf_attachment_tooldata = -1;
static int hf_smf_fragment_count = -1;
static int hf_smf_reassembled_length = -1;
static int hf_smf_reassembled_data = -1;
static int hf_smf_fragments = -1;
static int hf_smf_fragment = -1;
static int hf_smf_fragment_overlap = -1;
static int hf_smf_fragment_overlap_conflict = -1;
static int hf_smf_fragment_multiple_tails = -1;
static int hf_smf_fragment_too_long_fragment = -1;
static int hf_smf_fragment_error = -1;
static int hf_smf_reassembled_in = -1;


/*Miscellaneous*/
static int hf_smf_unknown_param = -1;
static int hf_smf_payload = -1;
static int hf_smf_attachment = -1;
static int hf_smf_attachment_sdt = -1;
static int hf_smf_binary_metadata = -1;
static int hf_smf_pad_byte = -1;
static int hf_smf_orig_router_port_param = -1;
static int hf_smf_dest_router_port_param = -1;
static int hf_smf_cidlist_param = -1;
static int hf_smf_originator_port_param = -1;
static int hf_smf_destination_address_param = -1;
static int hf_smf_destination_port_param = -1;
static int hf_smf_topic_name_length_param = -1;
static int hf_smf_queue_name_length_param = -1;
static int hf_smf_metadata_param = -1;
static int hf_smf_xml_payload_param = -1;
static int hf_smf_cid_param = -1;
static int hf_smf_cidlist_size_param = -1;

/* Expert info */
static expert_field ei_trace_span_unsupported_version = EI_INIT;
static expert_field ei_trace_span_invalid_length = EI_INIT;

/* desegmentation of SMF over TCP */
static bool smf_desegment = true;

static bool extractAdMsgId = false;
 
#if 0
/* Global sample preference ("controls" display of numbers) */
static bool gPREF_HEX = false;
#endif

/* Initialize the subtree pointers */
static int ett_smf = -1;
static int ett_message_contents_summary = -1;
static int ett_consumer_id_list = -1;
static int ett_smf_fragments = -1;
static int ett_smf_fragment = -1;
static int ett_attachment_sdt = -1;
static int ett_trace_span_transport_context = -1;


static const fragment_items smf_frag_items =
{
    &ett_smf_fragment,
    &ett_smf_fragments,
    &hf_smf_fragments,
    &hf_smf_fragment,
    &hf_smf_fragment_overlap,
    &hf_smf_fragment_overlap_conflict,
    &hf_smf_fragment_multiple_tails,
    &hf_smf_fragment_too_long_fragment,
    &hf_smf_fragment_error,
    &hf_smf_fragment_count,
    &hf_smf_reassembled_in,
    &hf_smf_reassembled_length,
    &hf_smf_reassembled_data,
    "fragments"
};

/* Value to string conversion tables */
static const value_string uhnames[] =
{
{ 0, "Ignore and discard message" },
{ 1, "Ignore and discard message" },
{ 2, "Ignore and return error" },
{ 3, "Ignore and return error" },
{ 0, NULL } };

/* Minimum SMF Header length */
#define MIN_SMF_HEADER_LEN 12
#define MAX_SMF_HEADER_LEN 100000 // There is no such thing as max header length. But try to reduce error.

/* Maximum SMF Message length */
#define MAX_SMF_MESSAGE_BODY_LEN 64000000

/* Length Check */
#define SMF_LENGTH_CHECK 1
#define SMF_LENGTH_CHECK_NO 0

/* All the SMF-encapsulated protocols we support */
#define SMF_CSPF         0x01
#define SMF_CSMP         0x02
#define SMF_PUBMSG       0x03
#define SMF_XMLLINK      0x04
#define SMF_WSE          0x05
#define SMF_SEMP         0x06
#define SMF_SUBCTRL      0x07
#define SMF_PUBCTRL      0x08
#define SMF_ASSUREDCTRL  0x09
#define SMF_KEEPALIVE    0x0a
#define SMF_KEEPALIVE_V2 0x0b
#define SMF_CLIENTCTRL   0x0c
#define SMF_TRMSG        0x0d
#define SMF_JNDI         0x0e
#define SMF_SMP          0x0f
#define SMF_SMRP         0x10
#define SMF_ENCAP_SMF    0x11
#define SMF_ENCAP_RV     0x12
#define SMF_ASSUREDCTRL_PASSTHRU 0x13
/* Please set the last known protocol to SMF_PROTOCOL_MAX for validation purposes */
#define SMF_PROTOCOL_MAX SMF_ASSUREDCTRL_PASSTHRU

/* Standard Parameter Types */
#define STANDARD_PARAM_PUBLISHER_ID                         0x01
#define STANDARD_PARAM_PUBLISHER_MSG_ID                     0x02
#define STANDARD_PARAM_MESSAGE_PRIORITY                     0x03
#define STANDARD_PARAM_USER_DATA                            0x04
#define STANDARD_PARAM_MESSAGE_ID                           0x05
#define STANDARD_PARAM_USERNAME                             0x06
#define STANDARD_PARAM_PASSWORD                             0x07
#define STANDARD_PARAM_RESPONSE                             0x08
#define STANDARD_PARAM_ENTITLEMENT_LIST                     0x09
#define STANDARD_PARAM_SUBSCRIBER_ID_LIST                   0x0a
#define STANDARD_PARAM_GENERIC_ATTACHMENT                   0x0b
#define STANDARD_PARAM_BINARY_ATTACHMENT                    0x0c
#define STANDARD_PARAM_ORIGINATOR_ADDRESS                   0x0d
#define STANDARD_PARAM_DESTINATION_ADDRESS_LIST             0x0e
#define STANDARD_PARAM_DESTINATION_ADDRESS_AND_PORT_LIST    0x0f
#define STANDARD_PARAM_DEELIVERY_MODE                       0x10
#define STANDARD_PARAM_AD_MESSAGE_ID                        0x11
#define STANDARD_PARAM_AD_PREV_MESSAGE_ID                   0x12
#define STANDARD_PARAM_AD_REDELIVERED_FLAG                  0x13
#define STANDARD_PARAM_AD_TTL_DEPRICATED                    0x14
#define STANDARD_PARAM_AD_DESTINATION_SET                   0x15
#define STANDARD_PARAM_MESSAGE_CONTENTS_SUMMARY             0x16
#define STANDARD_PARAM_AD_FLOW_ID                           0x17
#define STANDARD_PARAM_TOPIC_NAME                           0x18
#define STANDARD_PARAM_AD_FLOW_REDELIVERED_FLAG             0x19
#define STANDARD_PARAM_POINT_OF_ENTRY_UNIQUE_ID             0x1a
#define STANDARD_PARAM_DELIVERY_ALWAYS_ONLY                 0x1b
#define STANDARD_PARAM_AD_TTL                               0x1c
#define STANDARD_PARAM_RETRYABLE_ERROR                      0x1d
#define STANDARD_PARAM_SEQUENCE_NUMBER                      0x1e
#define STANDARD_PARAM_EXTENDED_TYPE_STREAM                 0x1f

/* Lightweight Parameter Types */
#define LIGHTWEIGHT_PARAM_CORRELATION_TAG 0x00
#define LIGHTWEIGHT_PARAM_TOPIC_NAME_OFFSET 0x01
#define LIGHTWEIGHT_PARAM_QUEUE_NAME_OFFSET 0x02
#define LIGHTWEIGHT_PARAM_ACK_IMMEDIATELY 0x03
#define LIGHTWEIGHT_PARAM_HEADER_EXTENSION 0x04

/* Extended Parameters */
#define SMF_EXTENDED_PARAM_GSS_API_TOKEN                        0x28
#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_ACK_MESSAGE_ID      0x29
#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_TRANSACTION_ID      0x2a
#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_TRANSACTION_FLAGS   0x2b

#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_SPOOLER_UNIQUE_ID     0x2c
#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_REP_MATE_ACK_MES_ID   0x2d
#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_REDELIVERY_COUNT      0x2e
#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_ELIGIBLE_TIME         0x32
#define SMF_EXTENDED_PARAM_ASSURED_DELIVERY_QUEUED_FOR_REDELIVERY 0x33

#define SMF_EXTENDED_PARAM_OAUTH_ISSUE_IDENTIFIER                 0X2f
#define SMF_EXTENDED_PARAM_OPENID_CONNECT_ID_TOKEN                0x30
#define SMF_EXTENDED_PARAM_OAUTH_ACCESS_TOKEN                     0x31
#define SMF_EXTENDED_PARAM_TRACE_SPAN_TRANSPORT_CONTEXT           0x36

#define CSV_WRITE_LONG_VALUE(condition, eol, fileName, tvb, offset) \
    if (condition) {\
        FILE* output = fopen(fileName, "a+");\
        fprintf(output, "%d%s", tvb_get_ntohl(tvb, offset), eol? "\n":",");\
        fclose(output);\
    }
#define CSV_WRITE_SHORT_VALUE(condition, eol, fileName, tvb, offset) \
    if (condition) {\
        FILE* output = fopen(fileName, "a+");\
        fprintf(output, "%d%s", tvb_get_ntohs(tvb, offset), eol? "\n":",");\
        fclose(output);\
    }

static const char* default_subdissector_uat_topic = "_telemetry/broker/trace/receive/v1";
static const char* default_subdissector_uat_protocol = "protobuf";
static const char* default_subdissector_uat_extra_data = "message,solace.messaging.proto.broker.trace.receive.v1.SpanData";

/* Maps protocol numbers to protocol names */
static const value_string protocolnames[] =
{
{ SMF_CSPF, "CSPF" },
{ SMF_CSMP, "CSMP" },
{ SMF_PUBMSG, "PubMsg" },
{ SMF_XMLLINK, "XmlLink" },
{ SMF_WSE, "WSE" },
{ SMF_SEMP, "SEMP" },
{ SMF_SUBCTRL, "SubCtrl" },
{ SMF_PUBCTRL, "PubCtrl" },
{ SMF_ASSUREDCTRL, "AssuredCtrl" },
{ SMF_KEEPALIVE, "KeepAlive" },
{ SMF_KEEPALIVE_V2, "KeepAliveV2" },
{ SMF_CLIENTCTRL, "ClientCtrl" },
{ SMF_TRMSG, "TrMsg" },
{ SMF_JNDI, "JNDI" },
{ SMF_SMP, "SMP" },
{ SMF_SMRP, "SMRP" },
{ SMF_ENCAP_SMF, "SMF-Encap SMF: " },
{ SMF_ENCAP_RV, "SMF-Encap RV" },
{ SMF_ASSUREDCTRL_PASSTHRU, "AssuredCtrl PassThru" },
{ 0, NULL } };

/* Maps delivery mode values to names */
static const value_string deliverymodenames[] =
{
{ 0, "non-persistent" },
{ 1, "persistent" },
{ 2, "direct" },
{ 3, "express" },
{ 0, NULL } };

static const value_string trace_span_context_sampled_flag_names[] =
{
{ 0, "Not Sampled" },
{ 1, "Sampled" },
{ 2, "Debug" },
{ 0, NULL } };

static const value_string trace_span_context_injection_standard_names[] =
{
{ 0, "SMF" },
{ 1, "W3C" },
{ 0, NULL } };

/* A structure that keeps track of information parsed from SMF parameters */
struct param_info_t
{
    bool is_response;
    int metadata_start;
    int metadata_length;
    int xml_payload_start;
    int xml_payload_length;
    int attachment_start;
    int attachment_length;
    int cidlist_start;
    int cidlist_length;
    int binary_metadata_start;
    int binary_metadata_length;
    int32_t correlation_tag;
    bool ack_immediately_tag;
};

/* Dissector handles for external dissectors */
static dissector_handle_t xml_handle;
static dissector_handle_t pubctrl_handle;
static dissector_handle_t subctrl_handle;
static dissector_handle_t xmllink_handle;
static dissector_handle_t assuredctrl_handle;
static dissector_handle_t smp_handle;
static dissector_handle_t smrp_handle;
static dissector_handle_t clientctrl_handle;
static dissector_handle_t bm_handle;
static dissector_handle_t mama_payload_handle;
static dissector_handle_t protobuf_handle;
static dissector_handle_t smf_handle;

/* General Reassembly */
static reassembly_table smf_gen_reassembly_table;

static int hf_smf_gen_fragments = -1;
static int hf_smf_gen_fragment = -1;
static int hf_smf_gen_fragment_overlap = -1;
static int hf_smf_gen_fragment_overlap_conflicts = -1;
static int hf_smf_gen_fragment_multiple_tails = -1;
static int hf_smf_gen_fragment_too_long_fragment = -1;
static int hf_smf_gen_fragment_error = -1;
static int hf_smf_gen_fragment_count = -1;
static int hf_smf_gen_reassembled_in = -1;
static int hf_smf_gen_reassembled_length = -1;
//static int hf_smf_gen_segment_data = -1;

static int ett_smf_gen_fragment = -1;
static int ett_smf_gen_fragments = -1;

//static bool isFragmented = false;
//static fragment_head* fd_head = NULL;
//static bool more_frags = false;
//static int total_msg_length = -1;

static const fragment_items smf_gen_frag_items = {
    /* Fragment subtrees */
    &ett_smf_gen_fragment,
    &ett_smf_gen_fragments,
    /* Fragment fields */
    &hf_smf_gen_fragments,
    &hf_smf_gen_fragment,
    &hf_smf_gen_fragment_overlap,
    &hf_smf_gen_fragment_overlap_conflicts,
    &hf_smf_gen_fragment_multiple_tails,
    &hf_smf_gen_fragment_too_long_fragment,
    &hf_smf_gen_fragment_error,
    &hf_smf_gen_fragment_count,
    /* Reassembled in field */
    &hf_smf_gen_reassembled_in,
    /* Reassembled length field */
    &hf_smf_gen_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "SMF Gen fragments"
};

struct bd_reas_info_t
{
    bool inProgress;
    int seqNum;
    int pduLength;
    int curLength;
};

typedef enum _smf_attachment_type {
    _smf_attachment_type_none = 0,
    _smf_attachment_type_sdt,
    _smf_attachment_type_openmama_payload,
} _smf_attachment_type_t;

static struct bd_reas_info_t bdReasInfo[MAX_BD_CHANNEL + 1];

/* User Access Table for subdissection based off topic */
static char* topic_name;

typedef enum {
    MATCH_CRITERIA_EQUAL,
    MATCH_CRITERIA_CONTAINS,
    MATCH_CRITERIA_STARTS_WITH,
    MATCH_CRITERIA_ENDS_WITH,
    MATCH_CRITERIA_REGEX
} smf_subdissection_match_criteria_t;

static const value_string smf_subdissection_match_criteria[] = {
    { MATCH_CRITERIA_EQUAL,       "Equal to" },
    { MATCH_CRITERIA_CONTAINS,    "Contains" },
    { MATCH_CRITERIA_STARTS_WITH, "Starts with" },
    { MATCH_CRITERIA_ENDS_WITH,   "Ends with" },
    { MATCH_CRITERIA_REGEX,       "Regular Expression" },
    { 0, NULL }
};

typedef struct {
    smf_subdissection_match_criteria_t match_criteria;
    char* topic_pattern;
    GRegex* topic_regex;
    char* payload_proto_name;
    dissector_handle_t payload_proto;
    char* proto_more_info;
} smf_subdissection_uat_entry_t;

static smf_subdissection_uat_entry_t* smf_subdissection_uat_entries = NULL;
static unsigned int num_smf_subdissection_uat_entries;
static bool smf_subdissection_uat_loaded = 0;
static uat_t* smf_subdissection_uat = NULL;

static void* smf_subdissection_uat_entry_copy_cb(void* dest, const void* orig, size_t len _U_)
{
    const smf_subdissection_uat_entry_t* o = (const smf_subdissection_uat_entry_t*)orig;
    smf_subdissection_uat_entry_t* d = (smf_subdissection_uat_entry_t*)dest;

    d->match_criteria = o->match_criteria;
    d->topic_pattern = g_strdup(o->topic_pattern);
    d->payload_proto_name = g_strdup(o->payload_proto_name);
    d->payload_proto = o->payload_proto;
    d->proto_more_info = g_strdup(o->proto_more_info);

    return d;
}

static bool smf_subdissection_uat_entry_update_cb(void* record, char** error)
{
    smf_subdissection_uat_entry_t* u = (smf_subdissection_uat_entry_t*)record;

    if (u->topic_pattern == NULL || strlen(u->topic_pattern) == 0) {
        *error = g_strdup("Missing topic pattern");
        return false;
    }

    if (u->payload_proto_name == NULL || strlen(u->payload_proto_name) == 0) {
        *error = g_strdup("Missing payload protocol");
        return false;
    }

    if (u->match_criteria == MATCH_CRITERIA_REGEX) {
        u->topic_regex = g_regex_new(u->topic_pattern, (GRegexCompileFlags)G_REGEX_OPTIMIZE, (GRegexMatchFlags)0, NULL);
        if (!u->topic_regex) {
            *error = g_strdup_printf("Invalid regex: %s", u->topic_pattern);
            return false;
        }
    }

    return true;
}

static void smf_subdissection_uat_entry_free_cb(void* record)
{
    smf_subdissection_uat_entry_t* u = (smf_subdissection_uat_entry_t*)record;

    g_free(u->topic_pattern);
    if (u->topic_regex) {
        g_regex_unref(u->topic_regex);
    }
    g_free(u->payload_proto_name);
    g_free(u->proto_more_info);
}

static const smf_subdissection_uat_entry_t*
get_subdissector_from_uat(const char* topic)
{
    smf_subdissection_uat_entry_t* uat_entry = NULL;
    size_t topic_str_len;
    size_t topic_pattern_len;
    bool match_found = false;

    for (unsigned int i = 0; i < num_smf_subdissection_uat_entries; i++) {
        uat_entry = &smf_subdissection_uat_entries[i];
        switch (uat_entry->match_criteria) {

        case MATCH_CRITERIA_EQUAL:
            match_found = (strcmp(topic, uat_entry->topic_pattern) == 0);
            break;

        case MATCH_CRITERIA_CONTAINS:
            match_found = (strstr(topic, uat_entry->topic_pattern) != NULL);
            break;

        case MATCH_CRITERIA_STARTS_WITH:
            topic_str_len = strlen(topic);
            topic_pattern_len = strlen(uat_entry->topic_pattern);
            match_found = ((topic_str_len >= topic_pattern_len) &&
                (strncmp(topic, uat_entry->topic_pattern, topic_pattern_len) == 0));
            break;

        case MATCH_CRITERIA_ENDS_WITH:
            topic_str_len = strlen(topic);
            topic_pattern_len = strlen(uat_entry->topic_pattern);
            match_found = ((topic_str_len >= topic_pattern_len) &&
                (strcmp(topic + (topic_str_len - topic_pattern_len), uat_entry->topic_pattern) == 0));
            break;

        case MATCH_CRITERIA_REGEX:
            if (uat_entry->topic_regex) {
                GMatchInfo* match_info = NULL;
                g_regex_match(uat_entry->topic_regex, topic, (GRegexMatchFlags)0, &match_info);
                match_found = g_match_info_matches(match_info);
                g_match_info_free(match_info);
            }
            break;

        default:
            /* Unknown match criteria */
            break;
        }

        if (match_found) {
            return uat_entry;
        }
    }

    return NULL;
}

static int
smf_call_subdissector(const smf_subdissection_uat_entry_t* subdissector, tvbuff_t* next_tvb, packet_info* pinfo, proto_tree* tree)
{
    return call_dissector_only(subdissector->payload_proto, next_tvb, pinfo, tree, subdissector->proto_more_info);
}

UAT_VS_DEF(smf_subdissection, match_criteria, smf_subdissection_uat_entry_t, smf_subdissection_match_criteria_t, MATCH_CRITERIA_EQUAL, "Equal to")
UAT_CSTRING_CB_DEF(smf_subdissection, topic_pattern, smf_subdissection_uat_entry_t)
UAT_DISSECTOR_DEF(smf_subdissection, payload_proto, payload_proto, payload_proto_name, smf_subdissection_uat_entry_t)
UAT_CSTRING_CB_DEF(smf_subdissection, proto_more_info, smf_subdissection_uat_entry_t)

/* reassembly table used for calls into reassemble.h */
static reassembly_table reasTable;
static dissector_table_t smf_payload_dissector_table;

/* This is a helper function to prevent the sub-dissector from change to the protocol_column caused by the dissector. */
static int call_dissector_no_protocol_change(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree) {
    int rc;
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, false);
    rc = call_dissector(handle, tvb, pinfo, tree);
    col_set_writable(pinfo->cinfo, COL_PROTOCOL, true);
    return rc;
}
 
/* Initialise the reassembly table */
static void smf_reas_init(void)
{
    int i;

    reassembly_table_init(&reasTable,
                       &addresses_reassembly_table_functions);

    for (i = 0; i <= MAX_BD_CHANNEL; i++)
    {
        bdReasInfo[i].inProgress = false;
        bdReasInfo[i].seqNum = 0;
        bdReasInfo[i].pduLength = 0;
        bdReasInfo[i].curLength = 0;
    }
}
/*
static bool smf_reas_in_progress(int bdChannel)
{
    if (bdChannel > MAX_BD_CHANNEL)
        return false;
    return bdReasInfo[bdChannel].inProgress;
}
*/
static void stop_smf_reas(int bdChannel)
{
    if (bdChannel > MAX_BD_CHANNEL)
        return;
    bdReasInfo[bdChannel].inProgress = false;
    bdReasInfo[bdChannel].seqNum = 0;
    return;
}

static void start_smf_reas(tvbuff_t *tvb, packet_info *pinfo _U_, int bdChannel,
    int pduLength)
{
    if (bdChannel > MAX_BD_CHANNEL)
        return;
//    if (!tvb || !pinfo) return;  // get rid of warning...
    bdReasInfo[bdChannel].inProgress = true;
    bdReasInfo[bdChannel].seqNum = 0;
    bdReasInfo[bdChannel].curLength = tvb_reported_length_remaining(tvb, 0);
    bdReasInfo[bdChannel].pduLength = pduLength;
    return;
}

static bool smf_reas_add_fragment(int bdChannel, tvbuff_t *tvb,
    packet_info *pinfo _U_, int * seqNum)
{
    if (bdChannel > MAX_BD_CHANNEL)
        return false;
    bdReasInfo[bdChannel].seqNum += 1;
    *seqNum = bdReasInfo[bdChannel].seqNum;
    bdReasInfo[bdChannel].curLength += tvb_reported_length_remaining(tvb, 0);
    return (bdReasInfo[bdChannel].curLength < bdReasInfo[bdChannel].pduLength);
}

static int get_smf_bd_channel(packet_info *pinfo)
{
    uint16_t bdchannel;
    uint8_t direction;
    void *bdchannelPtr;

    if (!pinfo)
        return -1;
    if (pinfo->dl_src.len != 6)
        return -1;
    /* Channel number is least significant 10 bits of Ethernet source address */
    // return  ((uint8_t*)(pinfo->dl_src.data)[5]) + ((uint8_t*)((pinfo->dl_src.data)[4] & 0x3) << 8);
    bdchannelPtr = &bdchannel;
    memcpy(bdchannelPtr, (char*) (pinfo->dl_src.data) + 4, 2);
    bdchannel = pntoh16(&bdchannel);
    bdchannel &= 0x3ff;
    memcpy(&direction, (char*) (pinfo->dl_src.data) + 3, 1);
    return (direction == 0xcc) ? bdchannel : bdchannel | 0x400;
}

/* if we return 0, it means the current PDU is deferred until we
* get the next packet.
* If we return 1 (or anything less then the fix offset,
* it means the current PDU is an error and we will be marked as error
* and we move on to the next packet.
* If everything is OK return the length of the smf message
*/
static uint32_t test_smf(tvbuff_t *tvb, packet_info* pinfo, int offset)
{
    // If the remaining length is less then MIN_SMF_HEADER_LEN, we do not have enough to test
    int remainingLength = tvb_captured_length(tvb) - offset;
    if (remainingLength < MIN_SMF_HEADER_LEN)
    {
        if (pinfo->can_desegment) {
            return 0;
        } else {
            // Less than MIN_SMF_HEADER_LEN bytes of data, just junk it
            return 1;
        }
    }
    // Check SMF version
    uint8_t firstByte = tvb_get_uint8(tvb, offset);
    if ((firstByte & 0x07) != 0x03)
    {
        return 1;
    }
    // Check protocol
    uint8_t secondByte = tvb_get_uint8(tvb, offset+1);
    uint8_t smfProtocol = secondByte & 0x3f;
    if (smfProtocol > SMF_PROTOCOL_MAX)
    {
        return 1;
    }
    // Detect obsolete protocols 
    switch (smfProtocol) {
    case SMF_CSMP:
    case SMF_PUBMSG:
    case SMF_XMLLINK:
    case SMF_WSE:
    case SMF_SUBCTRL:
    case SMF_PUBCTRL:
    case SMF_KEEPALIVE:
        return 1;
    default:
        break;
    }
    uint32_t headerlen = tvb_get_ntohl(tvb, offset + 4);
    uint32_t msglen = tvb_get_ntohl(tvb, offset + 8);
    if (headerlen < MIN_SMF_HEADER_LEN) {
        return 1;
    }
    if (headerlen > MAX_SMF_HEADER_LEN) {
        return 1;
    }
    if (headerlen > MAX_SMF_MESSAGE_BODY_LEN) {
        return 1;
    }
    if (headerlen > msglen) {
        // Something is definitely wrong with the message
        return 1;
    }
    if ((msglen - headerlen) > MAX_SMF_MESSAGE_BODY_LEN) {
        // msgLen - headerlen is the size of the message body.
        // The message is too big.
        return 1;
    }
    
    return msglen;
}

/* Determine the total length of an SMF packet, given the first 8 or 12 bytes */
static unsigned int get_smf_pdu_len(packet_info* inf, tvbuff_t *tvb, int offset, void *randomPointer _U_)
{
    /* msglen initialze to 1 because
     * if we return 0, it means the current PDU is deferred until we
     * get the next packet.
     * If we return 1 (or anything less then the fix offset,
     * it means the current PDU is an error and we will be marked as error
     * and we move on to the next packet.
     */
    uint32_t msglen = test_smf(tvb, inf, offset);

    if (msglen == 1) {
        // Packet is not valid. One possibility is that the packet capture not done at from the beginning.
        // As SMF could start somewhere inside a TCP packet, we look for the next potential starting point
        if (scan_smf_in_stream) {
            unsigned int captured_length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);
            // Start from the MIN_SMF_HEADER_LEN byte. Returning anything less than MIN_SMF_HEADER_LEN is an error
            uint32_t index = offset + MIN_SMF_HEADER_LEN;
            uint32_t found = 0;
            // The reason for not checking the last 12 bytes of the packet is because it would trigger some 
            // other errors in decoding. The exact reason has not been studied.
            while (!found && ((index + MIN_SMF_HEADER_LEN) < captured_length_remaining) ) {
                if (test_smf(tvb, inf, index) != 1) {
                    // Found a good starting point. Indicate that our current smf message ends there.
                    msglen = index;
                    found = 1;
                    break;
                }
                index++;
            }
        }
    }

    /* Eliminate compiler warning */
    (void) &inf;

    return msglen;
}

/* Add a base-64 encoded string to the tree */
static void smf_proto_add_base64_string(proto_tree *tree, packet_info *pinfo, int id, tvbuff_t *tvb,
    int offset, int size)
{
    char* str;
   
    str = tvb_get_string_enc(NULL, tvb, offset, size, ENC_ASCII);
    if (size > 1) {
        if (strlen(str) > 1) {
            gsize len = size; // This is for type conversion, g_base64_decode_inplace wants gsize for len
            g_base64_decode_inplace(str, &len);
            str[len] = '\0'; // We now have a base64 decode string, let us null terminate it.
            size = len;
        } else {
            g_print("invalid base64 string found in packet %d, strlen is < 1", pinfo->fd->num);
        }
    }
    proto_tree_add_string(tree, id, tvb, offset, size, str);
}

/* Add an SMF username to the tree */
static void smf_proto_add_username_item(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
    int offset, int size)
{
    smf_proto_add_base64_string(tree, pinfo, hf_smf_username_param, tvb, offset, size);
}

/* Add an SMF password to the tree */
static void smf_proto_add_password_item(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
    int offset, int size)
{
    smf_proto_add_base64_string(tree, pinfo, hf_smf_password_param, tvb, offset, size);
}

/* Add an SMF response to the tree */
static void smf_proto_add_response_item(proto_tree *tree, tvbuff_t *tvb,
    int offset, int size)
{
    char* buffer;
    uint32_t code;
    char* str;

    /* Get the response code and string */
    code = tvb_get_ntohl(tvb, offset);
    str = tvb_get_string_enc(NULL, tvb, offset + 4, size - 4, ENC_ASCII);

    /* Format it like "200 OK" */
    buffer = (char*)wmem_alloc(wmem_packet_scope(), 300);
    g_snprintf(buffer, 300, "%d %s", code, str);

    /* Add the string to the tree */
    proto_tree_add_string(tree, hf_smf_response_param, tvb, offset, size,
        buffer);

}

/* Add a router id (addr, port) to the tree */
/*
static void smf_proto_add_router_id_item(proto_tree *tree, int id1, int id2,
    tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(tree, id1, tvb, offset + 3, 4, false);
    proto_tree_add_item(tree, id2, tvb, offset + 7, 2, false);
}
*/
/* Add an list of UINT16s to the tree */
static void smf_proto_add_uint16_list_item(proto_tree *tree, int id,
    tvbuff_t *tvb, int offset, int size)
{
    int i;
    char* buffer;
    uint16_t list_item;

    buffer = (char*)wmem_alloc(wmem_packet_scope(), 510);
    buffer[0] = '\0';
    for (i = 0; i < size; i += 2)
    {
        list_item = tvb_get_ntohs(tvb, offset + i);
        g_snprintf(buffer, 510, "%s %d", buffer, list_item);
    }

    proto_tree_add_string(tree, id, tvb, offset, size, buffer);

}

/* Add an entitlement list to the tree */
static void smf_proto_add_enttl_list_item(proto_tree *tree, tvbuff_t *tvb,
    int offset, int size)
{
    smf_proto_add_uint16_list_item(tree, hf_smf_entitlements_param, tvb, offset,
        size);
}

/* Add a subscriber id list to the tree */
static void smf_proto_add_subid_list_item(proto_tree *tree, tvbuff_t *tvb,
    int offset, int size)
{
    smf_proto_add_uint16_list_item(tree, hf_smf_subscriber_ids_param, tvb,
        offset, size);
}

/* Add a list of 32-bit items to the tree */
static void smf_proto_add_uint32_list_item(proto_tree *tree, int id,
    tvbuff_t * tvb, int offset, int size)
{
    int i;
    for (i = 0; i < size; i += 4)
    {
        proto_tree_add_item(tree, id, tvb, offset + i, 4, false);
    }
}

static void smf_proto_add_destination_list_item(proto_tree *tree, tvbuff_t *tvb,
    int offset, int size)
{
    smf_proto_add_uint32_list_item(tree, hf_smf_destination_address_param, tvb,
        offset, size);
}

static void smf_proto_add_cid_list_item(proto_tree *tree, tvbuff_t *tvb,
    int offset, int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_smf_cidlist_param, tvb, offset, size,
        false);

    sub_tree = proto_item_add_subtree(item, ett_consumer_id_list);

    smf_proto_add_uint32_list_item(sub_tree, hf_smf_cid_param, tvb, offset,
        size);
}

/* Add a list of IP addresses and ports to the tree */
static void smf_proto_add_ip_address_and_port_list_item(proto_tree *tree,
    int id1, int id2, tvbuff_t *tvb, int offset, int size)
{
    int i;
    for (i = 0; i < size; i += 6)
    {
        /* Add the address */
        proto_tree_add_item(tree, id1, tvb, offset + i, 4, false);
        /* Add the port */
        proto_tree_add_item(tree, id2, tvb, offset + i + 4, 2, false);
    }
}

/* Add a list of IP addresses, ports, and message ids to the tree */
static void smf_proto_add_ip_address_port_and_msgid_list_item(proto_tree *tree,
    int id1, int id2, int id3, tvbuff_t *tvb, int offset, int size)
{
    int i;
    for (i = 0; i < size; i += 14)
    {
        /* Add the address */
        proto_tree_add_item(tree, id1, tvb, offset + i, 4, false);
        /* Add the port */
        proto_tree_add_item(tree, id2, tvb, offset + i + 4, 2, false);
        /* Add the msgid */
        proto_tree_add_item(tree, id3, tvb, offset + i + 6, 8, false);
    }
}

/* Add a destination address and port list item to the tree */
static void smf_proto_add_destination_address_and_port_list_item(
    proto_tree *tree, tvbuff_t *tvb, int offset, int size)
{
    smf_proto_add_ip_address_and_port_list_item(tree,
        hf_smf_destination_address_param, hf_smf_destination_port_param, tvb,
        offset, size);
}

/* Add a destination set item to the tree */
static void smf_proto_add_ad_destination_set_item(proto_tree *tree,
    tvbuff_t *tvb, int offset, int size)
{
    smf_proto_add_ip_address_port_and_msgid_list_item(tree,
        hf_smf_destination_address_param, hf_smf_destination_port_param,
        hf_smf_ad_prev_msg_id_param, tvb, offset, size);
}

/* Add a variable-size element */
static int smf_proto_add_variable_size_item(proto_tree* tree, tvbuff_t* tvb,
    int offset, int len, int hfindex)
{
    int retval = 0;
    if (tree)
    {
        proto_tree_add_item(tree, hfindex, tvb, offset, len, false);
    }
    switch (len)
    {
        case 1:
            retval = tvb_get_uint8(tvb, offset);
            break;
        case 2:
            retval = tvb_get_ntohs(tvb, offset);
            break;
        case 3:
            retval = tvb_get_ntoh24(tvb, offset);
            break;
        case 4:
            retval = tvb_get_ntohl(tvb, offset);
            break;
    }

    return retval;
}

/* Add a message contents summary item to the tree */
static void smf_proto_add_message_contents_summary_item(proto_tree *tree,
    tvbuff_t *tvb, int offset, int size, struct param_info_t* param_info_p)
{
    uint8_t type;
    uint8_t len;
    int current_size = 0;
    int cumulative_size = 0;
    proto_tree* sub_tree;
    proto_item* item;
    int i;

    /* Zero out the xml payload length.  If there is no XML payload section in
     the message contents summary, then there is no XML payload.  If, however,
     there is an XML payload section, the length will be reset later.
     */
    param_info_p->xml_payload_length = 0;
    param_info_p->attachment_length = 0;

    item = proto_tree_add_item(tree, hf_smf_message_contents_summary_param, tvb,
        offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_message_contents_summary);

    for (i = 2; i < size; i += len)
    {
        type = (tvb_get_uint8(tvb, offset + i) & 0xF0) >> 4;
        len = tvb_get_uint8(tvb, offset + i) & 0x0F;
        if (len < 2)
            len = 2;

        switch (type)
        {
            case 0x0:
                current_size = smf_proto_add_variable_size_item(sub_tree, tvb,
                    offset + i + 1, len - 1, hf_smf_metadata_param);
                param_info_p->metadata_start = cumulative_size;
                param_info_p->metadata_length = current_size;
                cumulative_size += current_size;
                break;

            case 0x1:
                current_size = smf_proto_add_variable_size_item(sub_tree, tvb,
                    offset + i + 1, len - 1, hf_smf_xml_payload_param);
                param_info_p->xml_payload_start = cumulative_size;
                param_info_p->xml_payload_length = current_size;
                cumulative_size += current_size;
                break;

            case 0x2:
                current_size = smf_proto_add_variable_size_item(sub_tree, tvb,
                    offset + i + 1, len - 1, hf_smf_binary_attachment_param);
                param_info_p->attachment_start = cumulative_size;
                param_info_p->attachment_length = current_size;
                cumulative_size += current_size;
                break;

            case 0x3:
                current_size = smf_proto_add_variable_size_item(sub_tree, tvb,
                    offset + i + 1, len - 1, hf_smf_cidlist_size_param);
                param_info_p->cidlist_start = cumulative_size;
                param_info_p->cidlist_length = current_size;
                cumulative_size += current_size;
                break;

            case 0x4:
                current_size = smf_proto_add_variable_size_item(sub_tree, tvb,
                    offset + i + 1, len - 1, hf_smf_binary_metadata_param);
                param_info_p->binary_metadata_start = cumulative_size;
                param_info_p->binary_metadata_length = current_size;
                cumulative_size += current_size;
                break;

            default:
                proto_tree_add_item(sub_tree, hf_smf_unknown_param, tvb,
                    offset + i, len, false);
                break;
        }
    }
}

static void smf_proto_add_trace_span_transport_context_value_v1(proto_tree *tree, packet_info* pinfo,
        tvbuff_t *tvb, int offset, int size)
{
    if (size < 32) {
        expert_add_info_format(pinfo, proto_tree_get_parent(tree), &ei_trace_span_invalid_length,
            "Length must be >=32. Length was %i.", size);
        return;
    }

    int trace_state_len =  (int)tvb_get_ntohs(tvb, offset+30);
    if (size != trace_state_len + 32) {
        expert_add_info_format(pinfo, proto_tree_get_parent(tree), &ei_trace_span_invalid_length,
            "Length Error. Given size was %i, but calculated size was %i.", size, trace_state_len + 32);
        return;
    }

    proto_tree_add_item(tree, hf_smf_trace_span_context_struct_sampled_flag,
            tvb, offset, 1, false);
    proto_tree_add_item(tree, hf_smf_trace_span_context_struct_rfu_flag,
            tvb, offset, 1, false);
    proto_tree_add_item(tree, hf_smf_trace_span_context_struct_trace_id,
            tvb, offset+1, 16, false);
    proto_tree_add_item(tree, hf_smf_trace_span_context_struct_span_id,
            tvb, offset+17, 8, false);
    proto_tree_add_item(tree, hf_smf_trace_span_context_struct_injection_standard,
            tvb, offset+25, 1, false);
    proto_tree_add_item(tree, hf_smf_trace_span_context_struct_rfu,
            tvb, offset+26, 4, false);
    proto_tree_add_item(tree, hf_smf_trace_span_context_struct_trace_state_length,
            tvb, offset+30, 2, false);

    if (trace_state_len) {
        proto_tree_add_item(tree, hf_smf_trace_span_context_struct_trace_state,
                tvb, offset+32, trace_state_len, false);
    }
}

void smf_proto_add_trace_span_transport_context_value(proto_tree* tree, packet_info* pinfo,
    tvbuff_t* tvb, int offset, int size)
{
    if (size < 1) {
        expert_add_info_format(pinfo, proto_tree_get_parent(tree), &ei_trace_span_invalid_length,
            "Length must be >= 1. Length was %i", size);
        return;
    }
    uint8_t version = (tvb_get_uint8(tvb, offset) & 0xf0) >> 4;
    proto_item* version_item = proto_tree_add_item(tree, hf_smf_trace_span_context_struct_version,
        tvb, offset, 1, false);

    switch (version) {
    case 1:
        smf_proto_add_trace_span_transport_context_value_v1(tree, pinfo, tvb, offset, size);
        break;

    default:
        expert_add_info(pinfo, version_item, &ei_trace_span_unsupported_version);
    }
}

/*
 * Add an SMF parameter to the tree.
 * For standard parameters only - do not pass a lightweight parameter to
 * this function.
 * Will determine the parameter type and add the appropriate object to the
 * tree.
 */
static void add_smf_param(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, uint8_t param_type,
        int offset, int size, int header_overhead, struct param_info_t* param_info_p)
{

    offset += header_overhead;
    size -= header_overhead;
    proto_item *item;

    switch (param_type)
    {
        case STANDARD_PARAM_PUBLISHER_ID:
            proto_tree_add_item(tree, hf_smf_publisherid_param, tvb, offset, size, false);
            break;
        case STANDARD_PARAM_PUBLISHER_MSG_ID:
            proto_tree_add_item(tree, hf_smf_publisher_msgid_param, tvb, offset, size, false);
            break;
        case STANDARD_PARAM_MESSAGE_PRIORITY:
            proto_tree_add_item(tree, hf_smf_message_prio_param, tvb, offset, size, false);
            break;
        case STANDARD_PARAM_USER_DATA:
            proto_tree_add_item(tree, hf_smf_userdata_param, tvb, offset, size, false);
            break;
        case STANDARD_PARAM_MESSAGE_ID:
            proto_tree_add_item(tree, hf_smf_message_id_param, tvb, offset, size, false);
            break;
        case STANDARD_PARAM_USERNAME:
            smf_proto_add_username_item(tree, pinfo, tvb, offset, size);
            break;
        case STANDARD_PARAM_PASSWORD:
            smf_proto_add_password_item(tree, pinfo, tvb, offset, size);
            break;
        case STANDARD_PARAM_RESPONSE:
            smf_proto_add_response_item(tree, tvb, offset, size);
            param_info_p->is_response = true;
            break;
        case STANDARD_PARAM_ENTITLEMENT_LIST:
            smf_proto_add_enttl_list_item(tree, tvb, offset, size);
            break;
        case STANDARD_PARAM_SUBSCRIBER_ID_LIST:
            smf_proto_add_subid_list_item(tree, tvb, offset, size);
            break;
        case STANDARD_PARAM_GENERIC_ATTACHMENT:
            smf_proto_add_variable_size_item(tree, tvb, offset, size, hf_smf_generic_attachment_param);
            break;
        case STANDARD_PARAM_BINARY_ATTACHMENT:
            param_info_p->attachment_length = smf_proto_add_variable_size_item(
                tree, tvb, offset, size, hf_smf_binary_attachment_param);
            param_info_p->xml_payload_length -= param_info_p->attachment_length;
            param_info_p->attachment_start = param_info_p->xml_payload_length;
            break;
        case STANDARD_PARAM_ORIGINATOR_ADDRESS:
            proto_tree_add_item(tree, hf_smf_originator_address_param, tvb,
                offset, 4, false);
            if (size == 6)
            {
                proto_tree_add_item(tree, hf_smf_originator_port_param, tvb,
                    offset + 4, 2, false);
            }
            break;
        case STANDARD_PARAM_DESTINATION_ADDRESS_LIST:
            smf_proto_add_destination_list_item(tree, tvb, offset, size);
            break;
        case STANDARD_PARAM_DESTINATION_ADDRESS_AND_PORT_LIST:
            smf_proto_add_destination_address_and_port_list_item(tree, tvb,
                offset, size);
            break;
        case STANDARD_PARAM_DEELIVERY_MODE:
            proto_tree_add_item(tree, hf_smf_delivery_mode_param, tvb, offset,
                size, false);
            break;
        case STANDARD_PARAM_AD_MESSAGE_ID:
            CSV_WRITE_LONG_VALUE(extractAdMsgId, 0, "c:\\msgIdResults.txt",
                tvb, offset+4);
            proto_tree_add_item(tree, hf_smf_ad_msg_id_param, tvb, offset, size,
                false);
            break;
        case STANDARD_PARAM_AD_PREV_MESSAGE_ID:
            CSV_WRITE_LONG_VALUE(extractAdMsgId, 0, "c:\\msgIdResults.txt",
                tvb, offset+4);
            proto_tree_add_item(tree, hf_smf_ad_prev_msg_id_param, tvb, offset,
                size, false);
            break;
        case STANDARD_PARAM_AD_REDELIVERED_FLAG:
            proto_tree_add_item(tree, hf_smf_ad_redelivered_param, tvb, offset,
                size, false);
            break;
        case STANDARD_PARAM_AD_TTL_DEPRICATED:
            proto_tree_add_item(tree, hf_smf_ad_ttl_deprecated_param, tvb, offset, size,
                false);
            break;
        case STANDARD_PARAM_AD_DESTINATION_SET:
            smf_proto_add_ad_destination_set_item(tree, tvb, offset, size);
            break;
        case STANDARD_PARAM_MESSAGE_CONTENTS_SUMMARY:
            smf_proto_add_message_contents_summary_item(tree, tvb,
                offset - header_overhead, size + header_overhead, param_info_p);
            break;
        case STANDARD_PARAM_AD_FLOW_ID:
            CSV_WRITE_LONG_VALUE(extractAdMsgId, 1, "c:\\msgIdResults.txt",
                tvb, offset);
            proto_tree_add_item(tree, hf_smf_ad_flow_id_param, tvb, offset,
                size, false);
            // hf_assuredctrl_flow_id_hidden_param is for easier search with assuredctrl flow id
            item = proto_tree_add_item(tree, hf_assuredctrl_flow_id_hidden_param, tvb, offset,
                size, false);
            proto_item_set_hidden(item);
            break;
        case STANDARD_PARAM_TOPIC_NAME:           
            topic_name = tvb_get_string_enc(NULL, tvb, offset, size, ENC_ASCII);
            proto_tree_add_item(tree, hf_smf_topic_name_param, tvb, offset,
                size, false);
            break;
        case STANDARD_PARAM_AD_FLOW_REDELIVERED_FLAG:
            proto_tree_add_item(tree, hf_smf_ad_flow_redelivered_flag, tvb,
                offset, size, false);
            break;
        case STANDARD_PARAM_POINT_OF_ENTRY_UNIQUE_ID:
            // This is a fixed size param of 20 bytes
            proto_tree_add_item(tree, hf_smf_point_of_entry_unique_id_client_id, tvb,
                offset, 2, false);
            proto_tree_add_item(tree, hf_smf_point_of_entry_unique_id_ingress_vrid_hash, tvb,
                offset+2, 8, false);
            proto_tree_add_item(tree, hf_smf_point_of_entry_unique_id_vpn_name_hash, tvb,
                offset+10, 8, false);            
            break;
        case STANDARD_PARAM_DELIVERY_ALWAYS_ONLY:
            proto_tree_add_item(tree, hf_smf_deliver_always_only, tvb,
                offset, size, false);
            break;
        case STANDARD_PARAM_AD_TTL:
            proto_tree_add_item(tree, hf_smf_ad_ttl_param, tvb, offset,
                size, false);
            break;
        case STANDARD_PARAM_RETRYABLE_ERROR:
            proto_tree_add_item(tree, hf_smf_retryable_error, tvb, offset, size, false);
            break;
        case STANDARD_PARAM_SEQUENCE_NUMBER:
            proto_tree_add_item(tree, hf_smf_sequence_number_param, tvb, offset,
                size, false);
            break;
        case STANDARD_PARAM_EXTENDED_TYPE_STREAM:
            {   
                for (int local_offset = offset; local_offset < size + offset;)
                {
                    uint8_t format;
                    uint16_t type;
                    int paramSize = 0;
                    int headerSize = 2;
                    format = (tvb_get_uint8(tvb, local_offset)  & 0x70) >>4 ;
                    type = tvb_get_ntohs(tvb, local_offset) & 0xFFF;
                    switch (format)
                    {
                        case 0: 
                            paramSize = 0;
                            break;
                        case 1:
                            paramSize = 1;
                            break;
                        case 2:
                            paramSize = 2;
                            break;    
                        case 3:
                            paramSize = 4;
                            break;
                        case 4:
                            paramSize = 8;
                            break;
                        case 5:
                            paramSize = (int)tvb_get_uint8(tvb, local_offset + headerSize);
                            headerSize++;
                            paramSize -= headerSize;
                            break;
                        case 6:
                            paramSize = (int)tvb_get_ntohs(tvb, local_offset + headerSize);
                            headerSize += 2;
                            paramSize -= headerSize;
                            break;
                        default:
                            proto_tree_add_item(tree, hf_smf_unknown_param, tvb,
                                            local_offset, size + offset - local_offset, false);
                            return;
                    }

                    local_offset += headerSize;

                    switch (type)
                    {
                        case SMF_EXTENDED_PARAM_GSS_API_TOKEN:
                            proto_tree_add_item(tree, hf_smf_gss_api_token_param, tvb, local_offset, paramSize, false);
                            break;
                        
                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_ACK_MESSAGE_ID:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_ack_message_id_param, tvb, local_offset, 8, false);
                            break;
                        
                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_TRANSACTION_ID:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_trans_id_param, tvb, local_offset, 4, false);
                            break;
                        
                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_TRANSACTION_FLAGS:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_trans_sr_flag, tvb, local_offset, 1, false);
                            proto_tree_add_item(tree, hf_smf_assured_delivery_trans_pr_flag, tvb, local_offset, 1, false);
                            break;
                        
                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_SPOOLER_UNIQUE_ID:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_spooler_unique_id, tvb, local_offset, 8, false);
                            break;

                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_REP_MATE_ACK_MES_ID:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_rep_mate_ack_id, tvb, local_offset, 8, false);
                            break;

                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_REDELIVERY_COUNT:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_redelivery_count, tvb, local_offset, 4, false);
                            break;

                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_ELIGIBLE_TIME:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_eligible_time, tvb, local_offset, 4, false);
                            break;

                        case SMF_EXTENDED_PARAM_ASSURED_DELIVERY_QUEUED_FOR_REDELIVERY:
                            proto_tree_add_item(tree, hf_smf_assured_delivery_queued_for_redelivery, tvb, local_offset, 0, false);
                            break;

                        case SMF_EXTENDED_PARAM_OAUTH_ISSUE_IDENTIFIER:
                            proto_tree_add_item(tree, hf_smf_oauth_issuer_identifier, tvb, local_offset, paramSize, false);
                            break;

                        case SMF_EXTENDED_PARAM_OPENID_CONNECT_ID_TOKEN:
                            proto_tree_add_item(tree, hf_smf_openid_connect_id_token, tvb, local_offset, paramSize, false);
                            break;

                        case SMF_EXTENDED_PARAM_OAUTH_ACCESS_TOKEN:
                            proto_tree_add_item(tree, hf_smf_oauth_access_token, tvb, local_offset, paramSize, false);
                            break;

                        case SMF_EXTENDED_PARAM_TRACE_SPAN_TRANSPORT_CONTEXT:
                        {
                            proto_item* transport_context_item = proto_tree_add_item(tree, hf_smf_trace_span_transport_context_param,
                                tvb, local_offset, paramSize, false);
                            proto_tree* subtree = proto_item_add_subtree(transport_context_item, ett_trace_span_transport_context);

                            smf_proto_add_trace_span_transport_context_value(subtree, pinfo, tvb, local_offset, paramSize);
                            break;
                        }
                        default:
                            proto_tree_add_item(tree, hf_smf_unknown_param, tvb, local_offset - headerSize, size + offset - local_offset + headerSize, false);
                            return;
                    }
                    local_offset += paramSize;
                }
            }
            break;

        default:
            proto_tree_add_item(tree, hf_smf_unknown_param, tvb,
                offset - header_overhead, size + header_overhead, false);
            break;
    }
    smf_analysis_param(tvb, pinfo, param_type, offset);
}

/*
 * Add a lightweight SMF parameter to the tree.
 * For lightweight parameters only - do not pass a standard parameter to
 * this function.
 * Will determine the parameter type and add the appropriate object to the
 * tree.
 */
static void add_lightweight_smf_param(tvbuff_t *tvb, proto_tree *tree,
    uint8_t param_type, int offset, int size, struct param_info_t* param_info_p)
{

    switch (param_type)
    {
        case LIGHTWEIGHT_PARAM_CORRELATION_TAG:
            proto_tree_add_item(tree, hf_smf_correlation_tag_param, tvb, offset,
                size, false);
            param_info_p->correlation_tag = tvb_get_ntoh24(tvb, offset);
            break;

        case LIGHTWEIGHT_PARAM_TOPIC_NAME_OFFSET:
            proto_tree_add_item(tree, hf_smf_topic_name_offset_param, tvb,
                offset, 1, false);
            offset += 1;
            proto_tree_add_item(tree, hf_smf_topic_name_length_param, tvb,
                offset, 1, false);
            break;

        case LIGHTWEIGHT_PARAM_QUEUE_NAME_OFFSET:
            proto_tree_add_item(tree, hf_smf_queue_name_offset_param, tvb,
                offset, 1, false);
            offset += 1;
            proto_tree_add_item(tree, hf_smf_queue_name_length_param, tvb,
                offset, 1, false);
            break;

        case LIGHTWEIGHT_PARAM_ACK_IMMEDIATELY:
            proto_tree_add_item(tree, hf_smf_ack_immediately_tag_param, tvb,
                offset-1, 1, false);
            param_info_p->ack_immediately_tag = true;
            break;

        case LIGHTWEIGHT_PARAM_HEADER_EXTENSION:
            offset -= 1;
            proto_tree_add_item(tree, hf_smf_header_extension_param, tvb,
                offset, 4, false);
            offset += 1;
            proto_tree_add_item(tree, hf_smf_header_extension_param_rffu, tvb,
                offset, 3, false);
            offset += 2;
            proto_tree_add_item(tree, hf_smf_header_extension_param_odf, tvb,
                offset, 1, true);
            proto_tree_add_item(tree, hf_smf_header_extension_param_fac, tvb,
                offset, 1, false);
            break;

        default:
            proto_tree_add_item(tree, hf_smf_unknown_param, tvb, offset - 1,
                size + 1, false);
            break;
    }
}

/*
 * Dissects an SMF parameter.
 * Determines if it's a lightweight or standard parameter, extracts its type
 * and size, and calls the appropriate function to add it to the tree.
 */
static int dissect_smf_param(tvbuff_t * tvb, packet_info* pinfo, int offset, proto_tree * tree,
    struct param_info_t* param_info_p)
{

    int param_len;
    int param_offset;
    bool is_lightweight_param;
    uint8_t param_type;

    /* Is it a pad byte? */
    if (tvb_get_uint8(tvb, offset) == 0)
    {
        proto_tree_add_item(tree, hf_smf_pad_byte, tvb, offset, 1, false);
        return 1;
    }

    is_lightweight_param = tvb_get_uint8(tvb, offset) & 0x20;

    if (is_lightweight_param)
    {
        param_type = (tvb_get_uint8(tvb, offset) & 0x1c) >> 2;
        param_len = (tvb_get_uint8(tvb, offset) & 0x3);

        add_lightweight_smf_param(tvb, tree, param_type, offset + 1, param_len, param_info_p);

        // Add 1 byte for the type / len byte in the light param declaration
        param_len += 1;
    } else
    {
        param_type = tvb_get_uint8(tvb, offset) & 0x1f;
        param_len = tvb_get_uint8(tvb, offset + 1);
        param_offset = 2;

        if (param_len == 0)
        {
            /* Extended-length standard parameter */
            param_len = tvb_get_ntohl(tvb, offset + 2);
            param_offset += 4;
        }

        add_smf_param(tvb, pinfo, tree, param_type, offset, param_len, param_offset, param_info_p);
    }

    // Checks if param_len less than by how much the offset moves so that it doesn't get stuck in a loop
    if (param_len < 1)
        param_len = 1;
    return param_len;
}

static void dissect_smf_params(tvbuff_t *tvb, packet_info* pinfo, int param_offset_start,
    int param_offset_end, proto_tree *tree, struct param_info_t* param_info_p)
{

    int offset;

    for (offset = param_offset_start; offset < param_offset_end;)
    {
        int param_len = dissect_smf_param(tvb, pinfo, offset, tree, param_info_p);
        if (0 == param_len) {
            // A param cannot be 0 length. Something went wrong with the dissection. Just exit
            break;
        }
        offset += param_len;
    }
}

/* Code to actually dissect the packets */
static int dissect_smf_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int bdChannel)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item* ti;
    proto_tree* smf_tree;
    proto_item* attach_item = NULL;
    proto_tree* attach_tree = NULL;
    tvbuff_t* next_tvb;
    int payload_offset;
    int param_offset;
    uint8_t smf_version;
    uint32_t msg_len = -1;// hdr_len = -1;
    uint8_t encap_protocol;
    const char* encap_protocol_name;
    struct param_info_t param_info;
    char* buffer0;
    char* buffer1;
    char* encap_name_buf;
    struct smfdata encap_smfdata;
    //uint32_t dst_ref = 0;

    /* String to check against "magic number" of perf tool data */
    uint32_t magicNumber;

    memset(&param_info, 0, sizeof(param_info));
    param_info.correlation_tag = -1;

    /* Boolean flag to indicate whether the Assured Control (AC) Flag is set */
    bool acflag_set = false;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMF");

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

        "col_append_fstr()" can be used instead of "col_add_str()"; it takes
        "printf()"-like arguments.  Don't use "col_append_fstr()" with a format
        string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
        more efficient than "col_append_fstr()".

        If you will be fetching any data from the packet before filling in
        the Info column, clear that column first, in case the calls to fetch
        data from the packet throw an exception because they're fetching data
        past the end of the packet, so that the Info column doesn't have data
        left over from the previous dissector; do

        col_clear(pinfo->cinfo, COL_INFO);

        */

    col_clear(pinfo->cinfo, COL_INFO);

    encap_protocol = tvb_get_uint8(tvb, 1) & 0x3f;

    encap_protocol_name = try_val_to_str(encap_protocol, protocolnames);
    /*
    * Set up the "Protocol" and "Info" columns of the display.
    * We do this at the end so that we can display whether the packet is a
    * request or response, which we only know after dissecting the
    * parameters.
    */
    if (encap_protocol_name)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, encap_protocol_name);
    }

    /*  setup buffer for other protocol decoders to write packet type info
        sub-dissectors may choose to write the encapsulated message
        type to this buffer */

    encap_name_buf = (char*)wmem_alloc(wmem_packet_scope(), 60);
    encap_name_buf[0] = '\0';

    encap_smfdata.subtype = encap_name_buf;

    /* Dissect the SMF header */
    smf_version = tvb_get_uint8(tvb, 0) & 0x7;
    if (smf_version == 3)
    {
        msg_len = tvb_get_ntohl(tvb, 8);
    }
    else
    {
        return -1;
    }

    //if (tvb_reported_length_remaining(tvb, 0) < msg_len)
    //{
        //Ignore this error.  We want to keep parsing
        //until we get a parse error.
        //Allows us to dissect truncated messages.
    //}

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
        //if (tree)
        //{

            /* NOTE: The offset and length values in the call to
            "proto_tree_add_item()" define what data bytes to highlight in the hex
            display window when the line in the protocol tree display
            corresponding to that item is selected.

            Supplying a length of -1 is the way to highlight all data from the
            offset to the end of the packet. */

            /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_smf, tvb, 0, msg_len, false);

    smf_tree = proto_item_add_subtree(ti, ett_smf);

    proto_tree_add_item(smf_tree, hf_smf_di, tvb, 0, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_ee, tvb, 0, 1, false);

    proto_tree_add_item(smf_tree, hf_smf_dto, tvb, 0, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_adf, tvb, 0, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_dmqe, tvb, 0, 1, false);

    proto_tree_add_item(smf_tree, hf_smf_version, tvb, 0, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_uh, tvb, 1, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_encap_protocol, tvb, 1, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_priority, tvb, 2, 1, false);

    param_offset = MIN_SMF_HEADER_LEN;
    if (tvb_captured_length_remaining(tvb, 0) < param_offset) {
        return -1;
    }
    /* Determines if the Assured Control (AC) Flag is set or not */
    if (tvb_get_uint8(tvb, 2) & 0x02) { acflag_set = true; }
    else { acflag_set = false; }

    proto_tree_add_item(smf_tree, hf_smf_retain, tvb, 2, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_acf, tvb, 2, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_sni, tvb, 2, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_ttl, tvb, 3, 1, false);
    proto_tree_add_item(smf_tree, hf_smf_header_len_v3, tvb, 4, 4, false);
    proto_tree_add_item(smf_tree, hf_smf_msg_len_v3, tvb, 8, 4, false);

    payload_offset = tvb_get_ntohl(tvb, 4);


    //hdr_len = tvb_get_ntohl(tvb, 4);
    msg_len = tvb_get_ntohl(tvb, 8);

    switch (encap_protocol)
    {
    case SMF_TRMSG:
        /* Default the attachment length to the size of the message.  This will
            get overwritten if there is a MessageContentsSummary parameter. */
        param_info.attachment_start = 0;
        param_info.attachment_length = msg_len - payload_offset;
        break;
    default:
        /* Default the xml payload length to the size of the message.  This will
            get overwritten if there is a MessageContentsSummary parameter. */
        param_info.xml_payload_start = 0;
        param_info.xml_payload_length = msg_len - payload_offset;
        break;
    }

    /* If TrMsg AND AC Flag is set then parse the params as an AssuredCtrl Msg */
    /* Otherwise, parse the params as regular TrMsg (i.e. continue as before) */
    if ((encap_protocol == SMF_TRMSG) && acflag_set) {

        next_tvb = tvb_new_subset_length_caplen(tvb, payload_offset, -1, param_info.attachment_length);
        call_dissector_with_data(assuredctrl_handle, next_tvb, pinfo, tree, encap_name_buf);
    }
    else {

        dissect_smf_params(tvb, pinfo, param_offset, payload_offset, smf_tree, &param_info);

        /* Analyse the SMF data and add expert section */
        smf_analysis(tvb, pinfo, smf_tree);

        /* Add payload components */
        next_tvb = tvb_new_subset_length_caplen(tvb, payload_offset, -1, msg_len - payload_offset);

        switch (encap_protocol)
        {
        case SMF_PUBMSG:
        case SMF_TRMSG:
            /* Consumer ID list */
            if (param_info.cidlist_length > 0) {
                smf_proto_add_cid_list_item(smf_tree, tvb, payload_offset + param_info.cidlist_start, param_info.cidlist_length);
            }

            /* XML metadata */
            if (param_info.metadata_length > 0) {
                next_tvb = tvb_new_subset_length_caplen(tvb, payload_offset + param_info.metadata_start, -1, param_info.metadata_length);
                call_dissector_no_protocol_change(xml_handle, next_tvb, pinfo, tree);
            }

            /* XML payload */
            if (param_info.xml_payload_length > 0) {
                next_tvb = tvb_new_subset_length_caplen(tvb, payload_offset + param_info.xml_payload_start, -1, param_info.xml_payload_length);
                call_dissector_no_protocol_change(xml_handle, next_tvb, pinfo, tree);
            }

            /* Binary attachment */
            if (param_info.attachment_length > 0)
            {
                _smf_attachment_type_t attachment_type = _smf_attachment_type_none;

                /* Only check for perf tool if the payload length is long enough for perf tool to exist. In certain cases, usually testing, a payload that is less than four 
                 * bytes will be sent. In those cases, the call to ntohl() below causes a malformed packet because there are fewer than four bytes to pull.
                 */
                if ((msg_len - payload_offset) >= 4) {
                    magicNumber = tvb_get_ntohl(tvb, payload_offset + param_info.attachment_start);

                    if (magicNumber == 0x501ACE01) {
                        attach_item = proto_tree_add_item(smf_tree, hf_smf_attachment, tvb, payload_offset + param_info.attachment_start, param_info.attachment_length, false);
                        attach_tree = proto_item_add_subtree(attach_item, ett_attachment_sdt);
                    }
                }
                if (param_info.attachment_length > 5) {
                    uint8_t type = tvb_get_uint8(tvb, payload_offset + param_info.attachment_start);
                    /* Within this if statement, length is compared to param_info.attachment_length. the length is encoded as an 
                     * unsigned 32-bit integer value on the wire, so it is necessary to use tvb_get_ntohl since it fetches an 
                     * unsigned 32-bit value from the packet. However, param_info.attachment_length is declared as a regular int 
                     * and is referenced in many places, so it would be at least tedious if not difficult to change its declaration 
                     * from type 'int' to type 'unsigned int'. The easiest solution was to declare length as an unsigned 64-bit 
                     * variable, and typecast any assignments or comparisons to type 'uint64_t' so that there is no overflow like 
                     * there might be if we typecasted int to unsigned int or vice versa. 
                     */
                    uint64_t length = (uint64_t)tvb_get_ntohl(tvb, payload_offset + param_info.attachment_start + 1);

                    if ((type == 0x2f || //Decode as SDT if an SDT stream is contained
                        type == 0x2b || //Decode as SDT if an SDT map is contained
                        type == 0x1f    //Decode as SDT if an SDT string is contained
                        )
                        && length == (uint64_t)param_info.attachment_length) {
                        attachment_type = _smf_attachment_type_sdt;
                    }
                    else if ((type == 0x31) && (param_info.attachment_length > 7)) { /* 0x31 = Solace openMAMA payload*/
                        type = tvb_get_uint8(tvb,
                            payload_offset + param_info.attachment_start + 2);
                        length = (uint64_t)tvb_get_ntohl(tvb,
                            payload_offset + param_info.attachment_start + 3);


                        if ((type == 0x2F) && (length + 2 == (uint64_t)param_info.attachment_length)) { /* Stream of fields starts with 0x2F */
                            attachment_type = _smf_attachment_type_openmama_payload;
                        }
                    }
                }

                int subdissectorSuccess = 0;
                if (attach_item == NULL)
                {  
                    // Try the subdirector first...
                    next_tvb = tvb_new_subset_length_caplen(tvb,
                        payload_offset + param_info.attachment_start,
                        -1,
                        param_info.attachment_length);

                    const smf_subdissection_uat_entry_t* subdissector = get_subdissector_from_uat(topic_name);
                    if (subdissector != NULL) {
                        int rc;
                        rc = smf_call_subdissector(subdissector, next_tvb, pinfo, tree);
                        if (rc) {
                            subdissectorSuccess = 1;
                        }
                    }
                    else if (dissector_try_payload_new(smf_payload_dissector_table,next_tvb,pinfo,tree,true,NULL))
                    {
                        subdissectorSuccess = 1;
                    } else {
                        // Subdissector did not work out
                        subdissectorSuccess = 0;
                    }
                }

                if (!subdissectorSuccess) {
                    switch (attachment_type) {
                    case _smf_attachment_type_sdt:
                    {
                        /* Check if attach_item has already been created for perf tool data */
                        if (attach_tree == NULL)
                        {
                            attach_item = proto_tree_add_item(smf_tree,
                                hf_smf_attachment, tvb,
                                payload_offset + param_info.attachment_start,
                                -1, false);

                            attach_tree = proto_item_add_subtree(
                                attach_item, ett_attachment_sdt);
                        }

                        add_sdt_block(attach_tree, pinfo, hf_smf_attachment_sdt, tvb,
                            payload_offset + param_info.attachment_start + 5,
                            param_info.attachment_length - 5, 1, false);


                        break;
                    }
                    case _smf_attachment_type_openmama_payload:
                    {
                        /* openMAMA payload */
                        next_tvb = tvb_new_subset_length_caplen(tvb,
                            payload_offset + param_info.attachment_start,
                            -1,
                            param_info.attachment_length);
                        call_dissector(mama_payload_handle, next_tvb, pinfo, tree);
                        break;
                    }
                    default:
                    {
                        proto_tree_add_item(smf_tree, hf_smf_attachment, tvb,
                            payload_offset + param_info.attachment_start,
                            -1, false);
                        break;
                    }
                    }
                }
            }

            /* Binary metadata */
            if (param_info.binary_metadata_length > 0)
            {
                int metadata_start = payload_offset + param_info.binary_metadata_start;
                int remaining_len = tvb_reported_length_remaining(tvb, metadata_start);
                // Check to see still have data to dissect
                if (remaining_len > param_info.binary_metadata_length) {
                    next_tvb = tvb_new_subset_length_caplen(tvb,
                        metadata_start,
                        -1,
                        param_info.binary_metadata_length);
                    call_dissector(bm_handle, next_tvb, pinfo, smf_tree);
                }
            }
            break;

        case SMF_CSMP:
        case SMF_CSPF:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector_no_protocol_change(xml_handle, next_tvb, pinfo, tree);
            }
            break;

        case SMF_KEEPALIVE:
            /* Keepalive has no payload */
            break;

        case SMF_PUBCTRL:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector(pubctrl_handle, next_tvb, pinfo, tree);
            }
            break;

        case SMF_SUBCTRL:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector(subctrl_handle, next_tvb, pinfo, tree);
            }
            break;

        case SMF_XMLLINK:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector(xmllink_handle, next_tvb, pinfo, tree);
            }
            break;

        case SMF_ASSUREDCTRL:
        case SMF_ASSUREDCTRL_PASSTHRU:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector_with_data(assuredctrl_handle, next_tvb, pinfo, tree, encap_name_buf);
            }
            break;

        case SMF_SMP:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector_with_data(smp_handle, next_tvb, pinfo, tree, encap_name_buf);
            }
            break;

        case SMF_CLIENTCTRL:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector_with_data(clientctrl_handle, next_tvb, pinfo, tree, encap_name_buf);
            }
            break;

        case SMF_SMRP:
            if (param_info.xml_payload_length > 0)
            {
                call_dissector(smrp_handle, next_tvb, pinfo, tree);
            }
            break;

        case SMF_ENCAP_SMF:
            //Tried to dissect this as SMF but very hard to tell if there are multiple SMF messages, or an encap message.
            if (param_info.xml_payload_length > 0)
            {
                col_set_fence(pinfo->cinfo, COL_PROTOCOL);
                call_dissector(smf_handle, next_tvb, pinfo, tree);
            }
            break;
        case SMF_WSE:
        case SMF_SEMP:
        case SMF_KEEPALIVE_V2:
        case SMF_JNDI:
        default:
            /* Add the payload, if there is one */
            if (param_info.xml_payload_length > 0)
            {
                proto_tree_add_item(smf_tree, hf_smf_payload, tvb,
                    payload_offset, -1, false);
            }
            break;
        }
    }
    //}

    buffer0 = (char*)wmem_alloc(wmem_packet_scope(), 30);
    buffer0[0] = '\0';
    if (param_info.correlation_tag > 0)
    {
        g_snprintf(buffer0, 30, "Tag=%d", param_info.correlation_tag);
    }

    buffer1 = (char*)wmem_alloc(wmem_packet_scope(), 30);
    buffer1[0] = '\0';
    if (bdChannel >= 0)
    {
        g_snprintf(buffer1, 30, "Backdoor=%d", bdChannel);
    }

    if (strstr(encap_smfdata.subtype, "XaCtrl") || strstr(encap_smfdata.subtype, "TxnCtrl")) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%u > %u [%s %s] %s %s",
            pinfo->srcport, pinfo->destport,
            (encap_protocol_name ? encap_protocol_name : "SMF"),
            encap_smfdata.subtype, buffer0, buffer1);
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%u > %u [%s %s%s] %s %s",
            pinfo->srcport, pinfo->destport,
            (encap_protocol_name ? encap_protocol_name : "SMF"),
            (param_info.is_response ? "response" : "request"),
            encap_smfdata.subtype, buffer0, buffer1);
    }
    return msg_len;
}

static int dissect_smf_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data _U_);

/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
 that calls all the protocol registration.
 */

static void try_load_smf_subdissection_uat(void)
{
    if (!smf_subdissection_uat_loaded) {
        const smf_subdissection_uat_entry_t* subdissector = get_subdissector_from_uat(default_subdissector_uat_topic);
        if (subdissector == NULL) {
            smf_subdissection_uat_entry_t initial_rec = {
                MATCH_CRITERIA_STARTS_WITH,
                g_strdup(default_subdissector_uat_topic),
                NULL,
                g_strdup(default_subdissector_uat_protocol),
                find_dissector(default_subdissector_uat_protocol),
                g_strdup(default_subdissector_uat_extra_data)
            };

            uat_add_record(smf_subdissection_uat, &initial_rec, true);
        }
        smf_subdissection_uat_loaded = 1;
    }
}

void proto_register_smf(void)
{


    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] =
        {
        /* SMF Header */

            /* v3 */

            { &hf_smf_di,
                { "Discard Indication", "smf.di",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL
                    }},

            { &hf_smf_ee,
                { "Eliding Eligible", "smf.ee",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL
                    }},

            { &hf_smf_dto,
                { "Deliver To One", "smf.dto",
                    FT_BOOLEAN, 8, NULL, 0x20,
                    "", HFILL
                    }},

            { &hf_smf_adf,
                { "ADFlag", "smf.adf",
                    FT_BOOLEAN, 8, NULL, 0x10,
                    "", HFILL
                    }},

            { &hf_smf_dmqe,
                { "Dead Message Queue Waiting", "smf.dmqe",
                    FT_BOOLEAN, 8, NULL, 0x08,
                    "", HFILL
                    }},

            { &hf_smf_version,
                { "Version", "smf.version",
                    FT_UINT8, BASE_DEC, NULL, 0x7,
                    "", HFILL
                    }},

            { &hf_smf_uh,
                { "UH", "smf.uh",
                    FT_UINT8, BASE_HEX, VALS(uhnames), 0xC0,
                    "", HFILL
                    }},

            { &hf_smf_encap_protocol,
                { "Encapsulated protocol", "smf.encap_proto",
                    FT_UINT8, BASE_HEX, VALS(protocolnames), 0x3f,
                    "", HFILL
                    }},

            { &hf_smf_priority,
                { "Priority", "smf.priority",
                    FT_UINT8, BASE_DEC, NULL, 0xf0,
                    "", HFILL
                    }},

            { &hf_smf_retain,
                {"Retain", "smf.retain",
                    FT_UINT8, BASE_DEC, NULL, 0x0c,
                    "", HFILL
                    }},

            { &hf_smf_acf,
                { "ACFlag", "smf.acf",
                    FT_BOOLEAN, 8, NULL, 0x02,
                    "", HFILL
                    }},

            { &hf_smf_sni,
                { "SNI", "smf.sni",
                    FT_BOOLEAN, 8, NULL, 0x01,
                    "", HFILL
                    }},

            { &hf_smf_ttl,
                { "Time to live", "smf.ttl",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_header_len_v3,
                { "Header length", "smf.header_len",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_msg_len_v3,
                { "Message length", "smf.msg_len",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            /* v2 */

            { &hf_smf_rfu,
                { "RFUv2", "smf.rfu_v2",
                    FT_UINT8, BASE_DEC, NULL, 0x38,
                    "", HFILL
                    }},

            { &hf_smf_header_len,
                { "Header length", "smf.header_len",
                    FT_UINT16, BASE_DEC, NULL, 0x0fff,
                    "", HFILL
                    }},

            { &hf_smf_msg_len,
                { "Message length", "smf.msg_len",
                    FT_UINT24, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            /* Standard Parameters */

/*0x01*/    { &hf_smf_publisherid_param,
                { "Publisher Id", "smf.publisherid",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x02*/   { &hf_smf_publisher_msgid_param,
                { "Publisher Message id", "smf.publishermsgid",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x03*/    { &hf_smf_message_prio_param,
                { "Message priority", "smf.msg_priority",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x04*/    { &hf_smf_userdata_param,
                { "User data", "smf.userdata",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x05*/    { &hf_smf_message_id_param,
                { "Message id", "smf.message_id",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x06*/    { &hf_smf_username_param,
                { "User name", "smf.username",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x07*/    { &hf_smf_password_param,
                { "Password", "smf.password",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x08*/    { &hf_smf_response_param,
                { "Response", "smf.response",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x09*/    { &hf_smf_entitlements_param,
                { "Entitlement list", "smf.entitlements",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x0a*/    { &hf_smf_subscriber_ids_param,
                { "Subscriber id list", "smf.subscriber_ids",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x0b*/    { &hf_smf_generic_attachment_param,
                { "Generic attachment offset", "smf.generic_attachment",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x0c*/    { &hf_smf_binary_attachment_param,
                { "Binary attachment length", "smf.binary_attachment",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x0d*/    { &hf_smf_originator_address_param,
                { "Originator address", "smf.orig_address",
                    FT_IPv4, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x10*/    { &hf_smf_delivery_mode_param,
                { "Delivery mode", "smf.delivery_mode",
                    FT_UINT8, BASE_DEC, VALS(deliverymodenames), 0x0,
                    "", HFILL
                    }},

/*0x11*/    { &hf_smf_ad_msg_id_param,
                { "Assured delivery message id", "smf.ad_msg_id",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x12*/    { &hf_smf_ad_prev_msg_id_param,
                { "Assured delivery previous message id", "smf.ad_prev_msg_id",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x13*/    { &hf_smf_ad_redelivered_param,
                { "Assured delivery redelivered", "smf.ad_redelivered",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x14*/    { &hf_smf_ad_ttl_deprecated_param,
                { "Assured delivery time to live", "smf.ad_ttl",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x16*/    { &hf_smf_message_contents_summary_param,
                { "Message contents summary", "smf.message_contents_summary",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x17*/    { &hf_smf_ad_flow_id_param,
                { "Assured delivery flow id", "smf.ad_flow_id",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_assuredctrl_flow_id_hidden_param,
                { "Smf/AssuredCtrl Flow ID", "smf.flowid",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x18*/    { &hf_smf_topic_name_param,
                { "Topic name", "smf.topic_name",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x19*/    { &hf_smf_ad_flow_redelivered_flag,
                { "AD Flow Redelivered Flag", "smf.ad_flow_redelivered_flag",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x1a*/    { &hf_smf_point_of_entry_unique_id_client_id,
                { "Point-of-Entry Unique ID - Client ID", "smf.point_of_entry_unique_id.client_id",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_point_of_entry_unique_id_ingress_vrid_hash,
                { "Point-of-Entry Unique ID - Ingress VRID hash", "smf.point_of_entry_unique_id.ingress_vrid_hash",
                    FT_UINT64, BASE_HEX, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_point_of_entry_unique_id_vpn_name_hash,
                { "Point-of-Entry Unique ID - VPN Name hash", "smf.point_of_entry_unique_id.vpn_name_hash",
                    FT_UINT64, BASE_HEX, NULL, 0x0,
                    "", HFILL
                    }},

/*0x1b*/    { &hf_smf_deliver_always_only,
                { "Deliver-Always-Only", "smf.deliver_always_only",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x1c*/    { &hf_smf_ad_ttl_param,
                { "Assured delivery time to live", "smf.ad_ttl",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x1d*/    { &hf_smf_retryable_error,
                { "Retryable Error", "smf.retryable_error",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x1e*/    { &hf_smf_sequence_number_param,
                { "Sequence Number ", "smf.sequence_number",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            /* Lightweight Parameters */

/*0x00*/    { &hf_smf_correlation_tag_param,
                { "Correlation tag", "smf.correlation_tag",
                    FT_UINT24, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x01*/    { &hf_smf_topic_name_offset_param,
                { "Topic name offset", "smf.topic_name_offset",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x02*/    { &hf_smf_queue_name_offset_param,
                { "Queue name offset", "smf.queue_name_offset",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

/*0x03*/    { &hf_smf_ack_immediately_tag_param,
                { "ACK Immediately tag", "smf.ack_immediately_tag",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x04*/    { &hf_smf_header_extension_param,
                { "Header Extension", "smf.header_extension",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

/*0x04: FAC, RFFU, and ODF only possible if 'Header Extension' is active*/

            /* RFFU param needs to be decremented if adding another lightweight param (decrement from 0xfffffc bits to make room) */
            { &hf_smf_header_extension_param_rffu,
                { "Reserved for Future Use", "smf.header_extension.rffu",
                    FT_UINT24, BASE_DEC, NULL, 0xfffffc,
                    "", HFILL
                    }},

            { &hf_smf_header_extension_param_odf,
                { "Originally Direct Flag", "smf.header_extension.odf",
                    FT_BOOLEAN, 8, NULL, 0x02,
                    "", HFILL
                    }},

            { &hf_smf_header_extension_param_fac,
                { "From Another Cluster", "smf.header_extension.fac",
                    FT_BOOLEAN, 8, NULL, 0x01,
                    "", HFILL
                    }},

            /* Extended Parameters */

            { &hf_smf_gss_api_token_param,
                { "GSS API Token", "smf.gssapitoken",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_assured_delivery_ack_message_id_param,
                { "Assured Delivery Ack Message id", "smf.assureddeliveryackmessage_id",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_assured_delivery_trans_id_param,
                { "Assured Delivery Transaction Id", "smf.assureddelivery_trans_id",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_assured_delivery_trans_sr_flag,
                { "SR Flag", "smf.assureddelivery_trans_sr_flag",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL
                    }},

            { &hf_smf_assured_delivery_trans_pr_flag,
                { "PR Flag", "smf.assureddelivery_trans_pr_flag",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL
                    }},
            { &hf_smf_assured_delivery_spooler_unique_id,
                { "Spooler Unique Id", "smf.assureddelivery_spooler_unique_id",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},
            
            { &hf_smf_assured_delivery_rep_mate_ack_id, 
                { "Replication Mate Ack Message Id", "smf.assureddelivery_rep_mate_ack_id",
                    FT_UINT64, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},
            
            { &hf_smf_assured_delivery_redelivery_count,
                { "Redelivery Count", "smf.assureddelivery_redelivery_count",
                    FT_UINT32, BASE_DEC, NULL, 0x00,
                    "", HFILL
                    }},

            { &hf_smf_assured_delivery_eligible_time,
                { "Eligible Time", "smf.assureddelivery_eligible_time",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_assured_delivery_queued_for_redelivery,
                { "Queued For Redelivery", "smf.assureddelivery_queued_for_redelivery",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_oauth_issuer_identifier,
                { "OAuth Issuer Identifier", "smf.oauth_issuer_identifier",
                    FT_STRINGZ, BASE_NONE, NULL, 0x0,
                    "", HFILL
                }},

            { &hf_smf_openid_connect_id_token,
                { "OpenID Connect ID Token", "smf.openid_connect_id_token",
                    FT_STRINGZ, BASE_NONE, NULL, 0x0,
                    "", HFILL
                }},

            { &hf_smf_oauth_access_token,
                { "OAuth Access Token", "smf.oauth_access_token",
                    FT_STRINGZ, BASE_NONE, NULL, 0x0,
                    "", HFILL
                }},

            { &hf_smf_trace_span_transport_context_param,
                { "Trace Span Transport Context", "smf.trace",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                }},

            /* Trace Span Context Internal Struct*/
            { &hf_smf_trace_span_context_struct_version,
                { "Version", "smf.trace.version",
                    FT_UINT8, BASE_DEC, NULL, 0xf0,
                    "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_sampled_flag,
                { "Sampled Flag", "smf.trace.sampled_flag",
                    FT_UINT8, BASE_DEC,
                    VALS(trace_span_context_sampled_flag_names),
                    0x0c, "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_rfu_flag,
                { "Reserved for Future Use", "smf.trace.rfu_flag",
                    FT_UINT8, BASE_DEC, NULL, 0x03,
                    "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_trace_id,
                { "Trace ID", "smf.trace.trace_id",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_span_id,
                { "Span ID", "smf.trace.span_id",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_injection_standard,
                { "Injection Standard", "smf.trace.injection_standard",
                    FT_UINT8, BASE_DEC,
                    VALS(trace_span_context_injection_standard_names),
                    0x0, "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_rfu,
                { "Reserved for Future Use", "smf.trace.rfu_param",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_trace_state_length,
                { "Trace State Length", "smf.trace.state_length",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "", HFILL
                }},

            { &hf_smf_trace_span_context_struct_trace_state,
                { "Trace State", "smf.trace.state_data",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "", HFILL
                }},

            /* Message Contents Summary Elements */

            { &hf_smf_binary_metadata,
                { "Binary metadata", "smf.binary_metadata",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},




            /* Fragments, Reassembly, Perf Tool */

            { &hf_smf_fragment_overlap,
                { "Fragment overlap", "smf.fragment.overlap",
                    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                    "Fragment overlaps with other fragments", HFILL
                    }},

            { &hf_smf_fragment_overlap_conflict,
                { "Conflicting data in fragment overlap", "smf.fragment.overlap.conflict",
                    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                    "Overlapping fragments contained conflicting data", HFILL
                    }},

            { &hf_smf_fragment_multiple_tails,
                { "Multiple tail fragments found", "smf.fragment.multipletails",
                    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                    "Several tails were found when defragmenting the packet", HFILL
                    }},

            { &hf_smf_fragment_too_long_fragment,
                { "Fragment too long", "smf.fragment.toolongfragment",
                    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                    "Fragment contained data past end of packet", HFILL
                    }},

            { &hf_smf_fragment_error,
                { "Defragmentation error", "smf.fragment.error",
                    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                    "Defragmentation error due to illegal fragments", HFILL
                    }},

            { &hf_smf_fragment,
                { "SMF Fragment", "smf.fragment",
                    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                    "SMF Fragment", HFILL
                    }},

            { &hf_smf_fragments,
                { "SMF Fragments", "smf.fragments",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "SMF Fragments", HFILL
                    }},

            { &hf_smf_reassembled_in,
                { "Reassembled SMF in frame", "smf.reassembled_in", FT_FRAMENUM,
                    BASE_NONE, NULL, 0x0,
                    "This SMF message is reassembled in this frame", HFILL
                    }},

            { &hf_smf_attachment_tooldata,
                { "Perf Tool Data", "smf.tooldata",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "Data from perf tools", HFILL
                    }},



            /* SMF Miscellaneous */
            { &hf_smf_payload,
                { "Payload", "smf.payload",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL } },

            { &hf_smf_attachment,
                { "Attachment", "smf.attachment",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_attachment_sdt,
                { "SDTItem", "smf.attachment_sdt",
                    FT_STRING, BASE_NONE, NULL, 0x00,
                    "", HFILL
                    }},

            { &hf_smf_pad_byte,
                { "Pad byte", "smf.pad_byte",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_orig_router_port_param,
                { "Originator router port", "smf.orig_router_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_dest_router_port_param,
                { "Destination router port", "smf.dest_router_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_originator_port_param,
                { "Originator port", "smf.orig_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_destination_address_param,
                { "Destination address", "smf.dest_address",
                    FT_IPv4, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_destination_port_param,
                { "Destination port", "smf.dest_port",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_unknown_param,
                { "Unrecognized parameter", "smf.unknown_param",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_topic_name_length_param,
                { "Topic name length", "smf.topic_name_length",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_queue_name_length_param,
                { "Queue name length", "smf.queue_name_length",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_cidlist_param,
                { "Consumer ID list", "smf.consumer_id_list",
                    FT_NONE, BASE_NONE, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_metadata_param,
                { "XML meta-data size", "smf.xml_metadata_size",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_xml_payload_param,
                { "XML payload size", "smf.xml_payload_size",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_cidlist_size_param,
                { "Consumer id list size", "smf.cidlist_size",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_binary_metadata_param,
                { "Binary metadata size", "smf.binary_metadata_size",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},

            { &hf_smf_cid_param,
                { "Consumer id", "smf.consumer_id",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "", HFILL
                    }},
            HF_SMF_ANALYSIS,
        };

    /* Setup protocol subtree array */
    static int *ett[] =
    {
        &ett_smf,
        &ett_message_contents_summary,
        &ett_consumer_id_list,
        &ett_smf_fragments,
        &ett_smf_fragment,
        &ett_attachment_sdt,
        &ett_smf_gen_fragment,
        &ett_smf_gen_fragments,
        &ett_smf_analysis,
        &ett_trace_span_transport_context,
        &ett_trace_span_message_creation_context
    };

    static ei_register_info ei[] = {
        EI_SMF_EXPERT_ITEM,

        { &ei_trace_span_unsupported_version,
            { "smf.trace.expert.unsupported_version", PI_PROTOCOL,
                PI_WARN, "Unsupported version for trace span", EXPFILL
                }},

        { &ei_trace_span_invalid_length,
            { "smf.trace.expert.invalid_length", PI_PROTOCOL,
                PI_WARN, "Invalid Length for trace span", EXPFILL
                }}
    };

    /* Register the protocol name and description */
    proto_smf = proto_register_protocol("Solace Message Format", "SMF", "smf");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_smf, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t* expert_smf = expert_register_protocol(proto_smf);
    expert_register_field_array(expert_smf, ei, array_length(ei));

    smf_handle = register_dissector("solace.smf", dissect_smf_tcp_pdu, proto_smf);

    register_init_routine(&smf_proto_init);

    reassembly_table_register(&smf_gen_reassembly_table, &addresses_reassembly_table_functions);
  
    smf_payload_dissector_table = register_decode_as_next_proto(proto_smf,"smf_payload_dissector_table","SMF Attachment",NULL);
    module_t* smf_module;
    smf_module = prefs_register_protocol(proto_smf, NULL);

    // Register User access table for subdissection based off topic
    static uat_field_t smf_subdissection_table_columns[] = {
        UAT_FLD_VS(smf_subdissection, match_criteria, "Match criteria", smf_subdissection_match_criteria, "Match criteria"),
        UAT_FLD_CSTRING(smf_subdissection, topic_pattern, "Topic pattern", "Pattern to match for the topic"),
        UAT_FLD_DISSECTOR(smf_subdissection, payload_proto, "Payload dissector",
                      "Dissector to be used for the message part of the matching topic"),
        UAT_FLD_CSTRING(smf_subdissection, proto_more_info, "Additional Data", "Additional Data to pass to the disector"),
        UAT_END_FIELDS
    };
    smf_subdissection_uat = uat_new("Message Decoding",
        sizeof(smf_subdissection_uat_entry_t),
        "smf_subdissection",
        true,
        &smf_subdissection_uat_entries,
        &num_smf_subdissection_uat_entries,
        UAT_AFFECTS_DISSECTION,
        NULL,
        smf_subdissection_uat_entry_copy_cb,
        smf_subdissection_uat_entry_update_cb,
        smf_subdissection_uat_entry_free_cb,
        NULL,
        NULL,
        smf_subdissection_table_columns);
    prefs_register_uat_preference(smf_module, "subdissection",
        "SMF Subdissection Table",
        "A table that maps topics to protocols used to further subdissect a message.",
        smf_subdissection_uat);

    // Register scan smf in stream
    prefs_register_bool_preference(smf_module, "scan_smf_in_stream", "Scan for SMF in TCP Stream", 
        "Scan for SMF data inside the TCP Stream. Used in packet capture with busy SMF traffic. If unselected, SMF is scanned at the beginning of each TCP packet.", &scan_smf_in_stream);

    /* Register a sample preference */
#if 0
    module_t* smf_module;

    /* Register preferences module (See Section 2.6 for more on preferences) */
    smf_module = prefs_register_protocol(proto_smf, proto_reg_handoff_smf);

    prefs_register_bool_preference(smf_module, "showHex",
        "Display numbers in Hex",
        "Enable to display numerical values in hexadecimal.",
        &gPREF_HEX);
#endif
}


static int dissect_and_reassemble_smf_over_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    int id = 0;
    int seqNum = 0;
    int parsed = 0;
    bool updateColInfo = true;
    bool needMore = true;
    uint32_t pduLen;
    tvbuff_t* newTvb;
    fragment_head* fdHead = NULL;
    bool savedFragmented = pinfo->fragmented;
    fragment_head* fragmentData =
        fragment_get(&smf_gen_reassembly_table, pinfo, id, data);
    fragment_head* assembledData =
        fragment_get_reassembled_id(&smf_gen_reassembly_table, pinfo, id);

    // Try load the uat subdissection
    try_load_smf_subdissection_uat();

    if (// If fragments were assembled in the current frame, then display the
        // assembled data
        assembledData && assembledData->reassembled_in == pinfo->fd->num)
    {
        newTvb = process_reassembled_data(tvb, 0, pinfo, "SMF Reassembled",
            assembledData, &smf_gen_frag_items, &updateColInfo, tree);

        if (newTvb)
        {
            parsed = dissect_smf_common(newTvb, pinfo, tree, -1);
            //fragment_end_seq_next(pinfo, bdChannel, fragTable, reasTable);
            //stop_smf_reas(id);
        }
        else
        {
            // Create an INFO column that resembles the one created in dissect_smf_common
            col_append_fstr(pinfo->cinfo, COL_INFO,
                "%u > %u [SMF Fragment ]", pinfo->srcport,
                pinfo->destport);
        }
    }
    else if (fragmentData)
    {
        needMore = smf_reas_add_fragment(id, tvb, pinfo, &seqNum);
        pinfo->fragmented = true;
        fdHead = fragment_add_seq_next(&smf_gen_reassembly_table, tvb, 0, pinfo, id, data,
            tvb_reported_length_remaining(tvb, 0), needMore);
        newTvb = process_reassembled_data(tvb, 0, pinfo, "SMF Backdoor", fdHead,
            &smf_frag_items, &updateColInfo, tree);
        if (newTvb)
        {
            parsed = dissect_smf_common(newTvb, pinfo, tree, -1);
            //fragment_end_seq_next(pinfo, bdChannel, fragTable, reasTable);
            //stop_smf_reas(id);
        }
        else
        {
            // Create an INFO column that resembles the one created in dissect_smf_common
            col_append_fstr(pinfo->cinfo, COL_INFO,
                "%u > %u [SMF Fragment ]", pinfo->srcport,
                pinfo->destport);
        }
    }
    else
    {
        tvbuff_t* next_tvb = tvb;
        unsigned int offset = 0;

        do
        {
            parsed = dissect_smf_common(next_tvb, pinfo, tree, -1);

            if (parsed < 0)
            {
                pduLen = test_smf(next_tvb, pinfo, offset);
                if (pduLen >= MIN_SMF_HEADER_LEN)
                {
                    //start_smf_reas(next_tvb, pinfo, id, pduLen);
                    pinfo->fragmented = true;
                    fragment_add_seq(&smf_gen_reassembly_table, next_tvb, 0, pinfo, id,
                        data, 0, tvb_reported_length_remaining(next_tvb, 0), true, 0);
                    // Create an INFO column that resembles the one
                    // created in dissect_smf_common
                    col_append_fstr(pinfo->cinfo, COL_INFO,
                        "%u > %u [SMF Fragment ]",
                        pinfo->srcport, pinfo->destport);
                }
                else
                {
                    // Create an INFO column that resembles the one created in dissect_smf_common
                    col_append_fstr(
                        pinfo->cinfo,
                        COL_INFO,
                        "%u > %u [SMF Fragment ] ***** Can't extract message length!!",
                        pinfo->srcport, pinfo->destport);
                }
            }
            else
            {
                offset += parsed;
                if (offset > tvb_captured_length(tvb)) {
                    // Too far off. Possibly due to caplen
                    offset = tvb_captured_length(tvb);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "[Partial SMF]");
                }
                next_tvb = tvb_new_subset_length_caplen(tvb,
                    offset,
                    -1,
                    tvb_captured_length(tvb) - offset);
            }
        } while (parsed > 0 && tvb_captured_length(next_tvb) > 6);
    }

    pinfo->fragmented = savedFragmented;



    return tvb_captured_length(tvb);



}




/* The following function is a hack. This function calls dissect_smf_common from within this file, which is necessary since dissect_smf_common is a static function (see Microsoft error C2129).
 * dissect_smf_common needs to be called from sdt-decoder.c in order to dissect SMF messages that are embedded in a binary attachment. This function acts as a proxy so that sdt-decoder.c can
 * call dissect_smf_common indirectly.*/
void call_dissect_smf_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int bdChannel)
{
    dissect_smf_common(tvb, pinfo, tree, bdChannel);
}

/* Dissect an SMF packet over UDP */
static int dissect_smf_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{


#if 0
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMF");
#endif
    dissect_smf_common(tvb, pinfo, tree, -1);



    return tvb_captured_length(tvb);
}

/* Dissect an SMF packet in a reassembled TCP PDU */
static int dissect_smf_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data _U_)
{


#if 0
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMF");
#endif
    //dissect_smf_common(tvb, pinfo, tree, -1);
    //dissect_and_reassemble_smf_over_tls(tvb, pinfo, tree, data);
   tcp_dissect_pdus(tvb, pinfo, tree, smf_desegment, MIN_SMF_HEADER_LEN, get_smf_pdu_len,
        dissect_and_reassemble_smf_over_tls, data);

    return tvb_captured_length(tvb);
}

/* Reassemble and dissect an SMF packet over TCP */
static int dissect_smf_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, smf_desegment, MIN_SMF_HEADER_LEN, get_smf_pdu_len,
            dissect_smf_tcp_pdu, data);


    return tvb_captured_length(tvb);
}

static bool dissect_smf_heur_ws(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    if (test_smf(tvb, pinfo, 0) < MIN_SMF_HEADER_LEN)
    {
        return false;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, smf_desegment, MIN_SMF_HEADER_LEN, get_smf_pdu_len,
        dissect_smf_tcp_pdu, data);

    return true;
}

static bool dissect_smf_heur_http(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    if (test_smf(tvb, pinfo, 0) < MIN_SMF_HEADER_LEN)
    {
        return false;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, smf_desegment, MIN_SMF_HEADER_LEN, get_smf_pdu_len,
        dissect_smf_tcp_pdu, data);

    return true;
}

static bool dissect_smf_heur_tls(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    if (test_smf(tvb, pinfo, 0) < MIN_SMF_HEADER_LEN)
    {
        return false;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, smf_desegment, MIN_SMF_HEADER_LEN, get_smf_pdu_len,
        dissect_smf_tcp_pdu, data);

    return true;
}

/* Dissect an SMF packet over the backdoor bus. These appear as SMF
 messages encapsulated within Ethernet frames. The Ethernet header
 of a Backdoor frame is formatted as follows:

 Dst MAC    0xba:0xcd:00:<dir>:<channelNum_hi>:<channelNum_lo>
 Src MAX    0xba:0xcd:00:<dir>:<channelNum_hi>:<channelNum_lo>
 Ethertype  0xbacd

 Where <dir> identifies the direction the frame is being passed
 across the bus:
 0x1c - from linecard to control card
 0xcc - from control card to linecard

 The values of <channelNum_hi> and <channelNum_lo> when concatenated
 yield a 10 bit number indicating the DMA channel in use.

 */
static int dissect_smf_bd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{


    int seqNum = 0;
    int bdChannel = get_smf_bd_channel(pinfo);
    int parsed = 0;
    bool updateColInfo = true;
    bool needMore = true;
    uint32_t pduLen;
    tvbuff_t *newTvb;
    fragment_head *fdHead = NULL;
    bool savedFragmented = pinfo->fragmented;
    fragment_head *fragmentData =
        fragment_get(&reasTable, pinfo, bdChannel, data);
    fragment_head *assembledData =
        fragment_get_reassembled_id(&reasTable, pinfo, bdChannel);

    if (bdChannel < 0)
        /*dissectors started returning ints instead of returning nothing at all.
        Not sure if returning -1 will break anything, but using as placeholder for now.*/
        return -1;

    if (/* If fragments were assembled in the current frame, then display the
           assembled data */
        assembledData && assembledData->reassembled_in == pinfo->fd->num)
    {
        newTvb = process_reassembled_data(tvb, 0, pinfo, "SMF Backdoor",
            assembledData, &smf_frag_items, &updateColInfo, tree);

        if (newTvb)
        {
            parsed = dissect_smf_common(newTvb, pinfo, tree, bdChannel);
            //fragment_end_seq_next(pinfo, bdChannel, fragTable, reasTable);
            stop_smf_reas(bdChannel);
        }
        else
        {
            // Create an INFO column that resembles the one created in dissect_smf_common
            col_append_fstr(pinfo->cinfo, COL_INFO,
                "%u > %u [SMF Fragment ] Backdoor=%d", pinfo->srcport,
                pinfo->destport, bdChannel);
        }
    }
    else if (fragmentData)
    {
        needMore = smf_reas_add_fragment(bdChannel, tvb, pinfo, &seqNum);
        pinfo->fragmented = true;
        fdHead = fragment_add_seq_next(&reasTable, tvb, 0, pinfo, bdChannel, data,
            tvb_reported_length_remaining(tvb, 0), needMore);
        newTvb = process_reassembled_data(tvb, 0, pinfo, "SMF Backdoor", fdHead,
            &smf_frag_items, &updateColInfo, tree);
        if (newTvb)
        {
            parsed = dissect_smf_common(newTvb, pinfo, tree, bdChannel);
            //fragment_end_seq_next(pinfo, bdChannel, fragTable, reasTable);
            stop_smf_reas(bdChannel);
        }
        else
        {
            // Create an INFO column that resembles the one created in dissect_smf_common
            col_append_fstr(pinfo->cinfo, COL_INFO,
                "%u > %u [SMF Fragment ] Backdoor=%d", pinfo->srcport,
                pinfo->destport, bdChannel);
        }
    }
    else
    {
        tvbuff_t *next_tvb = tvb;
        unsigned int offset = 0;

        do
        {
            parsed = dissect_smf_common(next_tvb, pinfo, tree, bdChannel);

            if (parsed < 0)
            {
                void* randomPointer=NULL;
                pduLen = get_smf_pdu_len(pinfo, next_tvb, 0, randomPointer);
                if (pduLen > 0)
                {
                    start_smf_reas(next_tvb, pinfo, bdChannel, pduLen);
                    pinfo->fragmented = true;
                    fragment_add_seq(&reasTable, next_tvb, 0, pinfo, bdChannel,
                        data, 0, tvb_reported_length_remaining(next_tvb, 0), true, 0);
                    // Create an INFO column that resembles the one
                    // created in dissect_smf_common
                    col_append_fstr(pinfo->cinfo, COL_INFO,
                        "%u > %u [SMF Fragment ] Backdoor=%d",
                        pinfo->srcport, pinfo->destport, bdChannel);
                }
                else
                {
                    // Create an INFO column that resembles the one created in dissect_smf_common
                    col_append_fstr(
                        pinfo->cinfo,
                        COL_INFO,
                        "%u > %u [SMF Fragment ] Backdoor=%d ***** Can't extract message length!!",
                        pinfo->srcport, pinfo->destport, bdChannel);
                }
            }
            else
            {
                offset += parsed;
                next_tvb = tvb_new_subset_length_caplen(tvb,
                    offset,
                    -1,
                    tvb_captured_length(tvb) - offset);
            }
        } while(parsed > 0 && tvb_captured_length(next_tvb) > 6);
    }

    pinfo->fragmented = savedFragmented;



    return tvb_captured_length(tvb);
}

static const char* get_env(const char* varName) {
    const char* val = getenv( varName);
    if (val == 0 ) {
        return "";
    } else
    {
        return val;
    }
}

static void smf_proto_init(void)
{
    if (strcmp(get_env("WS_EXTRACT_AD_MSG_ID"), "1")==0) {
        extractAdMsgId = true;
    }

    smf_reas_init();
}

/* If this dissector uses sub-dissector registration add a registration routine.
 This exact format is required because a script is used to find these routines
 and create the code that calls these routines.

 This function is also called by preferences whenever "Apply" is pressed
 (see prefs_register_protocol above) so it should accommodate being called
 more than once.
 */
void proto_reg_handoff_smf(void)
{
    static bool inited = false;

    if (!inited)
    {
        // dissector_handle_t smf_rtg_tcp_handle;
        dissector_handle_t smf_udp_handle;
        dissector_handle_t smf_bd_handle;
        dissector_handle_t smf_tcp_handle;

        smf_tcp_handle = create_dissector_handle(dissect_smf_tcp, proto_smf);
        // smf_rtg_tcp_handle = create_dissector_handle(dissect_smf_tcp, proto_smf);
        smf_udp_handle = create_dissector_handle(dissect_smf_udp, proto_smf);
        smf_bd_handle = create_dissector_handle(dissect_smf_bd, proto_smf);

        dissector_add_uint("tcp.port", global_smf_port, smf_tcp_handle);
        dissector_add_uint("tcp.port", global_smf_rtg_port, smf_tcp_handle);
        dissector_add_uint("udp.port", global_smf_port, smf_udp_handle);
        dissector_add_uint("ethertype", ETHERTYPE_SMF_BACKDOOR, smf_bd_handle);
        heur_dissector_add("ws", dissect_smf_heur_ws, "SMF over Web-Socket", "smf_ws", proto_smf, (heuristic_enable_e)true);
        heur_dissector_add("http", dissect_smf_heur_http, "SMF over HTTP", "smf_http", proto_smf, (heuristic_enable_e)true);
        heur_dissector_add("tls", dissect_smf_heur_tls, "SMF over TLS/SSL", "smf_tls", proto_smf, (heuristic_enable_e)true);

        xml_handle = find_dissector("xml");
        pubctrl_handle = find_dissector("solace.pubctrl");
        subctrl_handle = find_dissector("solace.subctrl");
        xmllink_handle = find_dissector("solace.xmllink");
        assuredctrl_handle = find_dissector("solace.assuredctrl");
        smp_handle = find_dissector("solace.smp");
        smrp_handle = find_dissector("solace.smrp");
        clientctrl_handle = find_dissector("solace.clientctrl");
        bm_handle = find_dissector("solace.smf-bm");
        mama_payload_handle = find_dissector("solace.mama-payload");
        protobuf_handle = find_dissector("protobuf");
        dissector_add_for_decode_as("smf_payload_dissector_table", protobuf_handle);
        smf_reas_init();
        sdt_decoder_init();
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
     dissector_delete("tcp.port", currentPort, smf_handle);
     }

     currentPort = gPortPref;

     dissector_add("tcp.port", currentPort, smf_handle);

     */
}
