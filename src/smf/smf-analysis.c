/* smf-analysis.c
 * Routines for Solace Message Format analysis
 * Copyright 2021, Solace Corporation
 *
 * $Id: smf-analysis.c $
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
#include <epan/proto_data.h>
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
#include <inttypes.h>

#include "packet-smf.h"
#include "smf-analysis.h"
#include "sdt-decoder.h"
#include <epan/column-info.h>

int hf_smf_analysis = -1;
int hf_smf_analysis_flow_type = -1;
int hf_smf_analysis_msg_in_transport = -1;
int hf_smf_analysis_msg_unacked = -1;
int hf_smf_analysis_prev_handshake_frame = -1;
int hf_smf_analysis_transport_window = -1;
int ett_smf_analysis = -1;

expert_field ei_smf_expert_transport_window_full = EI_INIT;
expert_field ei_smf_expert_max_delivered_unacked_msgs = EI_INIT;

int hf_assuredctrl_smf_analysis = -1;
int hf_assuredctrl_smf_analysis_transaction_flow_id = -1;
int hf_assuredctrl_smf_analysis_num_msg_in_transport = -1;
int hf_assuredctrl_smf_analysis_num_msg_unacked = -1;
int hf_assuredctrl_smf_analysis_num_msg_transport_acked = -1;
int hf_assuredctrl_smf_analysis_min_transport_time = -1;
int hf_assuredctrl_smf_analysis_max_transport_time = -1;
int hf_assuredctrl_smf_analysis_num_msg_transaction_ctrl = -1;
int hf_assuredctrl_smf_analysis_num_msg_app_acked = -1;
int hf_assuredctrl_smf_analysis_transport_acked_id = -1;
int hf_assuredctrl_smf_analysis_transaction_ctrl_id = -1;
int hf_assuredctrl_smf_analysis_app_acked_id = -1;
int ett_assuredctrl_analysis = -1;

// This structure stores infromation about this particular message
// that cannot be worked out by the message alone.
// It is safed in the conversation
typedef struct _smf_analysis_buf_t {
    // Collected info
    // It is not nessary to store this info.
    // It is here for convinence instead of parameter passing.
    uint64_t ad_msg_id_m;
    int isFlowIdKnown_m;
    uint32_t ad_flow_id_m;
    
    // Analysised info
    uint32_t numMsgInTransport_m; // This is the number of messages still in the transport window.
    uint32_t numUnackedMsg_m; // This is the number of messages unack by the application.
    int isTransportWindownKnown_m;
    uint32_t transport_window_size_m; // Available transport window
    uint32_t transport_ack_frame_m;
} smf_analysis_buf_t;

// DOTO: Remove
// This structure stores infromation about this particular assuredctrl message
// The first part are collected paramters.
// The second part are analysed data.
typedef struct _smf_analysis_assuredctrl_buf_t {
    // Collected info
    int isFlowIdKnown_m;
    uint32_t ad_flow_id_m;

    // Analysised info
    uint32_t numTransportMsg_m; // This is the number of transport messages acknowledged by this message.
    uint32_t numMsgInTransport_m; // This is the number of messages still in the transport window. 
    wmem_list_t *transportAckList_m;
    uint32_t numAckedMsg_m;   // This is the number of messages App acked by this message.
    uint32_t numUnackedMsg_m; // This is the number of messages unack by the application.
    nstime_t min_transdeltatime_m;
    nstime_t max_transdeltatime_m;
    wmem_list_t *appAckList_m;
    wmem_list_t *transactionAckList_m;
} smf_analysis_assuredctrl_buf_t;

// Helper functions to get SMF Protocol int
static int getSmfProto(void) {
    static int proto_smf_s = -1;
    if (-1 == proto_smf_s) {
        proto_smf_s = proto_get_id_by_short_name("smf");
    }
    return proto_smf_s;
}

// Helper functions to get SMF Protocol int
static int getAssuredCtrlProto(void) {
    static int proto_assuredctrl_s = -1;
    if (-1 == proto_assuredctrl_s) {
        proto_assuredctrl_s = proto_get_id_by_short_name("AssuredCtrl");
    }
    return proto_assuredctrl_s;
}

// Helper functions to get the protocol data per message location
static smf_analysis_buf_t* getSmfAnalysisProtoData(tvbuff_t* tvb, packet_info* pinfo) {
    int proto_smf = getSmfProto();
    smf_analysis_buf_t *smf_analysis_buf_p = 
        (smf_analysis_buf_t *)p_get_proto_data(
            wmem_file_scope(), 
            pinfo,
            proto_smf, 
            (uint32_t)tvb_raw_offset(tvb));
    if (NULL == smf_analysis_buf_p) {
        smf_analysis_buf_p = wmem_new0(wmem_file_scope(), smf_analysis_buf_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_smf,
                (uint32_t)tvb_raw_offset(tvb), smf_analysis_buf_p);
        
    }
    return smf_analysis_buf_p;
}

// Helper functions to get the AssuredCtrl protocol data per message location
static smf_analysis_assuredctrl_buf_t* getAssuredCtrlAnalysisProtoData(tvbuff_t* tvb, packet_info* pinfo) {
    int proto_assuredctrl = getAssuredCtrlProto();
    smf_analysis_assuredctrl_buf_t *smf_analysis_assuredctrl_buf_p = 
        (smf_analysis_assuredctrl_buf_t *)p_get_proto_data(
            wmem_file_scope(), 
            pinfo,
            proto_assuredctrl, 
            (uint32_t)tvb_raw_offset(tvb));
    if (NULL == smf_analysis_assuredctrl_buf_p) {
        smf_analysis_assuredctrl_buf_p = wmem_new0(wmem_file_scope(), smf_analysis_assuredctrl_buf_t);
        smf_analysis_assuredctrl_buf_p->transportAckList_m = wmem_list_new(wmem_file_scope());
        smf_analysis_assuredctrl_buf_p->appAckList_m = wmem_list_new(wmem_file_scope());
        smf_analysis_assuredctrl_buf_p->transactionAckList_m = wmem_list_new(wmem_file_scope());
        nstime_set_unset(&smf_analysis_assuredctrl_buf_p->min_transdeltatime_m);
        nstime_set_unset(&smf_analysis_assuredctrl_buf_p->max_transdeltatime_m);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_assuredctrl,
                (uint32_t)tvb_raw_offset(tvb), smf_analysis_assuredctrl_buf_p);
    }
    return smf_analysis_assuredctrl_buf_p;
}

//*************************************************
// Structure used in parsing the flow conversation
//*************************************************
// structure about each message
typedef struct _smf_ad_msg_t {
    uint64_t msg_id_m;
    uint32_t frame_m;
    nstime_t time_m;
} smf_ad_msg_t;

static smf_ad_msg_t* create_msg(uint64_t msg_id_m) {
    smf_ad_msg_t *msg_p = wmem_new0(wmem_file_scope(), smf_ad_msg_t);
    msg_p->msg_id_m = msg_id_m;
    return msg_p;
}

static void putMsgIntoList(wmem_list_t *appAckList_p, smf_ad_msg_t *ad_msg) {
    wmem_list_append(appAckList_p, ad_msg);
}

// Transaction Ack list structure
typedef struct _trans_ack_msg_t {
    // Collected info
    uint32_t ad_flow_id_m;
    uint32_t messageCount_m;

    // Analysised info
    uint32_t numTransportMsg_m; // This is the number of transport messages acknowledged by this message.
    uint32_t numMsgInTransport_m; // This is the number of messages still in the transport window. 
    wmem_list_t *transportAckList_m;
    uint32_t numAckedMsg_m;   // This is the number of messages App acked by this message.
    uint32_t numUnackedMsg_m; // This is the number of messages unack by the application.
    wmem_list_t *appAckList_m;
} trans_ack_msg_t;

static trans_ack_msg_t* create_trans_ack_msg(uint32_t flow_id) {
    trans_ack_msg_t *msg_p = wmem_new0(wmem_file_scope(), trans_ack_msg_t);
    msg_p->ad_flow_id_m = flow_id;
    msg_p->transportAckList_m = wmem_list_new(wmem_file_scope());
    msg_p->appAckList_m = wmem_list_new(wmem_file_scope());
    return msg_p;
}

static void putTransIntoList(wmem_list_t *transList_p, trans_ack_msg_t *trans_ack_msg) {
    wmem_list_append(transList_p, trans_ack_msg);
}

typedef struct _smf_flow_t {
    uint32_t flow_id_m;
    int isFlowTypeKnown_m;
    int flowType_m;
    int isCombinedTransportAppAck_m; // Transport and App Ack are combined?
    int32_t maxDeliveredUnackedMsgsPerFlow_m;
    int isTransportWindownKnown_m;
    uint32_t transport_window_size_m; // Transport window available
    uint32_t transport_ack_frame_m;
    int numMsgInTransport_m; // Number of messages in Transport
    int numMsgUnacked_m;
    wmem_list_t *msgsInTransport_m;
    wmem_list_t *msgsUnacked_m;
} smf_flow_t;

static void init_smf_flow(smf_flow_t *flow_p, uint32_t flow_id) {
    flow_p->flow_id_m = flow_id;
    flow_p->maxDeliveredUnackedMsgsPerFlow_m = -1;
    flow_p->msgsInTransport_m = wmem_list_new(wmem_file_scope());
    flow_p->msgsUnacked_m = wmem_list_new(wmem_file_scope());
    // No need to touch the other fields since the should be zeroed at alloc
} 

static void insert_msg(smf_flow_t *flow_p, smf_ad_msg_t *msg) {
    flow_p->numMsgInTransport_m++;
    wmem_list_append(flow_p->msgsInTransport_m, msg);
    if (!flow_p->isCombinedTransportAppAck_m) { // This flow has the potential for separate application ack
        flow_p->numMsgUnacked_m++;
        wmem_list_append(flow_p->msgsUnacked_m, msg);
    }
}

typedef struct _smf_stream_t {
    // We store all the analysed information here
    wmem_tree_t *flows;
    // If this is an ack, the list of Messages that are transport acknowledged
    // The list of messages that are Applicationed acknowledged
} smf_stream_t;

static void init_smf_stream(smf_stream_t *stream_p) {
    stream_p->flows = wmem_tree_new(wmem_file_scope());
}

static smf_flow_t* find_or_create_smf_flow(smf_stream_t *stream_p, uint32_t flow_id) {
    smf_flow_t *flow_p = (smf_flow_t *)wmem_tree_lookup32(stream_p->flows, flow_id);
    if (flow_p != NULL) {
        if (flow_id == flow_p->flow_id_m) {
            return flow_p;
        }
    }
    // Create a new flow
    flow_p = wmem_new0(wmem_file_scope(), smf_flow_t);
    init_smf_flow(flow_p, flow_id);
    wmem_tree_insert32(stream_p->flows, flow_id, flow_p);
    return flow_p;
}

typedef struct _smf_conv_t {
	/* These two structs are managed based on comparing the source
	 * and destination addresses and, if they're equal, comparing
	 * the source and destination ports.
	 *
	 * If the source is greater than the destination, then stuff
	 * sent from src is in stream1.
	 *
	 * If the source is less than the destination, then stuff
	 * sent from src is in stream2.
	 *
	 * XXX - if the addresses and ports are equal, we don't guarantee
	 * the behavior.
	 */
    smf_stream_t stream1;
    smf_stream_t stream2;
} smf_conv_t;

void init_smf_conv(smf_conv_t *smf_conv_p) {
    init_smf_stream(&smf_conv_p->stream1);
    init_smf_stream(&smf_conv_p->stream2);
}

// Save the parameters that we are interested in
void smf_analysis_param(tvbuff_t *tvb, packet_info *pinfo, uint8_t param_type, int offset) {
    smf_analysis_buf_t *smf_analysis_buf_p = getSmfAnalysisProtoData(tvb, pinfo);
    switch (param_type) 
    {
        case 0x11: // Assured Delivery Message Id
        {            
            smf_analysis_buf_p->ad_msg_id_m = tvb_get_uint64(tvb, offset, false);
            break;
        }
        case 0x17: // Assured Delivery Flow Id
        {
            smf_analysis_buf_p->isFlowIdKnown_m = 1;
            smf_analysis_buf_p->ad_flow_id_m = tvb_get_uint32(tvb, offset, false);
            break;
        }
        default:
            break;
    }
}

static smf_stream_t* smf_analysis_get_stream(packet_info *pinfo, int direction) {
    conversation_t *conv;
    smf_conv_t *smf_conv;
    smf_stream_t *forward_stream_p, *backward_stream_p;
    conv = find_or_create_conversation(pinfo);
    int proto_smf = getSmfProto();
    smf_conv = (smf_conv_t *)conversation_get_proto_data(conv, proto_smf);
    if (!smf_conv) {
        // This is the first time.
        // Initialize the conversation
        smf_conv = wmem_new0(wmem_file_scope(), smf_conv_t);
        init_smf_conv(smf_conv);
        conversation_add_proto_data(conv, proto_smf, smf_conv);
    }
     /* check direction */
    int packet_direction=cmp_address(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if(packet_direction==0) {
        packet_direction = (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }
    if(packet_direction>=0) {
        forward_stream_p = &smf_conv->stream1;
        backward_stream_p = &smf_conv->stream2;
    } else {
        forward_stream_p = &smf_conv->stream2;
        backward_stream_p = &smf_conv->stream1;
    }
    if (direction >= 0) {
        return forward_stream_p;
    } else {
        return backward_stream_p;
    }
}

// Provide analysis information in SMF
int smf_analysis(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    smf_stream_t *currentStream_p;

    uint8_t firstByte = tvb_get_uint8(tvb, 0);
    bool adflag = (firstByte & 0x10); // AD flag
    currentStream_p = smf_analysis_get_stream(pinfo, 1 /* forward */);

    smf_analysis_buf_t *smf_analysis_buf_p = getSmfAnalysisProtoData(tvb, pinfo);
    if (!PINFO_FD_VISITED(pinfo)) {
        if (adflag) // AD flag
        {
            // Process the AD message
            // Get flow id
            if (!((smf_analysis_buf_p->ad_msg_id_m) && (smf_analysis_buf_p->isFlowIdKnown_m))) {
                // This is an AD message without AD information
                // This could be a transaction message
                // g_print("Ad Message without a flow or message id. Packet: %d, Flow: %d, Msg Id: %ld", 
                //    pinfo->fd->num, smf_analysis_buf_p->ad_flow_id_m, smf_analysis_buf_p->ad_msg_id_m);
                return 0;
            }

            // Add the message to the flow
            smf_flow_t *smf_flow_p = find_or_create_smf_flow(currentStream_p, smf_analysis_buf_p->ad_flow_id_m);
            smf_ad_msg_t *smf_msg_p = create_msg(smf_analysis_buf_p->ad_msg_id_m);
            smf_msg_p->frame_m = pinfo->fd->num;
            smf_msg_p->time_m = pinfo->abs_ts;
            insert_msg(smf_flow_p, smf_msg_p);

            // Safe the count in the smf analysis.
            smf_analysis_buf_p->numMsgInTransport_m = smf_flow_p->numMsgInTransport_m;
            smf_analysis_buf_p->numUnackedMsg_m = smf_flow_p->numMsgUnacked_m;
            smf_analysis_buf_p->isTransportWindownKnown_m = smf_flow_p->isTransportWindownKnown_m;
            smf_analysis_buf_p->transport_window_size_m = smf_flow_p->transport_window_size_m;
            smf_analysis_buf_p->transport_ack_frame_m = smf_flow_p->transport_ack_frame_m;
        }
    }

    if (adflag && smf_analysis_buf_p->isFlowIdKnown_m) {
        smf_flow_t *smf_flow_p = find_or_create_smf_flow(currentStream_p, smf_analysis_buf_p->ad_flow_id_m);
        // Put the analysis in the tree
        proto_item *item = proto_tree_add_item(tree, hf_smf_analysis, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(item);
        proto_tree *flags_tree = proto_item_add_subtree(item, ett_smf_analysis);

        if (smf_flow_p->isFlowTypeKnown_m) {
            char *flow_type_name_p = "";
            switch (smf_flow_p->flowType_m) {
                case 0x00:
                    flow_type_name_p = "OpenFlow";
                    break;
                case 0x04:
                    flow_type_name_p = "Bind";
                    break;
                default:
                    flow_type_name_p = "Unknown";
                    break;
            }
            item = proto_tree_add_string(flags_tree, hf_smf_analysis_flow_type,
                                    tvb, 0, 0, flow_type_name_p);
            proto_item_set_generated(item);
        }

        if (smf_analysis_buf_p->isTransportWindownKnown_m) {
            item = proto_tree_add_uint(flags_tree, hf_smf_analysis_transport_window,
                                    tvb, 0, 0, smf_analysis_buf_p->transport_window_size_m);
            proto_item_set_generated(item);
            item = proto_tree_add_uint(flags_tree, hf_smf_analysis_prev_handshake_frame,
                                    tvb, 0, 0, smf_analysis_buf_p->transport_ack_frame_m);
            proto_item_set_generated(item);         
        }
        item = proto_tree_add_uint(flags_tree, hf_smf_analysis_msg_in_transport,
                                tvb, 0, 0, smf_analysis_buf_p->numMsgInTransport_m);
        if (smf_analysis_buf_p->isTransportWindownKnown_m) {
            if (smf_analysis_buf_p->transport_window_size_m == smf_analysis_buf_p->numMsgInTransport_m) {
                expert_add_info(pinfo, item, &ei_smf_expert_transport_window_full);
                col_append_fstr(pinfo->cinfo, COL_INFO, "[Transport Window Full] ");
            }
        }
        proto_item_set_generated(item);
        item = proto_tree_add_uint(flags_tree, hf_smf_analysis_msg_unacked,
                                tvb, 0, 0, smf_analysis_buf_p->numUnackedMsg_m);
        if (smf_flow_p->maxDeliveredUnackedMsgsPerFlow_m != -1) {
            if (smf_analysis_buf_p->numUnackedMsg_m == (uint32_t)smf_flow_p->maxDeliveredUnackedMsgsPerFlow_m) {
                expert_add_info(pinfo, item, &ei_smf_expert_max_delivered_unacked_msgs);
                col_append_fstr(pinfo->cinfo, COL_INFO, "[MaxDeliveredUnackedMsgs reached]  ");            
            }
        }
        proto_item_set_generated(item);

    }
    return 0;
}

void smf_analysis_assuredctrl_param(tvbuff_t *tvb, packet_info* pinfo, uint8_t param_type, int offset, int size) {
    // The flow information is stored in the reverse direction relative to the ack message
    smf_stream_t *forwardStream_p = smf_analysis_get_stream(pinfo, 1 /* forward stream */);
    smf_stream_t *reverseStream_p = smf_analysis_get_stream(pinfo, -1 /* reverse stream */);
    smf_analysis_assuredctrl_buf_t *smf_analysis_assuredctrl_buf_p = getAssuredCtrlAnalysisProtoData(tvb, pinfo);

    if (!PINFO_FD_VISITED(pinfo)) {
        int version = (tvb_get_uint8(tvb, 0) & 0x3f);
        int msg_type;
        if (version < 3) { 
            msg_type = (tvb_get_uint8(tvb, 1) & 0xf0) >> 4; 
        } else { 
            msg_type = tvb_get_uint8(tvb, 1); 
        }
        switch (param_type) {
            case 0x02:  { // ASSUREDCTRL_LAST_MSGID_ACKED_PARAM
                // Determine how many messages are removed from transport
                // Put this in a transport list in smf_analysis_buf_p
                uint64_t last_msgid_acked = tvb_get_uint64(tvb, offset, false);
                smf_flow_t *smf_flow_p;
                wmem_list_frame_t *frame_p;
                nstime_t min_transdeltatime = {INT_MAX-1, 0};
                nstime_t max_transdeltatime = NSTIME_INIT_ZERO;

                if (0 == smf_analysis_assuredctrl_buf_p->isFlowIdKnown_m) {
                    // There is no flow id in this message
                    // This is possible in a bind message where the queue is indicated
                    // and the last message id acked is indicated.
                    if (0x03 == msg_type) { // It is client ack message type
                        g_print("No flow id in Client Ack packet %d\n", pinfo->fd->num);
                    }
                    break;
                }

                smf_flow_p = find_or_create_smf_flow(reverseStream_p, smf_analysis_assuredctrl_buf_p->ad_flow_id_m);
                frame_p = wmem_list_head(smf_flow_p->msgsInTransport_m);
                while ((frame_p != NULL) && 
                       (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m <= last_msgid_acked)) {
                    smf_ad_msg_t *ad_msg_p = (smf_ad_msg_t *)(wmem_list_frame_data(frame_p));
                    putMsgIntoList(smf_analysis_assuredctrl_buf_p->transportAckList_m, (smf_ad_msg_t *)wmem_list_frame_data(frame_p));
                    smf_analysis_assuredctrl_buf_p->numTransportMsg_m++;
                    smf_flow_p->numMsgInTransport_m--;

                    nstime_t cur_deltatime;
                    nstime_delta(&cur_deltatime, &pinfo->abs_ts, &ad_msg_p->time_m);
                    if (nstime_cmp(&cur_deltatime, &min_transdeltatime) < 0) {
                        nstime_copy(&min_transdeltatime, &cur_deltatime);
                    }
                    if (nstime_cmp(&cur_deltatime, &max_transdeltatime) > 0) {
                        nstime_copy(&max_transdeltatime, &cur_deltatime);
                    }

                    wmem_list_frame_t *nextFrame_p = wmem_list_frame_next(frame_p);
                    wmem_list_remove_frame(smf_flow_p->msgsInTransport_m, frame_p);
                    frame_p = nextFrame_p;
                }
                smf_analysis_assuredctrl_buf_p->numMsgInTransport_m = smf_flow_p->numMsgInTransport_m;
                smf_analysis_assuredctrl_buf_p->numUnackedMsg_m = smf_flow_p->numMsgUnacked_m;
                nstime_copy(&smf_analysis_assuredctrl_buf_p->min_transdeltatime_m, &min_transdeltatime);
                nstime_copy(&smf_analysis_assuredctrl_buf_p->max_transdeltatime_m, &max_transdeltatime);
                break;
            }
            case 0x03: //ASSUREDCTRL_WINDOW_SIZE_PARAM
            {
                smf_flow_t *smf_flow_p;
                if (0 == smf_analysis_assuredctrl_buf_p->isFlowIdKnown_m) {
                    switch (msg_type) {
                    case 0x00: // Open flow
                    case 0x04: // Bind
                        // No flow is expected. It is OK.
                        break;
                    case 0x03: // Client Ack
                        g_print("No flow id in Client Ack packet %d. Type is 0x%x.\n", pinfo->fd->num, msg_type);
                        break;
                    default:
                        g_print("No flow id in packet %d. Type is 0x%x.\n", pinfo->fd->num, msg_type);
                    }
                    break;
                }
                smf_flow_p = find_or_create_smf_flow(reverseStream_p, smf_analysis_assuredctrl_buf_p->ad_flow_id_m);
                smf_flow_p->isTransportWindownKnown_m = 1;
                smf_flow_p->transport_window_size_m = tvb_get_uint8(tvb, offset);
                smf_flow_p->transport_ack_frame_m = pinfo->fd->num;
                break;
            }
            case 0x05: { // ASSUREDCTRL_APPLICATION_ACK_PARAM
                // Determine how many messages are acked and remove from unacked list
                // Put this in an ack list in smf_analysis_buf_p
                uint64_t ack_min_id = tvb_get_uint64(tvb, offset, false);
                uint64_t ack_max_id = tvb_get_uint64(tvb, offset+8, false);
                smf_flow_t *smf_flow_p;
                wmem_list_frame_t *frame_p;
                if (0 == smf_analysis_assuredctrl_buf_p->isFlowIdKnown_m) {
                    if (0x03 == msg_type) { // It is client ack message type
                        g_print("No flow id in Client Ack packet %d\n", pinfo->fd->num);
                    } else if (0x0d == msg_type) { // ExternalAck
                        // External acks are used in DR. There is no flow id.
                    } else {
                        g_print("No flow id in packet %d\n", pinfo->fd->num);
                    }
                    break;
                }
                smf_flow_p = find_or_create_smf_flow(reverseStream_p, smf_analysis_assuredctrl_buf_p->ad_flow_id_m);
                frame_p = wmem_list_head(smf_flow_p->msgsUnacked_m);
                while ((frame_p != NULL) && 
                       (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m < ack_min_id)) {
                    frame_p = wmem_list_frame_next(frame_p);
                }
                while ((frame_p != NULL) && 
                       (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m <= ack_max_id)) {
                    putMsgIntoList(smf_analysis_assuredctrl_buf_p->appAckList_m, (smf_ad_msg_t *)wmem_list_frame_data(frame_p));
                    smf_analysis_assuredctrl_buf_p->numAckedMsg_m++;
                    smf_flow_p->numMsgUnacked_m--;
                    wmem_list_frame_t *nextFrame_p = wmem_list_frame_next(frame_p);
                    wmem_list_remove_frame(smf_flow_p->msgsUnacked_m, frame_p);
                    frame_p = nextFrame_p;
                }
                smf_analysis_assuredctrl_buf_p->numMsgInTransport_m = smf_flow_p->numMsgInTransport_m;
                smf_analysis_assuredctrl_buf_p->numUnackedMsg_m = smf_flow_p->numMsgUnacked_m;
                break;
            }
            case 0x06: { // ASSUREDCTRL_FLOWID_PARAM
                smf_flow_t *smf_flow_p;
                smf_analysis_assuredctrl_buf_p->isFlowIdKnown_m = 1;
                smf_analysis_assuredctrl_buf_p->ad_flow_id_m = tvb_get_uint32(tvb, offset, false);

                // Determine if this is a bind (to an endpoint). If it is NOT a bind, then no applicaiton ack is needed.
                switch (msg_type) { 
                    case 0x00: // OpenFlow (Ack, because there is a flow id param)
                        smf_flow_p = find_or_create_smf_flow(reverseStream_p, smf_analysis_assuredctrl_buf_p->ad_flow_id_m);
                        smf_flow_p->isFlowTypeKnown_m = 1;
                        smf_flow_p->flowType_m = msg_type;
                        smf_flow_p->isCombinedTransportAppAck_m = 1;
                        break;
                    case 0x04: // Bind (Ack, because there is a flow id param)
                        smf_flow_p = find_or_create_smf_flow(forwardStream_p, smf_analysis_assuredctrl_buf_p->ad_flow_id_m);
                        smf_flow_p->isFlowTypeKnown_m = 1;
                        smf_flow_p->flowType_m = msg_type;
                        smf_flow_p->isCombinedTransportAppAck_m = 0;
                        break;                    
                    default:
                        break;
                }
                break;
            }
            case 0x0e: //ASSUREDCTRL_TRANSPORT_WINDOW_SIZE_PARAM
            {
                smf_flow_t *smf_flow_p;
                if (0 == smf_analysis_assuredctrl_buf_p->isFlowIdKnown_m) {
                    if (0x03 == msg_type) { // It is client ack message type
                        g_print("zero flow id in Client Ack packet %d\n", pinfo->fd->num);
                    } else {
                        g_print("zero flow id in packet %d\n", pinfo->fd->num);
                    }
                    break;
                }
                smf_flow_p = find_or_create_smf_flow(reverseStream_p, smf_analysis_assuredctrl_buf_p->ad_flow_id_m);
                smf_flow_p->isTransportWindownKnown_m = 1;
                smf_flow_p->transport_window_size_m = tvb_get_uint32(tvb, offset, false);
                smf_flow_p->transport_ack_frame_m = pinfo->fd->num;
                break;
            }
            case 0x1c: // ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORPUBNOTIFY_PARAM
            {
                int local_offset = offset;
                uint32_t flowid = 0;
                uint32_t messageCount = 0;
                uint64_t lastMsgId = 0;
                while( local_offset < offset+size )
                {
                    flowid = tvb_get_ntohl(tvb, local_offset); // 32 bit flowid
                    messageCount = tvb_get_ntohl(tvb, local_offset + 4); // 32-bit count
                    lastMsgId = tvb_get_ntoh64(tvb, local_offset + 8);

                    if(flowid != 0xFFFFFFFF) {
                        smf_flow_t *smf_flow_p = find_or_create_smf_flow(forwardStream_p, flowid);
                        trans_ack_msg_t *transAckMsg_p = create_trans_ack_msg(flowid);
                        putTransIntoList(smf_analysis_assuredctrl_buf_p->transactionAckList_m, transAckMsg_p);

                        wmem_list_frame_t *frame_p = wmem_list_head(smf_flow_p->msgsInTransport_m);
                        while ((frame_p != NULL) && 
                            (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m <= lastMsgId)) {
                            putMsgIntoList(transAckMsg_p->transportAckList_m, (smf_ad_msg_t *)wmem_list_frame_data(frame_p));
                            transAckMsg_p->numTransportMsg_m++;
                            smf_flow_p->numMsgInTransport_m--;
                            wmem_list_frame_t *nextFrame_p = wmem_list_frame_next(frame_p);
                            wmem_list_remove_frame(smf_flow_p->msgsInTransport_m, frame_p);
                            frame_p = nextFrame_p;
                        }

                        frame_p = wmem_list_head(smf_flow_p->msgsUnacked_m);
                        while ((frame_p != NULL) && 
                            (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m <= lastMsgId)) {
                            putMsgIntoList(transAckMsg_p->appAckList_m, (smf_ad_msg_t *)wmem_list_frame_data(frame_p));
                            transAckMsg_p->numAckedMsg_m++;
                            smf_flow_p->numMsgUnacked_m--;
                            wmem_list_frame_t *nextFrame_p = wmem_list_frame_next(frame_p);
                            wmem_list_remove_frame(smf_flow_p->msgsUnacked_m, frame_p);
                            frame_p = nextFrame_p;
                        }
                        transAckMsg_p->messageCount_m = messageCount;
                        transAckMsg_p->numMsgInTransport_m = smf_flow_p->numMsgInTransport_m;
                        transAckMsg_p->numUnackedMsg_m = smf_flow_p->numMsgUnacked_m;                        
                    }
                    local_offset += 16;
                }
                break;
            }
            case 0x1e: //ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORSUBACK_PARAM
            {
                int local_offset = offset;
                uint32_t flowid = 0;
                uint64_t min = 0;
                uint64_t max = 0;
                uint32_t msgCount = 0;
                uint64_t lastMsgIdRecved = 0;
                uint32_t windowSz = 0;
                while( local_offset < offset+size )
                {
                    flowid = tvb_get_ntohl(tvb, local_offset); // 32 bit flowid
                    min = tvb_get_ntoh64(tvb, local_offset + 4);
                    max = tvb_get_ntoh64(tvb, local_offset + 12);
                    msgCount = tvb_get_ntohl(tvb, local_offset + 20);
                    lastMsgIdRecved = tvb_get_ntoh64(tvb, local_offset + 24);
                    windowSz = tvb_get_ntohl(tvb, local_offset + 32);
                    
                    if(flowid != 0xFFFFFFFF) {
                        smf_flow_t *smf_flow_p = find_or_create_smf_flow(reverseStream_p, flowid);
                        smf_flow_p->isTransportWindownKnown_m = 1;
                        smf_flow_p->transport_window_size_m = windowSz;
                        trans_ack_msg_t *transAckMsg_p = create_trans_ack_msg(flowid);
                        putTransIntoList(smf_analysis_assuredctrl_buf_p->transactionAckList_m, transAckMsg_p);  

                        wmem_list_frame_t *frame_p = wmem_list_head(smf_flow_p->msgsInTransport_m);
                        while ((frame_p != NULL) && 
                            (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m <= lastMsgIdRecved)) {
                            putMsgIntoList(transAckMsg_p->transportAckList_m, (smf_ad_msg_t *)wmem_list_frame_data(frame_p));
                            transAckMsg_p->numTransportMsg_m++;
                            smf_flow_p->numMsgInTransport_m--;
                            wmem_list_frame_t *nextFrame_p = wmem_list_frame_next(frame_p);
                            wmem_list_remove_frame(smf_flow_p->msgsInTransport_m, frame_p);
                            frame_p = nextFrame_p;
                        }

                        frame_p = wmem_list_head(smf_flow_p->msgsUnacked_m);
                        while ((frame_p != NULL) && 
                            (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m <= max)) {
                            if (((smf_ad_msg_t *)(wmem_list_frame_data(frame_p)))->msg_id_m >= min) {
                                putMsgIntoList(transAckMsg_p->appAckList_m, (smf_ad_msg_t *)wmem_list_frame_data(frame_p));
                                transAckMsg_p->numAckedMsg_m++;
                                smf_flow_p->numMsgUnacked_m--;
                                wmem_list_frame_t *nextFrame_p = wmem_list_frame_next(frame_p);
                                wmem_list_remove_frame(smf_flow_p->msgsUnacked_m, frame_p);
                                frame_p = nextFrame_p;
                            }
                        }
                        transAckMsg_p->messageCount_m = msgCount;
                        transAckMsg_p->numMsgInTransport_m = smf_flow_p->numMsgInTransport_m;
                        transAckMsg_p->numUnackedMsg_m = smf_flow_p->numMsgUnacked_m;                     }
                    local_offset += 36;
                }
                break;
            }
            case 0x31: //ASSUREDCTRL_MAXDELIVEREDUNACKEDMSGSPERFLOW_PARAM
            {
                smf_flow_t *smf_flow_p;
                if (0 == smf_analysis_assuredctrl_buf_p->isFlowIdKnown_m) {
                    g_print("zero flow id in packet %d\n", pinfo->fd->num);
                    break;
                }
                smf_flow_p = find_or_create_smf_flow(reverseStream_p, smf_analysis_assuredctrl_buf_p->ad_flow_id_m);
                smf_flow_p->maxDeliveredUnackedMsgsPerFlow_m = tvb_get_int32(tvb, offset, false);
                break;
            }
            default:
                break;
        }
    }
}

void smf_analysis_assuredctrl(tvbuff_t *tvb, packet_info* pinfo, proto_tree* tree) {
    smf_analysis_assuredctrl_buf_t *smf_analysis_assuredctrl_buf_p = (smf_analysis_assuredctrl_buf_t *)p_get_proto_data(wmem_file_scope(), pinfo,
            getAssuredCtrlProto(), (uint32_t)tvb_raw_offset(tvb));
    if (smf_analysis_assuredctrl_buf_p->numTransportMsg_m != 0 || smf_analysis_assuredctrl_buf_p->numAckedMsg_m != 0) {
        proto_item *item = proto_tree_add_item(tree, hf_assuredctrl_smf_analysis, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(item);
        proto_tree *flags_tree = proto_item_add_subtree(item, ett_assuredctrl_analysis);

        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_in_transport,
                                tvb, 0, 0, smf_analysis_assuredctrl_buf_p->numMsgInTransport_m);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_unacked,
                                tvb, 0, 0, smf_analysis_assuredctrl_buf_p->numUnackedMsg_m);
        proto_item_set_generated(item);       

        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_transport_acked,
                                tvb, 0, 0, smf_analysis_assuredctrl_buf_p->numTransportMsg_m);
        proto_item_set_generated(item);
        if (smf_analysis_assuredctrl_buf_p->numTransportMsg_m != 0) { // There are no transport message ack, so no delta time
            item = proto_tree_add_time(flags_tree, hf_assuredctrl_smf_analysis_min_transport_time,
                                tvb, 0, 0, &smf_analysis_assuredctrl_buf_p->min_transdeltatime_m);
            proto_item_set_generated(item);
            item = proto_tree_add_time(flags_tree, hf_assuredctrl_smf_analysis_max_transport_time,
                                tvb, 0, 0, &smf_analysis_assuredctrl_buf_p->max_transdeltatime_m);
            proto_item_set_generated(item);
        }

        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_app_acked,
                                tvb, 0, 0, smf_analysis_assuredctrl_buf_p->numAckedMsg_m);
        proto_item_set_generated(item);

        wmem_list_frame_t *list_p = wmem_list_head(smf_analysis_assuredctrl_buf_p->transportAckList_m);
        while (NULL != list_p) {
            smf_ad_msg_t *ad_msg_p = (smf_ad_msg_t *)wmem_list_frame_data(list_p);
            item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_transport_acked_id,
                                tvb, 0, 0, ad_msg_p->frame_m);   
            proto_item_set_generated(item);
            list_p = wmem_list_frame_next(list_p);
        }
        list_p = wmem_list_head(smf_analysis_assuredctrl_buf_p->appAckList_m);
        while (NULL != list_p) {
            smf_ad_msg_t *ad_msg_p = (smf_ad_msg_t *)wmem_list_frame_data(list_p);
            item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_app_acked_id,
                                tvb, 0, 0, ad_msg_p->frame_m);   
            proto_item_set_generated(item);
            list_p = wmem_list_frame_next(list_p);
        }        
    }

    // This is for transactions
    wmem_list_frame_t *translist_p = wmem_list_head(smf_analysis_assuredctrl_buf_p->transactionAckList_m);
    while (NULL != translist_p) {
        trans_ack_msg_t *transAckMsg_p = (trans_ack_msg_t *)wmem_list_frame_data(translist_p);
        proto_item *item = proto_tree_add_item(tree, hf_assuredctrl_smf_analysis, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(item);
        proto_tree *flags_tree = proto_item_add_subtree(item, ett_assuredctrl_analysis);

        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_transaction_flow_id,
                                tvb, 0, 0, transAckMsg_p->ad_flow_id_m);
        proto_item_set_generated(item); 

        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_transport_acked,
                                tvb, 0, 0, transAckMsg_p->numTransportMsg_m);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_in_transport,
                        tvb, 0, 0, transAckMsg_p->numMsgInTransport_m);
        proto_item_set_generated(item);        
        wmem_list_frame_t *list_p = wmem_list_head(transAckMsg_p->transportAckList_m);
        while (NULL != list_p) {
            smf_ad_msg_t *ad_msg_p = (smf_ad_msg_t *)wmem_list_frame_data(list_p);
            item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_transport_acked_id,
                                tvb, 0, 0, ad_msg_p->frame_m);   
            proto_item_set_generated(item);
            list_p = wmem_list_frame_next(list_p);
        }

        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_transaction_ctrl,
                                tvb, 0, 0, transAckMsg_p->numAckedMsg_m);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_num_msg_unacked,
                tvb, 0, 0, transAckMsg_p->numUnackedMsg_m);
        proto_item_set_generated(item); 
        list_p = wmem_list_head(transAckMsg_p->appAckList_m);
        while (NULL != list_p) {
            smf_ad_msg_t *ad_msg_p = (smf_ad_msg_t *)wmem_list_frame_data(list_p);
            item = proto_tree_add_uint(flags_tree, hf_assuredctrl_smf_analysis_transaction_ctrl_id,
                                tvb, 0, 0, ad_msg_p->frame_m);   
            proto_item_set_generated(item);
            list_p = wmem_list_frame_next(list_p);
        }

        translist_p = wmem_list_frame_next(translist_p);
    }
}
