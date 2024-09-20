/* smf-analysis.h
 * Defines functions and constants for smf-analysis.c, packet-smf.c, and packet-assuredctrl.c
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


#ifndef SMF_ANALYSIS_H_
#define SMF_ANALYSIS_H_

#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <epan/expert.h>

#define HF_SMF_ANALYSIS \
            { &hf_smf_analysis, \
                { "SMF analysis", "smf.analysis", \
                    FT_NONE, BASE_NONE, NULL, 0x0, \
                    "This frame has some of the SMF analysis shown", HFILL \
                    }}, \
            { &hf_smf_analysis_flow_type, \
                { "Flow Type", "smf.analysis.flowtype", \
                    FT_STRING, BASE_NONE, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_smf_analysis_msg_in_transport, \
                { "Number of Msgs Not Transport Acked", "smf.analysis.transportunacked", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_smf_analysis_msg_unacked, \
                { "Number of Msgs Not Application Acked", "smf.analysis.appunack", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_smf_analysis_prev_handshake_frame, \
                { "Previous Assured Ctrl Handshake in frame", "smf.analysis.prevhandshakeframe", \
                    FT_FRAMENUM, BASE_NONE, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_smf_analysis_transport_window, \
                { "Transport Message Window Size (from previous Assured Ctrl Handshake)", "smf.analysis.prev_window_size", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}

#define EI_SMF_EXPERT_ITEM \
            { &ei_smf_expert_transport_window_full, \
                { "smf.expert.transportfull", PI_SEQUENCE, \
                    PI_WARN, "Transport Window is Full", EXPFILL \
                    }}, \
            { &ei_smf_expert_max_delivered_unacked_msgs, \
                { "smf.expert.maxdeliveredunack", PI_SEQUENCE, \
                    PI_WARN, "Max Delivered Unacked Msgs Reached", EXPFILL \
                    }}

extern int hf_smf_analysis;
extern int hf_smf_analysis_flow_type;
extern int hf_smf_analysis_msg_in_transport;
extern int hf_smf_analysis_msg_unacked;
extern int hf_smf_analysis_prev_handshake_frame;
extern int hf_smf_analysis_transport_window;
extern int ett_smf_analysis;
extern expert_field ei_smf_expert_transport_window_full;
extern expert_field ei_smf_expert_max_delivered_unacked_msgs;

#define HF_ASSUREDCTRL_SMF_ANALYSIS \
            { &hf_assuredctrl_smf_analysis, \
                { "Assured Control Analysis", "assuredctrl.analysis", \
                    FT_NONE, BASE_NONE, NULL, 0x0, \
                    "This frame has some of the Assured Control analysis shown", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_transaction_flow_id, \
                { "Transaction Flow Id", "assuredctrl.analysis.flowid", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_num_msg_in_transport, \
                { "Num Msgs In Flight (Not Transport Acked)", "assuredctrl.analysis.transportunacked", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_num_msg_unacked, \
                { "Num Msgs Not Application Acked", "assuredctrl.analysis.appunack", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_num_msg_transport_acked, \
                { "Num Msgs Transport Acked (by this msg)", "assuredctrl.analysis.transportacked", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_min_transport_time, \
                { "Min Transport Time (of all the messages transport acked)", "assuredctrl.analysis.mintransporttime", \
                    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_max_transport_time, \
                { "Max Transport Time (of all the messages transport acked)", "assuredctrl.analysis.maxtransporttime", \
                    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_num_msg_transaction_ctrl, \
                { "Number of Msgs Transaction Ctrl (by this msg)", "assuredctrl.analysis.transactionacked", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_num_msg_app_acked, \
                { "Number of Msg Application Acked (by this msg)", "assuredctrl.analysis.appack", \
                    FT_UINT32, BASE_DEC, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_transport_acked_id, \
                { "Transport Ack to Msg in frame", "assuredctrl.analysis.msgtransportacked", \
                    FT_FRAMENUM, BASE_NONE, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_transaction_ctrl_id, \
                { "Transaction Ctrl to Msg in frame", "assuredctrl.analysis.msgtransactionacked", \
                    FT_FRAMENUM, BASE_NONE, NULL, 0x0, \
                    "", HFILL \
                    }}, \
            { &hf_assuredctrl_smf_analysis_app_acked_id, \
                { "Application Ack to Msg in frame", "assuredctrl.analysis.msgappacked", \
                    FT_FRAMENUM, BASE_NONE, NULL, 0x0, \
                    "", HFILL \
                    }}

// There is nothing here at this moment for expert item
// This is for future expension
#define EI_ASSUREDCTRL_SMF_EXPERT_ITEM 

extern int hf_assuredctrl_smf_analysis;
extern int hf_assuredctrl_smf_analysis_transaction_flow_id;
extern int hf_assuredctrl_smf_analysis_num_msg_in_transport;
extern int hf_assuredctrl_smf_analysis_num_msg_unacked;
extern int hf_assuredctrl_smf_analysis_num_msg_transport_acked;
extern int hf_assuredctrl_smf_analysis_min_transport_time;
extern int hf_assuredctrl_smf_analysis_max_transport_time;
extern int hf_assuredctrl_smf_analysis_num_msg_transaction_ctrl;
extern int hf_assuredctrl_smf_analysis_num_msg_app_acked;
extern int hf_assuredctrl_smf_analysis_transport_acked_id;
extern int hf_assuredctrl_smf_analysis_transaction_ctrl_id;
extern int hf_assuredctrl_smf_analysis_app_acked_id;
extern int ett_assuredctrl_analysis;

int smf_analysis(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree);

void smf_analysis_param(tvbuff_t *tvb, packet_info* pinfo, uint8_t param_type, int offset);

void smf_analysis_assuredctrl_param(tvbuff_t *tvb, packet_info* pinfo, uint8_t param_type, int offset, int size);

void smf_analysis_assuredctrl(tvbuff_t *tvb, packet_info* pinfo, proto_tree* tree);

#endif /* SMF_ANALYSIS_H_ */
