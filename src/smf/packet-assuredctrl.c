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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/wmem_scopes.h>

#include "packet-smf.h"
#include "smf-analysis.h"

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
/* #include "packet-assuredctrl.h" */

/* Forward declaration we need below */
void proto_reg_handoff_assuredctrl(void);

/* Initialize the protocol and registered fields */
static int hf_assuredctrl_8_bit_field  = -1;
static int hf_assuredctrl_16_bit_field = -1;
static int hf_assuredctrl_32_bit_field = -1;
static int hf_assuredctrl_64_bit_field = -1;

static int proto_assuredctrl = -1;
static int hf_assuredctrl_version = -1;
static int hf_assuredctrl_msg_type = -1;
static int hf_assuredctrl_msg_type_v3 = -1;
static int hf_assuredctrl_msg_len = -1;
static int hf_assuredctrl_msg_len_v3 = -1;
static int hf_assuredctrl_unknown_param = -1;
static int hf_assuredctrl_pad_byte = -1;

static int hf_assuredctrl_last_msgid_sent_param = -1;
static int hf_assuredctrl_last_msgid_acked_param = -1;
static int hf_assuredctrl_window_size_param = -1;
static int hf_assuredctrl_transport_prio_param = -1;
static int hf_assuredctrl_application_ack_pubid_param = -1;
static int hf_assuredctrl_application_ack_min_id_param = -1;
static int hf_assuredctrl_application_ack_max_id_param = -1;
static int hf_assuredctrl_application_ack_outcome_param = -1;
static int hf_assuredctrl_flowid_param = -1;
static int hf_smf_flowid_hidden_param = -1;
static int hf_assuredctrl_queue_name_param = -1;
static int hf_assuredctrl_dte_name_param = -1;
static int hf_assuredctrl_topic_name_param = -1;
static int hf_assuredctrl_flow_name_param = -1;
static int hf_assuredctrl_durability_param = -1;
static int hf_assuredctrl_access_type_param = -1;
static int hf_assuredctrl_message_selector_param = -1;
static int hf_assuredctrl_transport_window_size_param = -1;
static int hf_assuredctrl_unbind_linger_param = -1;
static int hf_assuredctrl_last_msgid_recved_param = -1;

static int hf_assuredctrl_all_others_permissions_param = -1;
static int hf_assuredctrl_flow_type_param = -1;
static int hf_assuredctrl_endpoint_quota_mb_param = -1;
static int hf_assuredctrl_endpoint_max_message_size_param = -1;
static int hf_assuredctrl_max_redelivery_param = -1;
static int hf_assuredctrl_granted_permissions_param = -1;
static int hf_assuredctrl_respect_ttl_param = -1;

static int hf_assuredctrl_transactionctrlmessagetype_param          = -1;
static int hf_assuredctrl_transactedsessionid_param                 = -1;
static int hf_assuredctrl_transactedsessionname_param               = -1;
static int hf_assuredctrl_transactionid_param                       = -1;
static int hf_assuredctrl_transactedsessionstate_param              = -1;
static int hf_assuredctrl_transactionflowdescriptorpubnotify_param  = -1;
static int hf_assuredctrl_transactionflowdescriptorpuback_param     = -1;
static int hf_assuredctrl_transactionflowdescriptorsuback_param     = -1;

static int hf_assuredctrl_transactionflow_pubnotify_string          = -1;
static int hf_assuredctrl_transactionflow_puback_string             = -1;
static int hf_assuredctrl_transactionflow_suback_string             = -1;

static int hf_assuredctrl_no_local_param                            = -1;

static int hf_assuredctrl_activeflowindication_param                = -1;
static int hf_assuredctrl_wantflowchangeupdate_param                = -1;
static int hf_assuredctrl_epbehaviour_param             = -1;
static int hf_assuredctrl_publisherid_param             = -1;
static int hf_assuredctrl_nummsgspooled_param           = -1;
static int hf_assuredctrl_cutthrough_param              = -1;

static int hf_asssuredctrl_enableCutThrough_param                       = -1;
static int hf_asssuredctrl_disableCutThrough_param                      = -1;
static int hf_asssuredctrl_enableNotifySender_param                     = -1;
static int hf_asssuredctrl_disableNotifySender_param                    = -1;
static int hf_asssuredctrl_enableDeliveryCount_param                    = -1;
static int hf_asssuredctrl_disableDeliveryCount_param                   = -1; 

static int hf_assuredctrl_xamsg_type_transacted_session_name    = -1;
static int hf_assuredctrl_xamsg_type_openXaSessionRequest       = -1;
static int hf_assuredctrl_xamsg_type_openXaSessionResponse      = -1;
static int hf_assuredctrl_xamsg_type_resumeXaSessionRequest     = -1;
static int hf_assuredctrl_xamsg_type_resumeXaSessionResponse    = -1;
static int hf_assuredctrl_xamsg_type_xa_session_name            = -1;
static int hf_assuredctrl_xamsg_type_closeXaSessionRequest      = -1;
static int hf_assuredctrl_xamsg_type_closeXaSessionResponse     = -1;
static int hf_assuredctrl_xamsg_type_xaStartRequest             = -1;
static int hf_assuredctrl_xamsg_type_xaEndRequest               = -1;
static int hf_assuredctrl_xamsg_type_xaPrepareRequest           = -1;
static int hf_assuredctrl_xamsg_type_xaCommitRequest            = -1;
static int hf_assuredctrl_xamsg_type_xaRollbackRequest          = -1;
static int hf_assuredctrl_xamsg_type_xaForgetRequest            = -1;
static int hf_assuredctrl_xamsg_type_xaRecoverRequest           = -1;
static int hf_assuredctrl_xamsg_type_xaRecoverResponse          = -1;
static int hf_assuredctrl_xamsg_type_xaResponse                 = -1;
static int hf_assuredctrl_xamsg_type_unknown                    = -1;

static int hf_assuredctrl_payload_transactionId             = -1;
static int hf_assuredctrl_payload_branchQualifier           = -1;
static int hf_assuredctrl_xaStartRequestFlags_byte          = -1;
static int hf_assuredctrl_xaEndRequestFlags_byte            = -1;
static int hf_assuredctrl_xaCommitRequestFlags_byte         = -1;
static int hf_assuredctrl_xaRecoverRequestFlags_byte        = -1;
static int hf_assuredctrl_xaRecoverResponseFlags_byte       = -1;
static int hf_assuredctrl_scanCursorData                    = -1;
static int hf_assuredctrl_xaResponseCode                    = -1;
static int hf_assuredctrl_xaResponseAction                  = -1;
static int hf_assuredctrl_xaResponseLogLevel                = -1;
static int hf_assuredctrl_xaResponseSubcode                 = -1;
static int hf_assuredctrl_EndpointId_param                  = -1;
static int hf_assuredctrl_ack_msg_id                        = -1;

static int hf_assuredctrl_ackSequenceNum_param              = -1;
static int hf_assuredctrl_ackReconcileReq_param             = -1;
static int hf_assuredctrl_ackReconcileStart_param           = -1;
static int hf_assuredctrl_drAckConsumed_param               = -1;
static int hf_assuredctrl_appMsgIdType_param                = -1;
static int hf_assuredctrl_qEndPointHash_param               = -1;

static int hf_assuredctrl_txnmsg_type_txnResponse           = -1;
static int hf_assuredctrl_txnmsg_type_syncPrepareRequest    = -1;
static int hf_assuredctrl_txnmsg_type_asyncCommitRequest    = -1;
static int hf_assuredctrl_txnmsg_type_syncCommitRequest     = -1;
static int hf_assuredctrl_txnmsg_type_syncCommitStart       = -1;
static int hf_assuredctrl_txnmsg_type_syncCommitEnd         = -1;
static int hf_assuredctrl_txnmsg_type_syncRespoolRequest    = -1;
static int hf_assuredctrl_txnmsg_type_asyncRollbackRequest  = -1;
static int hf_assuredctrl_txnmsg_type_syncUncommitRequest   = -1;
static int hf_assuredctrl_txnmsg_type_unknown               = -1;
static int hf_assuredctrl_txnmsg_type                       = -1;

static int hf_assuredctrl_txnClientFields                   = -1;
static int hf_assuredctrl_msgIdList                         = -1;
static int hf_assuredctrl_endpointHash                      = -1;
static int hf_assuredctrl_msgIdType                         = -1;
static int hf_assuredctrl_heuristic_operation               = -1;

static int hf_assuredctrl_header_rfu = -1;
static int hf_assuredctrl_timestamp_param = -1;
static int hf_assuredctrl_timestamp_gmt_string = -1;
static int hf_assuredctrl_timestamp_local_time_zone_string = -1;
static int hf_assuredctrl_max_delivered_unacked_msgs_per_flow_param = -1;
static int hf_assuredctrl_dr_queue_priority_param = -1;
static int hf_assuredctrl_start_replay_param = -1;
static int hf_assuredctrl_start_replay_type_param = -1;
static int hf_assuredctrl_start_replay_location_param = -1;
static int hf_assuredctrl_start_replay_location_gmt_string = -1;
static int hf_assuredctrl_start_replay_location_local_time_zone_string = -1;
static int hf_assuredctrl_start_replay_location_rgmid_string = -1;
static int hf_assuredctrl_endpoint_error_id_param = -1;
static int hf_assuredctrl_retransmit_request_param = -1;
static int hf_assuredctrl_spooler_unique_id_param = -1;
static int hf_assuredctrl_transaction_get_session_state_and_id = -1;
static int hf_assuredctrl_partition_group_id = -1;
static int hf_assuredctrl_redelivery_delay_config_initial_interval_ms = -1;
static int hf_assuredctrl_redelivery_delay_config_max_interval_ms = -1;
static int hf_assuredctrl_redelivery_delay_config_back_off_multiplier = -1;
static int hf_assuredctrl_redelivery_delay_config_rfu = -1;

// Expert info fields
static expert_field ei_assuredctrl_smf_expert_transport_window_zero = EI_INIT;

/* Global sample preference ("controls" display of numbers) */
// static bool gPREF_HEX = false;

/* Initialize the subtree pointers */
static int ett_assuredctrl                         = -1;
static int ett_FD_suback_list                      = -1;
static int ett_FD_puback_list                      = -1;
static int ett_FD_pubnotify_list                   = -1;
static int ett_EP_behaviour_list                   = -1;
static int ett_XA_msg_openXaSessionRequest_list    = -1;
static int ett_XA_msg_openXaSessionResponse_list   = -1;
static int ett_XA_msg_resumeXaSessionRequest_list  = -1;
static int ett_XA_msg_resumeXaSessionResponse_list = -1;
static int ett_XA_msg_closeXaSessionRequest_list   = -1;
static int ett_XA_msg_closeXaSessionResponse_list  = -1;
static int ett_XA_msg_xaResponse_list              = -1;
static int ett_XA_msg_xaStartRequest_list          = -1;
static int ett_XA_msg_xaEndRequest_list            = -1;
static int ett_XA_msg_xaPrepareRequest_list        = -1;
static int ett_XA_msg_xaCommitRequest_list         = -1;
static int ett_XA_msg_xaRollbackRequest_list       = -1;
static int ett_XA_msg_xaForgetRequest_list         = -1;
static int ett_XA_msg_xaRecoverRequest_list        = -1;
static int ett_XA_msg_xaRecoverResponse_list       = -1;

static int ett_TXN_msg_txnResponse_list            = -1;
static int ett_TXN_msg_syncPrepareRequest_list     = -1;
static int ett_TXN_msg_asyncCommitRequest_list     = -1;
static int ett_TXN_msg_syncCommitRequest_list      = -1;
static int ett_TXN_msg_syncCommitStart_list        = -1;
static int ett_TXN_msg_syncCommitEnd_list          = -1;
static int ett_TXN_msg_syncRespoolRequest_list     = -1;
static int ett_TXN_msg_asyncRollbackRequest_list   = -1;
static int ett_TXN_msg_syncUncommitRequest_list    = -1;

static int ett_assuredctrl_start_replay_param      = -1;
static int ett_assuredctrl_timestamp_param = -1;

#define ASSUREDCTRL_LAST_MSGID_SENT_PARAM   0x01
#define ASSUREDCTRL_LAST_MSGID_ACKED_PARAM  0x02
#define ASSUREDCTRL_WINDOW_SIZE_PARAM       0x03
#define ASSUREDCTRL_TRANSPORT_PRIO_PARAM    0x04
#define ASSUREDCTRL_APPLICATION_ACK_PARAM   0x05
#define ASSUREDCTRL_FLOWID_PARAM            0x06
#define ASSUREDCTRL_QUEUE_NAME_PARAM        0x07
#define ASSUREDCTRL_DTE_NAME_PARAM          0x08
#define ASSUREDCTRL_TOPIC_NAME_PARAM        0x09
#define ASSUREDCTRL_FLOW_NAME_PARAM         0x0a
#define ASSUREDCTRL_DURABILITY_PARAM        0x0b
#define ASSUREDCTRL_ACCESS_TYPE_PARAM       0x0c
#define ASSUREDCTRL_MESSAGE_SELECTOR_PARAM  0x0d
#define ASSUREDCTRL_TRANSPORT_WINDOW_SIZE_PARAM   0x0e
#define ASSUREDCTRL_UNBIND_LINGER_PARAM           0x0f
#define ASSUREDCTRL_LAST_MSGID_RECVED_PARAM       0x10

#define ASSUREDCTRL_ALL_OTHERS_PERMISSIONS_PARAM    0x11
#define ASSUREDCTRL_FLOW_TYPE_PARAM                 0x12
#define ASSUREDCTRL_ENDPOINT_QUOTA_MB_PARAM         0x13
#define ASSUREDCTRL_ENDPOINT_MAX_MESSAGE_SIZE_PARAM 0x14
#define ASSUREDCTRL_GRANTED_PERMISSIONS_PARAM       0x15
#define ASSUREDCTRL_RESPECT_TTL_PARAM               0x16

#define ASSUREDCTRL_TRANSACTIONCTRLMESSAGETYPE_PARAM          0x17
#define ASSUREDCTRL_TRANSACTEDSESSIONID_PARAM                 0x18
#define ASSUREDCTRL_TRANSACTEDSESSIONNAME_PARAM               0x19
#define ASSUREDCTRL_TRANSACTIONID_PARAM                       0x1a
#define ASSUREDCTRL_TRANSACTEDSESSIONSTATE_PARAM              0x1b
#define ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORPUBNOTIFY_PARAM  0x1c
#define ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORPUBACK_PARAM     0x1d
#define ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORSUBACK_PARAM     0x1e
#define ASSUREDCTRL_NO_LOCAL_PARAM                            0x1f
#define ASSUREDCTRL_ACTIVEFLOWINDICATION_PARAM                0x20
#define ASSUREDCTRL_WANTFLOWCHANGEUPDATE_PARAM                0x21
#define ASSUREDCTRL_EP_BEHAVIOUR_PARAM                        0x22
#define ASSUREDCTRL_PUBLISHDERID_PARAM                        0x23
#define ASSUREDCTRL_APPLICATION_PUBACK_PARAM                  0x24
#define ASSUREDCTRL_NUMMSGSPOOLED_PARAM                       0x25
#define ASSUREDCTRL_CUTTHROUGH_PARAM                          0x26
#define ASSUREDCTRL_PUBLISHERFLAGS_PARAM                      0x27
#define ASSUREDCTRL_APPMSGIDTYPE_PARAM                        0x28
#define ASSUREDCTRL_QENDPOINTHASH_PARAM                       0x29
#define ASSUREDCTRL_MAX_REDELIVERY_PARAM                      0x2a
#define ASSUREDCTRL_PAYLOAD_PARAM                             0x2b
#define ASSUREDCTRL_ENDPOINTID_PARAM                          0x2c
#define ASSUREDCTRL_ACKSEQUENCENUM_PARAM                      0x2d
#define ASSUREDCTRL_ACKRECONCILEREQ_PARAM                     0x2e
#define ASSUREDCTRL_ACKRECONCILESTART_PARAM                   0x2f
#define ASSUREDCTRL_TIMESTAMP_PARAM                           0x30
#define ASSUREDCTRL_MAXDELIVEREDUNACKEDMSGSPERFLOW_PARAM      0x31
#define ASSUREDCTRL_DRQUEUEPRIORITY_PARAM                     0x32
#define ASSUREDCTRL_STARTREPLAY_PARAM                         0x33
#define ASSUREDCTRL_ENDPOINTERRORID_PARAM                     0x34
#define ASSUREDCTRL_RETRANSMIT_REQUEST_PARAM                  0x35
#define ASSUREDCTRL_SPOOLER_UNIQUE_ID_PARAM                   0x36
#define ASSUREDCTRL_TRANSACTION_GET_SESSION_STATE_AND_ID      0x37
#define ASSUREDCTRL_PARTITION_GROUP_ID                        0x38
#define ASSUREDCTRL_REDELIVERY_DELAY_CONFIGURATION            0x39

/* XaMsgType Parameters */
#define ASSUREDCTRL_XAMSGTYPE_OPEN_XASESSION_REQUEST        0x00 
#define ASSUREDCTRL_XAMSGTYPE_OPEN_XASESSION_RESPONSE       0x01   
#define ASSUREDCTRL_XAMSGTYPE_RESUME_XASESSION_REQUEST      0x02 
#define ASSUREDCTRL_XAMSGTYPE_RESUME_XASESSION_RESPONSE     0x03
#define ASSUREDCTRL_XAMSGTYPE_CLOSE_XASESSION_REQUEST       0x04
#define ASSUREDCTRL_XAMSGTYPE_CLOSE_XASESSION_RESPONSE      0x05
#define ASSUREDCTRL_XAMSGTYPE_XARESPONSE                    0x06
#define ASSUREDCTRL_XAMSGTYPE_XASTART_REQUEST               0x07
#define ASSUREDCTRL_XAMSGTYPE_XAEND_REQUEST                 0x08
#define ASSUREDCTRL_XAMSGTYPE_XAPREPARE_REQUEST             0x09
#define ASSUREDCTRL_XAMSGTYPE_XACOMMIT_REQUEST              0x0a
#define ASSUREDCTRL_XAMSGTYPE_XAROLLBACK_REQUEST            0x0b
#define ASSUREDCTRL_XAMSGTYPE_XAFORGET_REQUEST              0x0c
#define ASSUREDCTRL_XAMSGTYPE_XARECOVER_REQUEST             0x0d
#define ASSUREDCTRL_XAMSGTYPE_XARECOVER_RESPONSE            0x0e


/* TxnMsgType Parameters */
#define ASSUREDCTRL_TXNMSGTYPE_TXN_RESPONSE             0x00
#define ASSUREDCTRL_TXNMSGTYPE_SYNC_PREPARE_REQUEST     0x01
#define ASSUREDCTRL_TXNMSGTYPE_ASYNC_COMMIT_REQUEST     0x02
#define ASSUREDCTRL_TXNMSGTYPE_SYNC_COMMIT_REQUEST      0x03
#define ASSUREDCTRL_TXNMSGTYPE_SYNC_COMMIT_START        0x04
#define ASSUREDCTRL_TXNMSGTYPE_SYNC_COMMIT_END          0x05
#define ASSUREDCTRL_TXNMSGTYPE_SYNC_RESPOOL_REQUEST     0x06
#define ASSUREDCTRL_TXNMSGTYPE_ASYNC_ROLLBACK_REQUEST   0x07
#define ASSUREDCTRL_TXNMSGTYPE_SYNC_UNCOMMIT_REQUEST    0x08


static const value_string msgtypenames[] = {
    { 0x00, "Handshake / OpenFlow" },
    { 0x01, "Inter-router ACK" },
    { 0x02, "Inter-router handshake ACK" },
    { 0x03, "Client ACK" },
    { 0x04, "Bind" },
    { 0x05, "Unbind" },
    { 0x06, "Unsubscribe" },
    { 0x07, "CloseFlow" },
    { 0x08, "Create" },
    { 0x09, "Delete" },
    { 0x0a, "FlowRecover" },
    { 0x0b, "TransactionCtrl" },
    { 0x0c, "FlowChangeUpdate" },
    { 0x0d, "ExternalAck"},
    { 0x0e, "XaCtrl"},
    { 0x10, "TxnCtrl"},
    { 0x00, NULL }
};

static const value_string xamsgtypenames[] = {
    { 0x00, "openXaSessionRequest" },
    { 0x01, "openXaSessionResponse" },
    { 0x02, "resumeXaSessionRequest" },
    { 0x03, "resumeXaSessionResponse" },
    { 0x04, "closeXaSessionRequest" },
    { 0x05, "closeXaSessionResponse" },
    { 0x06, "xaResponse" },
    { 0x07, "xaStartRequest" },
    { 0x08, "xaEndRequest" },
    { 0x09, "xaPrepareRequest" },
    { 0x0a, "xaCommitRequest" },
    { 0x0b, "xaRollbackRequest" },  
    { 0x0c, "xaForgetRequest" },
    { 0x0d, "xaRecoverRequest"},
    { 0x0e, "xaRecoverResponse"},
    { 0x00, NULL }
};

static const value_string txnmsgtypenames[] = {
    { 0x00, "TxnResponse" },
    { 0x01, "SyncPrepareRequest" },
    { 0x02, "AsyncCommitRequest" },
    { 0x03, "SyncCommitRequest" },
    { 0x04, "SyncCommitStart" },
    { 0x05, "SyncCommitEnd" },
    { 0x06, "SyncRespoolRequest" },
    { 0x07, "AsyncRollbackRequest" },
    { 0x08, "SyncUncommitRequest" },
    { 0x00, NULL }
};

static const value_string xactrlresponsecodenames[] = {
    { 0x64, "XA_RBROLLBACK"},       /* 100 */
    { 0x65, "XA_RBCOMMFAIL"},       /* 101 */
    { 0x66, "XA_RBDEADLOCK"},       /* 102 */
    { 0x67, "XA_RBINTEGRITY"},      /* 103 */  
    { 0x68, "XA_RBOTHER"},          /* 104 */
    { 0x69, "XA_RBPROTO"},          /* 105 */
    { 0x6a, "XA_RBTIMEOUT"},        /* 106 */   
    { 0x6b, "XA_RBTRANSIENT"},      /* 107 */
    { 0x09, "XA_NOMIGRATE" },       /* 9 */ 
    { 0x08, "XA_HEURHAZ" },
    { 0x07, "XA_HEURCOM" },
    { 0x06, "XA_HEURRB" },
    { 0x05, "XA_HEURMIX" },
    { 0x03, "XA_RDONLY" },
    { 0x00, "XA_OK" },
    { 0xFD, "XA_RMERR" },      /* -3 */
    { 0xFC, "XAER_NOTA" },     /* -4 */
    { 0xFB, "XAER_INVAL" },    /* -5 */
    { 0xFA, "XAER_PROTO" },    /* -6 */
    { 0xF9, "XAER_RMFAIL" },   /* -7 */
    { 0xF8, "XAER_DUPID" },    /* -8 */
    { 0xF7, "XAER_OUTSIDE" },  /* -9*/
    { 0x00, NULL }
};

static const value_string xactrlresponsesubcodenames[] = {
    { 0x0 ,  "INVALID"},
    { 0x01,  "OK"},
    { 0x02,  "FAIL"},
    { 0x03 , "ROLLBACK"},
    { 0x04 , "IN_PROGRESS"},
    { 0x05 , "AD_NOT_READY"},
    { 0x06 , "EXCEEDED_MAX_SESSIONS"},
    { 0x07 , "XA_SESSION_ALREADY_EXISTS"},
    { 0x08 , "XA_SESSION_NOT_FOUND"},
    { 0x08 , "XA_SESSION_IS_LOCAL"},
    { 0x0a , "XA_SESSION_IS_ASSOCIATED"},
    { 0x0b , "XA_SESSION_IS_PROCESSING_REQUEST"},
    { 0x0c , "XA_TXN_ALREADY_EXISTS"},
    { 0x0d , "XA_TXN_NOT_FOUND"},
    { 0x0e , "XA_TXN_NOT_ASSOCIATED_TO_SESSION"},
    { 0x0f , "XA_TXN_NOT_ASSOCIATION_SUSPENDED"},
    { 0x10 , "XA_TXN_NOT_IDLE"},
    { 0x11 , "XA_TXN_NOT_PREPARED"},
    { 0x12 , "XA_TXN_NOT_HEURISTICALLY_COMPLETED"},
    { 0x13 , "XA_TXN_IDLE_TIMEOUT"},
    { 0x14 , "PUBLISHER_LAST_MSG_ID_MISMATCH"},
    { 0x15 , "SYSTEM_EXCEEDED_MAX_TXNS"},
    { 0x16 , "VPN_EXCEEDED_MAX_TXNS"},
    { 0x17 , "CLIENT_EXCEEDED_MAX_TXNS"},
    { 0x18 , "EXCEEDED_MAX_TXN_SIZE"},
    { 0x19 , "OUT_OF_TXN_RESOURCES"},
    { 0x1a , "ENDPOINT_MODIFIED_OR_DELETED"},
    { 0x1b , "ENDPOINT_QUOTA_EXCEEDED"},
    { 0x1c , "NO_PUB_ID_FOR_MSG"},
    { 0x1d , "XA_TXN_IS_ACTIVE"},
    { 0x1e , "XA_TXN_IS_HEURISTICALLY_COMMITED"},
    { 0x1f , "XA_TXN_IS_HEURISTICALLY_ROLLED_BACK"},
    { 0x20 , "XA_TXN_IS_PROCESSING_REQUEST"},
    { 0x21 , "EXCEEDED_MAX_SPOOL_UTILIZATION"},
    { 0x22 , "PUBLISHER_MSG_COUNT_MISMATCH"},
    { 0x23 , "NO_PUBLISHER_FLOW"},
    { 0x24 , "SUBSCRIBER_MSG_REASSIGNED"},
    { 0x25 , "XA_TXN_IS_ROLLBACK_ONLY"},
    { 0x26 , "SPOOL_QUOTA_EXCEEDED"},
    { 0x27 , "VPN_QUOTA_EXCEEDED"},
    { 0x28 , "QUEUE_NOT_FOUND"},
    { 0x29 , "NO_LOCAL_DISCARD"},
    { 0x2a , "NOT_COMPATIBLE_WITH_FORWARDING_MODE"},
    { 0x2b , "DOCUMENT_TOO_LARGE"},
    { 0x2c , "QUEUE_SHUTDOWN"},
    { 0x2d , "DTE_SHUTDOWN"},
    { 0x2e , "SMF_TTL_EXCEEDED"},
    { 0x2f , "REJECT_LOW_PRIORITY_MSG"},
    { 0x30 , "SPOOL_TO_DISK_FAIL"},
    { 0x31 , "SPOOL_FILE_LIMIT_EXCEEDED"},
    { 0x32 , "REPLICATION_IS_STANDBY"},
    { 0x33 , "SYNC_REPLICATION_INELIGIBLE"},
    { 0x34 , "ENDPOINT_OUT_OF_RESOURCES_ROLLBACK"},
    { 0x35 , "ENDPOINT_OUT_OF_RESOURCES_RETRY"},
    { 0x36 , "XA_JOIN_IS_NOT_SUPPORTED"},
    { 0x37 , "SUBSCRIBER_MSG_NOT_FOUND"},
    { 0x38 , "MISSING_PUBLISHER_MSGS"},
    { 0x39 , "EXTRA_PUBLISHER_MSGS"},
    { 0x3a , "INVALID_PUBLISHER_FLOW"},
    { 0x3b , "MISSING_PUBLISHER_MSGS_RETRY"},
    { 0x3c , "REPLICATION_TIMEOUT"},
    /* 0x3d (i.e. 61) is 'reserved to be used by the API for disaster recovery failover.' */
    /* 0x3e (i.e. 62) is 'Reserved to be used by the API for unbound flow.' */
    { 0x3f , "REPLICATION_FAIL"},
    { 0x40 , "NO_SUBSCRIPTION_MATCH"},
    { 0x41 , "ENDPOINT_SHUTDOWN"},
    { 0x00,  NULL }
};

static const value_string transactionctrlmsgtypenames[] = {
    { 0x00, "OpenTransactedSession" },
    { 0x01, "CloseTransactedSession" },
    { 0x02, "Commit" },
    { 0x03, "Rollback" }, //not sure about the 4 through 9
    { 0x04, "OpenTransactedSessionResponse" },
    { 0x05, "CloseTransactedSessionResponse" },
    { 0x06, "ResumeTransactedSession" },
    { 0x07, "ResumeTransactedSessionResponse" },
    { 0x08, "CommitTransactionResponse" }, // AssuredCtrlPassThru only
    { 0x09, "RollbackTransactionResponse" }, //AssuredCtrlPassThru only
    { 0x00, NULL }
};

static const value_string transactedsessionstatenames[] = {
    { 0x00, "New" },
    { 0x01, "Committed" },
    { 0x02, "RolledBack" },
    { 0x00, NULL }
};


static const value_string durability_names[] = {
    { 0x00, "???" },
    { 0x01, "Durable" },
    { 0x02, "Non-Durable-Guaranteed" },
    { 0x03, "Non-Durable-Reliable" },
    { 0x00, NULL }
};

static const value_string access_type_names[] = {
    { 0x00, "???" },
    { 0x01, "Exclusive" },
    { 0x02, "Non-Exclusive" },
    { 0x00, NULL }
};

static const value_string flow_type_names[] = {
    { 0x00, "???" },
    { 0x01, "Consumer" },
    { 0x02, "Browser" },
    { 0x00, NULL }
};

static const value_string xa_startrequest_flags[] = {
    { 0x00, "No flags" },
    { 0x01, "R" },
    { 0x02, "J" },
    { 0x00, NULL }
};
static const value_string xa_endrequest_flags[] = {
    { 0x00, "No flags" },
    { 0x01, "S" },
    { 0x02, "F" },
    { 0x04, "R" },
    { 0x08, "C" },
    { 0x00, NULL }
};

static const value_string xa_commitrequest_flags[] = {
    { 0x00, "No flags" },
    { 0x01, "O" },
    { 0x00, NULL }
};

static const value_string xa_recoverrequest_flags[] = {
    { 0x00, "No flags" },
    { 0x01, "R" },
    { 0x00, NULL }
};

static const value_string xa_recoverresponse_flags[] = {
    { 0x00, "No flags" },
    { 0x01, "M" },
    { 0x00, NULL }
};

static const value_string xaresponseactionnames[] = {
    { 0x00, "RETURN" },
    { 0x01, "DISCARD" },
    { 0x00, NULL }
};

static const value_string xaresponseloglevelnames[] = {
    { 0x00, "EMERGENCY (FATAL)" },
    { 0x01, "ALERT (FATAL)" },
    { 0x02, "CRITICAL (FATAL)" },
    { 0x03, "ERROR (ERROR)" },
    { 0x04, "WARNING (WARN)" },
    { 0x05, "NOTICE (INFO)" },
    { 0x06, "INFO (INFO)" },
    { 0x07, "DEBUG (DEBUG)" },
    { 0x08, "NONE (NONE)" },
    { 0x00, NULL }
};

static const value_string publisher_flags[] = {
    { 0x00, "Default" },
    { 0x01, "Disabled" },
    { 0x02, "Enabled" },
    { 0x00, NULL }
};

static const value_string appMsgId_type_names[] = {
    { 0x01, "External" },
    { 0x02, "Internal" },
    { 0x03, "Global" },
    { 0x00, NULL }
};

static const value_string app_ack_outcome_names[] = {
    { 0x00, "Accepted" },
    { 0x01, "Failed" },
    { 0x02, "Released" },
    { 0x03, "Rejected" },
    { 0x00, NULL }
};

/* ---------- Custom Format Fields Functions ----------- */
static void redelivery_delay_back_off_multiplier_format(gchar* s, uint16_t v)
{
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u (%.2f)", v, (float)v / 100.f);
}

/* ---------- Byte Accessor Helper Functions ----------- */
static int get_8_bit_value (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    char const * const field_name)
{
    uint8_t value = tvb_get_uint8(tvb, offset);                 /* gets value of the 8-bit field */
    proto_tree_add_string_format(                               /* adds formatted string to proto tree*/
        tree, hf_assuredctrl_8_bit_field, tvb, offset, 1, NULL, "%s: %d", field_name, value
    );
    return 1;                                                   /* returns the number of bytes processed */      
}

static int get_16_bit_value (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    char const * const field_name)
{
    uint16_t value = tvb_get_ntohs(tvb, offset);                 /* gets value of the 16-bit field */
    proto_tree_add_string_format(                               /* adds formatted string to proto tree*/
        tree, hf_assuredctrl_16_bit_field, tvb, offset, 2, NULL, "%s: %d", field_name, value
    );
    return 2;                                                   /* returns the number of bytes processed */      
}

static int get_32_bit_value (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    char const * const field_name)
{
    uint32_t value = tvb_get_ntohl(tvb, offset);                 /* gets value of the 32-bit field */
    proto_tree_add_string_format(                               /* adds formatted string to proto tree*/
        tree, hf_assuredctrl_32_bit_field, tvb, offset, 4, NULL, "%s: %d", field_name, value
    );
    return 4;                                                   /* returns the number of bytes processed */      
}

static int get_64_bit_value (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    char const * const field_name)
{
    uint64_t value = tvb_get_ntoh64(tvb, offset);                /* gets value of the 64-bit field */
    proto_tree_add_string_format(                               /* adds formatted string to proto tree*/
        tree, hf_assuredctrl_64_bit_field, tvb, offset, 8, NULL, "%s: %" G_GUINT64_FORMAT, field_name, value
    );
    return 8;                                                   /* returns the number of bytes processed */
}

/* ---------- XaCtrl Functions ------------------------- */
static int add_assuredCtrl_xaSessionName_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset)
{
    uint8_t nameLen = 0;
    char sessionName[200];
    
    nameLen = tvb_get_uint8(tvb, offset++);
    tvb_memcpy(tvb, sessionName, offset, nameLen-1);
    proto_tree_add_string_format(tree,
        hf_assuredctrl_xamsg_type_transacted_session_name,
        tvb, offset, nameLen-1, NULL, "SessionName: %s", sessionName);
    
    return nameLen;
}

static void add_assuredCtrl_xaResponse_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaResponse, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaResponse_list);
    offset +=1;

    /* skip first 2 bytes of XaResponse*/
    offset += 2;

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaResponseAction, tvb, offset, 1, false);

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaResponseLogLevel, tvb, offset++, 1, false);

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaResponseCode, tvb, offset++, 1, false);

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaResponseSubcode, tvb, offset, 4, false);

    // I'm assuming this skips forward 4 bytes for the LastPublishedAckMsgId
    // which is no longer in the specifications
    
    // offset += 4;
}

static int add_assuredCtrl_Xid_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset)
{
    uint8_t txnIdSize = 0;
    uint8_t bQualSize = 0;
    int old_offset = offset;

    offset += get_32_bit_value(tree, tvb, offset, "FormatId");

    txnIdSize = tvb_get_uint8(tvb, offset);
    offset += get_8_bit_value(tree, tvb, offset, "TransactionIdSize");

    bQualSize = tvb_get_uint8(tvb, offset);
    offset += get_8_bit_value(tree, tvb, offset, "BranchQualifierSize");

    if (txnIdSize != 0) {
        proto_tree_add_item(tree, 
            hf_assuredctrl_payload_transactionId, tvb, offset, txnIdSize, false);
        offset += txnIdSize;
    }
    if (bQualSize != 0) {
         proto_tree_add_item(tree, 
            hf_assuredctrl_payload_branchQualifier, tvb, offset, bQualSize, false);
        offset += bQualSize;
    }
    return offset - old_offset;
}

static void add_assuredCtrl_openXaSessionRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_openXaSessionRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_openXaSessionRequest_list);
    offset++;
    offset += get_8_bit_value(sub_tree, tvb, offset, "XAVersion");
}

static void add_assuredCtrl_openXaSessionResponse_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_openXaSessionResponse, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_openXaSessionResponse_list);
    offset++;
    offset += get_32_bit_value(sub_tree, tvb, offset, "TransactedSessionId");
    offset += add_assuredCtrl_xaSessionName_item(sub_tree, tvb, offset);
}

static void add_assuredCtrl_resumeXaSessionRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
         hf_assuredctrl_xamsg_type_resumeXaSessionRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_resumeXaSessionRequest_list);
    offset++;
    offset += get_8_bit_value(sub_tree, tvb, offset, "XAVersion");
    offset += add_assuredCtrl_xaSessionName_item(sub_tree, tvb, offset);
}

static void add_assuredCtrl_resumeXaSessionResponse_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_resumeXaSessionResponse, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_resumeXaSessionResponse_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TransactedSessionId");
}

static void add_assuredCtrl_closeXaSessionRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    uint8_t nameLen =0;
    char  sessionName[200];

    item = proto_tree_add_item(tree, 
         hf_assuredctrl_xamsg_type_closeXaSessionRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_closeXaSessionRequest_list);
    offset++;

    nameLen = tvb_get_uint8(tvb, offset++);
    tvb_memcpy(tvb, sessionName, offset, nameLen-1);

    proto_tree_add_string_format(sub_tree,
        hf_assuredctrl_xamsg_type_xa_session_name,
        tvb, offset, nameLen, NULL, "XASessionName: %s", sessionName);
}

static void add_assuredCtrl_closeXaSessionResponse_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{

    proto_tree_add_item(tree, hf_assuredctrl_xamsg_type_closeXaSessionResponse, tvb, offset, size, false);
               

    /* // Below is old code that doesn't make any sense but I left it in case for some reason it was needed at a later point
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_closeXaSessionResponse, tvb, offset, size, false);
        */

}

static void add_assuredCtrl_consumedMsgList_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset,
    int *itemSize)
{
    uint16_t numMsgIds = 0;
    uint64_t msgId = 0;
    int loop =0;

    *itemSize = 0;

    proto_tree_add_item(tree, 
            hf_assuredctrl_EndpointId_param, tvb, offset, 4, false);
    offset += 4;
    *itemSize +=4;

    get_16_bit_value(tree, tvb, offset, "NumMsgIds");
    offset += 2;
    *itemSize +=2;

    for (loop = 0; loop < numMsgIds; loop++) {
        msgId = tvb_get_ntoh64(tvb, offset);
        proto_tree_add_string_format(tree,
            hf_assuredctrl_ack_msg_id,
            tvb, offset, 8, NULL, "AckMessageId[%d]: %" G_GUINT64_FORMAT, loop, msgId);
        offset += 8;
        *itemSize +=8;
    }
}

static void add_assuredCtrl_xaStartRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaStartRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaStartRequest_list);
    offset++;

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaStartRequestFlags_byte, tvb, offset++, 1, false);

    offset += get_32_bit_value(sub_tree, tvb, offset, "TransactedSessionId");
    offset += get_32_bit_value(sub_tree, tvb, offset, "Transaction Timeout");

    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);
}

static void add_assuredCtrl_xaEndRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    int   loop =0;
    uint16_t numMsgLists = 0;
    int  listSize = 0;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaEndRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaEndRequest_list);
    offset++;

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaEndRequestFlags_byte, tvb, offset++, 1, false);

    offset += get_32_bit_value(sub_tree, tvb, offset, "RequestorTransactedSessionId");
    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);
    offset += get_64_bit_value(sub_tree, tvb, offset, "LastPublishedMsgId");
    offset += get_32_bit_value(sub_tree, tvb, offset, "MessageReceiverSessionId");
    numMsgLists = tvb_get_ntohs(tvb, offset);
    offset += get_16_bit_value(sub_tree, tvb, offset, "NumConsumedMessageLists");
    
    for (loop = 0; loop < numMsgLists; loop++) {
        add_assuredCtrl_consumedMsgList_item(sub_tree,  tvb, offset, &listSize);
        offset += listSize;
    }
}

static void add_assuredCtrl_xaPrepareRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaPrepareRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaPrepareRequest_list);
    offset++;

    /* no flags*/
    offset++;
    offset += get_32_bit_value(sub_tree, tvb, offset, "TransactedSessionId");

    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);
}

static void add_assuredCtrl_xaCommitRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaCommitRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaCommitRequest_list);
    offset++;

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaCommitRequestFlags_byte, tvb, offset++, 1, false);
    offset += get_32_bit_value(sub_tree, tvb, offset, "TransactedSessionId");

    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);
}

static void add_assuredCtrl_xaRollbackRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaRollbackRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaRollbackRequest_list);
    offset++;

    /* no flags*/
    offset++;
    offset += get_32_bit_value(sub_tree, tvb, offset, "TransactedSessionId");

    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);
}

static void add_assuredCtrl_xaForgetRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaForgetRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaForgetRequest_list);
    offset++;

    /* no flags*/
    offset++;
    offset += get_32_bit_value(sub_tree, tvb, offset, "TransactedSessionId");

    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);
}

static void add_assuredCtrl_xaRecoverRequest_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    uint8_t flags = 0;
    uint32_t scanCursorLen =0;


    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaRecoverRequest, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaRecoverRequest_list);
    offset++;

    flags = tvb_get_uint8(tvb, offset);

    proto_tree_add_item(sub_tree, 
    hf_assuredctrl_xaRecoverRequestFlags_byte, tvb, offset++, 1, false);

    offset += get_32_bit_value(sub_tree, tvb, offset, "MaxNumIDs");

    if (flags & 0x01) {
        offset += get_32_bit_value(sub_tree, tvb, offset, "ScanCursorLength");
        proto_tree_add_item(sub_tree, 
            hf_assuredctrl_scanCursorData, tvb, offset++, scanCursorLen, false);
    }
}

static void add_assuredCtrl_xaRecoverResponse_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    uint32_t numXids = 0;
    uint8_t flags = 0;
    uint32_t scanCursorLen =0;
    uint32_t loop = 0;

    item = proto_tree_add_item(tree, 
        hf_assuredctrl_xamsg_type_xaRecoverResponse, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_XA_msg_xaRecoverResponse_list);
    offset++;

    flags = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaRecoverResponseFlags_byte, tvb, offset++, 1, false);

    /* skip the first 2 bytes of XaResponse*/
    offset +=2;

    proto_tree_add_item(sub_tree, 
         hf_assuredctrl_xaResponseAction, tvb, offset, 1, false);

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaResponseLogLevel, tvb, offset++, 1, false);

    proto_tree_add_item(sub_tree, 
         hf_assuredctrl_xaResponseCode, tvb, offset++, 1, false);

    proto_tree_add_item(sub_tree, 
        hf_assuredctrl_xaResponseSubcode, tvb, offset, 4, false);

    offset += 4;

    if (flags&0x01) {
        scanCursorLen = tvb_get_ntohl(tvb, offset);
        offset += get_32_bit_value(sub_tree, tvb, offset, "ScanCursorLength");
        proto_tree_add_item(sub_tree, 
            hf_assuredctrl_scanCursorData, tvb, offset, scanCursorLen, false);
        offset += scanCursorLen;
    }

    numXids = tvb_get_ntohl(tvb, offset);
    offset += get_32_bit_value(sub_tree, tvb, offset, "NumXids");
    for (loop = 0; loop < numXids; loop++) {
        offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);
    }
}

/* ---------- TxnCtrl Functions ------------------------ */
static int add_assuredCtrl_txnClientFields_item (
    proto_tree *tree, 
    tvbuff_t *tvb,
    int offset,
    char const * const field_name)
{
    uint8_t length = 0;
    char data[254];     /* 254 bytes = max 253 byte string + 1 NULL byte*/

    length = tvb_get_uint8(tvb, offset);
    offset++;

    tvb_memcpy(tvb, data, offset, length-1);
    proto_tree_add_string_format(
        tree, hf_assuredctrl_txnClientFields, tvb, offset, length-1, NULL, "%s %s", field_name, data
    );
    return length;
}

static int add_assuredCtrl_msgIdList_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset)
{
    int old_offset = offset;
    uint32_t msgIdCount = 0;
    uint64_t msgId = 0;
    unsigned int i = 0;

    msgIdCount = tvb_get_ntohl(tvb, offset);
    offset += get_32_bit_value(tree, tvb, offset, "MsgIdCount");

    proto_tree_add_item(tree, hf_assuredctrl_msgIdType, tvb, offset, 1, false);
    offset++;

    /* Cannot call get_64_bit_value because of special formatting (i.e. MsgId[%d]) */
    for (i=0; i<msgIdCount; i++) {
        msgId = tvb_get_ntoh64(tvb, offset);
        proto_tree_add_string_format(
            tree, hf_assuredctrl_msgIdList, tvb, offset, 8, NULL, "MsgId[%d]: %" G_GUINT64_FORMAT, i, msgId
        );
        offset += 8;
    }
    return offset - old_offset;
}

static int add_assuredCtrl_endpoint_item (
    proto_tree *tree,
    tvbuff_t *tvb, 
    int offset)
{
    int old_offset = offset;
    uint32_t ackCount = 0;
    unsigned int i = 0;

    proto_tree_add_item(tree, hf_assuredctrl_endpointHash, tvb, offset, 8, false);
    offset += 8;
    
    ackCount = tvb_get_ntohl(tvb, offset);
    offset += get_32_bit_value(tree, tvb, offset, "AckCount");

    for (i=0; i<ackCount; i++) {
        offset += add_assuredCtrl_msgIdList_item(tree, tvb, offset);
    }

    return offset - old_offset;
}

static int add_assuredCtrl_externalAckList_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset)
{
    int old_offset = offset;
    uint32_t endpointCount = 0;
    unsigned int i = 0;

    endpointCount = tvb_get_ntohl(tvb, offset);
    offset += get_32_bit_value(tree, tvb, offset, "EndpointCount");

    for (i=0; i<endpointCount; i++) {
        offset += add_assuredCtrl_endpoint_item(tree, tvb, offset);
    }

    return offset - old_offset;
}

static void add_assuredCtrl_txnResponse_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_txnResponse, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_txnResponse_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_64_bit_value(sub_tree, tvb, offset, "CorrelationId");

    /* txnResponseSubcode is identical to xaResponseSubCode; hence using `hf_assuredctrl_xaResponseSubcode` field*/
    proto_tree_add_item(sub_tree, hf_assuredctrl_xaResponseSubcode, tvb, offset, 4, false);
    offset += 4;
}

static void add_assuredCtrl_syncPrepareRequest_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_syncPrepareRequest, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_syncPrepareRequest_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_32_bit_value(sub_tree, tvb, offset, "SpoolMsgCount");
    offset += get_32_bit_value(sub_tree, tvb, offset, "ConsumeMsgCount");
    offset += get_64_bit_value(sub_tree, tvb, offset, "CorrelationId");

    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);

    offset += add_assuredCtrl_txnClientFields_item(sub_tree, tvb, offset, "ClientName:");
    offset += add_assuredCtrl_txnClientFields_item(sub_tree, tvb, offset, "ClientUsername:");
    offset += add_assuredCtrl_externalAckList_item(sub_tree, tvb, offset);
}

static void add_assuredCtrl_asyncCommitRequest_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_asyncCommitRequest, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_asyncCommitRequest_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_32_bit_value(sub_tree, tvb, offset, "ConsumeMsgCount");
    offset += add_assuredCtrl_externalAckList_item(sub_tree, tvb, offset);
}

static void add_assuredCtrl_syncCommitRequest_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_syncCommitRequest, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_syncCommitRequest_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_64_bit_value(sub_tree, tvb, offset, "CorrelationId");

    proto_tree_add_item(sub_tree, hf_assuredctrl_heuristic_operation, tvb, offset, 1, false);
    offset++;
}

static void add_assuredCtrl_syncCommitStart_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_syncCommitStart, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_syncCommitStart_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_32_bit_value(sub_tree, tvb, offset, "SpoolMsgCount");
    offset += get_32_bit_value(sub_tree, tvb, offset, "ConsumeMsgCount");
    offset += get_64_bit_value(sub_tree, tvb, offset, "CorrelationId");

    offset += add_assuredCtrl_Xid_item(sub_tree,  tvb, offset);

    offset += add_assuredCtrl_txnClientFields_item(sub_tree, tvb, offset, "ClientName:");
    offset += add_assuredCtrl_txnClientFields_item(sub_tree, tvb, offset, "ClientUsername:");
    offset += add_assuredCtrl_externalAckList_item(sub_tree, tvb, offset);
}

static void add_assuredCtrl_syncCommitEnd_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_syncCommitEnd, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_syncCommitEnd_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_64_bit_value(sub_tree, tvb, offset, "CorrelationId");
}

static void add_assuredCtrl_syncRespoolRequest_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_syncRespoolRequest, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_syncRespoolRequest_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_64_bit_value(sub_tree, tvb, offset, "PubMsgId");
    offset += get_64_bit_value(sub_tree, tvb, offset, "RespoolMsgId");
}

static void add_assuredCtrl_asyncRollbackRequest_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_asyncRollbackRequest, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_asyncRollbackRequest_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");

    proto_tree_add_item(sub_tree, hf_assuredctrl_heuristic_operation, tvb, offset, 1, false);
    offset++;
}

static void add_assuredCtrl_syncUncommitRequest_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;

    item = proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type_syncUncommitRequest, tvb, offset, size, false);
    sub_tree = proto_item_add_subtree(item, ett_TXN_msg_syncUncommitRequest_list);
    offset++;

    offset += get_32_bit_value(sub_tree, tvb, offset, "TxnId");
    offset += get_64_bit_value(sub_tree, tvb, offset, "CorrelationId");
}

/* ---------- Additional Functions --------------------- */
static void add_assuredCtrl_payload_param_xa_item (
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size,
    int lenbytes,
    const char **str_transactionctrl_msgtype)
{
    uint8_t msgType = tvb_get_uint8(tvb, offset);
    *str_transactionctrl_msgtype = try_val_to_str(msgType, xamsgtypenames);
    switch (msgType) 
    {
        case ASSUREDCTRL_XAMSGTYPE_OPEN_XASESSION_REQUEST:
            add_assuredCtrl_openXaSessionRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_OPEN_XASESSION_RESPONSE:  
            add_assuredCtrl_openXaSessionResponse_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_RESUME_XASESSION_REQUEST:
            add_assuredCtrl_resumeXaSessionRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_RESUME_XASESSION_RESPONSE:
            add_assuredCtrl_resumeXaSessionResponse_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_CLOSE_XASESSION_REQUEST:
            add_assuredCtrl_closeXaSessionRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_CLOSE_XASESSION_RESPONSE:
            add_assuredCtrl_closeXaSessionResponse_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XARESPONSE:
            add_assuredCtrl_xaResponse_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XASTART_REQUEST:
            add_assuredCtrl_xaStartRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XAEND_REQUEST:
            add_assuredCtrl_xaEndRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XAPREPARE_REQUEST:
            add_assuredCtrl_xaPrepareRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XACOMMIT_REQUEST:
            add_assuredCtrl_xaCommitRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XAROLLBACK_REQUEST:
            add_assuredCtrl_xaRollbackRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XAFORGET_REQUEST:
            add_assuredCtrl_xaForgetRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XARECOVER_REQUEST:
            add_assuredCtrl_xaRecoverRequest_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_XAMSGTYPE_XARECOVER_RESPONSE:
            add_assuredCtrl_xaRecoverResponse_item(tree, tvb, offset, size);
            break;
        default:
            proto_tree_add_item(tree,
                hf_assuredctrl_xamsg_type_unknown,
                tvb, offset-(lenbytes+1), size+(lenbytes+1), false);
            break;
    }
}

static void add_assuredCtrl_payload_param_txn_item (
    proto_tree *tree,
    tvbuff_t *tvb,
    int offset,
    int size,
    int lenbytes,
    const char **str_transactionctrl_msgtype)
{
    uint8_t msgType = tvb_get_uint8(tvb, offset);
    *str_transactionctrl_msgtype = try_val_to_str(msgType, txnmsgtypenames);
    proto_tree_add_item(tree, hf_assuredctrl_txnmsg_type, tvb, offset, 1, false);

    switch (msgType)
    {
        case ASSUREDCTRL_TXNMSGTYPE_TXN_RESPONSE:
            add_assuredCtrl_txnResponse_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_SYNC_PREPARE_REQUEST:
            add_assuredCtrl_syncPrepareRequest_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_ASYNC_COMMIT_REQUEST:
            add_assuredCtrl_asyncCommitRequest_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_SYNC_COMMIT_REQUEST:
            add_assuredCtrl_syncCommitRequest_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_SYNC_COMMIT_START:
            add_assuredCtrl_syncCommitStart_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_SYNC_COMMIT_END:
            add_assuredCtrl_syncCommitEnd_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_SYNC_RESPOOL_REQUEST:
            add_assuredCtrl_syncRespoolRequest_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_ASYNC_ROLLBACK_REQUEST:
            add_assuredCtrl_asyncRollbackRequest_item(tree, tvb, offset, size);
            break;
        
        case ASSUREDCTRL_TXNMSGTYPE_SYNC_UNCOMMIT_REQUEST:
            add_assuredCtrl_syncUncommitRequest_item(tree, tvb, offset, size);
            break;
        
        default:
            proto_tree_add_item(tree,
                hf_assuredctrl_txnmsg_type_unknown,
                tvb, offset-(lenbytes+1), size+(lenbytes+1), false);
            break;
    }
}

static void add_transactionid_param(
    proto_tree *tree, 
    int id,
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    char* str;
    int field_a, field_b;

    str = (char *)wmem_alloc(wmem_packet_scope(), 100);
    field_a = tvb_get_ntohl(tvb, offset);
    field_b = tvb_get_ntohl(tvb, offset+4);
    g_snprintf(str, 100, "A=%d B=%d", field_a, field_b);
    proto_tree_add_string(tree, id, tvb, offset, size, str);
}

static void add_FD_suback_item(
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    int local_offset = offset;
    uint32_t flowid = 0;
    uint64_t min = 0;
    uint64_t max = 0;
    uint32_t msgCount = 0;
    uint64_t lastMsgIdRecved = 0;
    uint32_t windowSz = 0;
    
    item = proto_tree_add_item(tree, 
        hf_assuredctrl_transactionflowdescriptorsuback_param, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_FD_suback_list);
    while( local_offset < offset+size )
    {
        flowid = tvb_get_ntohl(tvb, local_offset); // 32 bit flowid
        min = tvb_get_ntoh64(tvb, local_offset + 4);
        max = tvb_get_ntoh64(tvb, local_offset + 12);
        msgCount = tvb_get_ntohl(tvb, local_offset + 20);
        lastMsgIdRecved = tvb_get_ntoh64(tvb, local_offset + 24);
        windowSz = tvb_get_ntohl(tvb, local_offset + 32);
        
        if(flowid == 0xFFFFFFFF) {
            if(min == 0 && max == 0 && msgCount == 1 && lastMsgIdRecved == 0 && windowSz == 0) {
                proto_tree_add_string_format(sub_tree,
                hf_assuredctrl_transactionflow_suback_string, tvb, offset, 36, NULL, "ROLLBACK_ONLY_CONSUMER");
            } else {
                proto_tree_add_string_format(sub_tree,
                hf_assuredctrl_transactionflow_suback_string, tvb, offset, 36, NULL, "INVALID_FLOW_ID");
            }
        } else {
            proto_tree_add_string_format(sub_tree,
            hf_assuredctrl_transactionflow_suback_string, tvb, offset, 36, NULL,
            "SubFlow:%u minAck:%" G_GINT64_MODIFIER "u maxAck:%" G_GINT64_MODIFIER "u msgCount:%u lastTpMsg:%" G_GINT64_MODIFIER "u windowSz:%u", flowid, min, max, msgCount, lastMsgIdRecved, windowSz);
        }

        local_offset += 36;
    }
}

static void add_FD_pubnotify_item(
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    int local_offset = offset;
    uint32_t flowid = 0;
    uint32_t messageCount = 0;
    uint64_t lastMsgId = 0;
    
    item = proto_tree_add_item(tree, 
        hf_assuredctrl_transactionflowdescriptorpubnotify_param, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_FD_pubnotify_list);
    while( local_offset < offset+size )
    {
        flowid = tvb_get_ntohl(tvb, local_offset); // 32 bit flowid
        messageCount = tvb_get_ntohl(tvb, local_offset + 4); // 32-bit count
        lastMsgId = tvb_get_ntoh64(tvb, local_offset + 8);
        
        if(flowid == 0xFFFFFFFF) {
            if(messageCount == 1 && lastMsgId == 0) {
                proto_tree_add_string_format(sub_tree,
                hf_assuredctrl_transactionflow_pubnotify_string, tvb, offset, 16, NULL, "ROLLBACK_ONLY_PUBLISHER");
            } else {
                proto_tree_add_string_format(sub_tree,
                hf_assuredctrl_transactionflow_pubnotify_string, tvb, offset, 16, NULL, "INVALID_FLOW_ID");
            }
        } else {
            proto_tree_add_string_format(sub_tree,
            hf_assuredctrl_transactionflow_pubnotify_string, tvb, offset, 16, NULL,
            "PubFlow:%u messageCount:%u lastMsgId:%" G_GINT64_MODIFIER "u", flowid, messageCount, lastMsgId);
        }

        local_offset += 16;
    }
}

static void add_FD_puback_item(
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    int local_offset = offset;
    uint32_t flowid = 0;
    uint64_t lastMsgId = 0;
    uint32_t windowSz = 0;
    
    item = proto_tree_add_item(tree, 
        hf_assuredctrl_transactionflowdescriptorpuback_param, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_FD_puback_list);
    while( local_offset < offset+size )
    {
        flowid = tvb_get_ntohl(tvb, local_offset); // 32 bit flowid
        lastMsgId = tvb_get_ntoh64(tvb, local_offset + 4);
        windowSz = tvb_get_ntohl(tvb, local_offset + 12);
        
        proto_tree_add_string_format(sub_tree,
            hf_assuredctrl_transactionflow_puback_string, tvb, offset, 16, NULL,
            "PubFlow:%u lastMsgId:%" G_GINT64_MODIFIER "u windowSize:%u", flowid, lastMsgId, windowSz
        );

        local_offset += 16;
    }
}

static void add_EP_behaviour_item(
    proto_tree *tree, 
    tvbuff_t *tvb, 
    int offset, 
    int size)
{
    proto_tree* sub_tree;
    proto_item* item;
    int     num_bool_bytes = size;
    uint8_t      behaviours;

    item = proto_tree_add_item(tree, hf_assuredctrl_epbehaviour_param, tvb, offset, size, false);

    sub_tree = proto_item_add_subtree(item, ett_EP_behaviour_list);
    if ( num_bool_bytes >= 1 ) {
            behaviours = tvb_get_uint8(tvb, offset);
            /*
             * TODO: I'm sure there is a better way to handle this loonie field which contains 4 2-bit values 
             */
            if (behaviours & 0x80) {
                proto_tree_add_item(sub_tree, hf_asssuredctrl_enableCutThrough_param, tvb, offset, 1, false);
            } 
            if (behaviours & 0x40) {
                proto_tree_add_item(sub_tree, hf_asssuredctrl_disableCutThrough_param, tvb, offset, 1, false);
            }
            if (behaviours & 0x20) {
                proto_tree_add_item(sub_tree, hf_asssuredctrl_enableNotifySender_param, tvb, offset, 1, false);
            }
            if (behaviours & 0x10) {
                proto_tree_add_item(sub_tree, hf_asssuredctrl_disableNotifySender_param, tvb, offset, 1, false);
            }
            if (behaviours & 0x08) {
                proto_tree_add_item(sub_tree, hf_asssuredctrl_enableDeliveryCount_param, tvb, offset, 1, false);
            }
            if (behaviours & 0x04) {
                proto_tree_add_item(sub_tree, hf_asssuredctrl_disableDeliveryCount_param, tvb, offset, 1, false);
            }
    }
}

static void
add_assuredctrl_param(
    tvbuff_t *tvb,
    packet_info* pinfo,
    proto_tree *tree,
    uint8_t param_type,
    int offset,
    int size,
    int lenbytes,
    const char **str_transactionctrl_msgtype)
{
    uint8_t transactionctrl_type;

    // skip type byte and lenbytes
    offset += (lenbytes + 1);
    size -= (lenbytes + 1);

    /* local variables needed to separate XaCtrl and TxnCtrl (used in ASSUREDCTRL_PAYLOAD_PARAM) */
    int version;
    int msg_type;
    proto_item* item = NULL;

    switch (param_type)
    {
        case ASSUREDCTRL_LAST_MSGID_SENT_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_last_msgid_sent_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_LAST_MSGID_ACKED_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_last_msgid_acked_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_WINDOW_SIZE_PARAM:
        {
            uint32_t windowSize = 0;
            version = (tvb_get_uint8(tvb, 0) & 0x3f);            
            if (version < 3) { msg_type = (tvb_get_uint8(tvb, 1) & 0xf0) >> 4; }
            else { msg_type = tvb_get_uint8(tvb, 1); }

            item = proto_tree_add_item_ret_uint(tree,
                hf_assuredctrl_window_size_param,
                tvb, offset, size, false, &windowSize);
            if (0 == windowSize) {
                if (msg_type != 0x04) { // Not Bind request (Bind request main contain a window size param of 0)
                    expert_add_info(pinfo, item, &ei_assuredctrl_smf_expert_transport_window_zero);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "[Transport Window Zero] ");
                }
            }
            break;
        }
        case ASSUREDCTRL_TRANSPORT_PRIO_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_transport_prio_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_APPLICATION_ACK_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_application_ack_min_id_param,
                tvb, offset, 8, false);
            proto_tree_add_item(tree,
                hf_assuredctrl_application_ack_max_id_param,
                tvb, offset+8, 8, false);
            if (size == 17) {
                proto_tree_add_item(tree,
                    hf_assuredctrl_application_ack_outcome_param,
                    tvb, offset+16, 1, false);
            }
            break;

        case ASSUREDCTRL_FLOWID_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_flowid_param,
                tvb, offset, size, false);
            item = proto_tree_add_item(tree, // This parameter is for easier search and filtering with flows
                hf_smf_flowid_hidden_param,
                tvb, offset, size, false);
            proto_item_set_hidden(item);
            break;

        case ASSUREDCTRL_QUEUE_NAME_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_queue_name_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_DTE_NAME_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_dte_name_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_TOPIC_NAME_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_topic_name_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_FLOW_NAME_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_flow_name_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_DURABILITY_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_durability_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_ACCESS_TYPE_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_access_type_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_MESSAGE_SELECTOR_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_message_selector_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_TRANSPORT_WINDOW_SIZE_PARAM:
        {
            uint32_t windowSize = 0;

            version = (tvb_get_uint8(tvb, 0) & 0x3f);            
            if (version < 3) { msg_type = (tvb_get_uint8(tvb, 1) & 0xf0) >> 4; }
            else { msg_type = tvb_get_uint8(tvb, 1); }

            item = proto_tree_add_item_ret_uint(tree,
                hf_assuredctrl_transport_window_size_param,
                tvb, offset, size, false, &windowSize);
            if (0 == windowSize) {
                if (msg_type != 0x04) { // Not Bind request (Bind request main contain a window size param of 0)
                    expert_add_info(pinfo, item, &ei_assuredctrl_smf_expert_transport_window_zero);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "[Transport Window Zero] ");
                }
            }
            break;
        }
        case ASSUREDCTRL_UNBIND_LINGER_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_unbind_linger_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_LAST_MSGID_RECVED_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_last_msgid_recved_param,
                tvb, offset, size, false);
            break;

        case ASSUREDCTRL_ALL_OTHERS_PERMISSIONS_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_all_others_permissions_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_FLOW_TYPE_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_flow_type_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_ENDPOINT_QUOTA_MB_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_endpoint_quota_mb_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_ENDPOINT_MAX_MESSAGE_SIZE_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_endpoint_max_message_size_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_GRANTED_PERMISSIONS_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_granted_permissions_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_RESPECT_TTL_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_respect_ttl_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_TRANSACTIONCTRLMESSAGETYPE_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_transactionctrlmessagetype_param,
                tvb, offset, size, false);
            transactionctrl_type = tvb_get_uint8(tvb, offset);
            *str_transactionctrl_msgtype = try_val_to_str(transactionctrl_type, transactionctrlmsgtypenames);
            break;
        case ASSUREDCTRL_TRANSACTEDSESSIONID_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_transactedsessionid_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_TRANSACTEDSESSIONNAME_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_transactedsessionname_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_TRANSACTIONID_PARAM:
            add_transactionid_param(tree,
                hf_assuredctrl_transactionid_param,
                tvb, offset, size);
            break;
        case ASSUREDCTRL_TRANSACTEDSESSIONSTATE_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_transactedsessionstate_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORPUBNOTIFY_PARAM:
            /*
            proto_tree_add_item(tree,
                hf_assuredctrl_transactionflowdescriptorpubnotify_param,
                tvb, offset, size, false);
                */
                add_FD_pubnotify_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORPUBACK_PARAM:
            /*
            proto_tree_add_item(tree,
                hf_assuredctrl_transactionflowdescriptorpuback_param,
                tvb, offset, size, false);
                */
                add_FD_puback_item(tree, tvb, offset, size);

            break;
        case ASSUREDCTRL_TRANSACTIONFLOWDESCRIPTORSUBACK_PARAM:
            /*
            proto_tree_add_item(tree,
                hf_assuredctrl_transactionflowdescriptorsuback_param,
                tvb, offset, size, false);
                */
            add_FD_suback_item(tree, tvb, offset, size);
            break;
        case ASSUREDCTRL_NO_LOCAL_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_no_local_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_ACTIVEFLOWINDICATION_PARAM:
            proto_tree_add_item(tree,
                    hf_assuredctrl_activeflowindication_param,
                    tvb, offset, size, false);
                break;
        case ASSUREDCTRL_WANTFLOWCHANGEUPDATE_PARAM:
            proto_tree_add_item(tree,
                    hf_assuredctrl_wantflowchangeupdate_param,
                    tvb, offset, size, false);
                break;
        case ASSUREDCTRL_EP_BEHAVIOUR_PARAM:
            add_EP_behaviour_item(tree, tvb, offset, size);
                break;
        case ASSUREDCTRL_PUBLISHDERID_PARAM:
            proto_tree_add_item(tree,
                    hf_assuredctrl_publisherid_param,
                    tvb, offset, size, false);
                break;
        case ASSUREDCTRL_APPLICATION_PUBACK_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_application_ack_pubid_param,
                tvb, offset, 4, false);
            proto_tree_add_item(tree,
                hf_assuredctrl_application_ack_min_id_param,
                tvb, offset+4, 8, false);
            proto_tree_add_item(tree,
                hf_assuredctrl_application_ack_max_id_param,
                tvb, offset+12, 8, false);
                break;
        case ASSUREDCTRL_NUMMSGSPOOLED_PARAM:
            proto_tree_add_item(tree,
                    hf_assuredctrl_nummsgspooled_param,
                    tvb, offset, size, false);
                break;
        case ASSUREDCTRL_CUTTHROUGH_PARAM:
            proto_tree_add_item(tree,
                    hf_assuredctrl_cutthrough_param,
                    tvb, offset, size, false);
                break;
        case ASSUREDCTRL_PUBLISHERFLAGS_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_drAckConsumed_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_APPMSGIDTYPE_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_appMsgIdType_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_QENDPOINTHASH_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_qEndPointHash_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_MAX_REDELIVERY_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_max_redelivery_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_PAYLOAD_PARAM:
            /* The ASSUREDCTRL_PAYLOAD_PARAM is only parsed on two types of assuredCtrl msgs.
               So first, parse the message again from the tvBuff and make sure it is either XACtrl or TXNCtrl msg. */
            version = (tvb_get_uint8(tvb, 0) & 0x3f);
            
            if (version < 3) { msg_type = (tvb_get_uint8(tvb, 1) & 0xf0) >> 4; }
            else { msg_type = tvb_get_uint8(tvb, 1); }

            /* Only parse if msg is either an XaCtrl (0x0e) or TxnCtrl (0x10). */
            if ( (msg_type != 0x0e) && (msg_type != 0x10) ) { break; }

            if (msg_type == 0x0e) { add_assuredCtrl_payload_param_xa_item(tree, tvb, offset, size, lenbytes, str_transactionctrl_msgtype); }
            else { add_assuredCtrl_payload_param_txn_item(tree, tvb, offset, size, lenbytes, str_transactionctrl_msgtype); }

            break;
        case ASSUREDCTRL_ENDPOINTID_PARAM:
            proto_tree_add_item(tree,
                    hf_assuredctrl_EndpointId_param,
                    tvb, offset, size, false);
                break;
        case ASSUREDCTRL_ACKSEQUENCENUM_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_ackSequenceNum_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_ACKRECONCILEREQ_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_ackReconcileReq_param,
                tvb, offset-(lenbytes+1), size+(lenbytes+1), false);
            break;
        case ASSUREDCTRL_ACKRECONCILESTART_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_ackReconcileStart_param,
                tvb, offset-(lenbytes+1), size+(lenbytes+1), false);
            break;
        case ASSUREDCTRL_TIMESTAMP_PARAM:
	    {
                ; /* When building this file on Linux, an error is thrown if 'proto_item* ti2;'
                   * is the first line because "the first line to follow a label must be a
                   * statement, and a declaration is not a statement". To fix the error, I added
                   * a semicolon so that there would be a 'statement'. It's a complete hack and if
                   * you can find a way to fix it, you should.
                   */
                proto_item* ti2;
                proto_tree* timestamp_tree;

                ti2 = proto_tree_add_item(tree, hf_assuredctrl_timestamp_param, tvb, offset, size, false);
                timestamp_tree = proto_item_add_subtree(ti2, ett_assuredctrl_timestamp_param);

                    time_t epch2 = tvb_get_ntohl(tvb, offset);

                    // The function 'strftime' is the only function that I could find that would custom-parse the 64-bit time.
                    // The function 'strftime' sets the timezone to that of the computer, so I had to manually write
                    // 'Greenwhich Mean Time'. Note that this is still correct.

                    struct tm* GMTvar2 = gmtime(&epch2);
                    char buffer1[256];
                    strftime(buffer1, 256, "%Y-%m-%d  %H:%M:%S (Greenwhich Mean Time)", GMTvar2);

                    struct tm* LTvar2 = localtime(&epch2);
                    char local_buffer2[256];
                    strftime(local_buffer2, 256, "%Y-%m-%d  %H:%M:%S (%Z)", LTvar2);

                    proto_tree_add_string_format(
                        timestamp_tree, hf_assuredctrl_timestamp_gmt_string, tvb, offset, 4, NULL,
                        "Timestamp: %s (%" G_GUINT32_FORMAT ")", buffer1, tvb_get_ntohl(tvb, offset)
                    );
                    proto_tree_add_string_format(
                        timestamp_tree, hf_assuredctrl_timestamp_local_time_zone_string, tvb, offset, 4, NULL,
                        "Timestamp: %s (%" G_GUINT32_FORMAT ")", local_buffer2,
                        tvb_get_ntohl(tvb, offset)  
                    );
                break;
	    }
        case ASSUREDCTRL_MAXDELIVEREDUNACKEDMSGSPERFLOW_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_max_delivered_unacked_msgs_per_flow_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_DRQUEUEPRIORITY_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_dr_queue_priority_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_STARTREPLAY_PARAM:
            {
                proto_item* ti;
                proto_tree* start_replay_tree;

                ti = proto_tree_add_item(tree, hf_assuredctrl_start_replay_param, tvb, offset, size, false);
                start_replay_tree = proto_item_add_subtree(ti, ett_assuredctrl_start_replay_param);

                if (tvb_get_uint8(tvb, offset) == 0) {
                    proto_tree_add_string_format(start_replay_tree, hf_assuredctrl_start_replay_type_param, tvb, offset, 1, NULL,
                        "Start Replay Location: BEGINNING");
                }
                else if (tvb_get_uint8(tvb, offset) == 1) {
                    time_t epch = tvb_get_ntoh64(tvb, offset + 1)/1000000000;

                    // The function 'strftime' is the only function that I could find that would custom-parse the 64-bit time.
                    // The function 'strftime' sets the timezone to that of the computer, so I had to manually write
                    // 'Greenwhich Mean Time'. Note that this is still correct.

                    struct tm* GMTvar = gmtime(&epch);
                    char buffer2[256];


                    strftime(buffer2, 256, "%Y-%m-%d  %H:%M:%S (Greenwhich Mean Time)", GMTvar);

                    struct tm* LTvar = localtime(&epch);
                    char local_buffer[256];
                    strftime(local_buffer, 256, "%Y-%m-%d  %H:%M:%S (%Z)", LTvar);

                    proto_tree_add_string_format(
                        start_replay_tree, hf_assuredctrl_start_replay_location_gmt_string, tvb, offset + 1, 8, NULL,
                        "Start Replay Location: %s (%" G_GUINT64_FORMAT ".%" G_GUINT64_FORMAT ")", buffer2, (tvb_get_ntoh64(tvb, offset + 1) / 1000000000),
                        (tvb_get_ntoh64(tvb, offset + 1) - ((tvb_get_ntoh64(tvb, offset + 1) / 1000000000) * 1000000000))
                    );

                    proto_tree_add_string_format(
                        start_replay_tree, hf_assuredctrl_start_replay_location_local_time_zone_string, tvb, offset + 1, 8, NULL,
                        "Start Replay Location: %s (%" G_GUINT64_FORMAT ".%" G_GUINT64_FORMAT ")", local_buffer,
                        (tvb_get_ntoh64(tvb, offset + 1)/1000000000), 
                        (tvb_get_ntoh64(tvb, offset + 1) - ((tvb_get_ntoh64(tvb, offset + 1)/1000000000)*1000000000))
                    );
                } 
                /* 
                 * Below we want a 128 bit MUID field.  However the display should show a rmid1:  which is a well defined 
                 * serializatoin:
                 *    rmid1:xxxxx-xxxxxxxxxxx-xxxxxxxx-xxxxxxxx  (5,11,8,8)
                 */
                else if (tvb_get_uint8(tvb, offset) == 2) {
                    proto_tree_add_string_format(
                        start_replay_tree, hf_assuredctrl_start_replay_location_rgmid_string, tvb, offset + 1, 8, NULL,
                        "Start Replay Location: Replay Messages after: rmid1:%05x-%011lx-%08x-%08x",
                        (tvb_get_ntohl(tvb, offset + 1) >> 12), // remove lowest 12 bits of first 32 bytes to get 20 bit value)
                        (tvb_get_ntoh64(tvb, offset + 1) & 0xFFFFFFFFFFF), // only show last 11 nybbles ( 44 bits) 
                        (tvb_get_ntohl(tvb, offset + 9)),        // third field, 32 bytes at offset 9)
                        (tvb_get_ntohl(tvb, offset + 13))        // last field, 32 bytes at offset 13)
                    );
                }
                break;
            }
        case ASSUREDCTRL_ENDPOINTERRORID_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_endpoint_error_id_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_RETRANSMIT_REQUEST_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_retransmit_request_param,
                tvb, offset, size, false);  // param only consists of length/uh/type so I'm having it highlight it all
            break;
        case ASSUREDCTRL_SPOOLER_UNIQUE_ID_PARAM:
            proto_tree_add_item(tree,
                hf_assuredctrl_spooler_unique_id_param,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_TRANSACTION_GET_SESSION_STATE_AND_ID:
        	proto_tree_add_item(tree,
                hf_assuredctrl_transaction_get_session_state_and_id,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_PARTITION_GROUP_ID:
            proto_tree_add_item(tree,
                hf_assuredctrl_partition_group_id,
                tvb, offset, size, false);
            break;
        case ASSUREDCTRL_REDELIVERY_DELAY_CONFIGURATION:
            proto_tree_add_item(tree,
                hf_assuredctrl_redelivery_delay_config_initial_interval_ms,
                tvb, offset, 4, false);
            proto_tree_add_item(tree,
                hf_assuredctrl_redelivery_delay_config_max_interval_ms,
                tvb, offset+4, 4, false);
            proto_tree_add_item(tree,
                hf_assuredctrl_redelivery_delay_config_back_off_multiplier,
                tvb, offset+8, 2, false);
            if (size > 10) {
                proto_tree_add_item(tree,
                    hf_assuredctrl_redelivery_delay_config_rfu,
                    tvb, offset+10, size-10, false);
            }
            break;
        default:
            proto_tree_add_item(tree,
                hf_assuredctrl_unknown_param,
                tvb, offset-(lenbytes+1), size+(lenbytes+1), false);
        break;
    }
    smf_analysis_assuredctrl_param(tvb, pinfo, param_type, offset, size);
}

static int
dissect_assuredctrl_param(
    tvbuff_t *tvb, 
    packet_info* pinfo,
    int offset, 
    proto_tree *tree,
    char **str_transactionctrl_msgtype)
{
    int param_len;
    int len_bytes; //number of bytes used for length
    uint8_t param_type;

    /* Is it a pad byte? */
    if (tvb_get_uint8(tvb, offset) == 0)
    {
        proto_tree_add_item(tree, hf_assuredctrl_pad_byte, tvb, offset, 1, false);
        return 1;
    }
    
    param_type = tvb_get_uint8(tvb, offset) & 0x3f;
    param_len  = tvb_get_uint8(tvb, offset+1);
    if (param_len == 0) {
        param_len = tvb_get_ntohl(tvb, offset+2); //32bit len starts after the 0
        len_bytes = 5;
    } else {
        len_bytes = 1;
    }

    add_assuredctrl_param(tvb, pinfo, tree, param_type, offset, param_len, len_bytes, (const char**)str_transactionctrl_msgtype);

    return param_len;
}

static void
dissect_assuredctrl_params(
    tvbuff_t *tvb, 
    packet_info* pinfo,
    int param_offset_start, 
    int param_offset_end,
    proto_tree *tree,
    char **str_transactionctrl_msgtype)
{
    int offset;

    for (offset=param_offset_start; offset<param_offset_end; )
    {
        int param_len = dissect_assuredctrl_param(tvb, pinfo, offset, tree, str_transactionctrl_msgtype);
        if (0 == param_len) {
            // A param cannot be 0 length. Something went wrong with the dissection. Just exit
            break;
        }
        offset += param_len;
    }
}

/* Code to actually dissect the packets */
static int
dissect_assuredctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *assuredctrl_tree;
    int header_len;
    int msgtype;
    const char *str_msgtype;
    char *str_transactionctrl_msgtype = NULL;
    char* str_buffer = (char*)data; /* This is done to get because we pass a char* to the dissector 
				     * from packet-smf.c, but the dissector_t prototype requires 
				     * dissect_assuredctrl to be passed a void*. To reconcile the two,
				     * we have the dissect_assuredctrl prototype being passed data as 
				     * a void*, and then we typecast it to a char*. 
				     */
    //(void)pinfo; 
/* This is done to get rid of a compiler warning since we don't 
		  * use this variable but we still need to pass it to dissect_assuredctrl() 
		  * so that the dissector matched the dissector_t prototype.
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

   "col_append_fstr()" can be used instead of "col_add_str()"; it takes
   "printf()"-like arguments.  Don't use "col_append_fstr()" with a format
   string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
   more efficient than "col_append_fstr()".

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
        ti = proto_tree_add_item(tree, proto_assuredctrl, tvb, 0, -1, false);

        assuredctrl_tree = proto_item_add_subtree(ti, ett_assuredctrl);

        if ((tvb_get_uint8(tvb, 0) & 0x3f) < 3) {
            /* Dissect header fields */
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_header_rfu,    tvb, 0, 1, false);
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_version,       tvb, 0, 1, false);
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_msg_type,      tvb, 1, 1, false);
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_msg_len,       tvb, 1, 2, false);

            /* Dissect parameters */
            header_len = tvb_get_ntohs(tvb, 1) & 0xfff;
            dissect_assuredctrl_params(tvb, pinfo, 3, 4*header_len, assuredctrl_tree, &str_transactionctrl_msgtype);
            msgtype = (tvb_get_uint8(tvb, 1) & 0xf0) >> 4;
        }
        else {
            /* Dissect header fields */
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_header_rfu,    tvb, 0, 1, false);
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_version,       tvb, 0, 1, false);
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_msg_type_v3,   tvb, 1, 1, false);
            proto_tree_add_item(assuredctrl_tree, hf_assuredctrl_msg_len_v3,    tvb, 2, 4, false);

            /* Dissect parameters */
            header_len = tvb_get_ntohl(tvb, 2);
            dissect_assuredctrl_params(tvb, pinfo, 6, header_len, assuredctrl_tree, &str_transactionctrl_msgtype);
            msgtype = tvb_get_uint8(tvb, 1) & 0xff;
        }

        smf_analysis_assuredctrl(tvb, pinfo, assuredctrl_tree);

        /* Figure out type of message and put it on the shared parent info */
        str_msgtype = try_val_to_str(msgtype, msgtypenames);
        
        if (str_msgtype != NULL) {
        
            if (str_transactionctrl_msgtype != NULL) {
                g_snprintf(str_buffer, 60, " (%s:%s)", str_msgtype, str_transactionctrl_msgtype);
            } else {
                g_snprintf(str_buffer, 60, " (%s)", str_msgtype);
            }

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
proto_register_assuredctrl(void)
{                 
    //module_t *assuredctrl_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_assuredctrl_8_bit_field,
            { "Field_8", "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_16_bit_field,
            { "Field_16", "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_32_bit_field,
            { "Field_32", "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_64_bit_field,
            { "Field_64", "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_version,
            { "Version",           "assuredctrl.version",
            FT_UINT8, BASE_DEC, NULL, 0x3f,
            "", HFILL }
        },
        { &hf_assuredctrl_msg_type,
            { "Message type",           "assuredctrl.msg_type",
            FT_UINT8, BASE_DEC, VALS(msgtypenames), 0xf0,
            "", HFILL }
        },
        { &hf_assuredctrl_msg_type_v3,
            { "Message type",           "assuredctrl.msg_type",
            FT_UINT8, BASE_DEC, VALS(msgtypenames), 0xff,
            "", HFILL }
        },
        { &hf_assuredctrl_msg_len,
            { "Message length",           "assuredctrl.msg_len",
            FT_UINT16, BASE_DEC, NULL, 0xfff,
            "", HFILL }
        },
        
        { &hf_assuredctrl_msg_len_v3,
            { "Message length",           "assuredctrl.msg_len",
            FT_UINT32, BASE_DEC, NULL, 0xfff,
            "", HFILL}
        },
        
        { &hf_assuredctrl_unknown_param,
            { "Unrecognized parameter",           "assuredctrl.unknown_param",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_pad_byte,
            { "Pad byte",           "assuredctrl.pad_byte",
            FT_NONE, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_last_msgid_sent_param,
            { "Last message id sent",           "assuredctrl.last_msgid_sent",
            FT_UINT64, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_last_msgid_acked_param,
            { "Last message id acked", "assuredctrl.last_msgid_acked",
            FT_UINT64, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_window_size_param,
            { "Window size",           "assuredctrl.window_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transport_prio_param,
            { "Transport priority",           "assuredctrl.transport_prio",
            FT_UINT8, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_application_ack_pubid_param,
            { "Application ACK Publisher ID",           
            "assuredctrl.application_ack_pubid",
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_application_ack_min_id_param,
            { "Application ACK min message ID",           
            "assuredctrl.application_ack_min_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_application_ack_max_id_param,
            { "Application ACK max message ID",           
            "assuredctrl.application_ack_max_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_application_ack_outcome_param,
            { "Application ACK outcome",
            "assuredctrl.application_ack_outcome",
            FT_UINT8, BASE_DEC, VALS(app_ack_outcome_names), 0x0,
            "", HFILL}
        },
        { &hf_assuredctrl_flowid_param,
            { "Flow ID",           "assuredctrl.flowid",
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_smf_flowid_hidden_param, // This parameter is for easier search and filtering of flow ids
            { "Smf/AssuredCtrl Flow ID",           "smf.flowid",
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_queue_name_param,
            { "Queue name",           "assuredctrl.queue_name",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_dte_name_param,
            { "Durable topic endpoint name",      "assuredctrl.dte_name",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_topic_name_param,
            { "Topic name",           "assuredctrl.topic_name",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_flow_name_param,
            { "Flow name",           "assuredctrl.flow_name",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_durability_param,
            { "Durability ",           "assuredctrl.durability",
            FT_UINT8, BASE_DEC, VALS(durability_names), 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_access_type_param,
            { "Access Type ",           "assuredctrl.access_type",
            FT_UINT8, BASE_DEC, VALS(access_type_names), 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_message_selector_param,
            { "Message Selector",           "assuredctrl.msg_selector",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transport_window_size_param,
            { "Transport Window Size", "assuredctrl.window_size", // We use the same short name as the window size to facilitate search
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_unbind_linger_param,
            { "Unbind Linger",           "assuredctrl.unbind_linger",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_last_msgid_recved_param,
            { "Last message id recved",           "assuredctrl.last_msgid_recved",
            FT_UINT64, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_all_others_permissions_param,
            { "All Others Permissions",           "assuredctrl.all_others_permissions",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_flow_type_param,
            { "Flow Type",           "assuredctrl.flow_type",
            FT_UINT8, BASE_HEX, VALS(flow_type_names), 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_endpoint_quota_mb_param,
            { "Endpoint Quota MB",           "assuredctrl.endpoint_quota_mb",
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_endpoint_max_message_size_param,
            { "Endpoint MaxMsgSize",           "assuredctrl.endpoint_max_message_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_max_redelivery_param,
            { "Max Redelivery",           "assuredctrl.max_redelivery",
              FT_UINT8, BASE_DEC, NULL, 0x0,
              "", HFILL }
        },
        { &hf_assuredctrl_granted_permissions_param,
            { "Granted Permissions",           "assuredctrl.granted_permissions",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_respect_ttl_param,
            { "Respect TTL",           "assuredctrl.respect_ttl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_transactionctrlmessagetype_param,
            { "XACtrl Message Type",           "assuredctrl.transactionctrl.messagetype",
            FT_UINT8, BASE_HEX, VALS(transactionctrlmsgtypenames), 0xff,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactedsessionid_param,
            { "XACtrl SessionId",           "assuredctrl.transactionctrl.sessionid",
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactedsessionname_param,
            { "XACtrl SessionName",           "assuredctrl.transactionctrl.sessionname",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactionid_param,
            { "XACtrl TransactionId",           "assuredctrl.transactionctrl.transactionid",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_transactedsessionstate_param,
            { "XACtrl TransactedSessionState",           "assuredctrl.transactionctrl.transactedsessionstate",
            FT_UINT8, BASE_HEX, VALS(transactedsessionstatenames), 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactionflowdescriptorpubnotify_param,
            { "XACtrl TFDPubNotify",           "assuredctrl.transactionctrl.tfdpubnotify",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactionflowdescriptorpuback_param,
            { "XACtrl TFDPubAck",           "assuredctrl.transactionctrl.tfdpuback",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactionflowdescriptorsuback_param,
            { "XACtrl TFDSubAck",           "assuredctrl.transactionctrl.tfdsuback",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        
        { &hf_assuredctrl_transactionflow_pubnotify_string,
            { "Field_PubNotify_Str",           "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactionflow_puback_string,
            { "Field_PubAck_Str",           "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_transactionflow_suback_string,
            { "Field_SubAck_Str",           "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },

        { &hf_assuredctrl_no_local_param,
            { "NoLocal",           "assuredctrl.nolocal",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_activeflowindication_param,
            { "Active Flow Indication",         "assuredctrl.activeflowindication",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_wantflowchangeupdate_param,
            { "Want Flow Change Update",            "assuredctrl.wantflowchangeupdate",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_epbehaviour_param,
            { "Endpoint Behaviour",         "assuredctrl.epbehaviour",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
                /* endpoint behaviours */
                { &hf_asssuredctrl_enableCutThrough_param,
                    { "Enable Cut Through Forwarding ",  "assuredctrl.epbehaviour.enable_cut_through",
                    FT_BOOLEAN, 8, NULL, 0x80,
                    "", HFILL }
                },
                { &hf_asssuredctrl_disableCutThrough_param,
                    { "Disable Cut Through Forwarding ",  "assuredctrl.epbehaviour.disable_cut_through",
                    FT_BOOLEAN, 8, NULL, 0x40,
                    "", HFILL }
                },
                { &hf_asssuredctrl_enableNotifySender_param,
                    { "Enable Notify Sender on Discard ",  "assuredctrl.epbehaviour.enable_notify_sender",
                    FT_BOOLEAN, 8, NULL, 0x20,
                    "", HFILL }
                },
                { &hf_asssuredctrl_disableNotifySender_param,
                    { "Disable Notify Sender on Discard ",  "assuredctrl.epbehaviour.disable_notify_sender",
                    FT_BOOLEAN, 8, NULL, 0x10,
                    "", HFILL }
                },
                { &hf_asssuredctrl_enableDeliveryCount_param,
                    { "Enable Delivery Count ",  "assuredctrl.epbehaviour.enable_delivery_count",
                    FT_BOOLEAN, 8, NULL, 0x08,
                    "", HFILL }
                },
                { &hf_asssuredctrl_disableDeliveryCount_param, 
                    { "Disable Delivery Count ",  "assuredctrl.epbehaviour.disable_delivery_count",
                    FT_BOOLEAN, 8, NULL, 0x04,
                    "", HFILL }
                },
                /* end of endpoint behaviours */
        { &hf_assuredctrl_publisherid_param,
            { "AD Publisher ID",            "assuredctrl.adpublisherid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_nummsgspooled_param,
            { "Number of Messages Spooled",         "assuredctrl.nummsgspooled",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_cutthrough_param,
            { "Cut Through",            "assuredctrl.cutthrough",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_timestamp_param,
            { "Timestamp", "assuredctrl.timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_timestamp_gmt_string,
            { "Timestamp GMT String", "assuredctrl.timestamp",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_timestamp_local_time_zone_string,
            { "Timestamp Local Time Zone String", "assuredctrl.timestamp",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_max_delivered_unacked_msgs_per_flow_param,
            { "Max Delivered Unacked Msgs Per Flow", "assuredctrl.max_delivered_unacked_msgs_per_flow",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_dr_queue_priority_param,
            { "DR Queue Priority", "assuredctrl.dr_queue_priority",
            FT_UINT8, BASE_DEC, NULL, 0x7f,
            "", HFILL }
        },
        { &hf_assuredctrl_start_replay_param,
            { "Start Replay", "assuredctrl.start_replay",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_start_replay_type_param,
            { "Start Replay Type", "assuredctrl.start_replay_type",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_start_replay_location_param,
            { "Start Replay Location", "assuredctrl.start_replay_location",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_start_replay_location_gmt_string,
            { "Start Replay Location GMT String", "assuredctrl.start_replay_location",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_start_replay_location_local_time_zone_string,
            { "Start Replay Location Local Time Zone String", "assuredctrl.start_replay_location",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_start_replay_location_rgmid_string,
            { "Start Replay Location Local Replication Group MessageId", "assuredctrl.start_replay_location",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_endpoint_error_id_param,
            {"Endpoint Error ID", "assuredctrl.endpoint_error_id",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            "", HFILL }
        },
        { &hf_assuredctrl_retransmit_request_param,
            {"Retransmit Request", "assuredctrl.retransmit_request",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "", HFILL}
        },
        
        { &hf_assuredctrl_spooler_unique_id_param,
            {"Spooler Unique Id", "assuredctrl.spooler_unique_id",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            "", HFILL}
        },

        { &hf_assuredctrl_transaction_get_session_state_and_id,
            {"Transaction Get Session State And Id", "assuredctrl.transaction_get_session_state_and_id",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "", HFILL}
        },

        { &hf_assuredctrl_partition_group_id,
            {"Partition Group Id", "assuredctrl.partition_group_id",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "", HFILL}
        },

        { &hf_assuredctrl_redelivery_delay_config_initial_interval_ms,
            {"Redelivery Delay Initial Interval MS", "assuredctrl.redelivery_delay_config.initial_interval_ms",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "", HFILL}
        },

        { &hf_assuredctrl_redelivery_delay_config_max_interval_ms,
            {"Redelivery Delay Max Interval MS", "assuredctrl.redelivery_delay_config.max_interval_ms",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "", HFILL}
        },

        { &hf_assuredctrl_redelivery_delay_config_back_off_multiplier,
            {"Redelivery Delay Back off Multiplier", "assuredctrl.redelivery_delay_config.back_off_multiplier",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(redelivery_delay_back_off_multiplier_format), 0x00,
            "", HFILL}
        },

        { &hf_assuredctrl_redelivery_delay_config_rfu,
            {"Redelivery Delay Reserved for Future", "assuredctrl.redelivery_delay_config.rfu",
            FT_BYTES, SEP_SPACE, NULL, 0x00,
            "", HFILL}
        },

        /* BEGIN HEADER FIELDS FOR XaCTRL MSG TYPES */
        { &hf_assuredctrl_xamsg_type_transacted_session_name,
            { "Field_TransSessionName",     "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_openXaSessionRequest,
            { "XACtrl OpenXaSessionRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_openXaSessionResponse,
            { "XACtrl OpenXaSessionResponse",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_resumeXaSessionRequest,
            { "XACtrl ResumeXaSessionRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_resumeXaSessionResponse,
            { "XACtrl ResumeXaSessionResponse",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_closeXaSessionRequest,
            { "XACtrl CloseXaSessionRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xa_session_name,
            { "Field_XaSessionName",     "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_closeXaSessionResponse,
            { "XACtrl CloseXaSessionResponse",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaStartRequest,
            { "XACtrl XaStartRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaEndRequest,
            { "XACtrl XaEndRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaPrepareRequest,
            { "XACtrl XaPrepareRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaCommitRequest,
            { "XACtrl XaCommitRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaRollbackRequest,
            { "XACtrl XaRollbackRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaForgetRequest,
            { "XACtrl XaForgetRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaRecoverRequest,
            { "XACtrl XaRecoverRequest",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaRecoverResponse,
            { "XACtrl XaRecoverResponse",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_xaResponse,
            { "XACtrl XaResponse",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "", HFILL }
        },
        { &hf_assuredctrl_payload_transactionId,
            { "TransactionId",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_payload_branchQualifier,
            { "BranchQualifier",     "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xaStartRequestFlags_byte,
            { "flags",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xa_startrequest_flags), 0xff,          
            "", HFILL }
        },
        { &hf_assuredctrl_xaEndRequestFlags_byte,
            { "flags",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xa_endrequest_flags), 0xff,          
            "", HFILL }
        },  
        { &hf_assuredctrl_xaCommitRequestFlags_byte,
            { "flags",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xa_commitrequest_flags), 0xff,          
            "", HFILL }
        },
        { &hf_assuredctrl_xaRecoverRequestFlags_byte,
            { "flags",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xa_recoverrequest_flags), 0xff,          
            "", HFILL }
        },
        { &hf_assuredctrl_xaRecoverResponseFlags_byte,
            { "flags",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xa_recoverresponse_flags), 0xff,          
            "", HFILL }
        },
            
        { &hf_assuredctrl_xaResponseCode,
            { "ResponseCode",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xactrlresponsecodenames), 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xaResponseSubcode,
            { "ResponseSubcode",           "assuredctrl.payload",
            FT_UINT32, BASE_HEX, VALS(xactrlresponsesubcodenames), 0x0,          
            "", HFILL } 
        },
        { &hf_assuredctrl_scanCursorData,
            { "ScanCursorData",           "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xaResponseAction,
            { "Action",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xaresponseactionnames), 0xf0,          
            "", HFILL }
        },
        { &hf_assuredctrl_xaResponseLogLevel,
            { "Log Level",           "assuredctrl.payload",
            FT_UINT8, BASE_HEX, VALS(xaresponseloglevelnames), 0x0f,          
            "", HFILL }
        },
        { &hf_assuredctrl_xamsg_type_unknown,
            { "Unrecognized XaMsgType",           "assuredctrl.payload.xamsgtype",
            FT_BYTES, BASE_NONE, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_EndpointId_param,
            { "Endpoint ID",           "assuredctrl.endpointid",
            FT_UINT32, BASE_DEC, NULL, 0x0,          
            "", HFILL } 
        },
        { &hf_assuredctrl_ack_msg_id,
            { "Field_AckMsgId",           "assuredctrl.discard",
            FT_UINT64, BASE_DEC, NULL, 0x0,          
            "", HFILL }
        },
        { &hf_assuredctrl_ackSequenceNum_param,
            { "Ack Sequence Number",           "assuredctrl.ackSequenceNum",
            FT_UINT16, BASE_DEC, NULL, 0x0,          
            "", HFILL } 
        },
        { &hf_assuredctrl_ackReconcileReq_param,
            { "Ack Reconcile Request",           "assuredctrl.ackReconcileReq",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "", HFILL } 
        },
        { &hf_assuredctrl_ackReconcileStart_param,
            { "Start of Ack Reconcile",           "assuredctrl.ackReconcileStart",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "", HFILL } 
        },
        { &hf_assuredctrl_drAckConsumed_param,
            { "DR Ack Consumed",           "assuredctrl.drAckConsumed",
            FT_UINT16, BASE_DEC, VALS(publisher_flags), 0xc000,          
            "", HFILL } 
        },
        { &hf_assuredctrl_appMsgIdType_param,
            { "App Msg Id Type",           "assuredctrl.appMsgIdType",
            FT_UINT24, BASE_DEC, VALS(appMsgId_type_names), 0x0,          
            "", HFILL } 
        },
        { &hf_assuredctrl_qEndPointHash_param,
            { "Qendpoint Hash",           "assuredctrl.qEndpointHash",
            FT_UINT64, BASE_DEC, NULL, 0x0,          
            "", HFILL } 
        },

        /* BEGIN HEADER FIELDS FOR TxnCTRL MSG TYPES */
        { &hf_assuredctrl_txnmsg_type_txnResponse,
            { "TxnCtrl TxnResponse", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_syncPrepareRequest,
            { "TxnCtrl SyncPrepareRequest", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_asyncCommitRequest,
            { "TxnCtrl AsyncCommitRequest", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_syncCommitRequest,
            { "TxnCtrl SyncCommitRequest", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_syncCommitStart,
            { "TxnCtrl SyncCommitStart", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_syncCommitEnd,
            { "TxnCtrl SyncCommitEnd", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_syncRespoolRequest,
            { "TxnCtrl SyncRespoolRequest", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_asyncRollbackRequest,
            { "TxnCtrl AsyncRollbackRequest", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_syncUncommitRequest,
            { "TxnCtrl SyncUncommitRequest", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type_unknown,
            { "Unrecognized TxnMsgType", "assuredctrl.payload.txnmsgtype",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_txnmsg_type,
            { "TxnMsgType", "assuredctrl.txn_msg_type",
            FT_UINT8, BASE_HEX, VALS(txnmsgtypenames), 0xff, "", HFILL }
        },
        { &hf_assuredctrl_txnClientFields,
            { "Field_Client", "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_msgIdList,
            { "Field_MsgIdList", "assuredctrl.discard",
            FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_endpointHash,
            { "EndpointHash", "assuredctrl.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, "", HFILL }
        },
        { &hf_assuredctrl_msgIdType,
            { "MsgIdType", "assuredctrl.msgIdType",
            FT_UINT8, BASE_DEC,  VALS(appMsgId_type_names), 0x0, "", HFILL } 
        },
        { &hf_assuredctrl_heuristic_operation,
            { "HeuristicOperationFlag", "assuredctrl.payload",
            FT_BOOLEAN, 8, NULL, 0x01, "", HFILL }
        },
        { &hf_assuredctrl_header_rfu,
            { "RFU",        "assuredctrl.rfu",
            FT_UINT8, BASE_DEC, NULL, 0xc0,
            "", HFILL }
        },
        HF_ASSUREDCTRL_SMF_ANALYSIS
    };

    static ei_register_info ei[] = {
        { &ei_assuredctrl_smf_expert_transport_window_zero, \
            { "smf.expert.transportzero", PI_SEQUENCE, \
                PI_WARN, "Transport Window is zero", EXPFILL \
                }
        },
        EI_ASSUREDCTRL_SMF_EXPERT_ITEM
    };

/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_assuredctrl,
        &ett_FD_suback_list,
        &ett_FD_puback_list,
        &ett_FD_pubnotify_list,
        &ett_EP_behaviour_list,

        &ett_XA_msg_openXaSessionRequest_list,
        &ett_XA_msg_openXaSessionResponse_list,
        &ett_XA_msg_resumeXaSessionRequest_list,
        &ett_XA_msg_resumeXaSessionResponse_list,
        &ett_XA_msg_closeXaSessionRequest_list,
        &ett_XA_msg_closeXaSessionResponse_list,
        &ett_XA_msg_xaResponse_list,
        &ett_XA_msg_xaStartRequest_list,
        &ett_XA_msg_xaEndRequest_list,
        &ett_XA_msg_xaPrepareRequest_list,
        &ett_XA_msg_xaCommitRequest_list,
        &ett_XA_msg_xaRollbackRequest_list,
        &ett_XA_msg_xaForgetRequest_list,
        &ett_XA_msg_xaRecoverRequest_list,
        &ett_XA_msg_xaRecoverResponse_list,

        &ett_TXN_msg_txnResponse_list,
        &ett_TXN_msg_syncPrepareRequest_list,
        &ett_TXN_msg_asyncCommitRequest_list,
        &ett_TXN_msg_syncCommitRequest_list,
        &ett_TXN_msg_syncCommitStart_list,
        &ett_TXN_msg_syncCommitEnd_list,
        &ett_TXN_msg_syncRespoolRequest_list,
        &ett_TXN_msg_asyncRollbackRequest_list,
        &ett_TXN_msg_syncUncommitRequest_list,

        &ett_assuredctrl_start_replay_param,
        &ett_assuredctrl_timestamp_param,
        &ett_assuredctrl_analysis,
    };

/* Register the protocol name and description */
    proto_assuredctrl = proto_register_protocol(
        "Assured Control",  /* name */
        "AssuredCtrl",      /* short name */
        "assuredctrl"       /* abbrev */
        );

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_assuredctrl, hf, array_length(hf));
    expert_module_t* expert_assuredctrl = expert_register_protocol(proto_assuredctrl);
    expert_register_field_array(expert_assuredctrl, ei, array_length(ei));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("solace.assuredctrl", dissect_assuredctrl, proto_assuredctrl);
        
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
proto_reg_handoff_assuredctrl(void)
{
    static bool inited = false;
    
    if (!inited) {

        //dissector_handle_t assuredctrl_handle;
	//assuredctrl_handle = create_dissector_handle(dissect_assuredctrl, proto_assuredctrl);
        (void)create_dissector_handle(dissect_assuredctrl, proto_assuredctrl);
	//dissector_add("smf.encap_proto", 0x8, assuredctrl_handle);
        
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
