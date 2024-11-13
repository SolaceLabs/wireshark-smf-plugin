/* packet-matelink.c
 * Routines for Solace Message Format with compression dissection
 * Copyright 2021, Solace Corporation
 *
 * $Id: packet-matelink.c 657 2007-07-31 20:42:07Z $
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
#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <epan/dissectors/packet-tcp.h>
/*
The matelink structure is based on
https://sol-repo.solace.com/viewvc/vrs32/trunk/solcbr/dataplane/sw/assuredDelivery/common/include/adCmnSoftMateLink.hpp
*/
/*
    struct MessageHdr
    {
        ...
        UINT8  type_m; // enum MateLinkMessageType
        UINT8  id_m;
        UINT16 pad0_m;
        UINT32 length_m;
        UINT64 sequence_m;
        ...
    };

    MessageHdr is 16 bytes.
*/
#define MATELINK_HDR_SIZE 16
#define MD5_BUF_LEN 16

static int proto_matelink = -1;

static int global_matelink_port = 8741;

static dissector_handle_t matelink_handle;

static bool matelink_desegment = true;

/* Header */
static int hf_matelink_type = -1;
static int hf_matelink_id = -1;
static int hf_matelink_pad0 = -1;
static int hf_matelink_len = -1;
static int hf_matelink_seq = -1;
// Default
static int hf_matelink_data = -1;
/* Hello */
static int hf_matelink_hello_magic = -1;
static int hf_matelink_hello_journalId = -1;
static int hf_matelink_hello_journalId2 = -1;
static int hf_matelink_hello_journalSequence = -1;
static int hf_matelink_hello_needAck = -1;
static int hf_matelink_hello_isAck = -1;
static int hf_matelink_hello_hasCheckSum = -1;
static int hf_matelink_hello_adbChkSumType = -1;
static int hf_matelink_hello_adbChkSumLen = -1;
static int hf_matelink_hello_pad1 = -1;
static int hf_matelink_hello_pad2 = -1;
static int hf_matelink_hello_mytimestamp = -1;
static int hf_matelink_hello_echoedtimestamp = -1;
static int hf_matelink_hello_diskAvail = -1;
static int hf_matelink_hello_diskUsage = -1;
static int hf_matelink_hello_iNodeAvail = -1;
static int hf_matelink_hello_adbSize = -1;
static int hf_matelink_hello_adbChkSum = -1;
static int hf_matelink_hello_processingDelayTimestamp = -1;
/* journal Write */
static int  hf_matelink_journalwrite_requestId= -1;
static int  hf_matelink_journalwrite_pad= -1;
static int  hf_matelink_journalwrite_data= -1;
/* journal Write */
static int  hf_matelink_journalwriteack_requestId= -1;
static int  hf_matelink_journalwriteack_nak= -1;
static int  hf_matelink_journalwriteack_pad= -1;
/* Door Bell */
static int  hf_matelink_doorbell_queueId= -1;
static int  hf_matelink_doorbell_pad= -1;
/* Sync Write */
static int  hf_matelink_syncwrite_offset= -1;
static int  hf_matelink_syncwrite_requestid= -1;
/* TransHeader */
static int  hf_matelink_transheader_length= -1;
static int  hf_matelink_transheader_type= -1;
static int  hf_matelink_transheader_checksum= -1;
static int  hf_matelink_transheader_sequence= -1;

/* Initialize the subtree pointers */
static int ett_matelink = -1;

enum MateLinkMessage
{
    MessageTypeUndefined,
    MessageTypeHello,
    MessageTypeJournalWrite,
    MessageTypeJournalWriteAck, // also for ack MessageTypeSyncWrite
    MessageTypeSyncWrite,
    MessageTypeDoorBell,
    MessageTypeSyncSpoolFileToDiskRequest,
    MessageTypeMoveMsgToDiskResponse,
    MessageTypeRemoveFileRequest,
    MessageTypeRemoveFileResponse,
    MessageTypeBulkRemoveFilesRequest,
    MessageTypeDpMateLinkHello,
    MAX_MATELINK_TYPE = MessageTypeDpMateLinkHello
};

/* Maps protocol numbers to protocol names */
static const value_string matelinktype_name[] =
{
{ MessageTypeUndefined, "Undefined" },
{ MessageTypeHello, "Hello" },
{ MessageTypeJournalWrite, "JournalWrite" },
{ MessageTypeJournalWriteAck, "JournalWriteAck" },
{ MessageTypeSyncWrite, "SyncWrite" },
{ MessageTypeDoorBell, "MessageTypeDoorBell" },
{ MessageTypeSyncSpoolFileToDiskRequest, "SyncSpoolFileToDiskRequest" },
{ MessageTypeMoveMsgToDiskResponse, "MoveMsgToDiskResponse" },
{ MessageTypeRemoveFileRequest, "RemoveFileRequest" },
{ MessageTypeRemoveFileResponse, "RemoveFileResponse" },
{ MessageTypeBulkRemoveFilesRequest, "BulkRemoveFilesRequest" },
{ MessageTypeDpMateLinkHello, "DpMateLinkHello" },
};

enum Type {
    TypeInvalid,
    TypeStart,
    TypeEntry,
    TypeTrailer,
    TypePadding,
    TypeCommitted,
    TypeInfo,
};

static const value_string transheaderType_name[] =
{
{TypeInvalid, "Invalid"},
{TypeStart, "Start"},
{TypeEntry, "Entry"},
{TypeTrailer, "Trailer"},
{TypePadding, "Padding"},
{TypeCommitted, "Committed"},
{TypeInfo, "Info"},
};

enum ChkSumType_t
{
    CHKSUM_NONE = 0,
    CHKSUM_SUM,
    CHKSUM_ADLER32,
    CHKSUM_MD5,
    CHKSUM_MAX
};

static const value_string adbChkSumType_name[] =
{
{ CHKSUM_NONE, "None"},
{ CHKSUM_SUM, "Sum"},
{ CHKSUM_ADLER32, "ADLER32"},
{ CHKSUM_MD5, "MD5"},
};

static const uint32_t MAX_MSG_SIZE_30MB = 32 * 1024 * 1024;

/* if we return 0, it means the current PDU is deferred until we
* get the next packet.
* If we return 1 (or anything less then the fix offset,
* it means the current PDU is an error and we will be marked as error
* and we move on to the next packet.
* If everything is OK return the length of the smf message
*/
static uint32_t test_matelink(tvbuff_t *tvb, packet_info* pinfo, int offset)
{
    // If the remaining length is less then 12, we do not have enough to test
    int remainingLength = tvb_captured_length(tvb) - offset;
    if (remainingLength < MATELINK_HDR_SIZE)
    {
        // Not enough data
        return 1;
    }
    // Check type
    uint8_t firstByte = tvb_get_uint8(tvb, offset);
    if (firstByte > MAX_MATELINK_TYPE)
    {
        return 1;
    }
    // Check length
    uint32_t msglen = tvb_get_uint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);
    if (msglen < MATELINK_HDR_SIZE) {
        // The message is too small.
        return 1;
    }
    if (msglen > MAX_MSG_SIZE_30MB) {
        // The message is too big.
        return 1;
    }
    if ((uint32_t)remainingLength < msglen)
    {
        // Need more data to complete the message
        if (pinfo->can_desegment) {
            return 0;
        } else {
            // Cannot Desegment from TCP, so just do what we can...
            return msglen;
        }
    }
    return msglen;
}

static void dissect_matelink_hello(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "Hello");
    // Header already dissected

    int size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_magic, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_journalId, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_journalId2, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_journalSequence, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    // bits within a byte
    size = 4;
    proto_tree_add_item(tree, hf_matelink_hello_needAck, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_matelink_hello_isAck, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_matelink_hello_hasCheckSum, tvb, 1, size, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_matelink_hello_adbChkSumType, tvb, offset, size, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_matelink_hello_adbChkSumLen, tvb, offset, size, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_matelink_hello_pad1, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 4;
    proto_tree_add_item(tree, hf_matelink_hello_pad2, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_mytimestamp, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_echoedtimestamp, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_diskAvail, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_diskUsage, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_iNodeAvail, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_adbSize, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = MD5_BUF_LEN;
    proto_tree_add_item(tree, hf_matelink_hello_adbChkSum, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 8;
    proto_tree_add_item(tree, hf_matelink_hello_processingDelayTimestamp, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    return;
}

static void dissect_matelink_journalWrite(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, int len)
{
    col_set_str(pinfo->cinfo, COL_INFO, "JournalWrite");
    // Header already dissected
    int size = 4;
    proto_tree_add_item(tree, hf_matelink_journalwrite_requestId, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 4;
    proto_tree_add_item(tree, hf_matelink_journalwrite_pad, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    // The rest
    while (offset < len) {
        uint32_t curlen;
        size = 4;
        proto_tree_add_item_ret_uint(tree, hf_matelink_transheader_length, tvb, offset, size, ENC_LITTLE_ENDIAN, &curlen);
        proto_tree_add_item(tree, hf_matelink_transheader_type, tvb, offset, size, ENC_LITTLE_ENDIAN);
        offset += size;
        size = 4;
        proto_tree_add_item(tree, hf_matelink_transheader_checksum, tvb, offset, size, ENC_LITTLE_ENDIAN);
        offset += size;
        size = 8;
        proto_tree_add_item(tree, hf_matelink_transheader_sequence, tvb, offset, size, ENC_LITTLE_ENDIAN);
        offset += size;
        size = curlen-16;
        proto_tree_add_item(tree, hf_matelink_journalwrite_data, tvb, offset, curlen-16, ENC_LITTLE_ENDIAN);
        offset += size;
    }    

    return;
}

static void dissect_matelink_journalWriteAck(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "JournalWriteAck");
    // Header already dissected
    int size = 4;
    proto_tree_add_item(tree, hf_matelink_journalwriteack_requestId, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 4;
    proto_tree_add_item(tree, hf_matelink_journalwriteack_nak, tvb, offset, size, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_matelink_journalwriteack_pad, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    return;
}

static void dissect_matelink_doorBell(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "DoorBell");
    // Header already dissected
    int size = 4;
    proto_tree_add_item(tree, hf_matelink_doorbell_queueId, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 4;
    proto_tree_add_item(tree, hf_matelink_doorbell_pad, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    return;
}

static void dissect_matelink_SyncWrite(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{
    col_set_str(pinfo->cinfo, COL_INFO, "SyncWrite");
    // Header already dissected
    int size = 4;
    proto_tree_add_item(tree, hf_matelink_syncwrite_offset, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    size = 4;
    proto_tree_add_item(tree, hf_matelink_syncwrite_requestid, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    proto_tree_add_item(tree, hf_matelink_data, tvb, offset, -1, ENC_LITTLE_ENDIAN);
    return;
}

/* Determine the total length of an matelink packet, given the message header */
static unsigned int get_matelink_pdu_len(packet_info* inf, tvbuff_t *tvb, int offset, void *data _U_)
{
    /* msglen initialze to 1 because
     * if we return 0, it means the current PDU is deferred until we
     * get the next packet.
     * If we return 1 (or anything less then the fix offset,
     * it means the current PDU is an error and we will be marked as error
     * and we move on to the next packet.
     */
    uint32_t msglen = test_matelink(tvb, inf, offset);
    return msglen;
}

/* Dissect an SMF packet in a reassembled TCP PDU */
static int dissect_matelink_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, void *data _U_)
{
    proto_item* ti;
    proto_tree* matelink_tree;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Matelink");
    col_clear(pinfo->cinfo, COL_INFO);

    uint8_t matelinktype = tvb_get_uint8(tvb, 0);
    uint32_t msglen = tvb_get_uint32(tvb, 4, ENC_LITTLE_ENDIAN);
    ti = proto_tree_add_item(tree, proto_matelink, tvb, 0, msglen, ENC_LITTLE_ENDIAN);
    matelink_tree = proto_item_add_subtree(ti, ett_matelink);

    // Message Header
    int offset = 0;
    proto_tree_add_item(matelink_tree, hf_matelink_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(matelink_tree, hf_matelink_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(matelink_tree, hf_matelink_pad0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    uint32_t len;
    proto_tree_add_item_ret_uint(matelink_tree, hf_matelink_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &len);
    offset += 4;
    proto_tree_add_item(matelink_tree, hf_matelink_seq, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    switch (matelinktype) {
    case MessageTypeHello: {
        dissect_matelink_hello(tvb, pinfo, matelink_tree, offset);
        break;
    }
    case MessageTypeJournalWrite: {
        dissect_matelink_journalWrite(tvb, pinfo, matelink_tree, offset, len);
        break;
    }
    case MessageTypeJournalWriteAck: {
        dissect_matelink_journalWriteAck(tvb, pinfo, matelink_tree, offset);
        break;
    }
    case MessageTypeDoorBell: {
        dissect_matelink_doorBell(tvb, pinfo, matelink_tree, offset);
        break;
    }
    case MessageTypeSyncWrite: {
        dissect_matelink_SyncWrite(tvb, pinfo, matelink_tree, offset);
        break;
    }
    default: {
        col_set_str(pinfo->cinfo, COL_INFO, "ToDo...");
        proto_tree_add_item(matelink_tree, hf_matelink_data, tvb, offset, msglen-offset, ENC_LITTLE_ENDIAN);
        break;
    }
    }

    return tvb_captured_length(tvb);
}

/* Reassemble and dissect an makelink packet over TCP */
static int dissect_matelink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, matelink_desegment, MATELINK_HDR_SIZE, get_matelink_pdu_len,
        dissect_matelink_tcp_pdu, data);

    return tvb_captured_length(tvb);
}

void proto_reg_handoff_matelink(void)
{
    static bool inited = false;
        
	if (!inited) {
        matelink_handle = create_dissector_handle(dissect_matelink, proto_matelink);
        dissector_add_uint("tcp.port", global_matelink_port, matelink_handle);        
    }
}

void proto_register_matelink(void)
{
    static hf_register_info hf[] = {
        // Header
        { &hf_matelink_type,
            { "Message Type", "matelink.type",
                FT_UINT8, BASE_HEX, VALS(matelinktype_name), 0x0,
                "", HFILL
            }},
        { &hf_matelink_id,
            { "Message Id", "matelink.id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_pad0,
            { "Pad0", "matelink.pad0",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_len,
            { "Message Length", "matelink.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_seq,
            { "Message Sequence", "matelink.sequence",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},        

        // default        
        { &hf_matelink_data,
            { "Message Data", "matelink.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "", HFILL
            }},    

        // Hello
        { &hf_matelink_hello_magic,
            { "Magic", "matelink.hello.magic",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                "", HFILL
            }},
         { &hf_matelink_hello_journalId,
            { "Journal Id", "matelink.hello.journalId",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
         { &hf_matelink_hello_journalId2,
            { "Journal Id2", "matelink.hello.journalId2",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
         { &hf_matelink_hello_journalSequence,
            { "Journal Sequence", "matelink.hello.journalSequence",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        // The bit encoding are most significant bit last
        { &hf_matelink_hello_needAck,
            { "Need Ack", "matelink.hello.needAck",
                FT_BOOLEAN, 32, NULL, 0x00000001,
                "", HFILL
            }},
        { &hf_matelink_hello_isAck,
            { "Is Ack", "matelink.hello.isAck",
                FT_BOOLEAN, 32, NULL, 0x00000002,
                "", HFILL
            }},
        { &hf_matelink_hello_hasCheckSum,
            { "Has Check Sum", "matelink.hello.hasCheckSum",
                FT_BOOLEAN, 32, NULL, 0x00000004,
                "", HFILL
            }},
        { &hf_matelink_hello_adbChkSumType,
            { "ADB Check Sum Type", "matelink.hello.adbCheckSumType",
                FT_UINT8, BASE_HEX, VALS(adbChkSumType_name), 0x00000018,
                "", HFILL
            }},
        { &hf_matelink_hello_adbChkSumLen,
            { "ADB Check Sum Len", "matelink.hello.adbCheckSumLen",
                FT_UINT8, BASE_HEX, NULL, 0x000007E0,
                "", HFILL
            }},
        { &hf_matelink_hello_pad1,
            { "Padding 1", "matelink.hello.pad1",
                FT_UINT32, BASE_DEC, NULL, 0xFFFFF800,
                "", HFILL
            }},
        { &hf_matelink_hello_pad2,
            { "Padding 2", "matelink.hello.pad2",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_mytimestamp,
            { "My Time Stamp", "matelink.hello.mytimestamp",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_echoedtimestamp,
            { "Echoed Time Stamp", "matelink.hello.echoedtimestamp",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_diskAvail,
            { "Disk Available", "matelink.hello.diskAvail",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_diskUsage,
            { "Disk Usage", "matelink.hello.diskUsage",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_iNodeAvail,
            { "iNode Available", "matelink.hello.iNodeAvail",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_adbSize,
            { "ADB Size", "matelink.hello.adbSize",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_adbChkSum,
            { "ADB Checksum", "matelink.hello.adbChkSum",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "", HFILL
            }},
        { &hf_matelink_hello_processingDelayTimestamp,
            { "Processing Delay Timestamp", "matelink.hello.processingDelayTimestamp",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 
        // Journal Write
        { &hf_matelink_journalwrite_requestId,
            { "Request Id", "matelink.journalwrite.requestId",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 
        { &hf_matelink_journalwrite_pad,
            { "Pad", "matelink.journalwrite.pad",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 
        { &hf_matelink_journalwrite_data,
            { "Data", "matelink.journalwrite.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "", HFILL
            }}, 
        // Journal Write Ack
        { &hf_matelink_journalwriteack_requestId,
            { "Request Id", "matelink.journalwriteack.requestId",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 
        { &hf_matelink_journalwriteack_nak,
            { "NAK", "matelink.journalwriteack.nak",
                FT_UINT32, BASE_DEC, NULL, 0x00000001,
                "", HFILL
            }}, 
        { &hf_matelink_journalwriteack_pad,
            { "Pad", "matelink.journalwriteack.pad",
                FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFE,
                "", HFILL
            }}, 
        // Door Bell
        { &hf_matelink_doorbell_queueId,
            { "Queue Id", "matelink.doorbell.queueid",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 
        { &hf_matelink_doorbell_pad,
            { "Pad", "matelink.doorbell.pad",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 
        // Sync Write
        { &hf_matelink_syncwrite_offset,
            { "Offset", "matelink.syncwrite.offset",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 
        { &hf_matelink_syncwrite_requestid,
            { "Request Id", "matelink.syncwrite.requestid",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }}, 

        // Trans Header (inside Journal Write)
        // UINT32          length : 28,
        //                 type : 4;
        // UINT32          checksum;
        // UINT64          sequence;
        { &hf_matelink_transheader_length,
            { "Length", "matelink.transheader.length",
                FT_UINT32, BASE_DEC, NULL, 0x0FFFFFFF,
                "", HFILL
            }}, 
        { &hf_matelink_transheader_type,
            { "Type", "matelink.transheader.type",
                FT_UINT32, BASE_DEC, VALS(transheaderType_name), 0xF0000000,
                "", HFILL
            }},     
        { &hf_matelink_transheader_checksum,
            { "Checksum", "matelink.transheader.checksum",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},                         
        { &hf_matelink_transheader_sequence,
            { "Sequence", "matelink.transheader.sequence",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                "", HFILL
            }},
    };

    /* Setup protocol subtree array */
    static int *ett[] =
    {
        &ett_matelink,
    };

    proto_matelink = proto_register_protocol("Solace Matelink", "Matelink", "matelink");

    proto_register_field_array(proto_matelink, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.matelink", dissect_matelink, proto_matelink);
}
