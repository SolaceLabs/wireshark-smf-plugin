/* sdt-decoder.c
 * Structured Data Type Dissector
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/wmem_scopes.h>
#include <epan/tvbuff.h>
#include <epan/column-info.h>

#include "packet-smf.h"
/* SDT Types */
#define SDT_NULL        0x00
#define SDT_BOOLEAN     0x01
#define SDT_INTEGER     0x02
#define SDT_UINTEGER    0x03
#define SDT_FLOAT       0x04
#define SDT_CHARACTER   0x05
#define SDT_BYTES       0x06
#define SDT_STRING      0x07
#define SDT_DESTINATION 0x08
#define SDT_SMF         0x09
#define SDT_MAP         0x0A
#define SDT_STREAM      0x0B

static const value_string sdttypenames[] = {
    { SDT_NULL,         "Null" },
    { SDT_BOOLEAN,      "Boolean" },
    { SDT_INTEGER,      "Integer" },
    { SDT_UINTEGER,     "UInteger" },
    { SDT_FLOAT,        "Float" },
    { SDT_CHARACTER,    "Character" },
    { SDT_BYTES,        "Bytes" },
    { SDT_STRING,       "String" },
    { SDT_DESTINATION,  "Destination" },
    { SDT_SMF,          "SMF Message" },
    { SDT_MAP,          "Map" },
    { SDT_STREAM,       "Stream" },
    { 0x00, NULL }
};

static const char *str_mapkey = "Key/";
static const char *str_mapval = "Val/";
static const char *str_mapnone = "";

static char *strtopic = "Topic";
static char *strqueue = "Queue";

static dissector_handle_t xml_handle;
static dissector_handle_t smrp_handle;

int ett_trace_span_message_creation_context = -1;

void get_embedded_smf_info(tvbuff_t* tvb, int offset, int length, int* embedded_smf_info)
{
    int pos;        /* position in payload */

    pos = offset;

    while (pos < offset + length) {
        int tag;        /* Code for current tag */
        int taglen;     /* How many bytes in length field? */
        int itemlen;    /* Length of this item */
        int payloadlen; /* Length of item payload */

        /* Parse the current tag */
        tag = (tvb_get_uint8(tvb, pos) & 0xFC) >> 2;
        taglen = (tvb_get_uint8(tvb, pos) & 0x03) + 1;
        pos++;
        switch (taglen)
        {
        case 1:
            itemlen = tvb_get_uint8(tvb, pos);
            break;
        case 2:
            itemlen = tvb_get_ntohs(tvb, pos);
            break;
        case 3:
            itemlen = tvb_get_ntoh24(tvb, pos);
            break;
        case 4:
            itemlen = tvb_get_ntohl(tvb, pos);
            break;
        }

        payloadlen = itemlen - taglen - 1; /* Just the item payload */
        pos += taglen; /* pos now points to beginning of payload */

                /* If it's a stream, call recursively to check contents */
        if (tag == SDT_STREAM)
        {
            get_embedded_smf_info(tvb, pos, payloadlen, embedded_smf_info);
        }

        /* If it is an embedded SMF message, fill array */
        if (tag == SDT_SMF) {
            embedded_smf_info[0] = pos;
            embedded_smf_info[1] = payloadlen;
        }

        pos += payloadlen;
    }


}

static void get_destination_string(tvbuff_t *tvb, int offset, int length, char *str, int str_len)
{
    int dest_type;
    char *dest_name;
    char *strdest_type;

    dest_type = tvb_get_uint8(tvb, offset);
    dest_name = tvb_get_string_enc(NULL, tvb, offset+1, length-1, ENC_ASCII);

    switch(dest_type) {
        case 0:
            strdest_type = strtopic;
            break;
        case 1:
            strdest_type = strqueue;
            break;
	default:
	    strdest_type = ""; // Default case causes strdest_type to be necessarily initialized, which resolves a compiler warning.
	    break;
    }

    g_snprintf(str, str_len, "%s \"%s\"", strdest_type, dest_name);
}

/* ********************************************************************************************************************************
   ********************************************************************************************************************************
   *********************************                                               ************************************************
   *********************************                                               ************************************************
   *********************************                                               ************************************************
   *********************************    SEE "Solsuite_Struct_Msg_Fmt_FS.docx"      ************************************************
   *********************************    FOR DETAILS ON STRUCTURED DATA TYPES       ************************************************
   *********************************                                               ************************************************
   *********************************                                               ************************************************
   *********************************                                               ************************************************
   ********************************************************************************************************************************
   ********************************************************************************************************************************
   ********************************************************************************************************************************
 */

void
add_sdt_block(proto_tree *bm_tree, packet_info* pinfo, int headerFieldIndex, tvbuff_t *tvb, int offset, int length, int indent, 
	 bool is_in_map)
{
	int pos;        /* position in payload */
    char *pad_buf;  /* buffer to use for left-padding our decode string */
    int item_cnt;   /* count of SDT items processed */

    int protocol_cnt = -1; /* position of "protocol" */
    int body_cnt = -1;     /* position of "body" */
    char *protocol_type = NULL; /* protocol type name */
    char* key_value = NULL; /* if the previous entry was a string and a key holds its value, otherwise is NULL */

    /* Generate a padding leader */
    pad_buf = (char*)malloc(indent + 1);
    memset( pad_buf, ' ', indent );
    pad_buf[indent] = '\0';

    item_cnt = 0;
    pos = offset;
    while(pos < offset+length) {
        int tag;        /* Code for current tag */
        int taglen;     /* How many bytes in length field? */
        int itemlen;    /* Length of this item */
        int payloadlen; /* Length of item payload */
        const char *tagtype_name; /* Holds the name of this item */
        char *buffer;               /* temp buffer to hold our decode string */
        char *string_payload;       /* extracted SDT string */
        char *dest_payload; /* use to build a destination string */
        const char *in_map_str;     /*   "Key/", "Val/" or ""   */
        enum { KEY, VALUE, NOT_IN_MAP } map_entry_type; /* if inside a map alternates between KEY and VALUE. Outside a map is NOT_IN_MAP */
        uint64_t int_payload = 0;
        tvbuff_t* next_tvb;
        //int payload_offset;
        int embedded_smf_info[2] = { 0, 0 };

        /* in_map_str is a prefix we print on keys and values: "Key/" on map keys, "Val/" on map values, if we're in a map */
        if (is_in_map) {
            if (item_cnt % 2 == 0) {
                in_map_str = str_mapkey;
                map_entry_type = KEY;
            }
            else {
                in_map_str = str_mapval;
                map_entry_type = VALUE;
            }
        } else {
            in_map_str = str_mapnone;
            map_entry_type = NOT_IN_MAP;
        }

        /* Parse the current tag */
        tag = (tvb_get_uint8(tvb, pos) & 0xFC) >> 2;
        taglen = (tvb_get_uint8(tvb, pos) & 0x03) + 1;
        pos++;
        switch (taglen)
        {
            case 1:
                itemlen = tvb_get_uint8(tvb, pos);
                break;
            case 2:
                itemlen = tvb_get_ntohs(tvb, pos);
                break;
            case 3:
                itemlen = tvb_get_ntoh24(tvb, pos);
                break;
            case 4:
                itemlen = tvb_get_ntohl(tvb, pos);
                break;
        }
        payloadlen = itemlen - taglen - 1; /* Just the item payload */
        pos += taglen; /* pos now points to beginning of payload */
        //payload_offset = taglen + 1;
        
        buffer = (char*)wmem_alloc(wmem_packet_scope(), 300);
        tagtype_name = try_val_to_str(tag, sdttypenames);

        switch (payloadlen)
        {
            case 1:
                int_payload = (uint64_t)tvb_get_uint8(tvb, pos);
            break;
            case 2:
                int_payload = (uint64_t)tvb_get_ntohs(tvb, pos);
            break;
            case 3:
                int_payload = (uint64_t)tvb_get_ntoh24(tvb, pos);
            break;
            case 4:
                int_payload = (uint64_t)tvb_get_ntohl(tvb, pos);
            break;
            case 5:
                int_payload = tvb_get_ntoh40(tvb, pos);
            break;
            case 6:
                int_payload = tvb_get_ntoh48(tvb, pos);
            break;
            case 7:
                int_payload = tvb_get_ntoh56(tvb, pos);
            break;
            case 8:
                int_payload = tvb_get_ntoh64(tvb, pos);
            break;
        }

        if (tagtype_name) {
            switch(tag) {
                case SDT_BOOLEAN:
                    g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d Value=%s",
                               pad_buf, in_map_str, tagtype_name, itemlen, payloadlen, int_payload == 0 ? "false" : "true");
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
                case SDT_INTEGER:
                    g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d Value=%" G_GUINT64_FORMAT "",
                               pad_buf, in_map_str, tagtype_name, itemlen, payloadlen, int_payload);
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
                case SDT_UINTEGER:
                    g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d Value=%" G_GUINT64_FORMAT "",
                               pad_buf, in_map_str, tagtype_name, itemlen, payloadlen, int_payload);
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
                case SDT_FLOAT:
                    if (payloadlen == 4)
                    {
                        g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d Value=%f",
                                   pad_buf, in_map_str, tagtype_name, itemlen, payloadlen, (float)int_payload);
                    }
                    else if (payloadlen == 8)
                    {
                        g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d Value=%f",
                                   pad_buf, in_map_str, tagtype_name, itemlen, payloadlen, (double)int_payload);
                    }
                    else
                    {
                        g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d",
                                   pad_buf, in_map_str, tagtype_name, itemlen, payloadlen);
                    }
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
                case SDT_CHARACTER:
                    if (payloadlen==2)
                    {
                        g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d Value=%lc",
                                   pad_buf, in_map_str, tagtype_name, itemlen, payloadlen, (uint16_t)int_payload);
                    }
                    else
                    {
                        g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d Value=%c",
                                   pad_buf, in_map_str, tagtype_name, itemlen, payloadlen, (uint8_t)int_payload);
                    }
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
                case SDT_BYTES:
                    if ((body_cnt != -1) && (item_cnt == body_cnt + 1)) {
                        if (strcmp(protocol_type, "SMRP") == 0) {
                            next_tvb = tvb_new_subset_length(tvb, pos, payloadlen);
                            call_dissector(smrp_handle, next_tvb, pinfo, bm_tree);
                            break;
                        }
                    }
                    if (map_entry_type == VALUE && key_value && strcmp(key_value, "ctx") == 0) {

                        g_snprintf(buffer, 300, "%s%sTrace Span Message Creation Context Length=%d, Payload=%d",
                            pad_buf, in_map_str, itemlen, payloadlen);

                        /* We highlight from 'pos' (beginning of payload) to end of payload */
                        proto_item* trace_item = proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                        proto_tree* subtree = proto_item_add_subtree(trace_item, ett_trace_span_message_creation_context);

                        // trace span message creation context is the same struct as trace span transport context
                        smf_proto_add_trace_span_transport_context_value(subtree, pinfo, tvb, pos, payloadlen);
                        break;
                    }

                    g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d",
                            pad_buf, in_map_str, tagtype_name, itemlen, payloadlen);
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
                case SDT_STRING:
                    string_payload = tvb_get_string_enc(NULL, tvb, pos, payloadlen, ENC_ASCII);
                    g_snprintf(buffer, 300, "%s%s%s \"%s\" Length=%d, Payload=%d", pad_buf, in_map_str, tagtype_name, string_payload, itemlen, payloadlen);
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    // Check to see if this is protocol
                    if (strcmp(string_payload, "protocol") == 0) {
                        protocol_cnt = item_cnt;
                    }
                    if ((protocol_cnt != -1) && (protocol_cnt + 1 == item_cnt)) {
                        protocol_type = string_payload;
                        if (strcmp(protocol_type, "CSPF") == 0) {
                            col_append_fstr(pinfo->cinfo, COL_PROTOCOL, " CSPF");
                        }
                    }
                    if (strcmp(string_payload, "body") == 0) {
                        body_cnt = item_cnt;
                    }
                    if (map_entry_type == KEY) {
                        key_value = string_payload;
                    }
                    break;
                case SDT_DESTINATION:
                    dest_payload = (char*)malloc(payloadlen+10);
                    get_destination_string(tvb, pos, payloadlen, dest_payload, payloadlen+10);
                    g_snprintf(buffer, 300, "%s%s%s %s Length=%d, Payload=%d", pad_buf, in_map_str, tagtype_name, dest_payload, itemlen, payloadlen);
                    free(dest_payload);
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
                case SDT_SMF:
                    g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d", pad_buf, in_map_str, tagtype_name, itemlen, payloadlen);
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    get_embedded_smf_info(tvb, offset, length, embedded_smf_info);
                    next_tvb = tvb_new_subset_length_caplen(tvb, embedded_smf_info[0], embedded_smf_info[1], embedded_smf_info[1]);
                    call_dissect_smf_common(next_tvb, pinfo, bm_tree, -1);
                    break;
                default:
                    /* Everything else is just a binary payload, which we'll highlight in the hexdump */
                    g_snprintf(buffer, 300, "%s%s%s Length=%d, Payload=%d", pad_buf, in_map_str, tagtype_name, itemlen, payloadlen);
                    /* We highlight from 'pos' (beginning of payload) to end of payload */
                    proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
                    break;
            }
        }
        //if (tagtype_name != SDT_SMF)
        //{
            /* We highlight from 'pos' (beginning of payload) to end of payload */
            //proto_tree_add_string(bm_tree, headerFieldIndex, tvb, pos, payloadlen, buffer);
        //}
        /* If we're starting a MAP or STREAM, we call ourselves recursively to parse its contents. */
        switch(tag) {
            case SDT_MAP:
                add_sdt_block(bm_tree, pinfo, headerFieldIndex, tvb, pos, payloadlen, indent+4, true);
                break;
            case SDT_STREAM:
                add_sdt_block(bm_tree, pinfo, headerFieldIndex, tvb, pos, payloadlen, indent+4, false);
                break;
        }

        if (!(map_entry_type == KEY && tag == SDT_STRING)) {
            key_value = NULL;
        }

        pos += payloadlen;
        item_cnt++;
    }
    free(pad_buf);
}

void sdt_decoder_init(void) 
{
    xml_handle = find_dissector("xml");
    smrp_handle = find_dissector("solace.smrp");
}
