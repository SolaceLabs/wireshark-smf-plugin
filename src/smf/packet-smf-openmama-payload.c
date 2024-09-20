/* packet-smf-openmama-payload.c
 * Solace OpenMAMA payload Dissector
 * Copyright 2015, Solace Corporation
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
#include <epan/exceptions.h>
//#include <epan/tvbuff_subset.c>

/* Forward declaration we need below */
void proto_reg_handoff_mama_payload(void);

static dissector_handle_t mama_payload_handle;

/* Initialize the protocol and registered fields */
static int proto_mama_payload = -1;

static int hf_mama_payload_type = -1;
static int hf_mama_payload_version = -1;
static int hf_mama_stream_length = -1;
static int hf_mama_payload_field = -1;
static int hf_mama_field_id = -1;
static int hf_mama_field_name = -1;
static int hf_mama_field_value_bool = -1;
static int hf_mama_field_value_char = -1;
static int hf_mama_field_value_i8 = -1;
static int hf_mama_field_value_u8 = -1;
static int hf_mama_field_value_i16 = -1;
static int hf_mama_field_value_u16 = -1;
static int hf_mama_field_value_i32 = -1;
static int hf_mama_field_value_u32 = -1;
static int hf_mama_field_value_i64 = -1;
static int hf_mama_field_value_u64 = -1;
static int hf_mama_field_value_f32 = -1;
static int hf_mama_field_value_f64 = -1;
static int hf_mama_field_value_string = -1;
static int hf_mama_field_value_datetime = -1;
static int hf_mama_field_value_datetime_seconds = -1;
static int hf_mama_field_value_datetime_microseconds = -1;
static int hf_mama_field_value_datetime_precision = -1;
static int hf_mama_field_value_datetime_hints = -1;
static int hf_mama_field_value_price = -1;
static int hf_mama_field_value_price_f64 = -1;
static int hf_mama_field_value_price_u8 = -1;
//static int hf_mama_field_value_msg = -1;
static int hf_mama_field_value_opaque = -1;
static int hf_mama_field_value_vector = -1;

/* */
#define SMF_PARAM_TYPE_NULL 0x0
#define SMF_PARAM_TYPE_BOOLEAN 0x04
#define SMF_PARAM_TYPE_INTEGER 0x08
#define SMF_PARAM_TYPE_UNSIGNED_INTEGER 0x0c
#define SMF_PARAM_TYPE_FLOAT 0x10
#define SMF_PARAM_TYPE_CHAR 0x14
#define SMF_PARAM_TYPE_BYTE_ARRAY 0x18
#define SMF_PARAM_TYPE_STRING 0x1c
#define SMF_PARAM_TYPE_DESTINATION 0x20
#define SMF_PARAM_TYPE_SMF_MSG 0x24
#define SMF_PARAM_TYPE_MAP 0x28
#define SMF_PARAM_TYPE_STREAM 0x2c

#define SMF_PARAM_MASK 0xFC  /* 6 higher bits for parameter types*/
#define SMF_PARAM_LENGTH_IN_BYTES_MASK 0x03 /* 2 lower bits for parameter length in byes */

/* SubTay Type*/
#define MAMA_PAYLOAD_SUBTAG_TYPE_MSG 1
#define MAMA_PAYLOAD_SUBTAG_TYPE_OPAQUE 7
#define MAMA_PAYLOAD_SUBTAG_TYPE_DATETIME 26
#define MAMA_PAYLOAD_SUBTAG_TYPE_PRICE 27
#define MAMA_PAYLOAD_SUBTAG_TYPE_BOOLEAN_VECTOR 29
#define MAMA_PAYLOAD_SUBTAG_TYPE_CHAR_VECTOR 30
#define MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_1BYTE_VECTOR 34
#define MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_1BYTE_VECTOR 35
#define MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_2BYTE_VECTOR 36
#define MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_2BYTE_VECTOR 37
#define MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_4BYTE_VECTOR 38
#define MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_4BYTE_VECTOR 39
#define MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_8BYTE_VECTOR 40
#define MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_8BYTE_VECTOR 41
#define MAMA_PAYLOAD_SUBTAG_TYPE_FLOAT_4BYTE_VECTOR 44
#define MAMA_PAYLOAD_SUBTAG_TYPE_FLOAT_8BYTE_VECTOR 45
#define MAMA_PAYLOAD_SUBTAG_TYPE_STRING_VECTOR 46
#define MAMA_PAYLOAD_SUBTAG_TYPE_MSG_VECTOR 47
#define MAMA_PAYLOAD_SUBTAG_TYPE_DATETIME_VECTOR 48
#define MAMA_PAYLOAD_SUBTAG_TYPE_PRICE_VECTOR 49
#define MAMA_PAYLOAD_SUBTAG_UNKNOWN  100
#define MAMA_PAYLOAD_SUBTAG_TYPE_FIELDNAME  101

/* Initialize the subtree pointers */
static int ett_mama_payload = -1;
static int ett_mama_payload_field = -1;
static int ett_mama_payload_field_price = -1;
static int ett_mama_payload_field_vector = -1;
static int ett_mama_payload_field_datetime = -1;

static int
dissect_mama_field_str(
    tvbuff_t *tvb,
    int offset,
    proto_tree *tree,
    packet_info *pinfo _U_)
{
    uint8_t type;
    uint32_t value_len;
    uint8_t len_bytes;
    int loop;

    /* field name (optional) or field value */
    type = tvb_get_uint8(tvb, offset);

    len_bytes = (type & SMF_PARAM_LENGTH_IN_BYTES_MASK) + 1 ;
    value_len = 0;
    for (loop=0; loop <len_bytes; loop++) {
        value_len = (value_len << 8) +  tvb_get_uint8(tvb, offset + 1 +loop );
    }
    value_len -= (len_bytes+1); /* */

    proto_tree_add_item(tree, hf_mama_field_value_string, tvb, offset+len_bytes +1, value_len, false);

    return value_len + len_bytes +1;
}

static int
dissect_mama_field_msg(
    tvbuff_t *tvb,
    int offset,
    proto_tree *tree,
    packet_info *pinfo)
{
    uint8_t type;
    uint32_t value_len;
    uint8_t len_bytes;
    tvbuff_t *next_tvb;
    int loop;

    /* field name (optional) or field value */
    type = tvb_get_uint8(tvb, offset);
    len_bytes = (type & SMF_PARAM_LENGTH_IN_BYTES_MASK) + 1 ;
    value_len = 0;
    for (loop=0; loop <len_bytes; loop++) {
        value_len = (value_len << 8) +  tvb_get_uint8(tvb, offset + 1 +loop );
    }
    value_len -= (len_bytes+2);

    next_tvb = tvb_new_subset_length_caplen(tvb, 
        offset+len_bytes +2, 
        value_len, 
        value_len);
    call_dissector(mama_payload_handle, next_tvb, pinfo, tree);

    return value_len + len_bytes +2;
}

static void 
dissect_vector_param(
    tvbuff_t *tvb,
    int offset,
    int value_len,
    uint8_t tag,
    proto_tree *tree,
    packet_info *pinfo)
{
    proto_tree   *field_tree;	        
    proto_item   *ti;
    int loop;
    int count;
    int local_offset;

    ti = proto_tree_add_item(tree, hf_mama_field_value_vector, tvb, offset, value_len, false);
    field_tree =   proto_item_add_subtree(ti, ett_mama_payload_field_vector);

    switch (tag) 
    {

    case MAMA_PAYLOAD_SUBTAG_TYPE_BOOLEAN_VECTOR:
        for (loop =0; loop < value_len; loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_bool, tvb, offset+loop, 1, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_CHAR_VECTOR:
        for (loop =0; loop < (value_len/2); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_char, tvb, offset+2*loop, 2, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_1BYTE_VECTOR:
        for (loop =0; loop < value_len; loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_i8, tvb, offset+loop, 1, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_1BYTE_VECTOR:
        for (loop =0; loop < value_len; loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_u8, tvb, offset+loop, 1, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_2BYTE_VECTOR:
        for (loop =0; loop < (value_len/2); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_i16, tvb, offset+2*loop, 2, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_2BYTE_VECTOR:
        for (loop =0; loop < (value_len/2); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_u16, tvb, offset+2*loop, 2, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_4BYTE_VECTOR:
        for (loop =0; loop < (value_len/4); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_i32, tvb, offset+4*loop, 4, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_4BYTE_VECTOR:
        for (loop =0; loop < (value_len/4); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_u32, tvb, offset+4*loop, 4, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_8BYTE_VECTOR:
        for (loop =0; loop < (value_len/8); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_i64, tvb, offset+8*loop, 8, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_8BYTE_VECTOR:
        for (loop =0; loop < (value_len/8); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_u64, tvb, offset+8*loop, 8, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_FLOAT_4BYTE_VECTOR:
        for (loop =0; loop < (value_len/4); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_f32, tvb, offset+4*loop, 4, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_FLOAT_8BYTE_VECTOR:
        for (loop =0; loop < (value_len/8); loop++) {
            proto_tree_add_item(field_tree, hf_mama_field_value_f64, tvb, offset+8*loop, 8, false);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_DATETIME_VECTOR:
        for (loop =0; loop < (value_len/8); loop++) {
            ti = proto_tree_add_item(field_tree, hf_mama_field_value_datetime, tvb, offset+8*loop, 8, false);
            field_tree =   proto_item_add_subtree(ti, ett_mama_payload_field_datetime);
            proto_tree_add_item(field_tree,
                hf_mama_field_value_datetime_seconds, tvb, offset+8*loop, 4, false);
            proto_tree_add_item(field_tree,
                hf_mama_field_value_datetime_precision, tvb, offset+8*loop+4, 1, false); 
            proto_tree_add_item(field_tree,
                hf_mama_field_value_datetime_hints, tvb, offset+8*loop+4, 1, false); 
            proto_tree_add_item(field_tree,
                hf_mama_field_value_datetime_microseconds, tvb, offset+8*loop+5, 3, false); 
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_PRICE_VECTOR:
        for (loop =0; loop < (value_len/9); loop++) {
            ti = proto_tree_add_item(field_tree, hf_mama_field_value_price, tvb, offset+9*loop, 9, false);
            field_tree =   proto_item_add_subtree(ti, ett_mama_payload_field_price);
            proto_tree_add_item(field_tree,
                hf_mama_field_value_price_f64, tvb, offset+9*loop, 8, false);
            proto_tree_add_item(field_tree,
                hf_mama_field_value_price_u8, tvb, offset+9*loop+8, 1, false);	
        }
        break;

    case MAMA_PAYLOAD_SUBTAG_TYPE_STRING_VECTOR:
        count = tvb_get_ntohl(tvb, offset);
        local_offset = 4;
        for (loop = 0; loop < count; loop++) {
            local_offset += dissect_mama_field_str(tvb, offset+local_offset, field_tree, pinfo);
        }
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_MSG_VECTOR:
        count = tvb_get_ntohl(tvb, offset);
        local_offset = 4;
        for (loop = 0; loop < count; loop++) {
            local_offset += dissect_mama_field_msg(tvb, offset+local_offset, field_tree, pinfo);
        }
        break;

    default:
        break;
    }
}

static void 
dissect_byte_array_param(
    tvbuff_t *tvb,
    int offset,
    int value_len,
    uint8_t tag,
    proto_tree *tree,
    packet_info *pinfo)
{
    tvbuff_t *next_tvb;
    proto_tree   *field_tree;	        
    proto_item   *ti;

    switch (tag)
    {
    case MAMA_PAYLOAD_SUBTAG_TYPE_MSG:
        next_tvb = tvb_new_subset_length_caplen(tvb, 
            offset, 
            value_len, 
            value_len);
        call_dissector(mama_payload_handle, next_tvb, pinfo, tree);
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_OPAQUE:
        proto_tree_add_item(tree,
            hf_mama_field_value_opaque, tvb, offset, value_len, false);
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_DATETIME:
        ti = proto_tree_add_item(tree, hf_mama_field_value_datetime, tvb, offset, value_len, false);
        field_tree =   proto_item_add_subtree(ti, ett_mama_payload_field_datetime);
        proto_tree_add_item(field_tree,
            hf_mama_field_value_datetime_seconds, tvb, offset, 4, false);
        proto_tree_add_item(field_tree,
            hf_mama_field_value_datetime_precision, tvb, offset+4, 1, false); 
        proto_tree_add_item(field_tree,
            hf_mama_field_value_datetime_hints, tvb, offset+4, 1, false); 
        proto_tree_add_item(field_tree,
            hf_mama_field_value_datetime_microseconds, tvb, offset+5, 3, false); 
        break;
    case MAMA_PAYLOAD_SUBTAG_TYPE_PRICE:
        ti = proto_tree_add_item(tree,
            hf_mama_field_value_price, tvb, offset, value_len, false);
        field_tree =   proto_item_add_subtree(ti, ett_mama_payload_field_price);
        proto_tree_add_item(field_tree,
            hf_mama_field_value_price_f64, tvb, offset, 8, false);
        proto_tree_add_item(field_tree,
            hf_mama_field_value_price_u8, tvb, offset+8, 1, false);
        break;

    case MAMA_PAYLOAD_SUBTAG_TYPE_BOOLEAN_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_CHAR_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_1BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_1BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_2BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_2BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_4BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_4BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_INTEGER_8BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_UNSIGNED_INTEGER_8BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_FLOAT_4BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_FLOAT_8BYTE_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_STRING_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_MSG_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_DATETIME_VECTOR:
    case MAMA_PAYLOAD_SUBTAG_TYPE_PRICE_VECTOR:
        dissect_vector_param(tvb, offset, value_len, tag, tree, pinfo);
        break;
    case MAMA_PAYLOAD_SUBTAG_UNKNOWN:
    default:
        break;
    }
}

static int mama_field_length(
    tvbuff_t *tvb,
    int offset)
{
    int field_len = 0;
    uint8_t tag;
    uint8_t param_type;
    uint32_t param_value_len;
    uint8_t param_len_bytes;
    int loop;

    /* field id*/
    field_len =4;

    /* field name (optional) or field value */
    param_type = tvb_get_uint8(tvb, offset+field_len);
    field_len++;
    param_len_bytes = (param_type & SMF_PARAM_LENGTH_IN_BYTES_MASK) + 1 ;
    param_value_len = 0;
    for (loop=0; loop <param_len_bytes; loop++) {
        param_value_len = (param_value_len << 8) +  tvb_get_uint8(tvb, offset + field_len+loop );
    }
    param_value_len -= (param_len_bytes+1); /* */
    field_len += param_len_bytes;

    /*  check for optional field name  */
    if ( (param_type & SMF_PARAM_MASK)  == SMF_PARAM_TYPE_BYTE_ARRAY  ) {
        tag = tvb_get_uint8(tvb, offset + field_len );
        /* check for field name */
        if (tag == MAMA_PAYLOAD_SUBTAG_TYPE_FIELDNAME) {
            field_len++;
            param_value_len--;
            field_len += param_value_len;
            param_type = tvb_get_uint8(tvb, offset + field_len);
            field_len++;
            param_len_bytes = (param_type & SMF_PARAM_LENGTH_IN_BYTES_MASK) +1;
            param_value_len = 0;
            for (loop=0; loop <param_len_bytes; loop++) {
                param_value_len = (param_value_len << 8) +  tvb_get_uint8(tvb, offset + field_len+loop );
            }
            param_value_len -= (param_len_bytes+1);
            field_len += param_len_bytes;
        }
    }

    /* field value */
    switch (param_type & SMF_PARAM_MASK)
    {
    case SMF_PARAM_TYPE_BYTE_ARRAY:
        tag=tvb_get_uint8(tvb, offset + field_len );
        field_len++;
        param_value_len--;
        break;
    default:
        break;
    }
    field_len += param_value_len;
    return field_len;
}

static int
dissect_mama_field(
    tvbuff_t *tvb,
    int offset,
    proto_tree *tree,
    packet_info *pinfo)
{
    int field_len = 0;
    uint8_t tag;
    uint8_t param_type;
    uint32_t param_value_len;
    uint8_t param_len_bytes;
    int loop;
    proto_tree   *field_tree;
    proto_item   *ti;
    field_len = mama_field_length(tvb, offset);
    ti = proto_tree_add_item(tree, hf_mama_payload_field, tvb, offset, field_len, false);
    field_tree =   proto_item_add_subtree(ti, ett_mama_payload_field);

    /* field id: skip the 1st 2 bytes */
    field_len =2;
    proto_tree_add_item(field_tree,
        hf_mama_field_id, tvb, offset+field_len, 2, false);
    field_len +=2;

    /* field name (optional) or field value */
    param_type = tvb_get_uint8(tvb, offset+field_len);
    field_len++;
    param_len_bytes = (param_type & SMF_PARAM_LENGTH_IN_BYTES_MASK) + 1 ;
    param_value_len = 0;
    for (loop=0; loop <param_len_bytes; loop++) {
        param_value_len = (param_value_len << 8) +  tvb_get_uint8(tvb, offset + field_len+loop );
    }
    param_value_len -= (param_len_bytes+1); /* */
    field_len += param_len_bytes;

    /*  check for optional field name  */
    if ( (param_type & SMF_PARAM_MASK)  == SMF_PARAM_TYPE_BYTE_ARRAY  ) {
        tag = tvb_get_uint8(tvb, offset + field_len );
        /* check for field name */
        if (tag == MAMA_PAYLOAD_SUBTAG_TYPE_FIELDNAME) {
            field_len++;
            param_value_len--;
            proto_tree_add_item(field_tree,
                hf_mama_field_name, tvb, offset+field_len, param_value_len, false);
            field_len += param_value_len;
            param_type = tvb_get_uint8(tvb, offset + field_len);
            field_len++;
            param_len_bytes = (param_type & SMF_PARAM_LENGTH_IN_BYTES_MASK) +1;
            param_value_len = 0;
            for (loop=0; loop <param_len_bytes; loop++) {
                param_value_len = (param_value_len << 8) +  tvb_get_uint8(tvb, offset + field_len+loop );
            }
            param_value_len -= (param_len_bytes+1);
            field_len += param_len_bytes;
        }
    }

    /* field value */
    switch (param_type & SMF_PARAM_MASK)
    {
    case SMF_PARAM_TYPE_BOOLEAN:
        proto_tree_add_item(field_tree, hf_mama_field_value_bool, tvb, offset+field_len, param_value_len, false);
        break;

    case SMF_PARAM_TYPE_INTEGER:
        switch (param_value_len)
        {
        case 1:
            proto_tree_add_item(field_tree, hf_mama_field_value_i8, tvb, offset+field_len, param_value_len, false);
            break;
        case 2:
            proto_tree_add_item(field_tree, hf_mama_field_value_i16, tvb, offset+field_len, param_value_len, false);
            break;
        case 4:
            proto_tree_add_item(field_tree, hf_mama_field_value_i32, tvb, offset+field_len, param_value_len, false);
            break;		
        case 8:
        default:
            proto_tree_add_item(field_tree, hf_mama_field_value_i64, tvb, offset+field_len, param_value_len, false);
            break;
        }
        break;
    case SMF_PARAM_TYPE_UNSIGNED_INTEGER:
        switch (param_value_len)
        {
        case 1:
            proto_tree_add_item(field_tree, hf_mama_field_value_u8, tvb, offset+field_len, param_value_len, false);
            break;
        case 2:
            proto_tree_add_item(field_tree, hf_mama_field_value_u16, tvb, offset+field_len, param_value_len, false);
            break;
        case 4:
            proto_tree_add_item(field_tree, hf_mama_field_value_u32, tvb, offset+field_len, param_value_len, false);
            break;		
        case 8:
        default:
            proto_tree_add_item(field_tree, hf_mama_field_value_u64, tvb, offset+field_len, param_value_len, false);
            break;
        }
        break;
    case SMF_PARAM_TYPE_FLOAT:
        if (param_value_len == 4) {
            proto_tree_add_item(field_tree, hf_mama_field_value_f32, tvb, offset+field_len, param_value_len, false);
        }
        else {
            proto_tree_add_item(field_tree, hf_mama_field_value_f64, tvb, offset+field_len, param_value_len, false);
        }
        break;
    case SMF_PARAM_TYPE_CHAR:
        proto_tree_add_item(field_tree, hf_mama_field_value_char, tvb, offset+field_len, param_value_len, false);
        break;

    case SMF_PARAM_TYPE_BYTE_ARRAY:
        tag=tvb_get_uint8(tvb, offset + field_len );
        field_len++;
        param_value_len--;
        dissect_byte_array_param(tvb, offset+field_len, param_value_len, tag, field_tree, pinfo);	
        break;

    case SMF_PARAM_TYPE_STRING:
        proto_tree_add_item(field_tree, hf_mama_field_value_string, tvb, offset+field_len, param_value_len, false);
        break;
    case SMF_PARAM_TYPE_DESTINATION:
    case SMF_PARAM_TYPE_SMF_MSG:
    case SMF_PARAM_TYPE_MAP:
    case SMF_PARAM_TYPE_NULL:
    default:
        break;
    }
    field_len += param_value_len;
    return field_len;
}

static void
dissect_mama_fields(
    tvbuff_t *tvb,
    int field_offset_start,
    int field_offset_end,
    proto_tree *tree,
    packet_info *pinfo)
{
    int offset;

    for (offset=field_offset_start; offset<field_offset_end; )
    {
        offset += dissect_mama_field(tvb, offset, tree, pinfo);
    }
}


/* Code to actually dissect the packets */
static int
dissect_mama_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *payload_tree;
    int stream_len;

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_mama_payload, tvb, 0, -1, false);
    payload_tree = proto_item_add_subtree(ti, ett_mama_payload);

    stream_len = tvb_get_ntohl(tvb, 3);
    proto_tree_add_item(payload_tree,
        hf_mama_payload_type, tvb, 0, 1, false);

    proto_tree_add_item(payload_tree,
        hf_mama_payload_version, tvb, 1, 1, false);

    proto_tree_add_item(payload_tree,
        hf_mama_stream_length, tvb, 3, 4, false);

    dissect_mama_fields(tvb, 7, stream_len-5, payload_tree, pinfo); 

    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_mama_payload(void)
{

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_mama_payload_type, { "Payload type", "mama-payload.type", FT_UINT8, BASE_HEX, NULL, 0xFF, "", HFILL } },
        { &hf_mama_payload_version,{ "Payload version",     "mama-payload.version",FT_UINT8, BASE_DEC, NULL, 0x0,  "", HFILL } },
        { &hf_mama_stream_length,{ "Field stream length",     "mama-payload.stream-length", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } },
        { &hf_mama_payload_field, { "Stream entry",           "mama-payload.field", FT_BYTES, BASE_NONE, NULL, 0x00, "", HFILL } },
        { &hf_mama_field_id,
            { "Field ID",     "mama-payload.field-id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
        { &hf_mama_field_name,
            { "Field name", "mama-payload.field-name", FT_STRING, BASE_NONE,
                NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_bool,
            { "Boolean value", "mama-payload.field-value.bool", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_i8,
            { "Int8 value", "mama-payload.field-value-i8",  FT_INT8, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_i16,
            { "Int16 value", "mama-payload.field-value-i16",  FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_i32,
            { "Int32 value", "mama-payload.field-value-i32",  FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_i64,
            { "Int64 value", "mama-payload.field-value-i64",  FT_INT64, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_u8,
            { "Uint8 value", "mama-payload.field-value-u8",  FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_u16,
            { "Uint16 value", "mama-payload.field-value-u16",  FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_u32,
            { "Uint32 value", "mama-payload.field-value-u32",  FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_u64,
            { "Uint64 value", "mama-payload.field-value-u64",  FT_UINT64, BASE_DEC, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_f32,
            { "Float32 value", "mama-payload.field-value-f32",  FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } 
        },
        { &hf_mama_field_value_f64,
            { "Float64 value", "mama-payload.field-value-f64",  FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } 
        },
        { &hf_mama_field_value_char,
            { "Char value", "mama-payload.field-value-char",  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } 
        },
        { &hf_mama_field_value_string,
            { "String value", "mama-payload.field-value-string",  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } 
        },
        { &hf_mama_field_value_opaque,
            { "Opaque value",           "mama-payload.field-opaque",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_mama_field_value_datetime,
            { "Datetime value",           "mama-payload.field-datetime",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "", HFILL }
        },
        { &hf_mama_field_value_datetime_seconds,
            { "Seconds",           "mama-payload.field-datetime-seconds",
            FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } 
        },
        { &hf_mama_field_value_datetime_precision,
            { "Precision",           "mama-payload.field-datetime-precision",
            FT_UINT8, BASE_DEC, NULL, 0xF0, "", HFILL } 
        },
        { &hf_mama_field_value_datetime_hints,
            { "Hints",           "mama-payload.field-datetime-hints",
            FT_UINT8, BASE_DEC, NULL, 0x0F, "", HFILL } 
        },
        { &hf_mama_field_value_datetime_microseconds,
            { "Microseconds",           "mama-payload.field-datetime-ms",
            FT_UINT32, BASE_HEX, NULL, 0x000FFFFF, "", HFILL } 
        },
        { &hf_mama_field_value_price,
            { "Price value (float64, uint8)", "mama-payload.field-value-price",  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } 
        },
        { &hf_mama_field_value_vector,
            { "Vector value", "mama-payload.field-value-vector",  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } 
        },
        { &hf_mama_field_value_price_f64,
            { "Price", "mama-payload.field-value-price-f64",  FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } 
        },
        { &hf_mama_field_value_price_u8,
            { "Hints", "mama-payload.field-value-price-u8",  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } 
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_mama_payload,
        &ett_mama_payload_field,
        &ett_mama_payload_field_price,
        &ett_mama_payload_field_vector,
        &ett_mama_payload_field_datetime
    };

    /* Register the protocol name and description */
    proto_mama_payload = proto_register_protocol(
        "OpenMAMA Payload",
        "OpenMAMA-Payload", "mama-payload");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_mama_payload, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("solace.mama-payload", dissect_mama_payload, proto_mama_payload);

}


/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these routines
   and create the code that calls these routines.

   This function is also called by preferences whenever "Apply" is pressed
   (see prefs_register_protocol above) so it should accommodate being called
   more than once.
*/
void
proto_reg_handoff_mama_payload(void)
{
    static bool inited = false;

    if (!inited) {
        mama_payload_handle = create_dissector_handle(dissect_mama_payload, proto_mama_payload);
        inited = true;
    }
}

