/* packet-smf-compress.c
 * Routines for Solace Message Format with compression dissection
 * Copyright 2021, Solace Corporation 
 *
 * $Id: packet-smf-compress.c 657 2007-07-31 20:42:07Z $
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
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>

#include <wsutil/str_util.h>

#include <zlib.h>

#define MAX_DECOMPRESS_LEN 16384 // This comes from packet-tls-utils.c

static int proto_smf_compressed = -1;
static int global_smf_compressed_port = 55003;
static guint dictionary_init = 0xee;
static int hf_smf_compressed_segment_data = -1;

static dissector_handle_t smf_tcp_compressed_handle;

typedef struct _smf_uncompressed_buf_t {
    guchar *buf;
    guint len;    // Total length of the buffer
    guint smf_ready; // Ready to call SMF dissector
} smf_uncompressed_buf_t;

typedef struct _smf_compressed_stream_t {
    z_stream stream; // Compression stream
    int desegment_offset; // Lower level desegment offset of the uncompressed buffer
    int desegment_len;    // The next PDU size
    guint16 want_pdu_tracking;
    guint32 bytes_until_next_pdu;
    smf_uncompressed_buf_t* uncompressed_buf;
} smf_compressed_stream_t;

/* This holds state information for a SMF compressed conversation */
typedef struct _smf_compressed_conv_t {
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
    smf_compressed_stream_t stream1;
    smf_compressed_stream_t stream2;
} smf_compressed_conv_t;

static void init_stream(smf_compressed_stream_t *compressed_stream_p)
{
    z_stream* stream_p = &compressed_stream_p->stream;
    gint z_rc;
    stream_p->next_in  = Z_NULL;
    stream_p->avail_in = 0;
    stream_p->zalloc   = Z_NULL;
    stream_p->zfree    = Z_NULL;
    stream_p->opaque   = Z_NULL;
    inflateInit2(stream_p, -MAX_WBITS);

    // The dictionary helps with patial packet captures when the capture does not start from the beginning
    char *dictionary = (char *)malloc(32767);
    memset(dictionary, dictionary_init, 32767);
    z_rc = inflateSetDictionary(stream_p, dictionary, 32767);
    if (z_rc != Z_OK) {
        g_print("inflateSetDictionary error: %d\n", z_rc);
    }
    free(dictionary);
    compressed_stream_p->desegment_offset = 0;
    compressed_stream_p->desegment_len = 0;
    compressed_stream_p->want_pdu_tracking = 0;
    compressed_stream_p->bytes_until_next_pdu = 0;
    compressed_stream_p->uncompressed_buf = NULL;
}

static int
decompress_record(smf_compressed_stream_t* compressed_stream_p, const guchar* in, guint inl, guchar* out_str, guint* outl, packet_info * pinfo)
{
    gint err = Z_OK;

    z_stream* stream_p = &compressed_stream_p->stream;
DIAG_OFF(cast-qual)
    stream_p->next_in = (Bytef *)in;
DIAG_ON(cast-qual)

    stream_p->avail_in = inl;
    stream_p->next_out = out_str;
    stream_p->avail_out = *outl;
    if (inl > 0)
        err = inflate(stream_p, Z_SYNC_FLUSH);

    if (err != Z_OK) {
        char* outStr = "Unknown";
        switch (err) {
        case Z_ERRNO:
            outStr = "Stdio error";
            break;
        case Z_STREAM_ERROR:
            outStr = "Invalid Compression Level";
            break;
        case Z_DATA_ERROR:
            outStr = "Invalid or Incomplete deflate data";
            break;
        case Z_MEM_ERROR:
            outStr = "Out of memory";
            break;
        case Z_VERSION_ERROR:
            outStr = "zlib version mismatch";
            break;
        default:
            outStr = "Unknown";
            break;
        }
        g_print("ssl_decompress_record: Frame %d inflate() failed (%d): %s: %s\n", pinfo->fd->num, err, outStr, stream_p->msg);

        return -1;

    }

    // The outl indicates how much data is compressed
    *outl = *outl - stream_p->avail_out;
    return 0;
}

/* Reassemble and dissect an SMF packet over TCP */
static int dissect_smf_compressed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    conversation_t *conv;
    smf_compressed_conv_t *smf_compressed_conv;
    conv = find_or_create_conversation(pinfo);
    smf_compressed_stream_t *currentStream_p;
    int direction;

    smf_compressed_conv = (smf_compressed_conv_t *)conversation_get_proto_data(conv, proto_smf_compressed);
    if (!smf_compressed_conv) {
        // This is the first time.
        // Initialize the conversation
        // The inflateInit2 is set similar to ccsmp
        smf_compressed_conv = wmem_new0(wmem_file_scope(), smf_compressed_conv_t);
        init_stream(&smf_compressed_conv->stream1);
        init_stream(&smf_compressed_conv->stream2);
        conversation_add_proto_data(conv, proto_smf_compressed, smf_compressed_conv);
    }

     /* check direction and get ua lists */
    direction=cmp_address(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if(direction==0) {
        direction= (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }
    if(direction>=0) {
        currentStream_p = &smf_compressed_conv->stream1;
    } else {
        currentStream_p = &smf_compressed_conv->stream2;
    }

    smf_uncompressed_buf_t *uncompressed_buf = NULL;
    if (!PINFO_FD_VISITED(pinfo)) {
        // First time decoding the frame
        guint outl;
        guchar out_str[MAX_DECOMPRESS_LEN];
        outl = MAX_DECOMPRESS_LEN;
        int err = decompress_record(currentStream_p,
                                    (const guchar *)tvb_get_ptr(tvb, 0, -1),
                                    tvb_captured_length_remaining(tvb, 0),
                                    out_str,
                                    &outl,
                                    pinfo);
        if (err == -1) {
            // Error is reported inside decompress_record()
            return 0;
        }

        int isSmfReady = 0;
        // See if there is something left in the previous desegment
        if (currentStream_p->uncompressed_buf) {
            // There is data left from previous desegment.
            // Check if this there is still more to come
            if (currentStream_p->want_pdu_tracking) {
                guchar* bufEnd = currentStream_p->uncompressed_buf->buf + currentStream_p->uncompressed_buf->len;
                // the uncompressed data may contain more than the pdu, but we have alocated more room just in case
                memcpy(bufEnd, out_str, outl);
                currentStream_p->uncompressed_buf->len += outl;

                if (currentStream_p->bytes_until_next_pdu > outl) {   
                    // There is still more data to come. Let us put everthing into the buffer
                    // Reduce the size of data we are looking for
                    currentStream_p->bytes_until_next_pdu -= outl;
                } else {
                    // We have everything in the buffer, ready to dissect it
                    uncompressed_buf = currentStream_p->uncompressed_buf;
                    uncompressed_buf->smf_ready = 1;
                    currentStream_p->uncompressed_buf = NULL;
                }
            } else {
                // We have something in the previous segment, but we do not want pdu tracking
                // This is unexpected...
                g_print("Unexpected data in currentStream that is not tracked at packet %d\n", pinfo->num);
            }
        } else {
            // This is a new buffer
            isSmfReady = 1;
        }

        if (!uncompressed_buf) {
            // There is nothing in the uncompressed buffer, let us create one and put the current uncompressed data in
            // This is a new decompression, let us allocate it.
            uncompressed_buf = (smf_uncompressed_buf_t *)wmem_alloc(wmem_file_scope(), sizeof(smf_uncompressed_buf_t));
            uncompressed_buf->len = outl;
            uncompressed_buf->buf = (guchar*)wmem_alloc(wmem_file_scope(), uncompressed_buf->len);
            uncompressed_buf->smf_ready = isSmfReady;
            memcpy(uncompressed_buf->buf, out_str, outl);
        }

        // Save it so that we do not need to do uncompress when we revisit
        p_add_proto_data(wmem_file_scope(), pinfo, proto_smf_compressed,
                (guint32)tvb_raw_offset(tvb), uncompressed_buf);

    } else {
        uncompressed_buf = (smf_uncompressed_buf_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                proto_smf_compressed, (guint32)tvb_raw_offset(tvb));
    }

    guint nbytes = uncompressed_buf->len;
    proto_tree_add_item(tree, proto_smf_compressed, tvb, 0, -1, ENC_NA);
    tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, uncompressed_buf->buf, nbytes, nbytes);
    add_new_data_source(pinfo, next_tvb, "Decompressed Data");

    if (!uncompressed_buf->smf_ready) {
        // Not ready for SMF.
        // This means we are reassembling in later frame
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[SMF Compressed segment of a reassembled PDU]");
        return tvb_captured_length(tvb);
    }

    if (pinfo->can_desegment > 0) {
        // Need to allow smf to desegment
        pinfo->can_desegment++;
    }

    // Show the decompressed data in an attribute.
    proto_tree_add_item(tree, hf_smf_compressed_segment_data, next_tvb, 0, -1, ENC_NA);

    // smf would return information in pinfo->desegment_offset, etc...
    call_dissector_only(find_dissector("smf"), next_tvb, pinfo, tree, data);

    if (!PINFO_FD_VISITED(pinfo)) {
        // Remember what has been processed by smf
        currentStream_p->desegment_offset = pinfo->desegment_offset;
        currentStream_p->desegment_len = pinfo->desegment_len;
        currentStream_p->want_pdu_tracking = pinfo->want_pdu_tracking;
        currentStream_p->bytes_until_next_pdu = pinfo->bytes_until_next_pdu;
        currentStream_p->uncompressed_buf = NULL;

        if (pinfo->want_pdu_tracking) {
            // Keep a buffer big enough for the PDU.
            // That is: what is left in the current buffer + expected bytes to come
            guint32 leftInBuffer = uncompressed_buf->len - currentStream_p->desegment_offset;
            guint32 pduSize = leftInBuffer + currentStream_p->desegment_len;
            // Give more room at the end because the next smf message may be right there in the buffer
            guchar * nextPduBuf = (guchar*)wmem_alloc(wmem_file_scope(), pduSize + MAX_DECOMPRESS_LEN);
            memcpy(nextPduBuf, uncompressed_buf->buf + currentStream_p->desegment_offset, leftInBuffer);

            // Create a new uncompressed buf to track the next pdu
            uncompressed_buf = (smf_uncompressed_buf_t *)wmem_alloc(wmem_file_scope(), sizeof(smf_uncompressed_buf_t));
            uncompressed_buf->buf = nextPduBuf;
            uncompressed_buf->len = leftInBuffer;
            uncompressed_buf->smf_ready = 0;

            currentStream_p->uncompressed_buf = uncompressed_buf;
        }
    }
    // Always clear the desegment information for parent tcp layer
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;
    pinfo->want_pdu_tracking = 0;
    pinfo->bytes_until_next_pdu = 0;

    // Just keep going.
    return tvb_captured_length(tvb);
}

void proto_reg_handoff_smf_compress(void)
{
    static gboolean inited = FALSE;
        
	if (!inited) {
        smf_tcp_compressed_handle = create_dissector_handle(dissect_smf_compressed, proto_smf_compressed);
        dissector_add_uint("tcp.port", global_smf_compressed_port, smf_tcp_compressed_handle);
    }
}

void proto_register_smf_compress(void)
{
    /* TODO: Display raw decompressed data. Not working yet */
    static hf_register_info hf[] = {
        { &hf_smf_compressed_segment_data,
          { "SMF Compressed segment data", "smf-comp.segment_data", FT_BYTES, BASE_NONE, NULL, 0x0,
            "A data segment used in reassembly of a lower-level protocol", HFILL}},
    };

    proto_smf_compressed = proto_register_protocol("Solace Message Format (Compressed)", "SMF-COMP", "smf-comp");
    register_dissector("smf-comp", dissect_smf_compressed, proto_smf_compressed);

    proto_register_field_array(proto_smf_compressed, hf, array_length(hf));

    module_t* smfcomp_module;
    smfcomp_module = prefs_register_protocol(proto_smf_compressed, NULL);
    if (smfcomp_module) {
        prefs_register_uint_preference(smfcomp_module, "compression_dictionary_init", 
        "SMF Compression Dictionary Initial Value", "SMF Compression Dictionary Initial Value", 16, &dictionary_init);
    }  
}
