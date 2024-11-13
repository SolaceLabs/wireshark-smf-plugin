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
#include <epan/expert.h>

#include <wsutil/str_util.h>

#include <zlib.h>

#define MAX_DECOMPRESS_LEN 16384 // This comes from packet-tls-utils.c
#define ERROR_MSG_SIZE 256 // This is the size of the error message string

static int proto_smf_compressed = -1;
static int global_smf_compressed_port = 55003;
static unsigned int dictionary_init = 0xee;
static int hf_smf_compressed_segment_data = -1;

static dissector_handle_t smf_tcp_compressed_handle;

static expert_field ei_decompression_error = EI_INIT;

typedef struct _smf_uncompressed_buf_t {
    guchar *buf;
    unsigned int len;
    char *errorMsg;
} smf_uncompressed_buf_t;

typedef struct _smf_compressed_stream_t {
    z_stream stream; // Compression stream
    int desegment_offset; // Lower level desegment offset of the uncompressed buffer
    int desegment_len;    // The next PDU size
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

static voidpf stream_alloc(void * opaque, uInt num, uInt size)
{
    (void)opaque; // avoid compiler warning
    return wmem_alloc0(wmem_file_scope(), num*size);
}

static void stream_free(void * opaque, voidpf stream_address)
{
    (void)opaque; // avoid compiler warning
    wmem_free(wmem_file_scope(), stream_address);
}

static void init_stream(smf_compressed_stream_t *compressed_stream_p)
{
    z_stream* stream_p = &compressed_stream_p->stream;
    int z_rc;
    stream_p->next_in  = Z_NULL;
    stream_p->avail_in = 0;
    stream_p->zalloc   = stream_alloc;
    stream_p->zfree    = stream_free;
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
    compressed_stream_p->uncompressed_buf = NULL;
}

static void
decompress_record(smf_compressed_stream_t* compressed_stream_p, const guchar* in, unsigned int inl, guchar* out_str, unsigned int* outl, char *errorMsg_p)
{
    int err = Z_OK;

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
        
        snprintf(errorMsg_p, ERROR_MSG_SIZE, "%s(%d): %s", outStr, err, stream_p->msg);
        *outl = *outl - stream_p->avail_out;
        
        // Cleanup the decompressor and re-initialize
        inflateEnd(&compressed_stream_p->stream);
        init_stream(compressed_stream_p);

        return;

    }

    // The outl indicates how much data is compressed
    *outl = *outl - stream_p->avail_out;
    return;
}

/* Reassemble and dissect an SMF packet over TCP */
static int dissect_smf_compressed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    conversation_t *conv;
    smf_compressed_conv_t *smf_compressed_conv;
    conv = find_or_create_conversation(pinfo);
    smf_compressed_stream_t *currentStream_p;
    int direction;
    char errorMsg[ERROR_MSG_SIZE] = {0};

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
        unsigned int outl;
        guchar out_str[MAX_DECOMPRESS_LEN];
        outl = MAX_DECOMPRESS_LEN;
        decompress_record(currentStream_p,
                            (const guchar *)tvb_get_ptr(tvb, 0, -1),
                            tvb_captured_length_remaining(tvb, 0),
                            out_str,
                            &outl,
                            errorMsg);

        uncompressed_buf = (smf_uncompressed_buf_t *)wmem_alloc(wmem_file_scope(), sizeof(smf_uncompressed_buf_t));
        uncompressed_buf->len = outl;
        uncompressed_buf->errorMsg = NULL;
        if (errorMsg[0] != '\0') {
            // Some error message
            uncompressed_buf->errorMsg = (char *)wmem_alloc(wmem_file_scope(), sizeof(errorMsg));
            strcpy(uncompressed_buf->errorMsg, (char *)errorMsg);
        }
        // See if there is something left in the previous desegment
        int prefBufOffset = 0;
        if (currentStream_p->uncompressed_buf) {
            // There is data left from previous desegment. Create a buffer that can contain both buffers
            prefBufOffset = currentStream_p->uncompressed_buf->len - currentStream_p->desegment_offset;
        }
        uncompressed_buf->len = outl + prefBufOffset;
        uncompressed_buf->buf = (guchar*)wmem_alloc(wmem_file_scope(), uncompressed_buf->len);
        guchar* curbuffer = uncompressed_buf->buf;
        if (currentStream_p->uncompressed_buf) {
            guchar* offsetbuf = currentStream_p->uncompressed_buf->buf + currentStream_p->desegment_offset;
            memcpy(curbuffer, offsetbuf, prefBufOffset);
            curbuffer += prefBufOffset;
            
            if (currentStream_p->desegment_offset == 0) {
                // The previous buffer was not used at all.
                // dealloc the old buffer
                wmem_free(wmem_file_scope(), currentStream_p->uncompressed_buf->buf);
                currentStream_p->uncompressed_buf->len = 0;
            }
        }
        memcpy(curbuffer, out_str, outl);

        // Save it so that we do not need to do uncompress when we revisit
        p_add_proto_data(wmem_file_scope(), pinfo, proto_smf_compressed,
                (uint32_t)tvb_raw_offset(tvb), uncompressed_buf);

    } else {
        uncompressed_buf = (smf_uncompressed_buf_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                proto_smf_compressed, (uint32_t)tvb_raw_offset(tvb));
        if (!uncompressed_buf) {
            // g_print("Cannot find previously parsed data - %d\n", tvb_raw_offset(tvb));
            return tvb_captured_length(tvb);
        }
    }

    unsigned int nbytes = uncompressed_buf->len;
    if (nbytes == 0) {
        // memory freed
        // This means we are reassembling in later frame
        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "[SMF Compressed segment of a reassembled PDU]");
        return 0;
    }
    proto_tree_add_item(tree, proto_smf_compressed, tvb, 0, -1, ENC_NA);

    tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, uncompressed_buf->buf, nbytes, nbytes);
    add_new_data_source(pinfo, next_tvb, "Decompressed Data");

    if (pinfo->can_desegment > 0) {
        // Need to allow smf to desegment
        pinfo->can_desegment++;
    }

    // Show the decompressed data in an attribute.
    proto_item *item = proto_tree_add_item(tree, hf_smf_compressed_segment_data, next_tvb, 0, -1, ENC_NA);

    if (uncompressed_buf->errorMsg) {
        char *isSnaplencapture = "";
        if (tvb_captured_length(tvb) != tvb_reported_length(tvb)) {
            // This is a packet capture with snap length
            // This is the likely cause of decompression failure
            isSnaplencapture = " (Snaplen capture)";
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "[Decompression Error%s]", isSnaplencapture);
        expert_add_info_format(pinfo, item, &ei_decompression_error, "Decompression Error%s: %s", isSnaplencapture, uncompressed_buf->errorMsg);
    }

    // Dont care what smf returns, just keep going
    // Could check if we have collect enough data in currentStream_p->desegment_len. To do later...
    // Does not hurt to call smf dissector, just a little slower.
    call_dissector_only(find_dissector("solace.smf"), next_tvb, pinfo, tree, data);

    if (!PINFO_FD_VISITED(pinfo)) {
        currentStream_p->desegment_offset = pinfo->desegment_offset;
        currentStream_p->desegment_len = pinfo->desegment_len;
        currentStream_p->uncompressed_buf = NULL;
        if ((currentStream_p->desegment_offset != 0) || 
            (currentStream_p->desegment_len != 0)) {
            // There is some data left for desegment.
            // Keep a link for the next segment
            currentStream_p->uncompressed_buf = uncompressed_buf;
        }
    }
    // Always clear the desegment information for tcp layer.
    pinfo->desegment_offset = 0;
    pinfo->desegment_len = 0;

    // Just keep going.
    return tvb_captured_length(tvb);
}

void proto_reg_handoff_smf_compress(void)
{
    static bool inited = false;
        
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

    static ei_register_info ei[] = {
        { &ei_decompression_error,
            { "smf-comp.decompression_error", PI_PROTOCOL,
                PI_ERROR, "Decompression Error", EXPFILL
                }},
    };

    proto_smf_compressed = proto_register_protocol("Solace Message Format (Compressed)", "SMF-COMP", "smf-comp");
    register_dissector("solace.smf-comp", dissect_smf_compressed, proto_smf_compressed);

    proto_register_field_array(proto_smf_compressed, hf, array_length(hf));

    expert_module_t* expert_smf_compressed = expert_register_protocol(proto_smf_compressed);
    expert_register_field_array(expert_smf_compressed, ei, array_length(ei));

    module_t* smfcomp_module;
    smfcomp_module = prefs_register_protocol(proto_smf_compressed, NULL);
    if (smfcomp_module) {
        prefs_register_uint_preference(smfcomp_module, "compression_dictionary_init", 
        "SMF Compression Dictionary Initial Value", "SMF Compression Dictionary Initial Value", 16, &dictionary_init);
    }  
}
