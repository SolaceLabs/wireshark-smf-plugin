#ifndef __PACKET_SMF_H__
#define __PACKET_SMF_H__

struct smfdata {
	char *subtype;
};
void call_dissect_smf_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int bdChannel);
void smf_proto_add_trace_span_transport_context_value(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb, int offset, int size);

#define ETHERTYPE_SMF_BACKDOOR 0xbacd

// 0x200 (1023) is max channel #, but..
// ...we use 0x400 as there are two 
// directions (LC->CC and CC->LC)
#define MAX_BD_CHANNEL         0x7ff
#endif
