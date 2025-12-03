// Copyright 2025 Solace Corporation. All rights reserved.

#include "config.h"

#include <gmodule.h>

/* plugins are DLLs on Windows */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#include <wsutil/plugins.h>

#include "epan/proto.h"

void proto_register_assuredctrl(void);
void proto_register_bm(void);
void proto_register_clientctrl(void);
void proto_register_mama_payload(void);
void proto_register_matelink(void);
void proto_register_pubctrl(void);
void proto_register_smf(void);
void proto_register_smf_compress(void);
void proto_register_smp(void);
void proto_register_smrp(void);
void proto_register_subctrl(void);
void proto_register_xmllink(void);
void proto_reg_handoff_assuredctrl(void);
void proto_reg_handoff_bm(void);
void proto_reg_handoff_clientctrl(void);
void proto_reg_handoff_mama_payload(void);
void proto_reg_handoff_matelink(void);
void proto_reg_handoff_pubctrl(void);
void proto_reg_handoff_smf(void);
void proto_reg_handoff_smf_compress(void);
void proto_reg_handoff_smp(void);
void proto_reg_handoff_smrp(void);
void proto_reg_handoff_subctrl(void);
void proto_reg_handoff_xmllink(void);

WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

uint32_t plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}

void plugin_register(void)
{
    static proto_plugin plug_assuredctrl;

    plug_assuredctrl.register_protoinfo = proto_register_assuredctrl;
    plug_assuredctrl.register_handoff = proto_reg_handoff_assuredctrl;
    proto_register_plugin(&plug_assuredctrl);
    static proto_plugin plug_bm;

    plug_bm.register_protoinfo = proto_register_bm;
    plug_bm.register_handoff = proto_reg_handoff_bm;
    proto_register_plugin(&plug_bm);
    static proto_plugin plug_clientctrl;

    plug_clientctrl.register_protoinfo = proto_register_clientctrl;
    plug_clientctrl.register_handoff = proto_reg_handoff_clientctrl;
    proto_register_plugin(&plug_clientctrl);
    static proto_plugin plug_mama_payload;

    plug_mama_payload.register_protoinfo = proto_register_mama_payload;
    plug_mama_payload.register_handoff = proto_reg_handoff_mama_payload;
    proto_register_plugin(&plug_mama_payload);
    static proto_plugin plug_matelink;

    plug_matelink.register_protoinfo = proto_register_matelink;
    plug_matelink.register_handoff = proto_reg_handoff_matelink;
    proto_register_plugin(&plug_matelink);
    static proto_plugin plug_pubctrl;

    plug_pubctrl.register_protoinfo = proto_register_pubctrl;
    plug_pubctrl.register_handoff = proto_reg_handoff_pubctrl;
    proto_register_plugin(&plug_pubctrl);
    static proto_plugin plug_smf;

    plug_smf.register_protoinfo = proto_register_smf;
    plug_smf.register_handoff = proto_reg_handoff_smf;
    proto_register_plugin(&plug_smf);
    static proto_plugin plug_smf_compress;

    plug_smf_compress.register_protoinfo = proto_register_smf_compress;
    plug_smf_compress.register_handoff = proto_reg_handoff_smf_compress;
    proto_register_plugin(&plug_smf_compress);
    static proto_plugin plug_smp;

    plug_smp.register_protoinfo = proto_register_smp;
    plug_smp.register_handoff = proto_reg_handoff_smp;
    proto_register_plugin(&plug_smp);
    static proto_plugin plug_smrp;

    plug_smrp.register_protoinfo = proto_register_smrp;
    plug_smrp.register_handoff = proto_reg_handoff_smrp;
    proto_register_plugin(&plug_smrp);
    static proto_plugin plug_subctrl;

    plug_subctrl.register_protoinfo = proto_register_subctrl;
    plug_subctrl.register_handoff = proto_reg_handoff_subctrl;
    proto_register_plugin(&plug_subctrl);
    static proto_plugin plug_xmllink;

    plug_xmllink.register_protoinfo = proto_register_xmllink;
    plug_xmllink.register_handoff = proto_reg_handoff_xmllink;
    proto_register_plugin(&plug_xmllink);
}

