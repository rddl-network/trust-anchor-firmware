#include "core.h"
#include <OSCMessage.h>
#include <wally_core.h>

#include "../SLIPSerialUtils/SLIPSerialUtils.h"

void routeWallyInit(OSCMessage &msg, int addressOffset)
{
    wally_init(0x00);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyInit");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyCleanup(OSCMessage &msg, int addressOffset)
{
    wally_cleanup(0x00);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyCleanup");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyGetSecpContext(OSCMessage &msg, int addressOffset)
{
    secp256k1_context_struct *ctxStrct;
    wally_get_secp_context();

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyGetSecpContext");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyGetNewSecpContext(OSCMessage &msg, int addressOffset)
{
    secp256k1_context_struct *ctxStrct;
    // wally_get_new_secp_context();

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyGetNewSecpContext");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallySecpContextFree(OSCMessage &msg, int addressOffset)
{
    secp256k1_context_struct *ctxStrct;
    // wally_secp_context_free(ctxStrct);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallySecpContextFree");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyBZero(OSCMessage &msg, int addressOffset)
{
    char *bytes;
    size_t len;
    wally_bzero(bytes, len);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyBZero");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyFreeString(OSCMessage &msg, int addressOffset)
{
    char *str;
    wally_free_string(str);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyBZero");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallySecpRandomize(OSCMessage &msg, int addressOffset)
{
    unsigned char *bytes;
    size_t len;
    wally_secp_randomize(bytes, len);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyBZero");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}