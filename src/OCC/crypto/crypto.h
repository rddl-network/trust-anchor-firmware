#ifndef WALLY_CORE_FUNCTIONS_H
#define WALLY_CORE_FUNCTIONS_H

#include <OSCMessage.h>
#include <wally_core.h>
#include "wally_crypto.h"

#include "../SLIPSerialUtils/SLIPSerialUtils.h"
#include "../../helper/helper.h"

void routeWallyEcSigFromBytes(OSCMessage &msg, int addressOffset);
void routeWallyEcSigNormalize(OSCMessage &msg, int addressOffset);
void routeWallyEcSigToDer(OSCMessage &msg, int addressOffset);
void routeWallyEcSigFromDer(OSCMessage &msg, int addressOffset);
void routeWallyEcSigVerify2(OSCMessage &msg, int addressOffset);
void routeWallyEcSigToPublicKey(OSCMessage &msg, int addressOffset);
void routeWallyFormatBitcoinMessage(OSCMessage &msg, int addressOffset);
void routeWallyEcdh(OSCMessage &msg, int addressOffset);

#endif // WALLY_CORE_FUNCTIONS_H
