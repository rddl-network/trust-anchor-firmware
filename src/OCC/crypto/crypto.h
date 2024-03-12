#pragma once

#include "OSCMessage.h"


void routeWallyEcSigFromBytes(OSCMessage &msg, int addressOffset);
void routeWallyEcSigNormalize(OSCMessage &msg, int addressOffset);
void routeWallyEcSigToDer(OSCMessage &msg, int addressOffset);
void routeWallyEcSigFromDer(OSCMessage &msg, int addressOffset);
void routeWallyEcSigVerify2(OSCMessage &msg, int addressOffset);
void routeWallyEcSigToPublicKey(OSCMessage &msg, int addressOffset);
void routeWallyFormatBitcoinMessage(OSCMessage &msg, int addressOffset);
void routeWallyEcdh(OSCMessage &msg, int addressOffset);
// void routeSeedToBlindingKey(OSCMessage &msg, int adressOffset);