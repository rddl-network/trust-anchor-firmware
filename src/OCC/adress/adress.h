#pragma once

#include "OSCMessage.h"

void routeWallyWifFromBytes(OSCMessage &msg, int addressOffset);
void routeWallyWifToBytes(OSCMessage &msg, int addressOffset);
void routeWallyBip32KeyToAddress(OSCMessage &msg, int addressOffset);
void routeWallyWifToPublicKey(OSCMessage &msg, int addressOffset);