#ifndef VALISE_HEADER_H
#define VALISE_HEADER_H

#include "../SLIPSerialUtils/SLIPSerialUtils.h"

void routeValiseSign(OSCMessage &msg, int addressOffset);
void routeValiseMnemonicSeedInit(OSCMessage &msg, int addressOffset);
void routeValiseMnemonicSet(OSCMessage &msg, int addressOffset);
void routeValiseMnemonicGet(OSCMessage &msg, int addressOffset);
void routeValiseSeedSet(OSCMessage &msg, int addressOffset);
void routeValiseSeedGet(OSCMessage &msg, int addressOffset);
void routeValiseCborEcho(OSCMessage &msg, int addressOffset);

#endif // VALISE_HEADER_H
