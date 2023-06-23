#ifndef OCC_CORE_H
#define OCC_CORE_H

#include "../utils/utils.h"


void routeWallyInit(OSCMessage &msg, int addressOffset);
void routeWallyCleanup(OSCMessage &msg, int addressOffset);
void routeWallyGetSecpContext(OSCMessage &msg, int addressOffset);
void routeWallyGetNewSecpContext(OSCMessage &msg, int addressOffset);
void routeWallySecpContextFree(OSCMessage &msg, int addressOffset);
void routeWallyBZero(OSCMessage &msg, int addressOffset);
void routeWallyFreeString(OSCMessage &msg, int addressOffset);
void routeWallySecpRandomize(OSCMessage &msg, int addressOffset);
void routeWallySymKeyFromSeed(OSCMessage &msg, int addressOffset);
void routeWallySymKeyFromParent(OSCMessage &msg, int addressOffset);
void routeEntropy(OSCMessage &msg, int addressOffset);
void routeTrnd(OSCMessage &msg, int addressOffset);



#endif // OCC_CORE_H
