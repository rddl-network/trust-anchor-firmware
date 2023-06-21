#ifndef VALISE_HEADER_H
#define VALISE_HEADER_H

#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "../SLIPSerialUtils/SLIPSerialUtils.h"
#include "../../helper/helper.h"
#include <Preferences.h>

extern Preferences valise;

class Preferences;
class OSCMessage;

void routeValiseSign(OSCMessage &msg, int addressOffset);
void routeValiseMnemonicSeedInit(OSCMessage &msg, int addressOffset);
void routeValiseMnemonicSet(OSCMessage &msg, int addressOffset);
void routeValiseMnemonicGet(OSCMessage &msg, int addressOffset);
void routeValiseSeedSet(OSCMessage &msg, int addressOffset);
void routeValiseSeedGet(OSCMessage &msg, int addressOffset);
void routeValiseCborEcho(OSCMessage &msg, int addressOffset);

#endif // VALISE_HEADER_H
