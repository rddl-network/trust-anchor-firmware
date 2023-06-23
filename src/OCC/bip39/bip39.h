#ifndef WALLY_BIP39_FUNCTIONS_H
#define WALLY_BIP39_FUNCTIONS_H

#include "../SLIPSerialUtils/SLIPSerialUtils.h"


// Forward declarations for OSCMessage class and other types used.
class OSCMessage;

/* ----------------------------------------------------------------*/
/* wally bip39 functions                                           */
/* ----------------------------------------------------------------*/

void routeBip39GetLanguages(OSCMessage &msg, int addressOffset);

void routeBip39GetWordlist(OSCMessage &msg, int addressOffset);

void routeBip39GetWord(OSCMessage &msg, int addressOffset);

void routeBip39NumberBouncer(OSCMessage &msg, int addressOffset);

void routeBip39MnemonicValidate(OSCMessage &msg, int addressOffset);

void routeBip39MnemonicToSeed(OSCMessage &msg, int addressOffset);

void routeBip39MnemonicToSeed512(OSCMessage &msg, int addressOffset);

void routeBip39Mnemonic(OSCMessage &msg, int addressOffset);

void routeBip39MnemonicToBytes(OSCMessage &msg, int addressOffset);

void routeBip39MnemonicFromBytes(OSCMessage &msg, int addressOffset);

void routeBip39MnemonicToPrivateKey(OSCMessage &msg, int addressOffset);

#endif // WALLY_BIP39_FUNCTIONS_H
