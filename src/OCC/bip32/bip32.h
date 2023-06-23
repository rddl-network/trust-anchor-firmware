#pragma once

#include "OSCMessage.h"


void routeBip32KeyInit(OSCMessage &msg, int addressOffset);
void routeBip32KeyFromSeed(OSCMessage &msg, int addressOffset);
void routeBip32KeyFromParent(OSCMessage &msg, int addressOffset);
void routeBip32KeyFromParent2(OSCMessage &msg, int addressOffset);
void routeBip32KeyToBase58(OSCMessage &msg, int addressOffset);
void routeBip32KeyFromParentPathString(OSCMessage &msg, int addressOffset);
void routeBip32KeySerialize(OSCMessage &msg, int addressOffset);
void routeBip32KeyUnserialize(OSCMessage &msg, int addressOffset);
void routeBip32KeyStripPriateKey(OSCMessage &msg, int addressOffset);
void routeBip32KeyGetFingerprint(OSCMessage &msg, int addressOffset);
void routeBip32KeyFromBase58(OSCMessage &msg, int addressOffset);

