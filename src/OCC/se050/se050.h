#ifdef DSE050

#pragma once

#include <vector>
#include "OSCMessage.h"

void routeSE050EncryptData(OSCMessage &msg, int addressOffset);
void routeSE050DecryptData(OSCMessage &msg, int addressOffset);

#endif