// SLIPSerialUtils.h
#ifndef SLIP_SERIAL_UTILS_H
#define SLIP_SERIAL_UTILS_H

#include <OSCBundle.h>
#include <OSCBoards.h>
#include "SLIPEncodedSerial.h"
#include <Preferences.h>

class SLIPSerialUtils
{
public:
    SLIPSerialUtils();
    void sendOSCMessage(OSCMessage &resp_msg);

private:
    HWCDC SerialESP;
    SLIPEncodedSerial SLIPSerial;
};

#endif // SLIP_SERIAL_UTILS_H
