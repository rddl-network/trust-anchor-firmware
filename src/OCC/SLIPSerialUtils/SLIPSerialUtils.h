// SLIPSerialUtils.h
#ifndef SLIP_SERIAL_UTILS_H
#define SLIP_SERIAL_UTILS_H

#include <OSCBundle.h>
#include "SLIPEncodedSerial.h"

extern SLIPEncodedSerial SLIPSerial;

#define  ESP_SERIAL               SLIPSerial
#define  ESP_SERIAL_BEGIN()       SLIPSerial.beginPacket()
#define  ESP_SERIAL_END()         SLIPSerial.endPacket()

// class SLIPSerialUtils
// {
// public:
    // SLIPSerialUtils();
void sendOSCMessage(OSCMessage &resp_msg);

// private:
    // HWCDC SerialESP;
    // SLIPEncodedSerial SLIPSerial;
// };

#endif // SLIP_SERIAL_UTILS_H
