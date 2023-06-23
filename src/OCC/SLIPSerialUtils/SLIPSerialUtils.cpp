// SLIPSerialUtils.cpp
#include "SLIPSerialUtils.h"
#include <OSCBundle.h>
#include <OSCBoards.h>

// USBCDC SeriSerialESPal(0); // for AI Thinker ESP-C3-32S

SLIPSerialUtils::SLIPSerialUtils() : SLIPSerial(SerialESP) {
    SLIPSerial.begin(115200);
    SerialESP.setRxBufferSize(1024);
    SerialESP.setTxBufferSize(1024);
}

void SLIPSerialUtils::sendOSCMessage(OSCMessage &resp_msg)
{
    SLIPSerial.beginPacket(); // mark the beginning of the OSC Packet
    resp_msg.send(SLIPSerial);
    SLIPSerial.endPacket();
    resp_msg.empty();
}