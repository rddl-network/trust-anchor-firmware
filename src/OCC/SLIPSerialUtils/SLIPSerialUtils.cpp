// SLIPSerialUtils.cpp
#include "SLIPSerialUtils.h"

// USBCDC SeriSerialESPal(0); // for AI Thinker ESP-C3-32S

void sendOSCMessage(OSCMessage &resp_msg)
{
    ESP_SERIAL_BEGIN(); // mark the beginning of the OSC Packet
    resp_msg.send(ESP_SERIAL);
    ESP_SERIAL_END();
    resp_msg.empty();
}

