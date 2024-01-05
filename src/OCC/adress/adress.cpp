// address.c
#include "../utils/utils.h"
#include "OSCMessage.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_crypto.h"
#include "wally_address.h"
#include <Preferences.h>
#include "wally_core.h"
#include "wally_address.h"


/**
 * Converts bytes to a WIF (Wallet Import Format) string.
 * 
 * @param msg The OSCMessage containing the byte array.
 * @param addressOffset The offset in the address where processing should begin.
 */
void routeWallyWifFromBytes(OSCMessage &msg, int addressOffset)
{
    int res;
    uint8_t bytes[32]; // Assuming the byte array size is 32
    char char_bytes[65]; // Double the size for hex representation

    const uint32_t prefix = get_wif_get_prefix_from_preferences();

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, char_bytes, length);
        memcpy(bytes, fromhex(char_bytes), sizeof(bytes));
    }

    char *wif = NULL;
    res = wally_wif_from_bytes(bytes, sizeof(bytes), prefix, 
                               WALLY_WIF_FLAG_COMPRESSED, // Adjust flag if necessary
                               &wif);

    if (res == WALLY_OK) {
        // Send back the WIF string
        OSCMessage resp_msg("/IHW/wallyWifFromBytes");
        resp_msg.add(wif);
        sendOSCMessage(resp_msg);

        wally_free_string(wif);
    } else {
        // Handle error
        OSCMessage resp_msg("/IHW/wallyWifFromBytes");
        resp_msg.add("Failed to convert bytes to WIF");
        sendOSCMessage(resp_msg);
    }
}


/**
 * Converts a Wally WIF (Wallet Import Format) to a byte array.
 * 
 * @param msg The OSCMessage object containing the WIF.
 * @param addressOffset The offset to be applied to the address.
 */
void routeWallyWifToBytes(OSCMessage &msg, int addressOffset)
{
    int res;
    uint8_t bytes[EC_PRIVATE_KEY_LEN]; // Size for a private key byte array
    size_t bytes_len = sizeof(bytes);

    char wif[53]; // WIF strings are typically 51-52 characters long

    const uint32_t prefix = get_wif_get_prefix_from_preferences();

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, wif, length);
    }

    uint32_t flags = WALLY_WIF_FLAG_COMPRESSED; // Adjust flag if necessary

    res = wally_wif_to_bytes(wif, prefix, flags, bytes, bytes_len);

    if (res == WALLY_OK) {
        // Convert byte array to hex string
        String hexStr = toHex(bytes, bytes_len);

        // Send back the byte array as a hex string
        OSCMessage resp_msg("/IHW/wallyWifToBytes");
        resp_msg.add(hexStr.c_str());
        sendOSCMessage(resp_msg);
    } else {
        // Handle error
        OSCMessage resp_msg(msg);
        resp_msg.add("Failed to convert WIF to bytes");
        sendOSCMessage(resp_msg);
    }
}


/**
 * Converts a WIF (Wallet Import Format) string to a public key and sends it back as an OSC message.
 * 
 * @param msg The OSC message containing the WIF string.
 * @param addressOffset The address offset.
 */
void routeWallyBip32KeyToAddress(OSCMessage &msg, int addressOffset)
{
    Preferences valise;
    char *address;

    const struct ext_key root = getRootKeyFromPreferences(msg);

    // Determine address type
    const uint32_t address_type = (root.version == BIP32_VER_MAIN_PRIVATE) ? WALLY_ADDRESS_VERSION_P2PKH_MAINNET : WALLY_ADDRESS_VERSION_P2PKH_TESTNET;

    // Generate Bitcoin address from BIP32 key
    const int res = wally_bip32_key_to_address(&root, address_type, 0, &address);
    if (res != WALLY_OK) {
        sendErrorMessage(msg, "Failed to generate address from BIP32 key");
        return;
    }

    // Send back the address
    OSCMessage resp_msg("/IHW/wallyBip32KeyToAddress");
    resp_msg.add(address);
    sendOSCMessage(resp_msg);

    wally_free_string(address);
}


/**
 * Converts a WIF (Wallet Import Format) string to a public key and sends it back as an OSC message.
 * 
 * @param msg The OSC message containing the WIF string.
 * @param addressOffset The offset value for the address.
 */
void routeWallyWifToPublicKey(OSCMessage &msg, int addressOffset)
{
    struct ext_key root = getRootKeyFromPreferences(msg);
    uint8_t pub_key[EC_PUBLIC_KEY_LEN];
    const size_t pub_key_len = sizeof(pub_key);

    // Generate public key from HD key's private key
    const int res = wally_ec_public_key_from_private_key(root.priv_key, EC_PRIVATE_KEY_LEN, pub_key, pub_key_len);
    if (res != WALLY_OK) {
        sendErrorMessage(msg, "Failed to generate public key from HD key");
        return;
    }

    // Convert public key to hex string for sending
    String hexStr = toHex(pub_key, pub_key_len);

    // Send back the public key
    OSCMessage resp_msg("/IHW/wallyWifToPublicKey");
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}
