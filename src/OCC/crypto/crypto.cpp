#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_elements.h>
#include "../utils/utils.h"

#include "crypto.h"


/* ----------------------------------------------------------------*/
/* Crypto functions                                                */
/* ----------------------------------------------------------------*/

void routeWallyEcSigFromBytes(OSCMessage &msg, int addressOffset)
{
    int res;

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    /* Private keys created on the trust anchor are starting with 0x00 as prefix*/
    /* Therefore the leading HEX 0x00 has to be dropped before signing          */
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    uint8_t priv_key[33];
    char char_priv_key[67]; // has to be inside the msg.isString() check ...

    uint8_t hash_key[32];
    char char_hash_key[65]; // has to be inside the msg.isString() check ...

    uint8_t bytes_out[64];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, char_priv_key, length);
    }
    if (msg.isString(2))
    {
        int length = msg.getDataLength(2);
        msg.getString(2, char_hash_key, length);
    }

    memcpy(priv_key,
           fromhex((const char *)char_priv_key),
           33);
    memcpy(hash_key,
           fromhex((const char *)char_hash_key),
           32);

    res = wally_ec_sig_from_bytes(
        priv_key + 1, /* first byte of priv_key is 0x00 */
        32,
        hash_key,
        32,
        EC_FLAG_ECDSA,
        bytes_out,
        64);

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(bytes_out, 64);

    OSCMessage resp_msg("/IHW/wallyEcSigFromBytes");
    resp_msg.add(hexStr.c_str());
    resp_msg.add(char_priv_key);
    resp_msg.add(char_hash_key);
    sendOSCMessage(resp_msg);

    wally_free_string(char_priv_key);
    wally_free_string(char_hash_key);
}

void routeWallyEcSigNormalize(OSCMessage &msg, int addressOffset)
{
    int res;

    uint8_t sig[64];
    char char_sig[129];

    uint8_t bytes_out[64];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, char_sig, length);
    }

    memcpy(sig,
           fromhex(char_sig),
           64);

    res = wally_ec_sig_normalize(
        sig,
        EC_SIGNATURE_LEN,
        bytes_out,
        EC_SIGNATURE_LEN);

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(bytes_out, 64);

    OSCMessage resp_msg("/IHW/wallyEcSigNormalize");
    resp_msg.add(hexStr.c_str());
    // resp_msg.add("test message");
    sendOSCMessage(resp_msg);
}

void routeWallyEcSigToDer(OSCMessage &msg, int addressOffset)
{
    int res;

    uint8_t sig[64];

    char str_sig[129];

    uint8_t der[73];

    size_t len;

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, str_sig, length);
    }

    memcpy(sig,
           fromhex(str_sig),
           64);

    res = wally_ec_sig_to_der(
        sig,
        EC_SIGNATURE_LEN,
        der,
        EC_SIGNATURE_DER_MAX_LEN,
        &len);

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(der, EC_SIGNATURE_DER_MAX_LEN);

    OSCMessage resp_msg("/IHW/wallyEcSigToDer");
    resp_msg.add(hexStr.c_str());
    // resp_msg.add("test message");
    sendOSCMessage(resp_msg);
}

void routeWallyEcSigFromDer(OSCMessage &msg, int addressOffset)
{
    int res;

    uint8_t der[72];

    char str_der[145];

    uint8_t sig[64];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, (char *)str_der, length);
    };
    memcpy(der,
           fromhex(str_der),
           72);

    res = wally_ec_sig_from_der(
        der,
        72,
        sig,
        64);

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(sig, 64);

    OSCMessage resp_msg("/IHW/wallyEcSigFromDer");
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}

void routeWallyEcSigVerify2(OSCMessage &msg, int addressOffset)
{
    int res;
    int ret;

    size_t pub_len;
    size_t hash_len;
    size_t sig_len;

    pub_len = 33;
    hash_len = 32;
    sig_len = 64;

    // uint8_t pub_key[33];
    char str_pub_key[] = "02822d18bd250a11e5c86d90a801bf42443c8dca93cb62724da660b849d2514277";

    uint8_t pub_key[] =
        {
            0x02, 0x82, 0x2d, 0x18, 0xbd, 0x25, 0x0a, 0x11,
            0xe5, 0xc8, 0x6d, 0x90, 0xa8, 0x01, 0xbf, 0x42,
            0x44, 0x3c, 0x8d, 0xca, 0x93, 0xcb, 0x62, 0x72,
            0x4d, 0xa6, 0x60, 0xb8, 0x49, 0xd2, 0x51, 0x42, 0x77};

    // 02822d18bd250a11e5c86d90a801bf42443c8dca93cb62724da660b849d2514277
    // 02822d18bd250a11e5c86d90a801bf42443c8dca93cb62724da660b849d2514277

    // uint8_t hash[32];
    // char str_hash[] = "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392";

    uint8_t hash[] =
        {
            0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3,
            0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68, 0x64,
            0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79,
            0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98, 0xf3, 0x92};

    // 3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392
    // 3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392

    // uint8_t sig[64];
    char str_sig[] = "7ed5651904434654f5a68cc079e3ef643266af00af0d81459d7a0b58d5d803885fa8865f987e8b25bf1ac099f0fe31598bf94b8913fcaea7e03d8feafa92323c";

    // 7ed5651904434654f5a68cc079e3ef643266af00af0d81459d7a0b58d5d803885fa8865f987e8b25bf1ac099f0fe31598bf94b8913fcaea7e03d8feafa92323c
    // 7ed5651904434654f5a68cc079e3ef643266af00af0d81459d7a0b58d5d803885fa8865f987e8b25bf1ac099f0fe31598bf94b8913fcaea7e03d8feafa92323c

    uint8_t sig[] =
        {
            0x7e, 0xd5, 0x65, 0x19, 0x04, 0x43, 0x46, 0x54,
            0xf5, 0xa6, 0x8c, 0xc0, 0x79, 0xe3, 0xef, 0x64,
            0x32, 0x66, 0xaf, 0x00, 0xaf, 0x0d, 0x81, 0x45,
            0x9d, 0x7a, 0x0b, 0x58, 0xd5, 0xd8, 0x03, 0x88,
            0x5f, 0xa8, 0x86, 0x5f, 0x98, 0x7e, 0x8b, 0x25,
            0xbf, 0x1a, 0xc0, 0x99, 0xf0, 0xfe, 0x31, 0x59,
            0x8b, 0xf9, 0x4b, 0x89, 0x13, 0xfc, 0xae, 0xa7,
            0xe0, 0x3d, 0x8f, 0xea, 0xfa, 0x92, 0x32, 0x3c};

    // memset(pub_key,0x00,33);
    // memset(hash,0x00,32);
    // memset(sig,0x00,64);

    // memcpy(pub_key, fromhex(str_pub_key), 33);
    // memcpy(hash, fromhex(str_hash), 32);
    // memcpy(sig, fromhex(str_sig),  64);

    ret = wally_ec_public_key_verify(pub_key, 33);

    res = wally_ec_sig_verify(
        (const unsigned char *)pub_key,
        pub_len, // EC_PUBLIC_KEY_LEN,
        (const unsigned char *)hash,
        hash_len, // EC_MESSAGE_HASH_LEN,
        EC_FLAG_ECDSA,
        (const unsigned char *)sig,
        sig_len // EC_SIGNATURE_LEN
    );

    String hexStr;
    hexStr = toHex(sig, 64);
    String hexStr2;
    hexStr2 = toHex(pub_key, 33);
    String hexStr3;
    hexStr3 = toHex(hash, 32);

    OSCMessage resp_msg("/IHW/wallyEcSigVerify2");
    resp_msg.add((int32_t)ret);
    resp_msg.add((int32_t)res);
    resp_msg.add(hexStr3.c_str());
    resp_msg.add(hexStr2.c_str());
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}

void routeWallyEcSigToPublicKey(OSCMessage &msg, int addressOffset)
{
    int res;

    uint8_t pub_key[33];

    uint8_t hash[32];
    char str_hash[65];

    uint8_t sig[64];
    char str_sig[129];

    size_t len;

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, (char *)str_hash, length);
    };
    memcpy(hash,
           fromhex(str_hash),
           32);

    if (msg.isString(1))
    {
        int length = msg.getDataLength(2);
        msg.getString(1, (char *)str_sig, length);
    }
    memcpy(sig,
           fromhex(str_sig),
           64);

    res = wally_ec_sig_to_public_key(
        hash,
        32,
        sig,
        64,
        pub_key,
        len);

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(pub_key, 33);

    OSCMessage resp_msg("/IHW/wallyEcSigToPublicKey");
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}

void routeWallyFormatBitcoinMessage(OSCMessage &msg, int addressOffset)
{
    int res;

    uint8_t btc_msg[512];
    char str_btc_msg[1025];

    uint8_t btc_msg_hash[32];

    int *len;
    size_t *written;

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, (char *)str_btc_msg, length);
        len = &length;
    };

    memcpy(btc_msg,
           fromhex(str_btc_msg),
           *len);

    res = wally_format_bitcoin_message(
        btc_msg, *len,
        BITCOIN_MESSAGE_FLAG_HASH,
        btc_msg_hash, 32,
        written);

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(btc_msg_hash, 32);

    OSCMessage resp_msg("/IHW/wallyFormatBitcoinMessage");
    resp_msg.add(hexStr.c_str());
    resp_msg.add(str_btc_msg);
    sendOSCMessage(resp_msg);
}

void routeWallyEcdh(OSCMessage &msg, int addressOffset)
{
    int res;

    uint8_t pub_key[33];
    char str_pub_key[66];

    uint8_t priv_key[32];
    char str_priv_key[64];

    uint8_t shared_secret[32];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, str_pub_key, length);
    };

    memcpy(pub_key,
           fromhex(str_pub_key),
           33);

    if (msg.isString(1))
    {
        int length = msg.getDataLength(1);
        msg.getString(1, str_priv_key, length);
    };

    memcpy(priv_key,
           fromhex(str_priv_key),
           32);

    res = wally_ecdh(
        (const unsigned char *)pub_key, EC_PUBLIC_KEY_LEN,
        (const unsigned char *)priv_key, EC_PRIVATE_KEY_LEN,
        (unsigned char *)shared_secret, SHA256_LEN);

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(shared_secret, 32);

    String hexStrPub;
    hexStrPub = toHex(pub_key, 33);

    String hexStrPriv;
    hexStrPriv = toHex(priv_key, 32);

    OSCMessage resp_msg("/IHW/wallyEcdh");
    resp_msg.add(hexStr.c_str());
    resp_msg.add(hexStrPub.c_str());
    resp_msg.add(hexStrPriv.c_str());

    // resp_msg.add(str_pub_key);
    // resp_msg.add(str_priv_key);
    sendOSCMessage(resp_msg);
}


void routeSeedToBlindingKey(OSCMessage &msg, int addressOffset) {
    int res;

    // Extract seed from OSC message
    uint8_t seed[64]; // Assuming a 512-bit seed, adjust size as needed
    if (msg.isBlob(0)) {
        size_t length = msg.getDataLength(0);
        msg.getBlob(0, seed, length);
    }

    // Generate asset blinding key from seed
    unsigned char blinding_key[32]; // Size of 256 bits for the blinding key
    res = wally_asset_blinding_key_from_seed(seed, sizeof(seed), blinding_key, sizeof(blinding_key));

    // Convert blinding_key to a hex string for sending
    String hex_key = toHex(blinding_key, sizeof(blinding_key));

    // Send the result back
    OSCMessage resp_msg("/IHW/wallyBlindingKeyPath");
    resp_msg.add(hex_key);

    SLIPSerial.beginPacket();
    resp_msg.send(SLIPSerial);
    SLIPSerial.endPacket();
    resp_msg.empty();

    // Clear sensitive data
    memset(seed, 0, sizeof(seed));
    memset(blinding_key, 0, sizeof(blinding_key));
}
