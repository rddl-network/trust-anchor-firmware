#include "core.h"


void routeWallyInit(OSCMessage &msg, int addressOffset)
{
    wally_init(0x00);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyInit");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyCleanup(OSCMessage &msg, int addressOffset)
{
    wally_cleanup(0x00);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyCleanup");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyGetSecpContext(OSCMessage &msg, int addressOffset)
{
    secp256k1_context_struct *ctxStrct;
    wally_get_secp_context();

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyGetSecpContext");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyGetNewSecpContext(OSCMessage &msg, int addressOffset)
{
    secp256k1_context_struct *ctxStrct;
    // wally_get_new_secp_context();

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyGetNewSecpContext");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallySecpContextFree(OSCMessage &msg, int addressOffset)
{
    secp256k1_context_struct *ctxStrct;
    // wally_secp_context_free(ctxStrct);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallySecpContextFree");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyBZero(OSCMessage &msg, int addressOffset)
{
    char *bytes;
    size_t len;
    wally_bzero(bytes, len);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyBZero");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallyFreeString(OSCMessage &msg, int addressOffset)
{
    char *str;
    wally_free_string(str);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyBZero");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeWallySecpRandomize(OSCMessage &msg, int addressOffset)
{
    unsigned char *bytes;
    size_t len;
    wally_secp_randomize(bytes, len);

    SLIPSerialUtils slipSerialUtils;

    OSCMessage resp_msg("/wallyBZero");
    resp_msg.add("0");
    slipSerialUtils.sendOSCMessage(resp_msg);
}

/**
 * Create a new symmetric key from a base seed or entropy.
 * This creates a new symmetric master or base seed.
 *
 * @param String(0) Give key base seed to use.
 * @return  The resulting symmetric master or base seed.
 */
void routeWallySymKeyFromSeed(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;

    SLIPSerialUtils slipSerialUtils;
    OSCMessage resp_msg("/wallySymKeyFromSeed");

    uint8_t seed[BIP32_ENTROPY_LEN_512];

    if (msg.isString(0))
    {
        // Get Key
        size_t len = msg.getDataLength(0);
        char char_seed[len];
        msg.getString(0, char_seed, len);

        memcpy(seed,
               fromhex(char_seed),
               BIP32_ENTROPY_LEN_512);

        uint8_t symmetric_key[HMAC_SHA512_LEN];
        wally_symmetric_key_from_seed(seed, BIP32_ENTROPY_LEN_512, symmetric_key, HMAC_SHA512_LEN);

        String hexStrSymKey;
        hexStrSymKey = toHex(symmetric_key, HMAC_SHA512_LEN);
        resp_msg.add(hexStrSymKey.c_str());
    }

    slipSerialUtils.sendOSCMessage(resp_msg);
}

/**
 * Create a new symmetric key from parent symmetric key or entropy.
 * This creates a new symmetric master or base key.
 *
 * @param String(0) Entropy to use.
 * @param int(1) Version byte to prepend label. Has to be 0
 * @param String(2) Label, a string according to SLIP-21
 * @param String(3) empty string for future use
 * @return  The resulting key.
 */
void routeWallySymKeyFromParent(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    SLIPSerialUtils slipSerialUtils;
    OSCMessage resp_msg("/wallySymKeyFromParent");

    uint8_t parent_sym_key[HMAC_SHA512_LEN];

    uint8_t version = 0x00; // has to be zero by default

    uint8_t child_sym_key[HMAC_SHA512_LEN];

    // Get parent symmetric key
    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char char_parent_sym_key[length];
        msg.getString(0, char_parent_sym_key, length);
        memcpy(parent_sym_key,
               fromhex(char_parent_sym_key),
               HMAC_SHA512_LEN);
    }

    if (msg.isString(2))
    {
        len = msg.getDataLength(2);
        char char_label[len];
        msg.getString(2, char_label, len);

        wally_symmetric_key_from_parent(parent_sym_key, HMAC_SHA512_LEN,
                                        version,
                                        //(const unsigned char*)char_label.c_str(), len,
                                        reinterpret_cast<unsigned char *>(char_label), len,
                                        child_sym_key, HMAC_SHA512_LEN);

        String hexStrSymKey;
        hexStrSymKey = toHex(child_sym_key, HMAC_SHA512_LEN);
        resp_msg.add(hexStrSymKey.c_str());
    }

    slipSerialUtils.sendOSCMessage(resp_msg);
}

void routeEntropy(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;

    uint8_t se_rnd[32] = {0};
    esp_fill_random(se_rnd, 32);

    // const char *seed;
    // seed = toHex(se_rnd, 32).c_str();

    char seed[32];

    memset(seed, '\0', sizeof(seed));
    for (int i = 0; i < 31; i++)
    {
        static char tmp[4] = {};
        sprintf(tmp, "%02X", se_rnd[i]);
        strcpy(seed + i, tmp);
    }

    // msg.add("2573548DF4251F3048ABA137EFEEC11E59C0738D47C88B46462EDE80BEFFA2CA");
    SLIPSerialUtils slipSerialUtils;
    msg.add(seed);
    slipSerialUtils.sendOSCMessage(msg);
}

void routeTrnd(OSCMessage &msg, int addressOffset)
{
    int len;

    if (msg.isInt(0))
    {
        len = msg.getInt(0);
        uint8_t se_rnd[len] = {0};
        esp_fill_random(se_rnd, len);

        char trnd[len];
        memset(trnd, '\0', sizeof(trnd));
        for (int i = 0; i < len - 1; i++)
        {
            static char tmp[4] = {};
            sprintf(tmp, "%02X", se_rnd[i]);
            strcpy(trnd + i, tmp);
        }

        SLIPSerialUtils slipSerialUtils;

        msg.add(trnd);
        slipSerialUtils.sendOSCMessage(msg);
    }
}