#include <vector>
#include <Preferences.h>
#include "wally_bip39.h"
#include "wally_bip32.h"
#include "../utils/utils.h"

#include "bip32.h"


ext_key *hdKey;
char tempBuff[1024];

/**
 * Create new extended key from given parameters
 *
 * @return  The extended key
 */
void routeBip32KeyInit(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    OSCMessage resp_msg("/bip32_key_init");
    uint32_t version = 0;   
    uint32_t depth = 0;
    uint32_t child_num = 0;
    uint8_t *temp_ptr = nullptr;
    std::vector<uint8_t> chainCode;
    std::vector<uint8_t> pubKey;
    std::vector<uint8_t> privKey;
    std::vector<uint8_t> hash160;
    std::vector<uint8_t> parent160;
    ext_key *output = nullptr;
    String hexStr;

    if (msg.isInt(0))
        version = msg.getInt(0);
    else
    {
        resp_msg.add("ERROR! Version Wrong Parameter");
        goto SEND_RESPONSE;
    }

    if (msg.isInt(1))
        depth = msg.getInt(1);
    else
    {
        resp_msg.add("ERROR! Depth Wrong Parameter");
        goto SEND_RESPONSE;
    }

    if (msg.isInt(2))
        child_num = msg.getInt(2);
    else
    {
        resp_msg.add("ERROR! Child num Wrong Parameter");
        goto SEND_RESPONSE;
    }

    if (msg.isString(3))
    {
        len = msg.getDataLength(3);
        msg.getString(3, tempBuff, len);

        temp_ptr = (uint8_t *)fromhex(tempBuff);
        chainCode.assign(temp_ptr, temp_ptr + len / 2);
    }
    else
    {
        resp_msg.add("ERROR! Chain code Wrong Parameter");
        goto SEND_RESPONSE;
    }

    if (msg.isString(4))
    {
        len = msg.getDataLength(4);
        msg.getString(4, tempBuff, len);

        temp_ptr = (uint8_t *)fromhex(tempBuff);
        pubKey.assign(temp_ptr, temp_ptr + len / 2);
    }
    else
    {
        resp_msg.add("ERROR! Pub key Wrong Parameter");
        goto SEND_RESPONSE;
    }

    if (msg.isString(5))
    {
        len = msg.getDataLength(5);
        msg.getString(5, tempBuff, len);

        temp_ptr = (uint8_t *)fromhex(tempBuff);
        privKey.assign(temp_ptr, temp_ptr + len / 2);
    }
    else
    {
        resp_msg.add("ERROR! Priv key Wrong Parameter");
        goto SEND_RESPONSE;
    }

    if (msg.isString(6))
    {
        len = msg.getDataLength(6);
        msg.getString(6, tempBuff, len);

        temp_ptr = (uint8_t *)fromhex(tempBuff);
        hash160.assign(temp_ptr, temp_ptr + len / 2);
    }
    else
    {
        resp_msg.add("ERROR! hash160 Wrong Parameter");
        goto SEND_RESPONSE;
    }

    if (msg.isString(7))
    {
        len = msg.getDataLength(7);
        msg.getString(7, tempBuff, len);

        temp_ptr = (uint8_t *)fromhex(tempBuff);
        parent160.assign(temp_ptr, temp_ptr + len / 2);
    }
    else
    {
        resp_msg.add("ERROR! parent160 Wrong Parameter");
        goto SEND_RESPONSE;
    }

    bip32_key_init_alloc(version, depth, child_num,
                         chainCode.data(), chainCode.size(),
                         pubKey.data(), pubKey.size(),
                         privKey.data(), privKey.size(),
                         hash160.data(), hash160.size(),
                         parent160.data(), parent160.size(),
                         &output);

    hexStr = toHex((uint8_t *)output, sizeof(ext_key));
    resp_msg.add(hexStr.c_str());

    bip32_key_free(output);

SEND_RESPONSE:
    sendOSCMessage(resp_msg);
}

/**
 * Generate key from given Seed
 *
 * @param string(0) seed in String type
 * @param int(1) <optional> key type. default is BIP32_VER_MAIN_PRIVATE
 * @return Generated key. Sending over OSC as string
 */
void routeBip32KeyFromSeed(OSCMessage &msg, int addressOffset)
{
    Preferences valise; // ESP32-C3 to use NVS
    int res;

    uint8_t seed[64];
    char char_seed[129];
    OSCMessage resp_msg("/bip32KeyFromSeed");

    if (msg.isString(0))
    {
        // Get seed
        size_t len = msg.getDataLength(0);
        msg.getString(0, char_seed, len);
        if (len != 0)
        {
            memcpy(
                seed,
                fromhex((const char *)char_seed),
                64);
        }
        else
        {
            valise.begin("vault", false);
            String valise_seed = valise.getString("valise_seed", "");
            valise.end();

            memcpy(
                seed,
                fromhex((const char *)valise_seed.c_str()),
                64);
        }

        /* Check if the user *indicate flag */
        int flag = BIP32_VER_MAIN_PRIVATE;
        if (msg.isInt(1))
        {
            switch (msg.getInt(1))
            {
            // case 0 and case 2, public keys are not supported.
            case 0:
                flag = BIP32_VER_MAIN_PUBLIC;
                break;

            case 1:
                flag = BIP32_VER_MAIN_PRIVATE;
                break;

            case 2:
                flag = BIP32_VER_TEST_PUBLIC;
                break;

            case 3:
                flag = BIP32_VER_TEST_PRIVATE;
                break;

            default:
                flag = BIP32_VER_MAIN_PRIVATE;
                break;
            }
        }


        res = bip32_key_from_seed_alloc(seed, sizeof(seed), flag, 0, &hdKey);

        /*String hexStrChainCode;
        hexStrChainCode = toHex((const uint8_t*)hdKey->chain_code,32);
        resp_msg.add(hexStrChainCode.c_str());

        String hexStrChildNum;
        hexStrChildNum = toHex((const uint8_t*)hdKey->child_num,4);
        resp_msg.add(hexStrChildNum.c_str());
        */

        // String hexStrDepth;
        // hexStrDepth = toHex((const uint8_t*)hdKey->depth,2);
        // resp_msg.add(hexStrDepth.c_str());

        /* String hexStrHash160;
        hexStrHash160 = toHex((const uint8_t*)hdKey->hash160,20);
        resp_msg.add(hexStrHash160.c_str());

        String hexStrPad1;
        hexStrPad1 = toHex((const uint8_t*)hdKey->pad1,10);
        resp_msg.add(hexStrPad1.c_str());

        String hexStrPad2;
        hexStrPad2 = toHex((const uint8_t*)hdKey->pad2,3);
        resp_msg.add(hexStrPad2.c_str());

        String hexStrParent160;
        hexStrParent160 = toHex((const uint8_t*)hdKey->parent160,20);
        resp_msg.add(hexStrParent160.c_str());
        */

        String hexStrPrivKey;
        hexStrPrivKey = toHex((const uint8_t *)hdKey->priv_key, 33);
        resp_msg.add(hexStrPrivKey.c_str());

        String hexStrPubKey;
        hexStrPubKey = toHex((const uint8_t *)hdKey->pub_key, 33);
        resp_msg.add(hexStrPubKey.c_str());

        /*String hexStrVersion;
        hexStrVersion = toHex((const uint8_t*)hdKey->version,4);
        resp_msg.add(hexStrVersion.c_str());
        */

        bip32_key_free(hdKey);
    }
    else
        resp_msg.add("ERROR! Couldnt get seed");

    sendOSCMessage(resp_msg);
}

/**
 * Generate child key from parent key and given number
 *
 * @param String(0) given base seed
 * @param int(1) num of child key. default value is 0
 * @param int(2) hardened or non-hardened 1 or 0, adds 0x8000000
 * @param int(3) <optional> network version type. default is BIP32_VER_MAIN_PRIVATE
 * @param int(4) <optional> key type. default is BIP32_FLAG_KEY_PRIVATE
 * @param String(5) empty string for future use
 * @return Generated child key. Private key raw and serialized. Sending over OSC as string
 */
void routeBip32KeyFromParent(OSCMessage &msg, int addressOffset)
{
    Preferences valise;
    int res;
    struct ext_key root, child_key;
    OSCMessage resp_msg("/bip32KeyfromParent");

    char *xprv = NULL;
    char *xpub = NULL;

    valise.begin("vault", false);
    String serialized_root = valise.getString("valise_root_key", "");
    valise.end();

    if (serialized_root.length() == 0) {
        sendErrorMessage(resp_msg, "HD key not found in NVS");
        return;
    }

    // Deserialize the HD key
    res = bip32_key_from_base58(serialized_root.c_str(), &root);
    if (res != WALLY_OK) {
        sendErrorMessage(resp_msg, "Failed to deserialize HD key");
        return;
    }

    // Get child number and type
    uint32_t childNum = 0;
    uint32_t flag = BIP32_FLAG_KEY_PRIVATE;
    if (msg.isInt(1)) {
        childNum = msg.getInt(1) | (msg.isInt(2) && msg.getInt(2) == 1 ? BIP32_INITIAL_HARDENED_CHILD : 0);
        flag = msg.isInt(4) && msg.getInt(4) == 1 ? BIP32_FLAG_KEY_PUBLIC : BIP32_FLAG_KEY_PRIVATE;
    }

    // Derive child key
    res = bip32_key_from_parent(&root, childNum, flag, &child_key);
    if (res != WALLY_OK) {
        sendErrorMessage(resp_msg, "Failed to derive child key");
        return;
    }

    // Serialize the child key
    res = bip32_key_to_base58(&child_key, flag, &xprv);
    if (res != WALLY_OK) {
        sendErrorMessage(resp_msg, "Failed to serialize child key");
        return;
    }

    // Add serialized key to response
    resp_msg.add(flag == BIP32_FLAG_KEY_PRIVATE ? xprv : xpub);

    sendOSCMessage(resp_msg);

    wally_free_string(xprv);
    wally_free_string(xpub);
}


/**
 * Convert key to base58 data
 *
 * @param String(0) given key as base seed
 * @param int(1) <optional> key type. default is BIP32_FLAG_KEY_PRIVATE
 * @return base58 type of serialized private or public key for given seed. Sending over OSC as string
 */
void routeBip32KeyToBase58(OSCMessage &msg, int addressOffset)
{
    Preferences valise;
    int res;
    struct ext_key root;
    OSCMessage resp_msg("/bip32KeytoBase58");

    // Retrieve the serialized HD key from NVS
    valise.begin("vault", false);
    String serialized_root = valise.getString("valise_root_key", "");
    valise.end();

    if (serialized_root.length() == 0) {
        resp_msg.add("Error: HD key not found in NVS");
        sendOSCMessage(resp_msg);
        return;
    }

    // Deserialize the HD key
    res = bip32_key_from_base58(serialized_root.c_str(), &root);
    if (res != WALLY_OK) {
        resp_msg.add("Error: Failed to deserialize HD key");
        sendOSCMessage(resp_msg);
        return;
    }

    // Check the flag
    uint32_t flag = BIP32_FLAG_KEY_PRIVATE;
    if (msg.isInt(1)) {
        flag = msg.getInt(1);
    }

    char *base58_key = NULL;
    res = bip32_key_to_base58(&root, flag, &base58_key);
    if (res != WALLY_OK) {
        resp_msg.add("Error: Failed to serialize HD key to Base58");
    } else {
        resp_msg.add(base58_key);
        wally_free_string(base58_key);
    }

    sendOSCMessage(resp_msg);
}

/**
 * Generate child key from parent key and path
 *
 * @param String(0) given key as base seed or empty
 * @param String(1) path of child key
 * @param int(2) <optional> Bip-32 entropy. default is BIP39_SEED_LEN_512;
 * @param int(3) Network version type. Main or testnet
 * @param int(4) <optional> key type. default is BIP32_FLAG_KEY_PRIVATE
 * @return Generated child key. Private Key raw and serialized .Sending over OSC as string
 */
void routeBip32KeyFromParentPathString(OSCMessage &msg, int addressOffset)
{
    Preferences valise;
    int res;
    struct ext_key root, child_key;
    OSCMessage resp_msg("/bip32KeyFromParentPathString");

    char *xprv = NULL;
    char *xpub = NULL;

    valise.begin("vault", false);
    String serialized_root = valise.getString("valise_root_key", "");
    String addrFamily = valise.getString("addr_family", "bc");
    valise.end();

    if (serialized_root.length() == 0) {
        resp_msg.add("Error: HD key not found in NVS");
        sendOSCMessage(resp_msg);
        return;
    }

    // Deserialize the HD key
    res = bip32_key_from_base58(serialized_root.c_str(), &root);
    if (res != WALLY_OK) {
        resp_msg.add("Error: Failed to deserialize HD key");
        sendOSCMessage(resp_msg);
        return;
    }

    // Get Path
    std::vector<uint32_t> childPath;
    if (msg.isString(1))
    {
        size_t len = msg.getDataLength(1);
        char pathString[len];
        msg.getString(1, pathString, len);
        childPath = getPath(pathString);
    }

    // Determine network version number
    uint32_t version = (addrFamily == "tb") ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;

    // Derive child key
    res = bip32_key_from_parent_path(&root, childPath.data(), childPath.size(), BIP32_FLAG_KEY_PRIVATE, &child_key);
    if (res != WALLY_OK) {
        resp_msg.add("Error: Failed to derive child key");
        sendOSCMessage(resp_msg);
        return;
    }

    // Serialize the child key
    res = bip32_key_to_base58(&child_key, BIP32_FLAG_KEY_PRIVATE, &xprv);
    res = bip32_key_to_base58(&child_key, BIP32_FLAG_KEY_PUBLIC, &xpub);

    // Add serialized key to response
    resp_msg.add(xprv);
    resp_msg.add(xpub);

    wally_free_string(xprv);
    wally_free_string(xpub);

    sendOSCMessage(resp_msg);
}

/**
 * Serialize an extended key to memory using BIP32 format.
 *
 * @param String(0) given key as base seed
 * @param String(1) intended derivation path
 * @param int(2) <optional> network version type. default is BIP32_VER_MAIN_PRIVATE
 * @param int(3) <optional> key type. default is BIP32_FLAG_KEY_PRIVATE
 * @param String(4) empty string for future use
 * @return serialized key
 */
void routeBip32KeySerialize(OSCMessage &msg, int addressOffset)
{
    Preferences valise;
    int res;
    struct ext_key root;
    ext_key child_key;
    OSCMessage resp_msg("/bip32KeySerialize");

    // Retrieve the serialized HD key from NVS
    valise.begin("vault", false);
    String serialized_root = valise.getString("valise_root_key", "");
    valise.end();

    if (serialized_root.length() == 0) {
        sendErrorMessage(resp_msg, "HD key not found in NVS");
        return;
    }

    // Deserialize the HD key
    res = bip32_key_from_base58(serialized_root.c_str(), &root);
    if (res != WALLY_OK) {
        sendErrorMessage(resp_msg, "Failed to deserialize HD key");
        return;
    }

    // Parse derivation path
    std::vector<uint32_t> childPath;
    if (msg.isString(1))
    {
        size_t len = msg.getDataLength(1);
        char pathString[len];
        msg.getString(1, pathString, len);
        childPath = getPath(pathString);
    }

    // Derive child key
    res = bip32_key_from_parent_path(&root, childPath.data(), childPath.size(), BIP32_FLAG_KEY_PRIVATE, &child_key);
    if (res != WALLY_OK) {
        sendErrorMessage(resp_msg, "Failed to derive child key");
        return;
    }

    // Serialize the derived child key
    uint8_t serialized_child[BIP32_SERIALIZED_LEN];
    res = bip32_key_serialize(&child_key, BIP32_FLAG_KEY_PRIVATE, serialized_child, sizeof(serialized_child));
    if (res != WALLY_OK) {
        sendErrorMessage(resp_msg, "Failed to serialize child key");
        return;
    }

    String hexStr = toHex(serialized_child, sizeof(serialized_child));
    resp_msg.add(hexStr.c_str());

    sendOSCMessage(resp_msg);
}

/**
 * Unserialize an serialized, extended key.
 *
 * @param String(0) given serialized, extended key as string
 * @param String(1) empty string for future use
 * @return Unserialized key
 */
void routeBip32KeyUnserialize(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    OSCMessage resp_msg("/bip32KeyUnserialize");

    uint8_t serialized_key[BIP32_SERIALIZED_LEN];

    if (msg.isString(0))
    {
        // Get Serialized Key as string
        size_t len = msg.getDataLength(0);
        char char_serialized_key[len];
        msg.getString(0, char_serialized_key, len);

        memcpy(serialized_key,
               fromhex(char_serialized_key),
               BIP32_SERIALIZED_LEN);

        ext_key unserialized_key_root;
        bip32_key_unserialize(serialized_key, BIP32_SERIALIZED_LEN, &unserialized_key_root);

        String hexStrPriv;
        hexStrPriv = toHex(unserialized_key_root.priv_key, 33);
        resp_msg.add(hexStrPriv.c_str());

        String hexStrPub;
        hexStrPub = toHex(unserialized_key_root.pub_key, 33);
        resp_msg.add(hexStrPub.c_str());

        // bip32_key_free(unserialized_key_root);
    }

    sendOSCMessage(resp_msg);
}

/**
 * Converts a private extended key to a public extended key. Afterwards, only public child extended
 * keys can be derived, and only the public serialization can be created.
 * If the provided key is already public, nothing will be done.
 *
 * @param String(0) The extended key.
 * @return   The converted extended key.
 */
void routeBip32KeyStripPriateKey(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    OSCMessage resp_msg("/bip32KeyStripPriateKey");

    if (msg.isString(0))
    {
        // Get Key
        size_t len = msg.getDataLength(0);
        char key[len];
        msg.getString(0, key, len);

        ext_key innerKey;
        memcpy(&innerKey, (char *)fromhex(key), sizeof(ext_key));
        bip32_key_strip_private_key(&innerKey);

        String hexStr;
        hexStr = toHex((uint8_t *)&innerKey, sizeof(ext_key));
        resp_msg.add(hexStr.c_str());
    }
    else
        resp_msg.add("ERROR! Couldnt get key");

    sendOSCMessage(resp_msg);
}

/**
 * Get fingerprint for Bip-32 encoded key.
 *
 * @param String(0) given key as base seed
 * @param String(1) intended derivation path
 * @param int(2) <optional> network version type. default is BIP32_VER_MAIN_PRIVATE
 * @param int(3) <optional> key type. default is BIP32_FLAG_KEY_PRIVATE
 * @param String(4) empty string for future use
 * @return serialized key
 */
void routeBip32KeyGetFingerprint(OSCMessage &msg, int addressOffset)
{
    Preferences valise;
    int res;
    size_t len;
    OSCMessage resp_msg("/bip32KeyGetFingerprint");

    char *xprv = NULL;
    char *xpub = NULL;
    uint8_t seed[BIP39_SEED_LEN_512];

    int version = BIP32_VER_MAIN_PRIVATE;
    int flag = BIP32_FLAG_KEY_PRIVATE;

    // Get seed
    if (msg.isString(0)) // logical 'AND' for msg.isString(0) and msg.isString(1)
    {
        int lengthSeed = msg.getDataLength(0);
        char hexStrSeed[lengthSeed];
        msg.getString(0, hexStrSeed, lengthSeed);
        if (lengthSeed != 0)
        {
            memcpy(seed,
                   fromhex(hexStrSeed),
                   BIP39_SEED_LEN_512);
        }
        else
        {
            valise.begin("vault", false);
            String valise_seed = valise.getString("valise_seed", "");
            valise.end();

            memcpy(
                seed,
                fromhex((const char *)valise_seed.c_str()),
                64);
        }
    }

    // Get Path
    std::vector<uint32_t> childPath;
    if (msg.isString(1))
    {
        len = msg.getDataLength(1);
        char pathString[len];
        msg.getString(1, pathString, len);
        childPath = getPath(pathString);
    }

    // Get network version number
    if (msg.isInt(3))
    {
        switch (msg.getInt(3))
        {
        case 0:
            version = BIP32_VER_MAIN_PRIVATE;
            break;

        case 1:
            version = BIP32_VER_TEST_PRIVATE;
            break;

        default:
            version = BIP32_VER_MAIN_PRIVATE;
            break;
        }
    }

    // Get key type flag
    if (msg.isInt(4))
    {
        switch (msg.getInt(4))
        {
        case 0:
            flag = BIP32_FLAG_KEY_PRIVATE;
            break;

        case 1:
            flag = BIP32_FLAG_KEY_PUBLIC;
            break;

        default:
            flag = BIP32_FLAG_KEY_PRIVATE;
            break;
        }
    }

    ext_key derived_key_root;
    ext_key child_key_root;

    res = bip32_key_from_seed(seed, BIP32_ENTROPY_LEN_512, version, 0, &derived_key_root);

    res = bip32_key_from_parent_path(&derived_key_root, childPath.data(), childPath.size(), BIP32_FLAG_KEY_PRIVATE,
                                     &child_key_root);

    uint8_t bytes_out[BIP32_SERIALIZED_LEN];
    res = bip32_key_get_fingerprint(&child_key_root, bytes_out, FINGERPRINT_LEN);

    String hexStrFingerprint;
    hexStrFingerprint = toHex(bytes_out, FINGERPRINT_LEN);
    resp_msg.add(hexStrFingerprint.c_str());

    sendOSCMessage(resp_msg);
}

/**
 * Convert a base58 encoded extended key to an extended key
 *
 * @param String(0) The extended key in base58.
 * @return Generated extended key. Private or public key raw. Sending over OSC as string
 */
void routeBip32KeyFromBase58(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;

    OSCMessage resp_msg("/bip32KeyFromBase58");

    ext_key decoded_key_root;

    // Get base58 encoded key
    if (msg.isString(0)) // logical 'AND' for msg.isString(0) and msg.isString(1)
    {
        int lengthBase58 = msg.getDataLength(0);
        char hexStrBase58[lengthBase58];
        msg.getString(0, hexStrBase58, lengthBase58);
        if (lengthBase58 != 0)
        {
            bip32_key_from_base58(hexStrBase58, &decoded_key_root);
        }
    }

    String hexStrPriv;
    hexStrPriv = toHex(decoded_key_root.priv_key, 33);
    resp_msg.add(hexStrPriv.c_str());

    String hexStrPub;
    hexStrPub = toHex(decoded_key_root.pub_key, 33);
    resp_msg.add(hexStrPub.c_str());

    sendOSCMessage(resp_msg);
}