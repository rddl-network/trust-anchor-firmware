#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include <Preferences.h>
#include "../utils/utils.h"

#include "valise.h"

void routeValiseSign(OSCMessage &msg, int addressOffset)
{
    secp256k1_context *ctx = NULL;

    int res;    // to store results of function calls
    size_t len; // to store serialization lengths

    // first we need to create the context
    // this is the size of memory to be allocated
    size_t context_size = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    // secret as hex string
    // bdb51a16eb6460ec16f84d7b6f19e20d9b9ab558fa0e9ae4bb493ef779f14055
    // import into python ecdsa code
    //
    // sk = ecdsa.SigningKey.from_string(binascii.unhexlify("bdb51a16eb6460ec16f84d7b6f19e20d9b9ab558fa0e9ae4bb493ef779f14055") ,curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    // private_key = sk.to_string()
    //
    // msg = hashlib.sha256(b"hello").digest().hex()
    // >>> '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    //
    // public_key = vk.to_string('compressed').hex()
    // >>> '02822d18bd250a11e5c86d90a801bf42443c8dca93cb62724da660b849d2514277'
    //
    //  msg = hashlib.sha256(b"hello").digest()
    // signature = sk.sign(msg,hashfunc=hashlib.sha256)
    // signature.hex()

    // some random secret key
    uint8_t secret[] = {
        0xbd, 0xb5, 0x1a, 0x16, 0xeb, 0x64, 0x60, 0xec,
        0x16, 0xf8, 0x4d, 0x7b, 0x6f, 0x19, 0xe2, 0x0d,
        0x9b, 0x9a, 0xb5, 0x58, 0xfa, 0x0e, 0x9a, 0xe4,
        0xbb, 0x49, 0x3e, 0xf7, 0x79, 0xf1, 0x40, 0x55};

    // Makes sense to check if secret key is valid.
    // It will be ok in most cases, only if secret > N it will be invalid
    res = secp256k1_ec_seckey_verify(ctx, secret);

    // computing corresponding pubkey
    secp256k1_pubkey pubkey;
    res = secp256k1_ec_pubkey_create(ctx, &pubkey, secret);

    // serialize the pubkey in compressed format
    uint8_t pub[33];
    len = sizeof(pub);
    secp256k1_ec_pubkey_serialize(ctx, pub, &len, &pubkey, SECP256K1_EC_COMPRESSED);

    // this is how you parse the pubkey
    res = secp256k1_ec_pubkey_parse(ctx, &pubkey, pub, 33);

    // hash of the string "hello"
    uint8_t hash[32] = {
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24};
    // signing
    secp256k1_ecdsa_signature sig;

    res = secp256k1_ecdsa_sign(ctx, &sig, hash, secret, NULL, NULL);

    // uint8_t sig_secp[64];
    // res = secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_secp);

    uint8_t der[72];
    len = sizeof(der);
    res = secp256k1_ecdsa_signature_serialize_der(ctx, der, &len, &sig);

    uint8_t compact[64];
    len = sizeof(compact);
    res = secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &sig);

    // signature verification
    Serial.print("=== Signature verification ===\r\n");
    res = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubkey);

    String pubStr;
    pubStr = toHex(pub, 33);

    String compactStr;
    compactStr = toHex(compact, 64);

    String derStr;
    derStr = toHex(der, 72);

    OSCMessage resp_msg("/IHW/valiseSign");
    resp_msg.add((int32_t)res);
    resp_msg.add(pubStr.c_str());
    resp_msg.add(compactStr.c_str());
    resp_msg.add(derStr.c_str());
    sendOSCMessage(resp_msg);
}

/**
 * Generate a mnemonic phrase and derive a seed, store both in memory
 *
 * @return Generated '0' or '1' string for failure or success Sending over OSC as string
 */

void routeValiseMnemonicSeedInit(OSCMessage &msg, int addressOffset)
{
    /* mnemonic stays unknown
       has to init menmonic and has to init seed
       cause, the seed is rquired for almost all bip32 calls
    */
    Preferences valise; // ESP32-C3 to use NVS
    int res;
    size_t len;
    uint8_t bytes_out[BIP39_SEED_LEN_512];

    valise.begin("vault", false);
    const char *mnemonic = "focus nature unfair swap kingdom supply weather piano fine just brief maximum federal nature goat cash crystal rally response joy unique drum merit surprise";
    valise.putString("valise_mnemonic", mnemonic);
    valise.end();

    valise.begin("vault", false);
    // converting recovery phrase to bytes
    // we have to consider which default passphrase we are going to use.
    res = bip39_mnemonic_to_seed(mnemonic, "trustanchor", bytes_out, sizeof(bytes_out), &len);
    valise.putString("valise_seed", (const char *)bytes_out);
    valise.end();

    OSCMessage resp_msg("/valiseMnemonicSeedInit");
    resp_msg.add("1");
    sendOSCMessage(resp_msg);
}

/**
 * Store the mnemonic phrase inside the trust anchor's memory
 *
 * @param String(0) The mnemonic phrase.
 * @return  Generated '0' or '1' string for failure or success Sending over OSC as string

 */
void routeValiseMnemonicSet(OSCMessage &msg, int addressOffset)
{
    Preferences valise; // ESP32-C3 to use NVS
    valise.begin("vault", false);

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char char_mnemonic[length];
        msg.getString(0, char_mnemonic, length);

        valise.putString("valise_mnemonic", char_mnemonic);
    }

    valise.end();

    OSCMessage resp_msg("/valiseMnemonicSet");
    resp_msg.add("1");
    sendOSCMessage(resp_msg);
}

/**
 * Get the mnemonic phrase from the trust anchor's memory
 *
 * @return The stored menmonic. Sending over OSC as string
.
 */
void routeValiseMnemonicGet(OSCMessage &msg, int addressOffset)
{
    Preferences valise; // ESP32-C3 to use NVS
    valise.begin("vault", false);

    String valise_mnemonic = valise.getString("valise_mnemonic", "");

    valise.end();

    OSCMessage resp_msg("/valiseMnemonicGet");
    resp_msg.add(valise_mnemonic.c_str());
    sendOSCMessage(resp_msg);
}

/**
 * Store the base seed inside the trust anchor's memory
 *
 * @param String(0) The base seed.
 * @param String(2) empty string for future use
 * @return  Generated '0' or '1' string for failure or success. Sending over OSC as string

 */
void routeValiseSeedSet(OSCMessage &msg, int addressOffset)
{
    Preferences valise; // ESP32-C3 to use NVS
    int res;

    char char_seed[129];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, char_seed, length);
    }

    valise.begin("vault", false);
    valise.putString("valise_seed", (const char *)char_seed);
    valise.end();

    OSCMessage resp_msg("/valiseSeedSet");
    resp_msg.add("1");
    sendOSCMessage(resp_msg);

    resp_msg.empty();
    delay(20);
}

/**
 * Get the base seed from the trust anchor's memory
 *
 * @param String(0) empty string for future use
 * @return The stored base seed. Sending over OSC as string
.
 */
void routeValiseSeedGet(OSCMessage &msg, int addressOffset)
{
    Preferences valise; // ESP32-C3 to use NVS
    valise.begin("vault", false);
    String valise_seed = valise.getString("valise_seed", "");
    valise.end();

    OSCMessage resp_msg("/valiseSeedGet");
    resp_msg.add(valise_seed.c_str());
    // resp_msg.add("hallo");
    // resp_msg.add(valise_seed);

    sendOSCMessage(resp_msg);
}

void routeValiseCborEcho(OSCMessage &msg, int addressOffset)
{
    OSCMessage msg2("/cbor/echo");
    int res;
    size_t len;

    uint8_t se_rnd[32] = {0};
    esp_fill_random(se_rnd, 32);

    char *phrase = NULL;
    res = bip39_mnemonic_from_bytes(NULL, se_rnd, sizeof(se_rnd), &phrase);

    msg2.add(
        "d08355a20101055001010101010101010101010101010101a10458246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c655820c4af85ac4a5134931993ec0a1863a6e8c66ef4c9ac16315ee6fecd9b2e1c79a1");
    sendOSCMessage(msg2);
} 