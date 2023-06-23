#include <wally_crypto.h>
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "../utils/utils.h"

#include "edsa.h"

uint8_t pub_key_buffer[33];
uint8_t hash_buffer[32];

#define EC_FLAGS_TYPES (EC_FLAG_ECDSA | EC_FLAG_SCHNORR)

static bool is_valid_ec_type(uint32_t flags)
{
    return ((flags & EC_FLAGS_TYPES) == EC_FLAG_ECDSA) ||
           ((flags & EC_FLAGS_TYPES) == EC_FLAG_SCHNORR);
}

/**
 * Create new extended key from given parameters
 *
 * @return  The extended key
 */
void routeEcdsaPubKey(OSCMessage &msg, int addressOffset)
{
    int res;
    bool secret_ok = false;
    size_t len; // to store serialization lengths

    secp256k1_context *ctx = NULL;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    uint8_t priv_key[32];
    char char_priv_key[65]; // has to be inside the msg.isString() check ...

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, char_priv_key, length);
    }

    memcpy(priv_key,
           fromhex(char_priv_key),
           32);

    secret_ok = secp256k1_ec_seckey_verify(ctx, priv_key);

    // Derive child key from parent key
    secp256k1_pubkey pubkey;
    bool create_pubkey = false;
    create_pubkey = secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key);

    // serialize the pubkey in compressed format
    uint8_t pub[33];
    len = sizeof(pub);
    secp256k1_ec_pubkey_serialize(ctx, pub, &len, &pubkey, SECP256K1_EC_COMPRESSED);

    String pub_key_hex_str;
    pub_key_hex_str = toHex(pub, 33);

    // Send the result back
    OSCMessage resp_msg("/IHW/ecdsaPubKey");
    resp_msg.add(pub_key_hex_str.c_str());
    resp_msg.add(char_priv_key);
    resp_msg.add((int32_t)len);

    sendOSCMessage(resp_msg);
    wally_free_string(char_priv_key);
}

/** routeEcdsaSigFromBytes
 * 0: priv key
 * 1: hash
 * 2: sig
 */
void routeEcdsaSigFromBytes(OSCMessage
                           &msg,
                       int addressOffset)
{
    int res;

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    /* Private keys created on the trust anchor are starting with 0x00 as prefix*/
    /* Therefore the leading HEX 0x00 has to be dropped before signing          */
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    size_t len;
    secp256k1_context *ctx = NULL;

    uint8_t priv_key[32];

    char char_priv_key[65]; // has to be inside the msg.isString() check ...

    uint8_t hash_key[32];
    char char_hash_key[65]; // has to be inside the msg.isString() check ...

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
           32);
    memcpy(hash_key,
           fromhex((const char *)char_hash_key),
           32);
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    secp256k1_ecdsa_signature sig;

    res = secp256k1_ecdsa_sign(ctx, &sig, hash_key, priv_key, NULL, NULL);

    uint8_t compact[64];
    len = sizeof(compact);
    res = secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &sig);

    bool sig_verify_ok = false;
    secp256k1_ecdsa_signature sig_secp;
    sig_verify_ok = secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, compact);

    String sig_hex_str;
    sig_hex_str = toHex(compact, 64);

    OSCMessage resp_msg("/IHW/ecdsaSigFromBytes");
    resp_msg.add(sig_hex_str
                     .

                 c_str()

    );
    resp_msg.add(sig
                     .data);
    resp_msg.add(sig_verify_ok);
    resp_msg.add(char_priv_key);
    resp_msg.add(char_hash_key);
    sendOSCMessage(resp_msg);

    wally_free_string(char_priv_key);
    wally_free_string(char_hash_key);
}

/** routeEcdsaSigVerifyPubkeyHash
 *  Verify a signature against a public key and a hash
 *  @param msg OSCMessage
 *  @param addressOffset int
 */
void routeEcdsaSigVerifyPubkeyHash(OSCMessage &msg, int
                                                        addressOffset)
{
    int res;

    char str_pub_key[67];
    char str_hash[65];

    int len;
    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        len = length;
        msg.getString(0, (char *)str_pub_key, length);
    };
    memcpy(pub_key_buffer,
           fromhex(str_pub_key),
           33);

    if (msg.isString(2))
    {
        int length = msg.getDataLength(2);
        msg.getString(2, (char *)str_hash, length);
    };
    memcpy(hash_buffer,
           fromhex(str_hash),
           32);
    
    OSCMessage resp_msg("/IHW/ecdsaSigVerifyPubkeyHash");
    resp_msg.add("PubKey and Hash stored");
    resp_msg.add((int32_t)
                     len);
    sendOSCMessage(resp_msg);
}

/* Verify a ECDSA signature */
void routeEcdsaSigVerify(OSCMessage &msg, int addressOffset)
{
    int res;

    uint8_t sig[64];
    char str_sig[129];


    int len;
    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        len = length;
        msg.getString(0, (char *)str_sig, length);
    }

    memcpy(sig,
           fromhex(str_sig),
           64);

    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature sig_secp;
    secp256k1_context *ctx = NULL;
    size_t context_size = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    bool ok;
    bool check_ok = true;
    bool ctx_ok = true;
    bool parse_ok = true;
    bool parse_compact_ok = true;
    bool verify_ok = true;

    int pub_key_len = 33;
    int hash_len = 32;
    int sig_len = 64;
    uint32_t flags = EC_FLAG_ECDSA;

    if (!pub_key_buffer || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !hash_buffer || hash_len != EC_MESSAGE_HASH_LEN ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_TYPES ||
        !sig || sig_len != EC_SIGNATURE_LEN)
    {
        check_ok = false;
    }

    if (!ctx)
    {
        ctx_ok = false;
    }

    ok = secp256k1_ec_pubkey_parse(ctx, &pub, pub_key_buffer, pub_key_len);
    if (!ok)
    {
        parse_ok = false;
    }

    ok = secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig);
    if (!ok)
    {
        parse_compact_ok = false;
    }

    ok = secp256k1_ecdsa_verify(ctx, &sig_secp, hash_buffer, &pub);
    if (!ok)
    {
        verify_ok = false;
    }

    String hexStr;
    hexStr = toHex(sig, 64);
    String hexStr2;
    hexStr2 = toHex(pub_key_buffer, 33);
    String hexStr3;
    hexStr3 = toHex(hash_buffer, 32);

    OSCMessage resp_msg("/IHW/ecdsaSigVerify");
    // resp_msg.add((int32_t)res);
    resp_msg.add((int32_t)pub_key_len);
    resp_msg.add(check_ok);
    resp_msg.add(ctx_ok);
    resp_msg.add(parse_ok);
    resp_msg.add(parse_compact_ok);
    resp_msg.add(verify_ok);
    resp_msg.add(ok);
    resp_msg.add(hexStr3.c_str());
    resp_msg.add(hexStr2.c_str());
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}