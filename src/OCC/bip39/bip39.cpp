#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_crypto.h"
#include "wally_address.h"
#include "../utils/utils.h"

#include "bip39.h"

#include <Preferences.h>

/* ----------------------------------------------------------------*/
/* wally bip39 functions                                           */
/* ----------------------------------------------------------------*/

// root HD key
ext_key root;

char* password = "Nato.0+55+3d";

/**
 * Get all te languages available to create mnemonic phrases
 *
 * @param String(0) empty string for future use
 * @return A list of all languages, available. Sending over OSC as string
.
 */
void routeBip39GetLanguages(OSCMessage &msg, int addressOffset)
{
    int res;
    char *output = NULL;

    res = bip39_get_languages(&output);

    OSCMessage resp_msg("/bip39GetLanguages");
    resp_msg.add(output);
    sendOSCMessage(resp_msg);

    wally_free_string(output);
}

/**
 * Get all the languages available to create mnemonic phrases
 *
 * @param String(0) The language identifier. 'en es fr it jp zhs zht'
 * @param String(1) empty string for future use
 * @return A list of all languages, available. Sending over OSC as string
.
 */
void routeBip39GetWordlist(OSCMessage &msg, int addressOffset)
{
    int res;

    if (msg.isString(0))
    {
        struct words *output;
        int length = msg.getDataLength(0);
        char lang[length];
        msg.getString(0, lang, length);

        res = bip39_get_wordlist(lang, &output);

        OSCMessage resp_msg("/bip39GetWordlist");
        resp_msg.add(output);
        sendOSCMessage(resp_msg);
    }
}

/**
 * Get all the nth word of the wordlist for mnemonic phrases
 *
 * @param String(0) The language identifier. 'en es fr it jp zhs zht'
 * @param String(1) The nth word out of the wordlist
 * @param String(2) empty string for future use
 * @return The nth word in the chosen language out of the wordlist. Sending over OSC as string
.
 */
void routeBip39GetWord(OSCMessage &msg, int addressOffset)
{
    int res;
    struct words *w;

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char lang[length];
        msg.getString(0, lang, length);
        res = bip39_get_wordlist(lang, &w);
    }

    if (msg.isInt(1))
    {
        // don't forget problem with endianess
        char *output;
        int nth_word = msg.getInt(1);
        res = bip39_get_word(w, nth_word, &output);

        OSCMessage resp_msg("/bip39GetNthWord");

        char str_nth_word[10];
        sprintf(str_nth_word, "%d", nth_word);
        resp_msg.add(str_nth_word);
        resp_msg.add(output);
        sendOSCMessage(resp_msg);

        wally_free_string(output);
    }
}

void routeBip39NumberBouncer(OSCMessage &msg, int addressOffset)
{
    int res;

    if (msg.isInt(0))
    {
        int nth_word = msg.getInt(0);

        OSCMessage resp_msg("/bip39GetNumberBouncer");

        char str_nth_word[10];
        sprintf(str_nth_word, "%d", nth_word);
        resp_msg.add((int32_t)nth_word);
        sendOSCMessage(resp_msg);
    }
}

/**
 * Validate the checksum in a mnemonic phrases
 *
 * @param String(0) The language identifier. 'en es fr it jp zhs zht'
 * @param String(1) The mnemonic phrase to validate
 * @param String(2) empty string for future use
 * @return Error Code. Sending over OSC as string
.
 */
void routeBip39MnemonicValidate(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    OSCMessage resp_msg("/IHW/Bip39MnemonicValidate");

    struct words *w;

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char lang[length];
        msg.getString(0, lang, length);
        res = bip39_get_wordlist(lang, &w);
    }

    if (msg.isString(1))
    {
        int length = msg.getDataLength(1);
        char phrase[length];
        msg.getString(1, phrase, length);

        res = bip39_mnemonic_validate(w, phrase);

        resp_msg.add((int32_t)res);
    }

    sendOSCMessage(resp_msg);
}

void routeBip39MnemonicToSeed(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    uint8_t bytes_out[BIP39_SEED_LEN_512];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char phrase[length];
        msg.getString(0, phrase, length);

        // converting recovery phrase to bytes
        // we have to consider which default passphrase we are going to use.
        res = bip39_mnemonic_to_seed(phrase, password, bytes_out, sizeof(bytes_out), &len);
        // res = bip39_mnemonic_to_bytes(NULL, phrase, bytes_out, sizeof(bytes_out), &len);
    }

    String hexStr;
    hexStr = toHex(bytes_out, 64);

    OSCMessage resp_msg("/bip39MnemonicToSeed");
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}

void routeBip39MnemonicToSeed512(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    uint8_t bytes_out[BIP39_SEED_LEN_512];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char phrase[length];
        msg.getString(0, phrase, length);

        // converting recovery phrase to bytes
        // we have to consider which default passphrase we are going to use.
        res = bip39_mnemonic_to_seed(phrase, password, bytes_out, sizeof(bytes_out), &len);
        // res = bip39_mnemonic_to_bytes(NULL, phrase, bytes_out, sizeof(bytes_out), &len);
    }

    String hexStr;
    hexStr = toHex(bytes_out, 64);

    OSCMessage resp_msg("/bip39MnemonicToSeed");
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}

void routeBip39Mnemonic(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;

    uint8_t se_rnd[32] = {0};
    esp_fill_random(se_rnd, 32);

    char *phrase = NULL;
    res = bip39_mnemonic_from_bytes(NULL, se_rnd, sizeof(se_rnd), &phrase);
    msg.add(phrase);
    sendOSCMessage(msg);

    wally_free_string(phrase);
}

void routeBip39MnemonicToBytes(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    uint8_t bytes_out[BIP39_SEED_LEN_512];

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char phrase[length];
        msg.getString(0, phrase, length);
        // Serial.println(phrase);

        // converting recovery phrase to bytes
        res = bip39_mnemonic_to_bytes(NULL, phrase, bytes_out, sizeof(bytes_out), &len);
    }

    String hexStr;
    hexStr = toHex(bytes_out, 32);
    // Serial.println(hexStr);
    OSCMessage resp_msg("/bip39MnemonicToBytes");
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}

void routeBip39MnemonicFromBytes(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    uint8_t bytes_out[BIP39_SEED_LEN_512];
    char *phrase = NULL;

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        char hexStr[length];
        msg.getString(0, hexStr, length);
        // Serial.println(hexStr);

        res = bip39_mnemonic_from_bytes(NULL, (const unsigned char *)fromhex(hexStr), 32, &phrase);
    }
    OSCMessage resp_msg("/Bip39MnemonicFromBytes");
    resp_msg.add(phrase);
    sendOSCMessage(resp_msg);

    wally_free_string(phrase);
}

void routeBip39MnemonicToPrivateKey(OSCMessage &msg, int addressOffset) {
    int res;

    char phrase[512];
    if (msg.isString(0)) {
        int length = msg.getDataLength(0);
        msg.getString(0, phrase, length);
    }

    // Convert mnemonic to seed
    uint8_t seed[BIP39_SEED_LEN_512];
    size_t seed_len;
    res = bip39_mnemonic_to_seed(phrase, password, seed, sizeof(seed), &seed_len);
    // Generate BIP32 master key from seed
    uint32_t bip32_prefix = get_get_prefix_from_preferences();
    res = bip32_key_from_seed(seed, sizeof(seed), bip32_prefix, 0, &root);

    // // Clear seed from memory for security
    memset(seed, 0, sizeof(seed_len));

    // // // Convert master_key to base58 string
    char *base58_master_key = NULL;

    res = bip32_key_to_base58(&root, BIP32_FLAG_KEY_PRIVATE, &base58_master_key);

    String hexStr;
    hexStr = toHex(root.priv_key, 33);

    const uint32_t prefix = get_wif_get_prefix_from_preferences();

    char *wif;
    wally_wif_from_bytes (root.priv_key, 
                          EC_PRIVATE_KEY_LEN, 
                          prefix,
                          WALLY_WIF_FLAG_COMPRESSED, 
                          &wif);

    

    // Send the result back
    OSCMessage resp_msg("/IHW/Bip39MnemonicToPrivateKey");
    resp_msg.add(hexStr.c_str());
    resp_msg.add(base58_master_key);
    resp_msg.add(wif);

    SLIPSerial.beginPacket();
    resp_msg.send(SLIPSerial);
    SLIPSerial.endPacket();
    resp_msg.empty();

    wally_free_string(base58_master_key);
}