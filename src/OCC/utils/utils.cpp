#include "utils.h"

#include <Preferences.h>

#include "wally_address.h"
#include "wally_bip32.h"

#define FROMHEX_MAXLEN 512

// USBCDC SeriSerialESPal(0); // for AI Thinker ESP-C3-32S

void sendOSCMessage(OSCMessage &resp_msg)
{
    ESP_SERIAL_BEGIN(); // mark the beginning of the OSC Packet
    resp_msg.send(ESP_SERIAL);
    ESP_SERIAL_END();
    resp_msg.empty();
}

void memzero(void *const pnt, const size_t len)
{
    /*#ifdef _WIN32
      SecureZeroMemory(pnt, len);
    #elif defined(HAVE_MEMSET_S)
      memset_s(pnt, (rsize_t)len, 0, (rsize_t)len);
    #elif defined(HAVE_EXPLICIT_BZERO)
      explicit_bzero(pnt, len);
    #elif defined(HAVE_EXPLICIT_MEMSET)
      explicit_memset(pnt, 0, len);
    #else*/
    volatile unsigned char *volatile pnt_ = (volatile unsigned char *volatile)pnt;
    size_t i = (size_t)0U;

    while (i < len)
    {
        pnt_[i++] = 0U;
    }
    // #endif
}

const uint8_t *fromhex(const char *str)
{
    static uint8_t buf[FROMHEX_MAXLEN];
    int len = strlen(str) / 2;
    if (len > FROMHEX_MAXLEN)
        len = FROMHEX_MAXLEN;
    for (int i = 0; i < len; i++)
    {
        uint8_t c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9')
            c += (str[i * 2] - '0') << 4;
        if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
            c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
            c += (str[i * 2 + 1] - '0');
        if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
            c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
        buf[i] = c;
    }
    return buf;
}

void tohexprint(char *hexbuf, uint8_t *str, int strlen)
{
    // char hexbuf[strlen];
    for (int i = 0; i < strlen / 2; i++)
    {
        sprintf(&hexbuf[2 * i], "%02X", str[i]);
    }
    hexbuf[strlen - 2] = '\0';
}

size_t toHex(const uint8_t *array, size_t arraySize, char *output, size_t outputSize)
{
    if (array == NULL || output == NULL)
    {
        return 0;
    }
    // uint8_t * array = (uint8_t *) arr;
    if (outputSize < 2 * arraySize)
    {
        return 0;
    }
    memzero(output, outputSize);

    for (size_t i = 0; i < arraySize; i++)
    {
        output[2 * i] = (array[i] >> 4) + '0';
        if (output[2 * i] > '9')
        {
            output[2 * i] += 'a' - '9' - 1;
        }

        output[2 * i + 1] = (array[i] & 0x0F) + '0';
        if (output[2 * i + 1] > '9')
        {
            output[2 * i + 1] += 'a' - '9' - 1;
        }
    }
    return 2 * arraySize;
}

String toHex(const uint8_t *array, size_t arraySize)
{
    if (array == NULL)
    {
        return String();
    }
    size_t outputSize = arraySize * 2 + 1;
    char *output = (char *)malloc(outputSize);
    if (output == NULL)
    {
        return String();
    }

    toHex(array, arraySize, output, outputSize);

    String result(output);

    memzero(output, outputSize);
    free(output);

    return result;
}

std::vector<uint32_t> getPath(char *pathStr)
{
    std::vector<uint32_t> myPath;
    uint32_t num = 0;
    char *token = strtok(pathStr + 2, "/"); /* derivation path always starts with 'm/' */
    token = strtok(NULL, "/");

    while (token != NULL)
    {
        size_t s = strlen(token);
        char t = token[s - 1];

        if (t == '\'')
        {
            token[s - 1] = '\0';
            num = BIP32_INITIAL_HARDENED_CHILD;
        }
        else
            num = 0;

        num += std::stoi(token);
        myPath.push_back(num);
        token = strtok(NULL, "/");
    }
    return myPath;
}

/**
 * Sends an error message using OSC protocol.
 *
 * @param message The error message to send.
 */
void sendErrorMessage(OSCMessage &msg, const char *message) {
    OSCMessage resp_msg("/IHW/wallyBip32KeyToAddress");
    resp_msg.add("Error: ");
    resp_msg.add(message);
    sendOSCMessage(resp_msg);
}

uint32_t get_wif_get_prefix_from_preferences() {
    Preferences valise;
    valise.begin("vault", false);
    const String addrFamily = valise.getString("addr_family", "bc"); // Default to "bc" if not set
    valise.end();

    const uint32_t prefix = (addrFamily == "tb") ? WALLY_ADDRESS_VERSION_WIF_TESTNET : WALLY_ADDRESS_VERSION_WIF_MAINNET;

    return prefix;
}

uint32_t get_get_prefix_from_preferences() {
    Preferences valise;
    valise.begin("vault", false);
    const String addrFamily = valise.getString("addr_family", "bc"); // Default to "bc" if not set
    valise.end();

    const uint32_t prefix = (addrFamily == "tb") ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;

    return prefix;
}

struct ext_key getRootKeyFromPreferences(OSCMessage &msg) {
    Preferences valise;
    struct ext_key root;
    int res;

    valise.begin("vault", false);
    String serialized_root = valise.getString("valise_root_key", "");
    valise.end();

    if (serialized_root.length() == 0) {
        sendErrorMessage(msg, "HD key not found in NVS");
        throw std::runtime_error("HD key not found in NVS");
    }

    // Deserialize root key from base58 string
    res = bip32_key_from_base58(serialized_root.c_str(), &root);
    if (res != WALLY_OK) {
        sendErrorMessage(msg, "Failed to deserialize HD key");
        throw std::runtime_error("Failed to deserialize HD key");
    }

    return root;
}