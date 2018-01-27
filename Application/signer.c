#include "signer.h"
#include "mbedtls/pk.h"
#include <time.h>

// The private key context that will be used for the entire encryption
mbedtls_pk_context privateKey;

#define PRIVATE_KEY_BUFFER_LEN 1
const unsigned char keyBuffer[PRIVATE_KEY_BUFFER_LEN] = {
    0x00,
};

void RSA_init() {
    int pk_error;

    // Initialize the private key state
    mbedtls_pk_init(&privateKey);

    pk_error = mbedtls_pk_parse_key(&privateKey, keyBuffer, PRIVATE_KEY_BUFFER_LEN, NULL, 0);
    return;
}
