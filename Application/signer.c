#include "signer.h"

// The private key context that will be used for the entire encryption
mbedtls_pk_context privateKey;

void RSA_init() {
    // Initialize the private key state
    mbedtls_pk_init(&privateKey);
    return;
}
