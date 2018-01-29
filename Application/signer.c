#include <xdc/runtime/system.h>

#include "signer.h"
#include "mbedtls/pk.h"
#include <time.h>

// The private key context that will be used for the entire encryption
mbedtls_pk_context privateKey;

int rsa_state = -1;

#define PRIVATE_KEY_BUFFER_LEN 888
const unsigned char keyBuffer[PRIVATE_KEY_BUFFER_LEN] = {
     '-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' ', 'R', 'S', 'A', ' ', 'P', 'R', 'I', 'V', 'A', 'T', 'E', ' ', 'K', 'E', 'Y', '-', '-', '-', '-', '-', '\n',
     'M', 'I', 'I', 'C', 'X', 'A', 'I', 'B', 'A', 'A', 'K', 'B', 'g', 'Q', 'C', 'T', 'a', 'h', '6', 'N', 'i', 'f', 'o', 'w', 's', 'X', 'Z', 'r', 'p', 'a', 'W', 'P', 'R', '/', 'L', 'J', 'k', 'W', 'k', 'z', 'Q', '9', '1', 'y', '2', 'C', 'B', 's', 'x', 'K', 'R', 'M', 'e', 'f', '8', 'K', '2', 'u', 'S', 'j', 'r', 'c', 'W', 'U', '\n',
     'm', '+', 'h', 'F', 'C', 'D', 'O', 'W', 'c', '1', '3', 'x', '+', 'c', 'k', 'k', '1', 's', 'w', 't', '1', 'R', 'P', 'T', 'o', 'k', 'U', 'U', 'b', 'Z', '3', 'L', 'L', 'u', 'O', 'm', '9', 'E', 'K', 'K', 'd', 'G', 'm', '/', 'j', 'y', 'd', 'K', 'N', 'y', 'S', '4', 'j', 'I', 'v', 'P', 'p', 'v', 'B', 'b', 'm', '5', 'V', 'q', '\n',
     'M', 'K', 'b', '1', 'v', 'a', 'y', 'r', 'K', 'c', 'E', 'p', 'u', 'z', 'q', 'U', 'b', 'E', 'c', 'F', 'B', 'x', 'L', 'u', 'S', '6', 'r', 'F', '1', 'k', 'Y', 'C', '/', 'W', 'f', 'S', 'd', 'h', 'P', 'x', 'j', '+', 's', 'V', 'X', '1', 't', 'P', 'i', '9', 'a', '0', 'A', 'p', 'G', '9', 'k', 'Q', 'I', 'D', 'A', 'Q', 'A', 'B', '\n',
     'A', 'o', 'G', 'A', 'L', 'J', 'I', 'O', 'U', 'M', '8', 'h', '9', 'S', '0', 'C', '2', 'A', 'N', 'K', 'b', 'm', 'r', 'b', 'j', 'n', 'R', 'H', 's', 'X', 'd', 'Y', 'c', 'k', 'v', 'E', 'a', 'f', '5', '+', 'i', 'p', 'z', 's', 'L', 'v', 'U', 'F', '4', 'j', 'M', '9', 'J', 'P', 'S', 'K', 'o', 'q', 'y', 'b', 'J', 'G', 'c', 'X', '\n',
     'R', 'X', '0', '3', 'g', 's', 'r', 'r', 'C', 'w', 'R', '8', 'r', 'S', 'V', 'H', '6', '6', 'h', 'E', '6', 'F', 'T', 'y', 'A', 'W', 'g', 'p', 'u', 'w', 'L', 'x', 'J', 'O', 'g', 'z', 'f', 'A', 'd', '/', 'g', 'j', '/', '6', 'F', 'w', 'K', 'g', '2', 'u', 'A', 'I', 'I', 'a', 'z', 'z', 'v', '7', 'm', 'A', 'A', '0', 'a', '4', '\n',
     'g', 't', 'm', '6', 'X', 'R', 'O', 'v', '+', 'b', 'e', 'V', '7', 's', 'R', 'g', 'D', '9', 'l', 'P', 'r', 'Y', 'O', 'd', 'x', '2', 'l', 'H', 'S', '7', '/', 'c', '7', '1', 'E', '3', 'u', 'W', '/', '4', 'i', '/', 'c', 'C', 'O', 'X', '0', 'C', 'Q', 'Q', 'D', 'D', 'L', 'B', 'U', 'Y', 's', 'r', 's', 'b', 'H', 'X', '8', '8', '\n',
     'c', 'B', 'D', 'K', 'I', 'r', 'B', '2', 'n', 'S', '/', 'y', 'Q', 'A', 'N', 'e', 'g', 'q', '9', '+', 'U', 'a', 'I', 'u', 'z', 'D', 'a', 'B', 'q', '4', 'y', 'S', 'i', 'd', 'h', 'Z', '+', 'a', 't', 'I', 'o', 'I', 'U', 'U', 'O', '+', 'b', '3', 'q', 't', 'f', 'r', '1', 'J', 'r', 'H', 'F', 'B', '/', 'V', 'H', 'j', '+', 'a', '\n',
     'X', '/', 'x', 'o', '8', '6', 'I', 'f', 'A', 'k', 'E', 'A', 'w', 'V', 'u', 'q', 'f', 'M', 'y', '8', 'r', 'l', 'N', '0', '+', 'X', 'I', 'O', '+', 'u', 'C', 'd', 'U', 'A', 'f', '1', 'q', 'M', '3', 'G', 'x', 'e', 'A', 'n', 'b', 'm', 'Y', 'f', 'd', 'r', 'P', 'd', '/', 'r', 'h', 'z', '/', '8', 'K', 'o', '+', 'v', 't', 'j', '\n',
     'J', 't', 'D', '9', 'p', 'j', 'Q', '+', 'A', 'o', 'R', '3', '6', 'Q', 'C', '7', 'E', 'E', '0', 'y', 'N', 'U', 'D', 'k', 'E', 'p', 'B', 'P', 'w', 'k', 'K', 'K', 'T', 'w', 'J', 'A', 'd', '3', 'k', 'm', 'u', 'O', 'X', 'A', 'L', '8', 's', 'Q', 't', 'j', 'i', 'L', 'r', 'p', 'E', 'p', 'o', 'J', 'J', '8', 'Z', 'T', 'j', 'W', '\n',
     'V', 'y', 'Z', '8', 's', '0', 'D', 'Z', 'n', 'P', 'g', 'Z', 'b', 'a', 't', 'L', '8', '/', 'A', '5', '5', 'm', 'o', '1', 'd', 'd', 'H', '9', 'Z', 'P', 'N', '+', 'Y', 'a', 'H', 'N', 'Z', '2', 'n', 'Q', 'D', 'Y', 'm', '+', 'K', 's', 'H', 'H', 'g', 'Y', 'K', '8', 'i', 'q', 'q', 'J', 'V', 'Q', 'J', 'A', 'R', 'q', 'G', '5', '\n',
     'k', 'Y', 'U', 'o', 'l', '3', 'W', 'd', 'E', 'V', 'H', '8', '7', 'u', 'A', 'G', 'F', 'y', 'o', 'R', 'L', 'u', 'y', 'c', 'Y', '8', 'Q', 'S', 'I', '1', '3', 'i', 'u', 'H', 'X', 'T', '7', 'i', 'x', 'r', 'E', '0', '6', 'E', 'c', '8', 'p', 'I', '2', 'f', 'E', 'V', '9', 'x', 'S', '2', 'Y', 'i', '0', 'J', 's', 'G', '+', '3', '\n',
     '5', 'a', 'i', 'N', 'Y', 'q', '6', 'l', 'o', 'b', 'J', 'd', 's', 'F', 'S', 'm', 'O', 'Q', 'J', 'B', 'A', 'L', 'N', 'I', 'T', '9', '6', 'H', 'm', 'h', '6', 'u', 'a', 'G', 'd', 'j', 'k', 'W', '7', 'b', 'I', 'L', '3', 'W', '7', 'M', 'B', 'H', 'u', 'W', 'o', 'J', 'F', 'x', 'f', 's', 's', 'w', 'M', 'P', 'Z', 'F', 'V', 'V', '\n',
     'j', 'K', 'i', 'k', 'A', 'L', 'o', 'z', '4', 'M', 'L', 'e', 'H', 'L', 'F', 'N', 'k', 'w', 'E', 'H', 'X', 'C', '0', 'R', '3', 'c', 'n', '3', '+', 'v', 'Z', 'z', 'N', 'F', '6', 'g', '0', 'U', 'p', 'h', 'y', 'C', 'Y', '=', '\n',
     '-', '-', '-', '-', '-', 'E', 'N', 'D', ' ', 'R', 'S', 'A', ' ', 'P', 'R', 'I', 'V', 'A', 'T', 'E', ' ', 'K', 'E', 'Y', '-', '-', '-', '-', '-', '\n', 0x00
};

int is_RSA_read() {

    // If it was not initialized we return -1.
    // If init was ok we return 0, otherwise we return -2
    return rsa_state;
}

void RSA_init() {
    int pk_error;

    // Initialize the private key state
    mbedtls_pk_init(&privateKey);

    pk_error = mbedtls_pk_parse_key(&privateKey, keyBuffer, PRIVATE_KEY_BUFFER_LEN, NULL, 0);
    if (pk_error != 0) {
        // Well this means loading the key failed. this sucks
        // TODO: figure out what to do from here, maybe we can notify the failure via BLE
        rsa_state = -2;
    }
    else {
        // Key loading worked!
        rsa_state = 0;

    }
    System_printf("RSA init ok: %d\n", rsa_state);
    return;
}
