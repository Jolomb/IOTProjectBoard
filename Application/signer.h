#ifndef SIGNER_H__
#define SIGNER_H__

/*
 * Initializes the RSA private key state for the entire program
 */
void RSA_init();

/*
 * Return the sate of the RSA stck. In order to make sure we can perform the required encryption operations
 */
int is_RSA_read();

/*
 * Perform a SHA256 signature for the input buffer
 */
int RSA_sign(const unsigned char *input, size_t input_len);

/*
 * Perform the AES encryption on the input. Places the result in the output buffer.
 *  Output buffer must be of length exactly 16.
 *  This will perform ECB operation of AES and use the hard coded key
 */
int AES_encrypt(const unsigned char *input, size_t input_len, unsigned char *output_buffer, size_t output_len);

/*
 * Initializes the True Random Generator hardware the board has
 */
int initialize_TRNG();

#endif // SIGNER_H__
