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

#endif
