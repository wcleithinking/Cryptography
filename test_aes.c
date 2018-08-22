/*
	Example for AES128.c
*/

#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

int main(void) {
	byte mbyte[16], cbyte[16], key[16],newmbyte[16], eqnewmbyte[16];
	for (int i = 0; i < 16; i++) {
		mbyte[i] = ((byte)i<<4) | ( (byte)i);
		key[i] = (byte)i;
	}
	printf("PLAINTEXT:         ");
	showarray(mbyte);
	printf("KEY:               ");
	showarray(key);
	printf("\n");
	printf("CIPHER (ENCRYPT):\n");
	aes128_encrypt(mbyte, cbyte, key);
	printf("\n");
	printf("CIPHERTEXT:        ");
	showarray(cbyte);
	printf("KEY:               ");
	showarray(key);
	printf("\n");
	printf("INVERSE CIPHER (DECRYPT):\n");
	aes128_decrypt(cbyte, newmbyte, key);
	printf("\n");
	printf("EQUIVALENT INVERSE CIPHER (DECRYPT):\n");
	aes128_eqdecrypt(cbyte, eqnewmbyte, key);
	printf("\n");
	//system("pause");
	return 0;
}