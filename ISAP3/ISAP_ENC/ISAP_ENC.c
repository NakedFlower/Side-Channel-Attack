#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>

#include "crypto_aead.h"
#include "api.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MESSAGE_LENGTH			32
#define ASSOCIATED_DATA_LENGTH	32

void init_buffer(unsigned char* buffer, unsigned long long numbytes);

void print_bstr(const char* label, const unsigned char* data, unsigned long long length);

int generate_test_vectors();

int main()
{
	int ret = generate_test_vectors();

	if (ret != KAT_SUCCESS) {
		printf("test vector generation failed with code %d\n", ret);
	}

	return ret;
}

int generate_test_vectors()
{
	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MESSAGE_LENGTH];
	unsigned char       msg2[MESSAGE_LENGTH];
	unsigned char		ad[ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long	clen, mlen2;
	int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;

	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));

	unsigned long long mlen = MESSAGE_LENGTH;
	unsigned long long adlen = ASSOCIATED_DATA_LENGTH;

	printf("Count = %d\n", count++);

	print_bstr("Key = ", key, CRYPTO_KEYBYTES);

	print_bstr("Nonce = ", nonce, CRYPTO_NPUBBYTES);

	print_bstr("PT = ", msg, mlen);

	print_bstr("AD = ", ad, adlen);

	if ((func_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key)) != 0) {
		printf("crypto_aead_encrypt returned <%d>\n", func_ret);
		ret_val = KAT_CRYPTO_FAILURE;
		return ret_val;
	}

	print_bstr("CT = ", ct, clen);

	printf("\n");

	if ((func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key)) != 0) {
		printf("crypto_aead_decrypt returned <%d>\n", func_ret);
		ret_val = KAT_CRYPTO_FAILURE;
		return ret_val;
	}

	if (mlen != mlen2) {
		printf("crypto_aead_decrypt returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen2, mlen);
		ret_val = KAT_CRYPTO_FAILURE;
		return ret_val;
	}

	if (memcmp(msg, msg2, mlen)) {
		printf("crypto_aead_decrypt did not recover the plaintext\n");
		ret_val = KAT_CRYPTO_FAILURE;
		return ret_val;
	}

	return ret_val;
}


void print_bstr(const char* label, const unsigned char* data, unsigned long long length)
{
	printf("%s", label);

	for (unsigned long long i = 0; i < length; i++)
		printf("%02X", data[i]);

	printf("\n");
}

void init_buffer(unsigned char* buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}