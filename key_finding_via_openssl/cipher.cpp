#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>

using namespace std;

int main()
{
	unsigned char plainBufUc[1024], resultCipherBufUc[1024 + EVP_MAX_BLOCK_LENGTH];
	int plainTextLen, resultCipherLen;
	string keySt;
	string resultCipherSt;

	ifstream cipherTextFile("ciphertext");
    string givenCipherSt((istreambuf_iterator<char>(cipherTextFile)), (istreambuf_iterator<char>()));

    ifstream plainTextFile("plaintext.txt");
    string givenPlainSt((istreambuf_iterator<char>(plainTextFile)), (istreambuf_iterator<char>()));

	plainTextLen = givenPlainSt.length();
	for(int i = 0; i<plainTextLen; i++)
	{
    	plainBufUc[i] = givenPlainSt[i];
	}

	ifstream keyFile("words.txt");
	
    while (getline(keyFile, keySt))
    {
    	resultCipherSt = "";

    	EVP_CIPHER_CTX *ctx;
		unsigned char keyUC[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		unsigned char ivUC[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	    ctx = EVP_CIPHER_CTX_new();
	    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
	                       1);

		OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
	    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

	    for(int i = 0; i<keySt.length(); i++)
	    {
	        keyUC[i] = keySt[i];
	    }

	    for(int i = 0; i<plainTextLen; i++)
	    {
	        plainBufUc[i] = givenPlainSt[i];
	    }

    	EVP_CipherInit_ex(ctx, NULL, NULL, keyUC, ivUC, 1);

		if(!EVP_CipherUpdate(ctx, resultCipherBufUc, &resultCipherLen, plainBufUc, plainTextLen)){
			// Error
            EVP_CIPHER_CTX_free(ctx);
            return 0;
		}

		for(int i = 0; i<resultCipherLen; i++)
	    {
	        resultCipherSt += resultCipherBufUc[i];
	    }

		if (!EVP_CipherFinal_ex(ctx, resultCipherBufUc, &resultCipherLen)) {
	        // Error
            EVP_CIPHER_CTX_free(ctx);
            return 0;
     	}

     	for(int i = 0; i<resultCipherLen; i++)
	    {
	        resultCipherSt += resultCipherBufUc[i];
	    }

     	if(resultCipherSt.compare(givenCipherSt))
	    {
	    	//not equal
	        continue;
	    }

        cout << keyUC << endl;
        EVP_CIPHER_CTX_free(ctx); 

        break;
     	
    }

}