/*
	File Name: "SHA-256.c"
	References: 
		1) https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf;
		2) https://blog.csdn.net/c_duoduo/article/details/43889759;
		3) https://blog.csdn.net/s_lisheng/article/details/77937202?locationNum=7&fps=1;
	Maintained by Wenchao Lei 
	Email: wcleithinking@gmail.com
*/


#include <stdio.h>
#include <stdlib.h>
#include <math.h>


// the rotate left/right (circular left/right shift) operation, where x is a 32-bit word, 0<=n<32
// #define SHA256_ROTL(x,n)	( (x<<n) | ( (x>>(32-n))&(0x7fffffff>>(31-n)) ) )	// 0x7fffffff = 0b 0111 1111 1111 1111 1111 1111 1111 1111
#define SHA256_ROTL(x,n)	( ((unsigned long)x<<n) | ((unsigned long)x>>(32-n)) )
#define SHA256_ROTR(x,n)	( ((unsigned long)x>>n) | ((unsigned long)x<<(32-n)) )

// the right shift operation, where x is a 32-bit word, 0<=n<32
//#define SHA256_SHR(x,n)		( (x>>n)&(0x7fffffff>>(n-1)) )
#define SHA256_SHR(x,n)		( (unsigned long)x>>n )

// six SHA-256 logical functions, where x,y and z are 32-bit words
#define SHA256_Ch(x,y,z)	( (x&y) ^ ((~x)&z) )
#define SHA256_Maj(x,y,z)	( (x&y) ^ (x&z) ^ (y&z) )
//#define SHA256_Sig0(x)		( SHA256_ROTL(x,30)  ^ SHA256_ROTL(x,19) ^ SHA256_ROTL(x,10) )
//#define SHA256_Sig1(x)		( SHA256_ROTL(x,26)  ^ SHA256_ROTL(x,21) ^ SHA256_ROTL(x,7) )
//#define SHA256_sig0(x)		( SHA256_ROTL(x,25)  ^ SHA256_ROTL(x,14) ^ SHA256_SHR(x,3) )
//#define SHA256_sig1(x)		( SHA256_ROTL(x,15) ^ SHA256_ROTL(x,13) ^ SHA256_SHR(x,10) )
#define SHA256_Sig0(x)		( SHA256_ROTR(x,2)  ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22) )
#define SHA256_Sig1(x)		( SHA256_ROTR(x,6)  ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25) )
#define SHA256_sig0(x)		( SHA256_ROTR(x,7)  ^ SHA256_ROTR(x,18) ^ SHA256_SHR(x,3) )
#define SHA256_sig1(x)		( SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ SHA256_SHR(x,10) )

extern char* StrSHA256(const char* str, long long length, char* sha256) {
	/*
		Aim: compute the hash value of a given string under SHA-256
		Parameters:
			str:	the origial string pointer
			length:	the length of the original string
			sha256: the sha-256 string pointer
	*/

	long i, t;
	long K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

	/* 
		Step 1. padding and parsing the message: "str" under the "big-endian" convention
	*/
	long long length_pp;	// the length of the string after padding
	char* str_pp;	// the string after padding
	length_pp = length + ((length % 64 < 56) ? (64 - length % 64) : (128 - length % 64));
	if(!(str_pp = (char*)malloc(length_pp*sizeof(char)))) return 0;
	for (i = 0; i < length; i++) str_pp[i + 3 - 2 * (i % 4)] = str[i];	// copy str: 1234 to 4321
	str_pp[i + 3 - 2 * (i % 4)] = 128;	// add 0b10000000
	for (i = length + 1; i < length_pp; i++) str_pp[i + 3 - 2 * (i % 4)] = 0;	// add 0b00000000
	// modify the last 64 bits
	*((long*)(str_pp + length_pp - 8)) = length * 8 / ((long)pow(2, 32));
	*((long*)(str_pp + length_pp - 4)) = length * 8 % ((long)pow(2, 32));
	/*	
		Step 2. setting the initial hash value $H^{(0)}$ 
	*/
	long H0, H1, H2, H3, H4, H5, H6, H7;
	H0 = 0x6a09e667;
	H1 = 0xbb67ae85;
	H2 = 0x3c6ef372;
	H3 = 0xa54ff53a;
	H4 = 0x510e527f;
	H5 = 0x9b05688c;
	H6 = 0x1f83d9ab;
	H7 = 0x5be0cd19;

	/*
		Step 3. update the hash value $H^{(i)}$
	*/
	char* str_pp_end;
	long W[64];
	long a, b, c, d, e, f, g, h;
	long T1, T2;
	for (str_pp_end = str_pp + length_pp; str_pp < str_pp_end; str_pp += 64) {
		// prepare the message schedule
		for (t = 0; t < 64; t++) {
			if (t < 16) W[t] = ((long*)str_pp)[t];	// 32 bits for "long" type
			else W[t] = SHA256_sig1(W[t - 2]) + W[t - 7] + SHA256_sig0(W[t - 15]) + W[t - 16];
		}
		// initialize the eight working variables
		a = H0; b = H1; c = H2; d = H3;
		e = H4; f = H5; g = H6; h = H7;
		// update the working variables
		for (t = 0; t < 64; t++) {
			T1 = h + SHA256_Sig1(e) + SHA256_Ch(e, f, g) + K[t] + W[t];
			T2 = SHA256_Sig0(a) + SHA256_Maj(a, b, c);
			h = g;	g = f;	f = e;	e = d + T1; 
			d = c;	c = b;	b = a;	a = T1 + T2;
		}
		// compute the intermediate hash value $H^{(i)}$ 
		H0 += a, H1 += b, H2 += c, H3 += d, H4 += e, H5 += f, H6 += g, H7 += h;
	}

	/*
		Step 4. get result
	*/
	free(str_pp - length_pp);
	sprintf_s(sha256, 65,"%08x%08x%08x%08x%08x%08x%08x%08x", H0, H1, H2, H3, H4, H5, H6, H7);
	return sha256;
}


extern char* FileSHA256(const char* file, char* sha256) {
	/*
	Aim: compute the hash value of a given file under SHA-256
	Parameters:
		file:	the origial file pointer
		sha256: the sha-256 string pointer
	*/

	long i, t;
	long K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

	/*
		Step 0. prepare the file
	*/
	FILE* fh;
	long long length;
	errno_t err;
	err = fopen_s(&fh, file, "rb");	// read in 0b mode
	fseek(fh, 0, SEEK_END);	// move to the end of file
	length = _ftelli64(fh);	// get the offset w.r.t. the start of file

	/*
		Step 1. padding and parsing the file "fh" under the "big-endian" convention
	*/
	long long length_add;
	char* pointer_add;
	long long length_copy, j;
	char* pointer_copy;
	length_add = (length % 64 < 56) ? (64) : (128);
	if (!(pointer_add = (char*)malloc(length_add * sizeof(char)))) return 0;
	length_copy = length % 64;
	if (!(pointer_copy = (char*)malloc(length_copy * sizeof(char)))) return 0;
	fseek(fh, -length_copy, SEEK_END);
	fread(pointer_copy, 1, length_copy, fh);	// length_copy * 1 byte to pointer "pointer_copy"
	for (i = 0; i < length_copy; i++) pointer_add[i + 3 - 2 * (i % 4)] = pointer_copy[i];
	free(pointer_copy);
	pointer_add[i + 3 - 2 * (i % 4)] = 128;	// add 0b10000000
	for (i = length_copy + 1; i < length_add; i++) pointer_add[i + 3 - 2 * (i % 4)] = 0;	// add 0b00000000
	// modify the last 64 bits
	*((long*)(pointer_add + length_add - 8)) = length * 8 / ((long)pow(2, 32));
	*((long*)(pointer_add + length_add - 4)) = length * 8 % ((long)pow(2, 32));

	/*
		Step 2. setting the initial hash value $H^{(0)}$
	*/
	long H0, H1, H2, H3, H4, H5, H6, H7;
	H0 = 0x6a09e667;
	H1 = 0xbb67ae85;
	H2 = 0x3c6ef372;
	H3 = 0xa54ff53a;
	H4 = 0x510e527f;
	H5 = 0x9b05688c;
	H6 = 0x1f83d9ab;
	H7 = 0x5be0cd19;

	/*
		Step 3. update the hash value $H^{(i)}$
	*/
	char M[64],Temp[64];
	long W[64];
	long a, b, c, d, e, f, g, h;
	long T1, T2;
	for (rewind(fh); 64 == fread(M, 1, 64, fh);) {
		// prepare the message schedule
		for (i = 0; i < 64; i++) Temp[i + 3 - 2 * (i % 4)] = M[i];	// get message block
		for (t = 0; t < 64; t++) {
			if (t < 16) W[t] = ((long *)Temp)[t];	// 32 bits for "long" type
			else W[t] = SHA256_sig1(W[t - 2]) + W[t - 7] + SHA256_sig0(W[t - 15]) + W[t - 16];
		}
		// initialize the eight working variables
		a = H0; b = H1; c = H2; d = H3;
		e = H4; f = H5; g = H6; h = H7;
		// update the working variables
		for (t = 0; t < 64; t++) {
			T1 = h + SHA256_Sig1(e) + SHA256_Ch(e, f, g) + K[t] + W[t];
			T2 = SHA256_Sig0(a) + SHA256_Maj(a, b, c);
			h = g;	g = f;	f = e;	e = d + T1;
			d = c;	c = b;	b = a;	a = T1 + T2;
		}
		// compute the intermediate hash value $H^{(i)}$ 
		H0 += a, H1 += b, H2 += c, H3 += d, H4 += e, H5 += f, H6 += g, H7 += h;
	}
	char* pointer_end;
	for (pointer_end = pointer_add + length_add; pointer_add < pointer_end; pointer_add += 64) {
		// prepare the message schedule
		for (t = 0; t < 64; t++) {
			if (t < 16) W[t] = ((long*)pointer_add)[t];	// 32 bits for "long" type
			else W[t] = SHA256_sig1(W[t - 2]) + W[t - 7] + SHA256_sig0(W[t - 15]) + W[t - 16];
		}
		// initialize the eight working variables
		a = H0; b = H1; c = H2; d = H3;
		e = H4; f = H5; g = H6; h = H7;
		// update the working variables
		for (t = 0; t < 64; t++) {
			T1 = h + SHA256_Sig1(e) + SHA256_Ch(e, f, g) + K[t] + W[t];
			T2 = SHA256_Sig0(a) + SHA256_Maj(a, b, c);
			h = g;	g = f;	f = e;	e = d + T1;
			d = c;	c = b;	b = a;	a = T1 + T2;
		}
		// compute the intermediate hash value $H^{(i)}$ 
		H0 += a, H1 += b, H2 += c, H3 += d, H4 += e, H5 += f, H6 += g, H7 += h;
	}

	/*
		Step 4. get result
	*/
	free(pointer_add - length_add);
	fclose(fh);
	sprintf_s(sha256, 65, "%08x%08x%08x%08x%08x%08x%08x%08x", H0, H1, H2, H3, H4, H5, H6, H7);
	return sha256;
}