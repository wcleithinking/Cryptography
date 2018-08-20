/*
	Example for SHA256.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

extern char* StrSHA256(const char* str, long long length, char* sha256);

int main(void) {
	char text[] = "abcd";
	char sha256[65];
	StrSHA256(text, sizeof(text) - 1, sha256);
	puts(sha256);
	system("pause");
	return 0;
}