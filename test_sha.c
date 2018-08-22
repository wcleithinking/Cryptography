/*
	Example for SHA256.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

extern char* StrSHA256(const char* str, long long length, char* sha256);

extern char* FileSHA256(const char* file, char* sha256);

int main(void) {
	char strsha256[65];
	char filesha256[65];
	char text = "wenchaolei";
	StrSHA256(text, sizeof(text) - 1, strsha256);
	puts(strsha256);
	FileSHA256("test_file.txt", filesha256);
	puts(filesha256);
	// system("pause");
	return 0;
}