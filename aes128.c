/*
	File Name: AES128.c
	References: 
		1) https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
		2) https://blog.csdn.net/qq_28205153/article/details/55798628
	Maintained by Wenchao Lei
	E-mail: wcleithinking@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include "aes.h"


void aes128_encrypt(byte mblock[4 * Nb], byte cblock[4 * Nb], byte key[4 * Nk]) {
	word w[Nb*(Nr + 1)];
	KeyExpansion(key, w);
	Cipher(mblock, cblock, w);
}

void aes128_decrypt(byte cblock[4 * Nb], byte mblock[4 * Nb], byte key[4 * Nk]) {
	word w[Nb*(Nr + 1)];
	KeyExpansion(key, w);
	InvCipher(cblock, mblock, w);
}

void KeyExpansion(byte key[4 * Nk], word w[Nb*(Nr+1)]) {
	word temp;
	int i = 0;
	while (i < Nk) {
		w[i] = getWordFromByte(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
		i++;
	}
	i = Nk;
	while (i < Nb*(Nr + 1)) {
		temp = w[i - 1];
		if (i%Nk == 0) {
			temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
		}
		//// for AES-256 where Nk = 8, see Page 19 of FIPS-197
		//else if ((Nk > 6) && (i%Nk == 4)) {
		//	temp = SubWord(temp);
		//}
		w[i] = w[i - Nk] ^ temp;
		i++;
	}
}

word RotWord(word a) {
	word temp;
	temp = ((a & 0x00ffffff) << 8);
	return temp | ((a & 0xff000000) >> 24);
}

word SubWord(word a) {
	byte b[4];
	getByteFromWord(a, b);
	return getWordFromByte(SubByte(b[0]), SubByte(b[1]), SubByte(b[2]), SubByte(b[3]));
}

void Cipher(byte in[4 * Nb], byte out[4 * Nb], word w[Nb*(Nr + 1)]) {
	byte state[4][Nb];
	int round = 0;
	printf("round[%2d].input    ", round);
	showarray(in);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < Nb; j++) {
			state[i][j] = in[i + 4 * j];
		}
	}
	printf("round[%2d].k_sch    ", round);
	showkey(w[round*Nb+0],w[round*Nb+1],w[round*Nb+2],w[round*Nb+3]);
	AddRoundKey(state, w, round);
	for (round = 1; round <=Nr; round++) {
		// Start
		printf("round[%2d].start    ", round);
		showstate(state);
		// SubBytes
		SubBytes(state);
		printf("round[%2d].s_box    ", round);
		showstate(state);
		// ShiftRows
		ShiftRows(state);
		printf("round[%2d].s_row    ", round);
		showstate(state);
		if (round < Nr) {
			// MixColumns
			MixColumns(state);
			printf("round[%2d].m_col    ", round);
			showstate(state);
		}
		// AddRoundKey
		printf("round[%2d].k_sch    ", round);
		showkey(w[round*Nb + 0], w[round*Nb + 1], w[round*Nb + 2], w[round*Nb + 3]);
		AddRoundKey(state, w, round);
		if (round == Nr) {
			printf("round[%2d].output   ", round);
			showstate(state);
		}
	}
	for (int i = 0; i < 4 * Nb; i++) {
		out[i] = state[i % 4][i / 4];
	}
}

void SubBytes(byte state[4][Nb]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < Nb; j++) {
			state[i][j] = SubByte(state[i][j]);
		}
	}
}

void ShiftRows(byte state[4][Nb]) {
	byte temp[4][Nb];
	int shift;
	for (int r = 0; r < 4; r++) {
		shift = r % 4;
		for (int c = 0; c < Nb; c++) {
			temp[r][c] = state[r][(c + shift) % Nb];
		}
	}
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < Nb; c++) {
			state[r][c] = temp[r][c];
		}
	}
}

void MixColumns(byte state[4][Nb]) {
	byte temp[4][Nb];
	int r, c;
	for (r = 0; r < 4; r++) {
		for (c = 0; c < Nb; c++) {
			temp[r][c] = GFMul(aMix[r][0], state[0][c]) ^ GFMul(aMix[r][1], state[1][c]) ^ GFMul(aMix[r][2], state[2][c]) ^ GFMul(aMix[r][3], state[3][c]);
		}
	}
	for (r = 0; r < 4; r++) {
		for (c = 0; c < Nb; c++) {
			state[r][c] = temp[r][c];
		}
	}
}

void AddRoundKey(byte state[4][Nb], word w[Nb*(Nr + 1)], int round) {
	byte b[4];
	for (int c = 0; c < Nb; c++) {
		getByteFromWord(w[round*Nb + c], b);
		for (int r = 0; r < 4; r++) {
			state[r][c] = state[r][c] ^ b[r];
		}
	}
}


void InvCipher(byte in[4 * Nb], byte out[4 * Nb], word w[Nb*(Nr + 1)]) {
	byte state[4][Nb];
	int round = Nr;
	printf("round[%2d].iinput   ", Nr - round);
	showarray(in);
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < Nb; j++) {
			state[i][j] = in[i + 4 * j];
		}
	}
	printf("round[%2d].ik_sch   ", Nr - round);
	showkey(w[round*Nb + 0], w[round*Nb + 1], w[round*Nb + 2], w[round*Nb + 3]);
	AddRoundKey(state, w, round);
	for (round = Nr-1; round >= 0; round--) {
		// Start
		printf("round[%2d].istart   ", Nr - round);
		showstate(state);
		// InvShiftRows
		InvShiftRows(state);
		printf("round[%2d].is_row   ", Nr - round);
		showstate(state);
		// InvSubBytes
		InvSubBytes(state);
		printf("round[%2d].is_box   ", Nr - round);
		showstate(state);
		// AddRoundKey
		printf("round[%2d].ik_sch   ", Nr - round);
		showkey(w[round*Nb + 0], w[round*Nb + 1], w[round*Nb + 2], w[round*Nb + 3]);
		AddRoundKey(state, w, round);
		printf("round[%2d].ik_add   ", Nr - round);
		showstate(state);
		if (round > 0) {
			// InvMixColumns
			InvMixColumns(state);
		}
		if (round == 0) {
			printf("round[%2d].ioutput  ", Nr - round);
			showstate(state);
		}
	}
	for (int i = 0; i < 4 * Nb; i++) {
		out[i] = state[i % 4][i / 4];
	}
}

void InvShiftRows(byte state[4][Nb]) {
	byte temp[4][Nb];
	int shift;
	for (int r = 0; r < 4; r++) {
		shift = r % 4;
		for (int c = Nb-1; c >=0; c--) {
			if (c - shift >= 0) temp[r][c] = state[r][c - shift];
			else temp[r][c] = state[r][c - shift + Nb];
		}
	}
	for (int r = 0; r < 4; r++) {
		for (int c = 0; c < Nb; c++) {
			state[r][c] = temp[r][c];
		}
	}
}

void InvSubBytes(byte state[4][Nb]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < Nb; j++) {
			state[i][j] = InvSubByte(state[i][j]);
		}
	}
}

void InvMixColumns(byte state[4][Nb]) {
	byte temp[4][Nb];
	int r, c;
	for (r = 0; r < 4; r++) {
		for (c = 0; c < Nb; c++) {
			temp[r][c] = GFMul(InvaMix[r][0], state[0][c]) ^ GFMul(InvaMix[r][1], state[1][c]) ^ GFMul(InvaMix[r][2], state[2][c]) ^ GFMul(InvaMix[r][3], state[3][c]);
		}
	}
	for (r = 0; r < 4; r++) {
		for (c = 0; c < Nb; c++) {
			state[r][c] = temp[r][c];
		}
	}
}

/* Auxiliary Functions */
void getByteFromWord(word a, byte b[4]) {
	b[0] = (byte)((a & 0xff000000) >> 24);
	b[1] = (byte)((a & 0x00ff0000) >> 16);
	b[2] = (byte)((a & 0x0000ff00) >> 8);
	b[3] = (byte)((a & 0x000000ff));
}
word getWordFromByte(byte byte0, byte byte1, byte byte2, byte byte3) {
	word word0, word1, word2, word3;
	word0 = ((word)byte0 & 0x000000ff) << 24;
	word1 = ((word)byte1 & 0x000000ff) << 16;
	word2 = ((word)byte2 & 0x000000ff) << 8;
	word3 = ((word)byte3 & 0x000000ff);
	return word0 | word1 | word2 | word3;
}
byte SubByte(byte b) {
	int row, col;
	row = (int)((b & 0b11110000) >> 4);
	col = (int)(b & 0b00001111);
	b = SBox[row][col];
	return b;
}

byte InvSubByte(byte b) {
	int row, col;
	row = (int)((b & 0b11110000) >> 4);
	col = (int)(b & 0b00001111);
	b = InvSBox[row][col];
	return b;
}

byte GFMul(byte b1, byte b2) {
	if (b1 == 0x01)
		return b2;
	else if (b1 == 0x02)
		return xtime(b2);
	else if (b1 == 0x03)
		return (xtime(b2) ^ b2);	// 0x02 ^ 0x01
	else if (b1 == 0x09)
		return ((xtime(xtime(xtime(b2)))) ^ b2);	// 0x08 ^ 0x01
	else if (b1 == 0x0b)
		return ((xtime(xtime(xtime(b2)))) ^ xtime(b2) ^ b2 );	// 0x08 ^ 0x02 ^ 0x01
	else if (b1 == 0x0d)
		return ((xtime(xtime(xtime(b2)))) ^ xtime(xtime(b2)) ^ b2);	// 0x08 ^ 0x04 ^ 0x01
	else if (b1 == 0x0e) 
		return ((xtime(xtime(xtime(b2)))) ^ xtime(xtime(b2)) ^ xtime(b2));	// 0x08 ^ 0x04 ^ 0x02
}

byte xtime(byte b) {
	if ((b & 0b10000000) == 0)
		return (b << 1);
	else
		return ((b << 1) ^ 0x1b);
}

void showarray(byte array[16]) {
	char str[33];
	word a[4];
	for (int i = 0; i < 4; i++) {
		a[i] = getWordFromByte(array[4 * i + 0], array[4 * i + 1], array[4 * i + 2], array[4 * i + 3]);
	}
	sprintf_s(str, 33, "%08x%08x%08x%08x", a[0], a[1], a[2], a[3]);
	puts(str);
}

void showkey(word w0, word w1, word w2, word w3) {
	char str[33];
	sprintf_s(str, 33, "%08x%08x%08x%08x", w0, w1, w2, w3);
	puts(str);
}

void showstate(byte state[4][Nb]) {
	byte temp[4 * Nb];
	for (int i = 0; i < 4 * Nb; i++) {
		temp[i] = state[i % 4][i / 4];
	}
	showarray(temp);
}