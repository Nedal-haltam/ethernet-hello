// this is from : https://github.com/FukuanWang/tiny_aes_gcm.git
#include <stdint.h>

#ifndef _AES_GCM_H_
#define _AES_GCM_H_

//Using AES 128
#define AES_128

#ifdef AES_128
	#define Nk 4	//bytes per key
	#define Nb 4	//bytes per block
	#define Nr 10	//round times
	#define BL 16	//block length
	#define KL 16	//key length
#endif

//enable aes invcipher function
#define AES_INV_CIPHER


//typedef unsigned char uint8_t;
//typedef unsigned long uint32_t;

typedef uint8_t Blcok_128[BL];
typedef uint8_t Key_128[KL];
typedef uint8_t State[4][4];

//the definition of the word type
typedef struct {
	uint8_t a0;
	uint8_t a1;
	uint8_t a2;
	uint8_t a3;
} word;


#ifdef AES_128
	#define Block Blcok_128
	#define Key Key_128
#endif

typedef struct {
	word roundkey[Nb*(Nr + 1)];
	//byte* iv;
	Block J0;
	Block H;
}AES_ctx;


//#define xtime(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))
#define xtime(x) (XTIME1[(x)])


//The constant within the algorithm for the block multiplication operation.
#define R 0xe1


//Change type from byte to uint32
#ifndef UINT32_TO_BYTE
	#define UINT32_TO_BYTE(ul,b)                \
	{										    \
		(b)[0] = (byte) ( (ul) >> 24 );         \
		(b)[1] = (byte) ( (ul) >> 16 );			\
		(b)[2] = (byte) ( (ul) >>  8 );			\
		(b)[3] = (byte) ( (ul)       );			\
	}
#endif


//judge if the i-th bit of X is zeros.
//(non-zero, if the reutrn value larger than 0)
#define VALUE(X,i) ((X)[(i) / 8] & (1 << (7 - i % 8)))

//ceil function of (num/den)
#ifndef ceil
	#define ceil(num,den) (((num) % (den) == 0) ? ((num) / (den)):((num) / (den) + 1))
#endif



/*====================================
	       public functions
======================================*/

/*
initialization of AES
including:
 -the key expansion.
*/
void AES_init(AES_ctx& ctx, const Key key);



/*
cipher the plain text using AES algorithm.
 -state should be a 2-dimensional uint_8 array.
 -length of plain text: 4*Nb bytes
 -length of cipher text: 4*Nb bytes
*/
void Cipher(State& state, const word roundkey[Nb * (Nr + 1)]);



#ifdef AES_INV_CIPHER
/*
Invcipher the cipher text using AES algorithm.
 -state should be a 2-dimensional uint_8 array.
 -length of plain text: 4*Nb bytes
 -length of cipher text: 4*Nb bytes
*/
void InvCipher(State& state, word& roundkey);
#endif

/*
initialization of AES_GCM
including:
 -the key expansion.
 -calculation of J0
 -calculation of H
*/
void AES_GCM_init(AES_ctx& ctx, const Key key, uint8_t* IV, uint32_t IVlen);


/*
cipher the plain text using AES-GCM.
Input parameters:
 -P:	  plain text
 -Plen: the length of the plain text. (bytes)
 -A:	  Authenticated data
 -Alen: the length of the Authenticated data.(bytes)
 -T:	  Authenticated Tag
 -Tlen: the length of the authenticated Tag. (bytes) T <= Block length
*/
void AES_GCM_cipher(const AES_ctx& ctx, uint8_t* P, uint32_t Plen, uint8_t* A, uint32_t Alen, uint8_t *T, uint32_t Tlen);



/*
Decrpyt the cipher text using AES-GCM.
Input parameters:
 -C:	  cipher text
 -Plen: the length of the cipher text
 -A:	  Authenticated data
 -Alen: the length of the Authenticated data
 -T:	  Authenticated Tag
 -Tlen: the length of the authenticated Tag. T <= Block length(suppose that the size of IV, A, C are supported and len(T) = t);
output:
 -failed if return 0
 -success if return 1
*/
int AES_GCM_Invcipher(AES_ctx& ctx, uint8_t* C, uint32_t Clen, uint8_t* A, uint32_t Alen, uint8_t *T, uint32_t Tlen);



#endif //_AES_GCM_H_

//The round constant word array.
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

//S-box
static const uint8_t S_box[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

#ifdef AES_INV_CIPHER
//Inv S-box
static const  uint8_t Inv_S_box[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
#endif

const uint8_t XTIME1[256] =
{
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
	0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
	0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
	0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
	0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
	0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
	0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
	0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
	0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
	0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5,
};


static void KeyExpansion(const uint8_t key[4 * Nk], word rk[Nb * (Nr + 1)]) {
	word temp;
	int i = 0;

	while (i < Nk) {
		rk[i].a0 = key[4 * i    ];
		rk[i].a1 = key[4 * i + 1];
		rk[i].a2 = key[4 * i + 2];
		rk[i].a3 = key[4 * i + 3];
		i++;
	}

	i = Nk;
	while (i < Nb*(Nr + 1)) {
		temp = rk[i - 1];
		if (i%Nk == 0) {
			uint8_t temp_b = temp.a0;
			temp.a0 = S_box[temp.a1] ^ Rcon[i / Nk];
			temp.a1 = S_box[temp.a2];
			temp.a2 = S_box[temp.a3];
			temp.a3 = S_box[temp_b ];
		}
#ifndef AES_128
		else if (Nk > 6 && (i%Nk) == 4) {
			temp.a0 = S_box[temp.a0];
			temp.a1 = S_box[temp.a1];
			temp.a2 = S_box[temp.a2];
			temp.a3 = S_box[temp.a3];
		}
#endif
		rk[i].a0 = rk[i - Nk].a0 ^ temp.a0;
		rk[i].a1 = rk[i - Nk].a1 ^ temp.a1;
		rk[i].a2 = rk[i - Nk].a2 ^ temp.a2;
		rk[i].a3 = rk[i - Nk].a3 ^ temp.a3;
		i++;
	}
}


static void AddRoundKey(unsigned int round, State& s, const word w[Nb * (Nr + 1)]) {
	unsigned int r = 0;
	while (r < Nb) {
		s[r][0] ^= w[round * Nb + r].a0;
		s[r][1] ^= w[round * Nb + r].a1;
		s[r][2] ^= w[round * Nb + r].a2;
		s[r][3] ^= w[round * Nb + r].a3;
		r++;
	}
}



static void SubShiftRows(State s) {
	s[0][0] = S_box[s[0][0]];
	s[1][0] = S_box[s[1][0]];
	s[2][0] = S_box[s[2][0]];
	s[3][0] = S_box[s[3][0]];

	uint8_t temp = s[0][1];
	s[0][1] = S_box[s[1][1]];
	s[1][1] = S_box[s[2][1]];
	s[2][1] = S_box[s[3][1]];
	s[3][1] = S_box[temp];

	temp = s[0][2];
	s[0][2] = S_box[s[2][2]];
	s[2][2] = S_box[temp];

	temp = s[1][2];
	s[1][2] = S_box[s[3][2]];
	s[3][2] = S_box[temp];

	temp = s[0][3];
	s[0][3] = S_box[s[3][3]];
	s[3][3] = S_box[s[2][3]];
	s[2][3] = S_box[s[1][3]];
	s[1][3] = S_box[temp];
}


static inline void MixColumns(State s) {
	int r;
	for (r = 0; r < Nb; r++) {
		uint8_t temp = s[r][0];
		uint8_t allXOR = s[r][0] ^ s[r][1] ^ s[r][2] ^ s[r][3];
		s[r][0] = xtime(s[r][0] ^ s[r][1]) ^ allXOR ^ s[r][0];
		s[r][1] = xtime(s[r][1] ^ s[r][2]) ^ allXOR ^ s[r][1];
		s[r][2] = xtime(s[r][2] ^ s[r][3]) ^ allXOR ^ s[r][2];
		s[r][3] = xtime(s[r][3] ^ temp   ) ^ allXOR ^ s[r][3];
	}
}



void Cipher(State& state, const word roundkey[Nb * (Nr + 1)]) {
	AddRoundKey(0, state, roundkey);

	unsigned int round=0;
	for (round = 1; round < Nr; round++) {
		SubShiftRows(state);
		MixColumns(state);
		AddRoundKey(round, state, roundkey);
	}
	SubShiftRows(state);
	AddRoundKey(Nr, state, roundkey);
}


#ifdef AES_INV_CIPHER
/*inv cipher functions*/

static void InvSubShiftRows(State& s) {
	s[0][0] = Inv_S_box[s[0][0]];
	s[1][0] = Inv_S_box[s[1][0]];
	s[2][0] = Inv_S_box[s[2][0]];
	s[3][0] = Inv_S_box[s[3][0]];

	uint8_t temp = s[3][1];
	s[3][1] = Inv_S_box[s[2][1]];
	s[2][1] = Inv_S_box[s[1][1]];
	s[1][1] = Inv_S_box[s[0][1]];
	s[0][1] = Inv_S_box[temp];

	temp = s[0][2];
	s[0][2] = Inv_S_box[s[2][2]];
	s[2][2] = Inv_S_box[temp];

	temp = s[1][2];
	s[1][2] = Inv_S_box[s[3][2]];
	s[3][2] = Inv_S_box[temp];

	temp = s[0][3];
	s[0][3] = Inv_S_box[s[1][3]];
	s[1][3] = Inv_S_box[s[2][3]];
	s[2][3] = Inv_S_box[s[3][3]];
	s[3][3] = Inv_S_box[temp];
}

static void InvMixColumns(State s) {
	int r;
	for (r = 0; r < Nb; r++) {
		uint8_t allXOR = s[r][0] ^ s[r][1] ^ s[r][2] ^ s[r][3];
		uint8_t allXORtimex3 = xtime(xtime(xtime(allXOR)));
		uint8_t temp0 = s[r][0];
		uint8_t temp1 = s[r][1];
		s[r][0] = s[r][0] ^ allXORtimex3 ^ xtime(xtime(s[r][0] ^ s[r][2])) ^ xtime(s[r][0] ^ s[r][1]) ^ allXOR;
		s[r][1] = s[r][1] ^ allXORtimex3 ^ xtime(xtime(s[r][1] ^ s[r][3])) ^ xtime(s[r][1] ^ s[r][2]) ^ allXOR;
		s[r][2] = s[r][2] ^ allXORtimex3 ^ xtime(xtime(s[r][2] ^ temp0  )) ^ xtime(s[r][2] ^ s[r][3]) ^ allXOR;
		s[r][3] = s[r][3] ^ allXORtimex3 ^ xtime(xtime(s[r][3] ^ temp1  )) ^ xtime(s[r][3] ^ temp0  ) ^ allXOR;
	}
}

void InvCipher(State& state, word& roundkey) {
	AddRoundKey(Nr, state, &roundkey);

	int round;
	for (round = Nr - 1; round > 0; round--) {
		InvSubShiftRows(state);
		AddRoundKey(round, state, &roundkey);
		InvMixColumns(state);
	}
	InvSubShiftRows(state);
	AddRoundKey(0, state, &roundkey);
}
#endif


//Copy a block from src to dst
static void BlockCPY(Block& dst, const Block& src) {
	int i;
	for (i = 0; i < BL; i++) {
		dst[i] = src[i];
	}
}

//Calculate the XOR operation of two blocks: Z = X xor Y.
static void BlockXOR(Block& Z, Block& Y) {
	int i;
	for (i = 0; i < BL; i++) {
		Z[i] ^= Y[i];
	}
}


//Calculate the Multiplication of X and Y module R: Z = (X * Y) mod R
static void Block_Mult(Block& Z, const Block& X, const Block& Y) {
	Block V;
	for (int i = 0; i < BL; i++)
	{
		V[i] = 0;
	}
	Block Z_temp;
	for (int i = 0; i < BL; i++)
	{
		Z_temp[i] = 0;
	}
	for (int i = 0; i < BL; i++)
	{
		V[i] = Y[i];
	}
	int i;

	for (i = 0; i < BL * 8; i++) {
		if (VALUE(X, i)) {
			BlockXOR(Z_temp, V);
		}
		uint8_t temp = (V)[0] << 7;
		//on the case LSB_1(V)==1
		if ((V)[BL - 1] & 0x1) {
			(V)[0] = ((V)[0] >> 1) ^ R;
		}
		//on the case LSB_1(V)==0
		else {
			(V)[0] = ((V)[0] >> 1);
		}
		int j;
		for (j = BL - 1; j > 1; j--) {
			(V)[j] = ((V)[j] >> 1) | ((V)[j - 1] << 7);
		}
		V[1] = (V[1] >> 1) | temp;
	}
	for (int i = 0; i < BL; i++)
	{
		Z[i] = Z_temp[i];
	}
}


//GHASH function
static void GHASH_H(Block& out, uint8_t X[], int xlen, const Block& H) {
	int i;
	
	uint8_t* pX = X;

	for (i = 0; i <= xlen - BL; i += BL) {
		BlockXOR(out, *((Block*)pX));
		Block_Mult(out, out, H);
		pX += BL;
	}
	if (i < xlen && i > 0) {
		Block end_x;
		int j;
		for (j = i; j < xlen; j++) {
			end_x[j - i] = X[j];
		}
		for (j = xlen; j < i + BL; j++) {
			end_x[j - i] = 0;
		}
		BlockXOR(out, end_x);
		Block_Mult(out, out, H);
	}
}


static void inc_32(Block& X) {
	uint32_t temp = ((uint32_t)X[BL - 1]) |
		((uint32_t)X[BL - 2] << 8) |
		((uint32_t)X[BL - 3] << 16) |
		((uint32_t)X[BL - 4] << 24);
	temp++;
	X[BL - 1] = (uint8_t)((temp));
	X[BL - 2] = (uint8_t)((temp) >> 8);
	X[BL - 3] = (uint8_t)((temp) >> 16);
	X[BL - 4] = (uint8_t)((temp) >> 24);
}


//GCTR function
static void GCTR(Block& CB, uint8_t* X, int xlen, const word rk[Nb * (Nr + 1)]) {
	int i, j;
	uint8_t *pX;
	pX = X;

	Block cipherCB;
	for (i = 0; i < xlen - BL; i += BL) {
		BlockCPY(cipherCB, CB);
		// Cipher(*(State*)(&cipherCB), rk);
		State state;
		for (int i = 0; i < BL; ++i) {
		    state[i / 4][i % 4] = cipherCB[i];
		}
		Cipher(state, rk);
		for (int i = 0; i < 16; ++i) {
		    cipherCB[i] = state[i / 4][i % 4];
		}
		for (j = 0; j < BL; j++) {
			(pX)[j] ^= cipherCB[j];
		}
		inc_32(CB);
		pX += BL;
	}
	// Cipher(*(State *)CB, rk);
	State state;
	for (int i = 0; i < BL; ++i) {
		state[i / 4][i % 4] = CB[i];
	}
	Cipher(state, rk);
	for (int i = 0; i < 16; ++i) {
		CB[i] = state[i / 4][i % 4];
	}

		for (j = 0; j < xlen - i; j++) {
		(pX)[j] ^= (CB)[j];
	}
}


/*
	public functions
*/

//initialization of AES
void AES_init(AES_ctx& ctx, const Key key) {
	//expansion the key.
	KeyExpansion(key, (ctx.roundkey));
}


//initialization of AES_GCM
void AES_GCM_init(AES_ctx& ctx, const Key key, uint8_t* IV, uint32_t IVlen) {
	//expansion of the key.
	KeyExpansion(key, (ctx.roundkey));

	for (int i = 0; i < BL; i++)
	{
		ctx.H[i] = 0;
	}

	//cipher the zero block as H.
	// Cipher(*(State*)(&(ctx.H)), ctx.roundkey);
	State state;
	for (int i = 0; i < BL; ++i) {
		state[i / 4][i % 4] = ctx.H[i];
	}
	Cipher(state, ctx.roundkey);
	for (int i = 0; i < 16; ++i) {
		ctx.H[i] = state[i / 4][i % 4];
	}


	//on the case IV length equal to 12 bytes
	if (IVlen == 12) {
		uint32_t i;
		for (int i = 0; i < BL; i++)
		{
			ctx.J0[i] = 0;
		}
		for (i = 0; i < IVlen; i++) {
			ctx.J0[i] = IV[i];
		}
		
		ctx.J0[BL - 1] = 1;
	}
	//on the case IV length not equal to 12 bytes
	else {
		//combine (IV, 0, IVlen) together.
		//calculate the G_HASH of (IV, 0, IVlen)
		for (int i = 0; i < BL; i++)
		{
			ctx.J0[i] = 0;
		}
		GHASH_H((ctx.J0), IV, IVlen, (ctx.H));
		Block temp;
		for (int i = 0; i < BL; i++)
		{
			temp[i] = 0;
		}
		uint32_t IVlen8 = IVlen * 8;
		temp[BL - 1] = (uint8_t)(IVlen8);
		temp[BL - 2] = (uint8_t)(IVlen8 >> 8);
		temp[BL - 3] = (uint8_t)(IVlen8 >> 16);
		temp[BL - 4] = (uint8_t)(IVlen8 >> 24);
		GHASH_H((ctx.J0), temp, BL, (ctx.H));
	}
}


//AES-GCM Encryption
void AES_GCM_cipher(const AES_ctx& ctx, uint8_t* P, uint32_t Plen, uint8_t* A, uint32_t Alen, uint8_t *T, uint32_t Tlen) {
	Block J0;
	BlockCPY(J0, (ctx.J0));
	inc_32(J0);

	//cipher the plain text by calling function GCTR
	GCTR(J0, P, Plen, ctx.roundkey);

	//combinate S = (A, 0^v, C, 0^u, Alen, Clen); Clen == Plen.
	//compute the GHASH value S from the combination  (A, 0^v, C, 0^u, Alen, Clen).
	Block S;
	for (int i = 0; i < BL; i++)
	{
		S[i] = 0;
	}
	GHASH_H(S, A, Alen, (ctx.H));
	GHASH_H(S, P, Plen, (ctx.H));
	Block s_end;
	for (int i = 0; i < 4; i++)
	{
		s_end[i] = 0;
	}
	uint32_t Alen8 = Alen << 3;  //change byte-length to bit-length.
	s_end[4 ] = (uint8_t)(Alen8 >> 24);
	s_end[5 ] = (uint8_t)(Alen8 >> 16);
	s_end[6 ] = (uint8_t)(Alen8 >>  8);
	s_end[7 ] = (uint8_t)(Alen8);
	for (int i = 8; i < 12; i++)
	{
		s_end[i] = 0;
	}
	uint32_t Plen8 = Plen << 3; //change byte-length to bit-length.
	s_end[12] = (uint8_t)(Plen8 >> 24);
	s_end[13] = (uint8_t)(Plen8 >> 16);
	s_end[14] = (uint8_t)(Plen8 >>  8);
	s_end[15] = (uint8_t)(Plen8	  );
	GHASH_H(S, s_end, BL, (ctx.H));

	//cipher the hash value S
	BlockCPY(J0, (ctx.J0));
	GCTR(J0, (uint8_t *)S, BL, ctx.roundkey);

	uint32_t i;
	//return the Tag;
	for (i = 0; i < Tlen; i++) {
		T[i] = S[i];
	}
}


//AES-GCM Decryption
int AES_GCM_Invcipher(AES_ctx& ctx, uint8_t* C, uint32_t Clen, uint8_t* A, uint32_t Alen, uint8_t *T, uint32_t Tlen) {
	Block J0;

	//combinate S = (A, 0^v, C, 0^u, Alen, Clen); Clen == Plen.
	//compute the GHASH value S from the combination  (A, 0^v, C, 0^u, Alen, Clen).
	Block S;
	for (int i = 0; i < BL; i++)
	{
		S[i] = 0;
	}
	GHASH_H(S, A, Alen, (ctx.H));
	GHASH_H(S, C, Clen, (ctx.H));
	Block s_end;
	for (int i = 0; i < 4; i++)
	{
		s_end[i] = 0;
	}
	uint32_t Alen8 = Alen << 3;  //change byte-length to bit-length.
	s_end[ 4] = (uint8_t)(Alen8 >> 24);
	s_end[ 5] = (uint8_t)(Alen8 >> 16);
	s_end[ 6] = (uint8_t)(Alen8 >>  8);
	s_end[ 7] = (uint8_t)(Alen8      );
	for (int i = 8; i < 12; i++)
	{
		s_end[i] = 0;
	}
	uint32_t Clen8 = Clen << 3; //change byte-length to bit-length.
	s_end[12] = (uint8_t)(Clen8 >> 24);
	s_end[13] = (uint8_t)(Clen8 >> 16);
	s_end[14] = (uint8_t)(Clen8 >>  8);
	s_end[15] = (uint8_t)(Clen8      );
	GHASH_H(S, s_end, BL, (ctx.H));

	//cipher the hash value S
	BlockCPY(J0, (ctx.J0));
	GCTR(J0, (uint8_t *)S, BL, ctx.roundkey);

	uint32_t i;
	//validate the Tag;
	for (i = 0; i < Tlen; i++) {
		if (T[i] != S[i]) {
			return 0;
		}
	}

	BlockCPY(J0, (ctx.J0));
	inc_32(J0);
	//invcipher the plain text by calling function GCTR
	GCTR(J0, C, Clen, ctx.roundkey);
	return 1;
}
