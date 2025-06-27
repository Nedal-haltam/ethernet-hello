// this is from : https://github.com/cpereida/AES128-GCM.git

#include <stdio.h>		// Used for printing and debugging
#include <stdint.h>
#include <string.h>
/* Key Length */
#define Nk 4
/* Block Size */
#define Nb 4
/* Number of Rounds */
#define Nr 10


/* State array */
static unsigned char stateMatrix[4][4];
/* All the Round Keys */
static unsigned char roundKeys[Nb * Nk * (Nr + 1)];
/* Round counter */
static unsigned char roundNumber;

/* Multiplication by two in GF(2^8). Multiplication by three is xtime(a) ^ a */
#define xtime(a) ( ((a) & 0x80) ? (((a) << 1) ^ 0x1b) : ((a) << 1) )

/* The S-box table */
static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; // F

/* The round constant table (needed in KeyExpansion) */
static const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 
    0x20, 0x40, 0x80, 0x1b, 0x36 };

  // ************************************************************************ //
 // Private functions                                                        //
// ************************************************************************ //

/* Method used for printing arrays with 4 by 4 values in Hex format 
static void Print(unsigned char myarray[4][4]) {		
	
	unsigned char i, j;

	for(i = 0; i < Nb; i++) 
	{
		for(j = 0; j < Nb; j++) 
		{
			printf("%#x ", myarray[i][j]);		// Print state array 
		}
		printf("%s\n", "");
	}
	printf("%s\n", "");
}*/

/* Method used for printing values in one dimension arrays 
static void PrintVector(unsigned char *myArray, unsigned char arraySize) {		
	
	unsigned char i, j;

	for(i = 0; i < arraySize; i++) 
	{
		printf("%#X ", myArray[i]);
	}
}*/

/* Return the Sbox translated value of a word, submethod of KeyExpansion function  */
static void SubWord(unsigned char word[4]) {
	word[0] = sbox[word[0]];
	word[1] = sbox[word[1]];
	word[2] = sbox[word[2]];
	word[3] = sbox[word[3]];
}

/* Key values (word) are rotated to the left, submethod of KeyExpansion function */
static void RotWord(unsigned char word[4]) {
	
	unsigned char tempRot;	// use of tempRot to hold the value of the first byte

	tempRot = word[0];									
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = tempRot;
}

/* Method to expand the key, only for AES128 */
static void KeyExpansion128(const unsigned char *key) {	

	unsigned char temp[4], i;

	/* Initial round key values of the key expansion */
	for (i = 0; i < Nb * Nk; i++) 
	{
		roundKeys[i] = key[i];							// We get the first 4 bytes directly from the original key
	}

	for (; i < Nb * Nk * (Nr + 1); i++)			// Iterate through the 176 - 4 bytes array
	{
		if (i % (Nk * Nb) == 0)							// If i % 16 == 0, we use the temp variable to store 4 bytes at a time
		{
			temp[0] = roundKeys[(i - Nk) + 0];			// We get the last 4 bytes from the roundKeys and store at temp
			temp[1] = roundKeys[(i - Nk) + 1];
			temp[2] = roundKeys[(i - Nk) + 2];
			temp[3] = roundKeys[(i - Nk) + 3];

			RotWord(temp);								// Last 4 bytes are rotated
			SubWord(temp);								// Last 4 bytes are replaced with Sbox values

			temp[0] = temp[0] ^ rcon[i / (Nk * Nb) - 1];// The leftmost byte of temp is multiplied with rcon[round] in GF(2)

			roundKeys[i + 0] = roundKeys[i - (Nb * Nk) + 0] ^ temp[0];	// First byte of temp is XORed with byte 16 positions before
			roundKeys[i + 1] = roundKeys[i - (Nb * Nk) + 1] ^ temp[1];	// Second byte of temp is XORed with byte 16 positions before
			roundKeys[i + 2] = roundKeys[i - (Nb * Nk) + 2] ^ temp[2];	// Third byte of temp is XORed with byte 16 positions before
			roundKeys[i + 3] = roundKeys[i - (Nb * Nk) + 3] ^ temp[3];	// Fourth byte of temp is XORed with byte 16 positions before

			i += 3;	// If we use the temp variable, then index needs to be added by 3 (plus the addition of the iteration)
		} 
		else 
		{
			roundKeys[i] = roundKeys[i - Nk] ^ roundKeys[i - (Nb * Nk)]; // Current byte == roundKeys 4 positions before XORed with roundKeys of 16 positions before
		}
	}
	//PrintVector(roundKeys, sizeof(roundKeys) / sizeof(roundKeys[0]));
}

/* Method used to add the roundKeys to the state array */
static void AddRoundKey() {

	unsigned char tempRoundKeys[4][4], i, j, tempArray[4];

	// Round keys are grabbed byte-by-byte on each round and stored in a temporal 4x4 matrix
	for(i = 0; i < Nb; i++) 
	{
		tempArray[0] = roundKeys[Nk * (i + roundNumber * Nb) + 0];	// First  byte of roundKeys[roundNumber] is grabbed and stored in tempArray 
		tempArray[1] = roundKeys[Nk * (i + roundNumber * Nb) + 1];	// Second byte of roundKeys[roundNumber] is grabbed and stored in tempArray
		tempArray[2] = roundKeys[Nk * (i + roundNumber * Nb) + 2];	// Third  byte of roundKeys[roundNumber] is grabbed and stored in tempArray
		tempArray[3] = roundKeys[Nk * (i + roundNumber * Nb) + 3];	// Fourth byte of roundKeys[roundNumber] is grabbed and stored in tempArray

		// iterate from 0 to 3 to fill the 4 columns
		for(j = 0; j < Nb; j++) 
		{
			tempRoundKeys[j][i] = tempArray[j];	// Four bytes are stored in the j column of tempRoundKeys
		}
	}

	//printf("%s\n", "");
	//Print(tempRoundKeys);

	for(i = 0; i < Nb; i++) 
	{
		for(j = 0; j < Nb; j++) 
		{
			stateMatrix[i][j] = stateMatrix[i][j] ^ tempRoundKeys[i][j];	// Round keys of the current round (tempRoundKeys) are XORed with state matrix
		}
	}
	//printf("%s\n", "");
	//Print(stateMatrix);
}

/* State values are mapped to the Sbox values */
static void SubBytes() {

	unsigned char i, j;

	for(i = 0; i < Nb; i++)
	{
		for(j = 0; j < Nb; j++)
		{
			stateMatrix[i][j] = sbox[stateMatrix[i][j]];
		}
	}
	//Print(stateMatrix);
}

/* Row bytes are shifted. Row N[i][] is shifted to the left by i bytes */
static void ShiftRows() {

	unsigned char tempRow;

	// Row N[1][] (second row) is shifted to the left by 1 byte
	tempRow = stateMatrix[1][0];
	stateMatrix[1][0] = stateMatrix[1][1];
	stateMatrix[1][1] = stateMatrix[1][2];
	stateMatrix[1][2] = stateMatrix[1][3];
	stateMatrix[1][3] = tempRow;

	// Row N[2][] (third row) is shifted to the left by 2 bytes
	tempRow = stateMatrix[2][0];
	stateMatrix[2][0] = stateMatrix[2][2];
	stateMatrix[2][2] = tempRow;

	tempRow = stateMatrix[2][1];
	stateMatrix[2][1] = stateMatrix[2][3];
	stateMatrix[2][3] = tempRow;

	// Row N[3][] (fourth row) is shifted to the left by 3 bytes
	tempRow = stateMatrix[3][3];
	stateMatrix[3][3] = stateMatrix[3][2];
	stateMatrix[3][2] = stateMatrix[3][1];
	stateMatrix[3][1] = stateMatrix[3][0];
	stateMatrix[3][0] = tempRow;
}

static void MixColumns() {

	unsigned char i, j, tempCell[4];

	for(i = 0; i < Nb; i++)
	{
		tempCell[0] = (xtime(stateMatrix[0][i])
					^ (xtime(stateMatrix[1][i]) ^ stateMatrix[1][i]) 
				   	^ (stateMatrix[2][i])
				   	^ (stateMatrix[3][i]));			// ({02} • s0c ) ({03} • s1c ) (s2c) (s3c)

		tempCell[1] = (stateMatrix[0][i]
					^ (xtime(stateMatrix[1][i]))
					^ (xtime(stateMatrix[2][i]) ^ stateMatrix[2][i]) 
				   	^ (stateMatrix[3][i]));			// (s0c) ({02} • s1c ) ({03} • s2c) (s3c)

		tempCell[2] = (stateMatrix[0][i] 
					^  stateMatrix[1][i]
					^ (xtime(stateMatrix[2][i]))
					^ (xtime(stateMatrix[3][i]) ^ stateMatrix[3][i]));	// (s0c) (s1c) ({02} • s2c) ({03} • s3c)

		tempCell[3] = ((xtime(stateMatrix[0][i]) ^ stateMatrix[0][i])	// ({03} • s0c) (s1c) (s2c) ({02} • s3c)
					^  stateMatrix[1][i] 
					^  stateMatrix[2][i]
					^ (xtime(stateMatrix[3][i])));

		for(j = 0; j < Nb; j++)
		{
			stateMatrix[j][i] = tempCell[j];	// Push each value from tempCell to stateMatrix
		}
	}
}

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k) {

	KeyExpansion128(k);

	for(unsigned char i = 0; i < Nb; i++) 
	{
		for(unsigned char j = 0; j < Nb; j++) 
		{
			stateMatrix[j][i] = p[(i * Nb) + j];	// Fill state array with values from plaintext p filling column by column
		}
	}
	
	roundNumber = 0;								// Initialize roundNumber to 0
	AddRoundKey();									// First key added

	// Iterate the process by Nr - 1 times which is 9 (10 - 1) times for 128 AES 
	for (roundNumber = 1; roundNumber < Nr; ++roundNumber) 
	{
		SubBytes();									// Bytes are substituted by Sbox values
		ShiftRows();								// Bytes rows are shifted to the left by N bytes 
		MixColumns();								// Byte columns are multiplied by a constant to mix the columns
		AddRoundKey();								// Round key added to the stateMatrix
		//Print(stateMatrix);
		//printf("%s%d\n", "Round: ", roundNumber);		
	}

	// The last round does not include MixColumns but adds a final round key
	SubBytes();
	ShiftRows();
	AddRoundKey();

	//Print(stateMatrix);

	for(unsigned char i = 0; i < Nb; i++)
	{
		for(unsigned char j = 0; j < Nb; j++)
		{
			c[(i * Nb) + j] = stateMatrix[j][i];	// stateMatrix values are stored in c
		}
	}
	//PrintVector(c, sizeof(c) / sizeof(c[0]));	
}


/* Block Length in bytes */
#define Block 16

/* IV Length in bytes */
#define IVlen 12


/* Hash subkey */
static unsigned char H[Block] = {0};

/* J0 = IV || 0^31 ||1 */
static unsigned char J0[Block] = {0};

/* CB Block used in the CTR */
static unsigned char CB[Block] = {0};

/* OUTPUT of the GHASH function */
static unsigned char OUTPUT[Block] = {0};

/* R used for the multiplication in GF(2^128) */
/* R = 11100001 || 0^120 */
static unsigned char R[Block] = {0xe1};

/* Z "zero" variable used in the multiplication function */
static unsigned char Z[Block] = {0};

/* V used inside the GCTR function */
static unsigned char V[Block] = {0};

/* 16 byte array of the concatenation of len(A) and len(C) */
static unsigned char len_concat[Block] = {0};

/* Hold and shift the values of len(A) */
static unsigned int len_ad_bits;
static unsigned char len_a[Block/2] = {0};

/* Hold and shift the values of len(C) */
static unsigned int len_c_bits;
static unsigned char len_c[Block/2] = {0};

/* 32 bit variable to hold the increments modulus 32 bits */
static unsigned long increment;

  // ************************************************************************ //
 // Private functions                                                        //
// ************************************************************************ //

/* Prints the array blocks */
// static void PrintVector(unsigned char *myArray, unsigned char arraySize) {		
	
// 	unsigned char i;

// 	for(i = 0; i < arraySize; i++) 
// 	{
// 		printf("%#X ", myArray[i]);
// 	}

// 	printf("%s\n", "");
// }

/* Hash subkey is created. H = E(K, 0^128) */
static void InitialHashSubkey (unsigned char *ENC, const unsigned char *k) {
	memset(ENC, 0, Block);	// H variable is set to 0
	aes128e(ENC, ENC, k);	// H (all zeros) is encrypted with the Key
}

/* J0 is defined. len(IV)=96, then let J0 = IV || 0^31 || 1 */
static void J0Definition (unsigned char *J0, const unsigned char *IV) {
	
	memcpy(J0, IV, IVlen);		// IV is copied to J0
	increment = 1;				// increment variable set to 1
	J0[Block - 1] = increment;	// increment is added to the end of J0
}

/*  Byte block is incremented by 1. Incrementing Function incs(X)=MSBlen(X)-s(X) || [int(LSBs(X))+1 mod 2s]s Fixed to 32 */
static void IncrementingFunction(unsigned char *INC) {

	increment += 1;										// Array received is increased by 1

	for (int i = 0; i < 4; ++i)
	{
		INC[Block - 1 - i] = increment >> 8 * i & 0xFF;	// increment value is pushed to the last 4 bytes of the INC array (J0)	
	}
	//PrintVector(INC, 16);
}

/* The bit representation of position value is returned */
static char BIT(unsigned char value) {	
	switch (value)
	{
		case 7:
			value = 0x80;
			break;
		case 6:
			value = 0x40;
			break;
		case 5:
			value = 0x20;
			break;
		case 4:
			value = 0x10;
			break;
		case 3:
			value = 0x08;
			break;
		case 2:
			value = 0x04;
			break;
		case 1:
			value = 0x02;
			break;
		case 0:
			value = 0x01;
			break;
	}
	return value;
}

/* Byte block received is shifted to the right */
static void ShiftRight(unsigned char *SHFT) {

	unsigned char prevcarry = 0x00;			// Carry of the previous position
	unsigned char currcarry = 0x00;			// Carry of the current position

	for (int i = 0; i < Block; i++)			// From 0 to 15 to iterate through the whole 16 bytes
	{
		prevcarry = currcarry;				// Previous carry is equal to the new carry

		if (SHFT[i] & 0x01)					// If the LSB of the byte is 1, we carry
			currcarry = 0x80;
		else
			currcarry = 0x00;				// Else the carry is 0

		SHFT[i] >>= 0x01;					// We shift the byte to the right by 1 position
		SHFT[i] += prevcarry;				// And we add the previous carry to the byte
	}

	/*
	printf("%s\n", "Shift: ");
	PrintVector(V, Block);*/
}

/* Byte blocks received are XORed */
static void xor_block(unsigned char *ZBLOCK, unsigned char *VBLOCK) {
	for (int i = 0; i < Block; i++)
	{
		ZBLOCK[i] = ZBLOCK[i] ^ VBLOCK[i];				// Every byte of the array is XORed
	}
}

/* GCTR function computed with the key K */
static void GCTR (unsigned char *C, const unsigned char *J0, const unsigned char *plaintext, const unsigned char *k, const unsigned long len_p) {

	unsigned char tempCB[Block] = {0};	// Used to save the last state of CB

	memcpy(CB, J0, Block);

	for (unsigned long i = 0; i < len_p; i++)		// Index i used to iterate from 0 to len_p and later access values with index j 
	{
		 
		aes128e(tempCB, CB, k);			// CIPHK(CBi)
		
		/*printf("%s\n", "CB Encrypted value:");
		PrintVector(tempCB, Block);*/

		for (int j = 0; j < Block; j++)	// Along with index i, we access the values of the plaintext up to the len_p
		{
		 	C[(i * Block) + j] = plaintext[(i * Block) + j] ^ tempCB[j];	// Yi = Xi XOR CIPHK(CBi)
		} 
		IncrementingFunction(CB);	// For i = 2 to n, let CBi = inc32(CBi-1)
	}	
}

/* Multiplication in GF(2^128) */
static void GFMult128 (unsigned char *Z, const unsigned char *X, const unsigned char *YBLOCK) {
	
	memset(Z, 0, Block);
	memcpy(V, YBLOCK, Block);

	for (int i = 0; i < Block; i++)						// Iterate through the whole 128 bits on the array (16 bytes)
	{
		for (int j = 0; j < Block / 2; j++)				// From i = 0 to 16 and j = 0 to 8
		{	
			if (X[i] & BIT(7 - j))						
			{											// Obtain the bit i from X, if it's different than 0
				xor_block(Z, V);						// Z and V are XORed
			}
			
			if (V[15] & 0x01)							// Test the LSB of V, if is 1
			{
				ShiftRight(V);							// The block is shifted to the right
				V[0] ^= R[0];							// V is XORed with the R constant previously defined R = 11100001 || 0^120
			}
			else
			{
				ShiftRight(V);					// Shift V withouth XORing
			}
		}
	}
}

/* Creation of the block concatenating A, C, len(A), len(C) */
static void ByteConcatenation (unsigned char *concat, const unsigned char *A, const unsigned char *C, int len_ad, int len_p, int len_total) {

	memset(len_c, 0, 8);					// len_c is set to 0
	memset(len_a, 0, 8);					// len_a is set to 0
	memset(concat, 0, len_total);			// concat is set to 0

	len_c_bits = len_p * 8 * Block;			// Bit len of C in Dec	(stored in an int)
	len_ad_bits = len_ad * 8 * Block;		// Bit len of AD in Dec (stored in an int)

	for (int i = 0; i < len_ad; i++)
	{
		len_a[i] = (len_ad_bits >> 8 * i) & 0xFF;	// Len in hex is shifted to the right and ANDed with 0xFF to get the value
	}

	for (int i = 0; i < len_p; i++)
	{
		len_c[i] = ( len_c_bits >> 8 * i) & 0xFF;	// Len in hex is shifted to the right and ANDed with 0xFF to get the value
	}

	for (int i = (Block - 1); i > -1; i--)			// Iterate from 15 to 0 to store the two 8 bytes arrays with the lenght
	{
		if (i > 7)									
		{
			len_concat[i] = len_c[7 - i % 8];		// Starting from right to left, first the ciphertext is added
		}
		else 										
		{
			len_concat[i] = len_a[7 - i % 8];		// Then the AAD length is added
		}
	}

	//PrintVector(len_concat, 16);

	for (int i = 0; i < len_total; i++)				// Once the concatenation of the lenght is shifted and stored, we can compute the final concatenation
	{
		if (i < len_ad * Block)
		{
			concat[i] = A[i % (len_ad * Block)];	// A is added to the concat array
		}
		else if (i >= len_ad * Block && i < (len_ad * Block) + (len_p * Block))
		{																			// Then C is added to the concat array, From 0 to 31
			concat[i] = C[(i - len_ad * Block) % (len_p * Block)];					// The index for accessing concat is reset to 0
		}																			// i - len_ad in bits modulo len_p in bits
		else
		{
			concat[i] = len_concat[i % Block];		// Finally we add the concatenation of len(A) and len(C)
		}
	}
	
	//printf("%s\n", "Concatenation: ");
	//PrintVector(concat, len_total);
}

/* GHASH function computed using H and X */
static void GHASH (unsigned char *OUT, const unsigned char *H, const unsigned char *X, const unsigned int len_total) {

	// GHASH Variables
	unsigned char Y[Block] = {0};
	unsigned char tempX[Block] = {0};

	for (unsigned long i = 0; i < (len_total / Block); i++)		// For the total length of the concatenation (bits / 16)
	{
		for (int j = 0; j < Block; j++)					// From 0 to size of Block in bytes (16)
		{
			tempX[j] = X[(i * Block) + j];				// Get the block from X and add it to tempX
		}
		
		xor_block(Y, tempX);							// XOR current block (tempX) with Y (initially is all zeroes)
		/*printf("After XORing: \n");
		PrintVector(Y, Block);*/
		
		GFMult128(Z, H, Y);								// Multiply H and Y in GF 2^128, Z is a zero array
		/*printf("After Multiplicating GF 2^128: \n");
		PrintVector(Z, Block);*/

		memcpy(Y, Z, Block);							// The result of the multiplication is copied to Y
	}
	memcpy(OUT, Y, Block);								// Finally the Y block is copied to OUT variable
}

/* Under the 16-byte (128-bit) key "k", 
and the 12-byte (96-bit) initial value "IV", 
encrypt the plaintext "plaintext" and store it at "ciphertext". 
The length of the plaintext is a multiple of 16-byte (128-bit) given by len_p (e.g., len_p = 2 for a 32-byte plaintext). 
The length of the ciphertext "ciphertext" is len_p*16 bytes. 
The authentication tag is obtained by the 16-byte tag "tag". 
For the authentication an additional data "add_data" can be added. 
The number of blocks for this additional data is "len_ad" (e.g., len_ad = 1 for a 16-byte additional data). 
*/
/* Main GCM-AES 128 function */
void aes128gcm(unsigned char *ciphertext, unsigned char *tag, const unsigned char *k, const unsigned char *IV, const unsigned char *plaintext, const unsigned long len_p, const unsigned char* add_data, const unsigned long len_ad) {
 
 	unsigned int len_total = (len_p * Block) + (len_ad * Block) + Block;	// Total lenght of the concatenation in bytes.
	unsigned char concat[len_total];										// Char array that holds the concatenation to be passed to GHASH

	/*
	// Key
	printf("%s\n", "Key:");
	PrintVector(k, Block);

	// IV
	printf("%s\n", "IV:");
	PrintVector(IV, 12);

	// Plaintext
	printf("%s\n", "Plaintext:");
	PrintVector(plaintext, Block);

	// ADD
	printf("%s\n", "ADD:");
	PrintVector(add_data, len_ad * Block);
	*/

	InitialHashSubkey(H, k);	// H is computed with zero array H and k H = E(K, 0^128)
	J0Definition(J0, IV);		// J0 is defined. len(IV)=96, then let J0 = IV || 0^31 || 1
	IncrementingFunction(J0);	// First we increase J0 before passing to GCTR
	
	GCTR(ciphertext, J0, plaintext, k, len_p);	// GCTR is called to compute all the ciphertext using the plaintext, k and J0
	
	ByteConcatenation(concat, add_data, ciphertext, len_ad, len_p, len_total);	// A, C, len(A) and len(C) are concatenated

	GHASH(OUTPUT, H, concat, len_total);		// GHASH is called using the previous computed concat, H

	J0Definition(J0, IV);			// J0 is redefined because the previous version had increments.
	GCTR(tag, J0, OUTPUT, k, 1);	// GCTR is called to generate the TAG, we pass 1 as the length is always 16 bytes long 
	
	/*printf("TAG: \n");
	PrintVector(tag, Block);*/
}