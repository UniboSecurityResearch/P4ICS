#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/field_lists.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sstream>

#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <ios>
#include <iomanip>

#include <bits/stdc++.h>

using namespace std;

// ------------- start defines for sha
#define int int64_t // 64-bit integer
// Using 64-bit integers, to avoid overflow, during additions
// But, in the end, we have to take modulo of each number with 2^32, making all numbers having MSB<=31

// Global Variables
int modulo=pow(2,32);

std::string sha256_hash_1024_internal(bm::Data & b, bm::Data & c, bm::Data & d, std::string e);

// ------------- end defines for sha

const long max_size_content = 256; //in byte

// The number of columns comprising a state in AES. This is a parameter
// that could be 4, 6, or 8.  For this example we set it to 4.
#define Nb 4

// The number of rounds in AES Cipher. It is initialized to zero. 
// The actual value is computed from the input.
int Nr=0;

// The number of 32 bit words in the key. It is initialized to zero. 
// The actual value is computed from the input.
int Nk=0;

// in - the array that holds the plain text to be encrypted.
// out - the array that holds the cipher text.
// state - the array that holds the intermediate results during encryption.
unsigned char in[2048], out[2048], state[4][Nb];

// The array that stores the round keys.
unsigned char RoundKey[240];

// The Key input to the AES Program
unsigned char Key[32];

int getSBoxValue(int num) {
   int sbox[256] = {
      // 0     1     2     3     4     5     6     7
      // 8     9     A     B     C     D     E     F
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 
      0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 
      0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 
      0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 
      0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 
      0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 
      0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 
      0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 
      0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 
      0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 
      0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F
   return sbox[num];
}

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the 
// field GF(28).  Note that i starts at 1, not 0).
int Rcon[255] = {
         0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
   0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 
   0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
   0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 
   0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
   0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 
   0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
   0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 
   0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
   0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 
   0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
   0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 
   0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 
   0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 
   0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 
   0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 
   0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 
   0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 
   0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 
   0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 
   0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 
   0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 
   0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 
   0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 
   0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 
   0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 
   0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 
   0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 
   0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 
   0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 
   0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 
   0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };

int getSBoxInvert(int num) {
   int rsbox[256] = { 
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 
      0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 
      0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 
      0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 
      0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
      0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 
      0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 
      0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 
      0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
      0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 
      0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 
      0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 
      0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 
      0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 
      0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 
      0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 
      0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
      0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 
      0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 
      0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
   return rsbox[num];
}

// This function produces Nb(Nr+1) round keys. The round keys are used in 
// each round to encrypt the states. 
void KeyExpansion() {
   int i,j;
   unsigned char temp[4],k;
	
   // The first round key is the key itself.
   for (i=0 ; i < Nk ; i++) {
      RoundKey[i*4] = Key[i*4];
      RoundKey[i*4+1] = Key[i*4+1];
      RoundKey[i*4+2] = Key[i*4+2];
      RoundKey[i*4+3] = Key[i*4+3];
   }

   // All other round keys are found from the previous round keys.
   while (i < (Nb * (Nr+1))) {
      for (j=0 ; j < 4 ; j++) {
	 temp[j] = RoundKey[(i-1) * 4 + j];
      }
      if (i % Nk == 0) {
	 // This function rotates the 4 bytes in a word to the left once.
	 // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
	 
	 // Function RotWord()
	 k = temp[0];
	 temp[0] = temp[1];
	 temp[1] = temp[2];
	 temp[2] = temp[3];
	 temp[3] = k;
	 
	 // SubWord() is a function that takes a four-byte input word and 
	 // applies the S-box to each of the four bytes to produce an output
         // word.
	 
	 // Function Subword()
	 temp[0] = getSBoxValue(temp[0]);
	 temp[1] = getSBoxValue(temp[1]);
	 temp[2] = getSBoxValue(temp[2]);
	 temp[3] = getSBoxValue(temp[3]);

	 temp[0] =  temp[0] ^ Rcon[i/Nk];
      } else if (Nk > 6 && i % Nk == 4) {
	 // Function Subword()
	 temp[0] = getSBoxValue(temp[0]);
	 temp[1] = getSBoxValue(temp[1]);
	 temp[2] = getSBoxValue(temp[2]);
	 temp[3] = getSBoxValue(temp[3]);
      }
      RoundKey[i*4+0] = RoundKey[(i-Nk)*4+0] ^ temp[0];
      RoundKey[i*4+1] = RoundKey[(i-Nk)*4+1] ^ temp[1];
      RoundKey[i*4+2] = RoundKey[(i-Nk)*4+2] ^ temp[2];
      RoundKey[i*4+3] = RoundKey[(i-Nk)*4+3] ^ temp[3];
      i++;
   }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(int round) {
   int i,j;
   for (i=0 ; i < Nb ; i++) {
      for (j=0 ; j < 4 ; j++) {
	 state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
      }
   }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void SubBytes() {
   int i,j;
   for (i=0 ; i < 4 ; i++) {
      for (j=0 ; j < Nb ; j++) {
	 state[i][j] = getSBoxValue(state[i][j]);
      }
   }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows() {
   unsigned char temp;

   // Rotate first row 1 columns to left	
   temp = state[1][0];
   state[1][0] = state[1][1];
   state[1][1] = state[1][2];
   state[1][2] = state[1][3];
   state[1][3] = temp;

   // Rotate second row 2 columns to left	
   temp = state[2][0];
   state[2][0] = state[2][2];
   state[2][2] = temp;

   temp = state[2][1];
   state[2][1] = state[2][3];
   state[2][3] = temp;

   // Rotate third row 3 columns to left
   temp = state[3][0];
   state[3][0] = state[3][3];
   state[3][3] = state[3][2];
   state[3][2] = state[3][1];
   state[3][1] = temp;
}

// xtime is a macro that finds the product of {02} and the argument to
// xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

// MixColumns function mixes the columns of the state matrix
void MixColumns() {
   int i;
   unsigned char Tmp,Tm,t;
   for (i=0 ; i < Nb ; i++) {	
      t = state[0][i];
      Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ;
      Tm = state[0][i] ^ state[1][i] ; 
      Tm = xtime(Tm); 
      state[0][i] ^= Tm ^ Tmp ;
      
      Tm = state[1][i] ^ state[2][i] ; 
      Tm = xtime(Tm); 
      state[1][i] ^= Tm ^ Tmp ;

      Tm = state[2][i] ^ state[3][i] ; 
      Tm = xtime(Tm); 
      state[2][i] ^= Tm ^ Tmp ;

      Tm = state[3][i] ^ t ; 
      Tm = xtime(Tm); 
      state[3][i] ^= Tm ^ Tmp ;
   }
}

// Cipher is the main function that encrypts the PlainText.
void Cipher() {
   int i,j,round=0;

   //Copy the input PlainText to state array.
   for (i=0 ; i < Nb ; i++) {
      for (j=0 ; j < 4 ; j++) {
	 state[j][i] = in[i*4 + j];
      }
   }

   // Add the First round key to the state before starting the rounds.
   AddRoundKey(0); 
	
   // There will be Nr rounds.
   // The first Nr-1 rounds are identical.
   // These Nr-1 rounds are executed in the loop below.
   for (round=1 ; round < Nr ; round++) {
      SubBytes();
      ShiftRows();
      MixColumns();
      AddRoundKey(round);
   }
	
   // The last round is given below.
   // The MixColumns function is not here in the last round.
   SubBytes();
   ShiftRows();
   AddRoundKey(Nr);
   
   // The encryption process is over.
   // Copy the state array to output array.
   for (i=0 ; i < Nb ; i++) {
      for (j=0 ; j < 4 ; j++) {
	 out[i*4+j]=state[j][i];
      }
   }
}

int fillBlock (int sz, char *str, unsigned char *in, long inputLength) {
   int j=0;
   while (sz < inputLength) {
      if (j >= Nb*4) break;
      in[j++] = (unsigned char)str[sz];
      sz++;
   }
   // Pad the block with 0s, if necessary
   if (sz >= inputLength) for ( ; j < Nb*4 ; j++) in[j] = 0;
   return sz;   
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void InvSubBytes() {
   int i,j;
   for (i=0 ; i < 4 ; i++) {
      for (j=0 ; j < Nb ; j++) {
	 state[i][j] = getSBoxInvert(state[i][j]);
      }
   }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void InvShiftRows() {
   unsigned char temp;

   // Rotate first row 1 columns to right	
   temp = state[1][3];
   state[1][3] = state[1][2];
   state[1][2] = state[1][1];
   state[1][1] = state[1][0];
   state[1][0] = temp;

   // Rotate second row 2 columns to right	
   temp = state[2][0];
   state[2][0] = state[2][2];
   state[2][2] = temp;
   
   temp = state[2][1];
   state[2][1] = state[2][3];
   state[2][3] = temp;

   // Rotate third row 3 columns to right
   temp = state[3][0];
   state[3][0] = state[3][1];
   state[3][1] = state[3][2];
   state[3][2] = state[3][3];
   state[3][3] = temp;
}

// xtime is a macro that finds the product of {02} and the argument to
// xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

// Multiplty is a macro used to multiply numbers in the field GF(2^8)
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the
// inexperienced.  Please use the references to gain more information.
void InvMixColumns() {
   int i;
   unsigned char a,b,c,d;
   for (i=0 ; i < Nb ; i++) {	
	
      a = state[0][i];
      b = state[1][i];
      c = state[2][i];
      d = state[3][i];
		
      state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ 
	 Multiply(c, 0x0d) ^ Multiply(d, 0x09);
      state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ 
	 Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
      state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ 
	 Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
      state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ 
	 Multiply(c, 0x09) ^ Multiply(d, 0x0e);
   }
}

// InvCipher is the main function that decrypts the CipherText.
void InvCipher() {
   int i,j,round=0;

   //Copy the input CipherText to state array.
   for (i=0 ; i < Nb ; i++) {
      for (j=0 ; j < 4 ; j++) {
	 state[j][i] = in[i*4 + j];
      }
   }

   // Add the First round key to the state before starting the rounds.
   AddRoundKey(Nr); 

   // There will be Nr rounds.
   // The first Nr-1 rounds are identical.
   // These Nr-1 rounds are executed in the loop below.
   for (round=Nr-1 ; round > 0 ; round--) {
      InvShiftRows();
      InvSubBytes();
      AddRoundKey(round);
      InvMixColumns();
   }
	
   // The last round is given below.
   // The MixColumns function is not here in the last round.
   InvShiftRows();
   InvSubBytes();
   AddRoundKey(0);

   // The decryption process is over.
   // Copy the state array to output array.
   for(i=0 ; i < Nb ; i++) {
      for(j=0 ; j < 4 ; j++) {
	 out[i*4+j] = state[j][i];
      }
   }
}


long get_crypt_payload_length(long content_length) {
    return ((content_length / 16) + 1) * 16;
}
long get_shift_size(long crypt_payload_length) {
    return max_size_content - crypt_payload_length; //in byte
}


void Decrypt(bm::Data & a, bm::Data & b, bm::Data & k1, bm::Data & k2, bm::Data & k3, bm::Data & k4, bm::Data & k5, bm::Data & k6, bm::Data & k7, bm::Data & k8, bm::Data & len, bm::Data & sha, bm::Data & seqNo, bm::Data & shaCalculated) {
	int i;
    if(k4.get_string() == "0") //128 bit encryption key
        Nk = 4;
    else if(k6.get_string() == "0") //192 bit encryption key
        Nk = 6;
    else Nk = 8; //256 bit encryption key


	// Calculate Nr from Nk and, implicitly, from Nb
	Nr = Nk + 6;

	// The key values are read here
    Key[0] = (k1.get_uint64() & 0xff000000UL) >> 24;
    Key[1] = (k1.get_uint64() & 0x00ff0000UL) >> 16;
    Key[2] = (k1.get_uint64() & 0x0000ff00UL) >>  8;
    Key[3] = (k1.get_uint64() & 0x000000ffUL)      ;

    Key[4] = (k2.get_uint64() & 0xff000000UL) >> 24;
    Key[5] = (k2.get_uint64() & 0x00ff0000UL) >> 16;
    Key[6] = (k2.get_uint64() & 0x0000ff00UL) >>  8;
    Key[7] = (k2.get_uint64() & 0x000000ffUL)      ;

    Key[8] = (k3.get_uint64() & 0xff000000UL) >> 24;
    Key[9] = (k3.get_uint64() & 0x00ff0000UL) >> 16;
    Key[10] = (k3.get_uint64() & 0x0000ff00UL) >>  8;
    Key[11] = (k3.get_uint64() & 0x000000ffUL)      ;

    Key[12] = (k4.get_uint64() & 0xff000000UL) >> 24;
    Key[13] = (k4.get_uint64() & 0x00ff0000UL) >> 16;
    Key[14] = (k4.get_uint64() & 0x0000ff00UL) >>  8;
    Key[15] = (k4.get_uint64() & 0x000000ffUL)      ;

    if(Nk == 6 || Nk == 8){
        Key[16] = (k5.get_uint64() & 0xff000000UL) >> 24;
        Key[17] = (k5.get_uint64() & 0x00ff0000UL) >> 16;
        Key[18] = (k5.get_uint64() & 0x0000ff00UL) >> 8;
        Key[19] = (k5.get_uint64() & 0x000000ffUL);

        Key[20] = (k6.get_uint64() & 0xff000000UL) >> 24;
        Key[21] = (k6.get_uint64() & 0x00ff0000UL) >> 16;
        Key[22] = (k6.get_uint64() & 0x0000ff00UL) >> 8;
        Key[23] = (k6.get_uint64() & 0x000000ffUL);
    }
    
    if(Nk == 8){
        Key[24] = (k7.get_uint64() & 0xff000000UL) >> 24;
        Key[25] = (k7.get_uint64() & 0x00ff0000UL) >> 16;
        Key[26] = (k7.get_uint64() & 0x0000ff00UL) >> 8;
        Key[27] = (k7.get_uint64() & 0x000000ffUL);

        Key[28] = (k8.get_uint64() & 0xff000000UL) >> 24;
        Key[29] = (k8.get_uint64() & 0x00ff0000UL) >> 16;
        Key[30] = (k8.get_uint64() & 0x0000ff00UL) >> 8;
        Key[31] = (k8.get_uint64() & 0x000000ffUL);
    }
  
	// The KeyExpansion routine is called before encryption.
	KeyExpansion();

	long totalLength = len.get_uint64();
	string input = a.get_string();
	char str[input.length()+1];

    long crypt_payload_length = get_crypt_payload_length(totalLength);
    long shift_size = get_shift_size(crypt_payload_length);

	// Copy the input string to str
    long initialPadding = crypt_payload_length - input.length();

    for (i=0; i < initialPadding; i++) {
        str[i] = 0x00;
    }
    for (i=initialPadding; i < crypt_payload_length; i++) {
        str[i] = input[i-initialPadding];
    }
    str[crypt_payload_length] = '\0';

    string result;

    int nBlocks = ((totalLength / 16) + 1);

    int bytesNotInserted;

    for(int block = 0; block < nBlocks; block++) {
        int number;
        for (int j=0 ; j < Nb*4 ; j++){
            i = j + block * 16;
            if((int)str[i] < 0)
                number = (int)str[i] + 256;
            else
                number = (int)str[i];
            in[j] = (unsigned char)number;
        }

        // The block is decrypted here - the result is in the array 'out'
        InvCipher();

        bool isLastBlock = block == (nBlocks - 1);

        int bytesInBlock = isLastBlock ? totalLength % (Nb*4) : Nb*4;

        bytesNotInserted = (Nb*4) - bytesInBlock;

        for (i=0; i < bytesInBlock; i++) {
            char s[3];
            sprintf(s, "%02x", out[i]);
            result += s;
        }
    }

    string shaCalculatedString = sha256_hash_1024_internal(k1, k2, seqNo, result);

    for(int i = 0; i < shift_size + bytesNotInserted; i++) {
        char s[9];
        sprintf(s, "%02x", '\0');
        result += s;
    }

    shaCalculated.set(shaCalculatedString);
    b.set(result);
}

void verify_hash_equals(bm::Data & equals, bm::Data & hash1, bm::Data & hash2) {
    string hash1String = hash1.get_string();
    string hash2String = hash2.get_string();
    unsigned char shaSavedChar1[32+1];
    unsigned char shaSavedChar2[32+1];
    bool areEquals = true;

    for(int i = 0; i < 32; i++) {
        shaSavedChar1[i] = hash1String[i];
    }
    for(int i = 0; i < 32; i++) {
        shaSavedChar2[i] = hash2String[i];
    }
    for(int i = 0; i < 32; i++) {
        areEquals &= shaSavedChar1[i] == shaSavedChar2[i];
    }
    if(areEquals) {
        printf("\n\nEQUALS\n\n");
    } else {
        printf("\n\nNOT EQUALS\n\n");
    }
    equals.set(areEquals);
}

void Encrypt(bm::Data & a, bm::Data & b, bm::Data & k1, bm::Data & k2, bm::Data & k3, bm::Data & k4, bm::Data & k5, bm::Data & k6, bm::Data & k7, bm::Data & k8, bm::Data & len) {
	int i;
    if(k4.get_string() == "0") //128 bit encryption key
        Nk = 4;
    else if(k6.get_string() == "0") //192 bit encryption key
        Nk = 6;
    else Nk = 8; //256 bit encryption key


	// Calculate Nr from Nk and, implicitly, from Nb
	Nr = Nk + 6;

	// The key values are read here
    Key[0] = (k1.get_uint64() & 0xff000000UL) >> 24;
    Key[1] = (k1.get_uint64() & 0x00ff0000UL) >> 16;
    Key[2] = (k1.get_uint64() & 0x0000ff00UL) >>  8;
    Key[3] = (k1.get_uint64() & 0x000000ffUL)      ;

    Key[4] = (k2.get_uint64() & 0xff000000UL) >> 24;
    Key[5] = (k2.get_uint64() & 0x00ff0000UL) >> 16;
    Key[6] = (k2.get_uint64() & 0x0000ff00UL) >>  8;
    Key[7] = (k2.get_uint64() & 0x000000ffUL)      ;

    Key[8] = (k3.get_uint64() & 0xff000000UL) >> 24;
    Key[9] = (k3.get_uint64() & 0x00ff0000UL) >> 16;
    Key[10] = (k3.get_uint64() & 0x0000ff00UL) >>  8;
    Key[11] = (k3.get_uint64() & 0x000000ffUL)      ;

    Key[12] = (k4.get_uint64() & 0xff000000UL) >> 24;
    Key[13] = (k4.get_uint64() & 0x00ff0000UL) >> 16;
    Key[14] = (k4.get_uint64() & 0x0000ff00UL) >>  8;
    Key[15] = (k4.get_uint64() & 0x000000ffUL)      ;

    if(Nk == 6 || Nk == 8){
        Key[16] = (k5.get_uint64() & 0xff000000UL) >> 24;
        Key[17] = (k5.get_uint64() & 0x00ff0000UL) >> 16;
        Key[18] = (k5.get_uint64() & 0x0000ff00UL) >> 8;
        Key[19] = (k5.get_uint64() & 0x000000ffUL);

        Key[20] = (k6.get_uint64() & 0xff000000UL) >> 24;
        Key[21] = (k6.get_uint64() & 0x00ff0000UL) >> 16;
        Key[22] = (k6.get_uint64() & 0x0000ff00UL) >> 8;
        Key[23] = (k6.get_uint64() & 0x000000ffUL);
    }
    
    if(Nk == 8){
        Key[24] = (k7.get_uint64() & 0xff000000UL) >> 24;
        Key[25] = (k7.get_uint64() & 0x00ff0000UL) >> 16;
        Key[26] = (k7.get_uint64() & 0x0000ff00UL) >> 8;
        Key[27] = (k7.get_uint64() & 0x000000ffUL);

        Key[28] = (k8.get_uint64() & 0xff000000UL) >> 24;
        Key[29] = (k8.get_uint64() & 0x00ff0000UL) >> 16;
        Key[30] = (k8.get_uint64() & 0x0000ff00UL) >> 8;
        Key[31] = (k8.get_uint64() & 0x000000ffUL);
    }


    // Get the input string
	string input = a.get_string();
	long totalLength = len.get_uint64();

	char str[totalLength+1];

	long inputLength = totalLength;

	// Copy the input string to str
	long initialPadding = totalLength - input.length();

	long crypt_payload_length = get_crypt_payload_length(totalLength);
    long shift_size = get_shift_size(crypt_payload_length);

	for (i=0; i < initialPadding; i++) {
        str[i] = 0x00;
    }

	for (i=initialPadding; i < totalLength; i++) {
	    str[i] = input[i-initialPadding];
	}
	str[totalLength] = '\0';

	// The KeyExpansion routine is called before encryption.
	KeyExpansion();

	string result;
	// sz is the cursor into the input string
	int sz=0;
	// Each iteration encrypts one block = Nb*4 bytes = 128 bits in this case
	while (sz < inputLength) {
		// Fill the array 'in' with the next plaintext block
		sz = fillBlock (sz, str, in, inputLength);

		// The block is encrypted here - the result is in the array 'out'
		Cipher();
		// Output the encrypted block.
		for (int i = 0; i < Nb*4; i++) {
			char s[9];
			sprintf(s, "%02x", out[i]);
			result += s;
		}
	}

    for(int i = 0; i < shift_size; i++) {
        char s[9];
        sprintf(s, "%02x", '\0');
        result += s;
    }
	b.set(result);
}


// -------------------------------------------------
// START SHA FUNCTIONS
// -------------------------------------------------

// Function to Rotate Right a 32-bit integer (word), by 'x' bits
int rot_right(int word, int x_bits)
{
    return ((word>>(x_bits)) | (word<<(32-x_bits)));
}

// Function to Compute 'sigma_1(x)'
int sigma1(int x)
{
    return (rot_right(x,17)^(rot_right(x,19))^((x)>>10));
}

// Function to Compute 'sigma_0(x)'
int sigma0(int x)
{
    return (rot_right(x,7)^(rot_right(x,18))^((x)>>3));
}

// Function to Compute 'S0(x)'
int S0(int x)
{
    return (rot_right(x,2)^(rot_right(x,13))^(rot_right(x,22)));
}

// Function to Compute 'S1(x)'
int S1(int x)
{
    return (rot_right(x,6)^(rot_right(x,11))^(rot_right(x,25)));
}

// Function to Compute 'Ch(a,b,c)'
int Ch(int a, int b, int c)
{
    return (a&b)^((~a)&c);
}

// Function to Compute 'Maj(a,b,c)'
int Maj(int a, int b, int c)
{
    return (a&b)^(a&c)^(b&c);
}

// Function to Convert a String, into a String of bits, corresponding to the ASCII Value of Characters in the String
string convert_string_to_bits(string &s)
{
    string ret="";
    for(auto x:s) // Iterate through the whole string 's'
    {
        int ascii_of_x=int(x);
        bitset<8> b(ascii_of_x); // Convert 'ascii_of_x' to a 8-bit binary string, using Bitset
        ret+=b.to_string();
    }
    return ret;
}

// Function to Convert a 32-bit Integer to 'hexadecimal' String
string int_to_hex(int integer)
{
    stringstream ss;
    ss<<hex<<setw(8)<<setfill('0')<<integer;
    string ret;
    ss>>ret;
    return ret;
}

// Function to perform Pre-Processing
void pre_process(string &input_str_in_bits) // Pre-Processing Step of the Algorithm
{
    int l=int(input_str_in_bits.size());
    input_str_in_bits+="1"; // Step '1'
    int k=0;
    while(true) // Finding 'k'
    {
        int curr_length_of_string=int(input_str_in_bits.size());
        int length_of_string_after_appending=k+curr_length_of_string+64;
        if(length_of_string_after_appending%512==0)
        {
            break;
        }
        k++;
    }
    for(int zeroes=0; zeroes<k; zeroes++) // Step '2'
    {
        input_str_in_bits+="0";
    }

    // Step '3'
    bitset<64> b(l);
    input_str_in_bits+=b.to_string(); // Appending 64-bit String (= 'l' in Integer) to the end of Current String
}

// Function to break the string into chunks (blocks) of 512 bits
vector<string> break_into_chunks(string &input_str_in_bits)
{
    vector<string> ret;
    for(int i=0; i<int(input_str_in_bits.size()); i+=512)
    {
        ret.push_back(input_str_in_bits.substr(i,512)); // '1' Chunk Added to the List
    }
    return ret;
}

// Function to Resize/Convert the 512-bit Blocks to '16' 32-bit Integers
vector<int> convert_512bits_to_16integers(string &s)
{
    vector<int> ret;
    for(int i=0; i<int(s.size()); i+=32)
    {
        bitset<32> b(s.substr(i,32)); // Using Bitset to Convert String of Bits, to Integer
        ret.push_back(b.to_ulong());
    }
    for(auto &x:ret) // Take Modulo with 2^32, for every Integer
    {
        x%=modulo;
    }
    return ret;
}

// Functin to Process the Hash Function, for i'th Message Block
void process_hash_function(int i, vector<int> &curr_block, vector<array<int,8>> &H, vector<int> &k)
{
    // Here, i = Current 'Message Block' Number

    // Initialize the 8 Working Variables, using Last Hash Values
    int a=H[i-1][0];
    int b=H[i-1][1];
    int c=H[i-1][2];
    int d=H[i-1][3];
    int e=H[i-1][4];
    int f=H[i-1][5];
    int g=H[i-1][6];
    int h=H[i-1][7];

    // Create a 64-entry Message Schedule Array w[0..63] of 32-bit Integers
    int w[64];

    // Copy the '16' 32-bit Integers of the Current Message Block, to w[0..15]
    for(int j=0; j<16; j++)
    {
        w[j]=curr_block[j];
    }

    // Extend the first 16 words (32-bit Integers) into Remaining 48 [16..63] words, using Sigma Functions
    for(int j=16; j<64; j++)
    {
        w[j]=w[j-16]+sigma0(w[j-15])+sigma1(w[j-2])+w[j-7];
        w[j]%=modulo; // Take Modulo, to avoid overflow
    }

    // Main Hashing Loop
    for(int j=0; j<64; j++)
    {
        int temp1=h+S1(e)+Ch(e,f,g)+k[j]+w[j];
        int temp2=S0(a)+Maj(a,b,c);
        h=g;
        g=f;
        f=e;
        e=d+temp1;
        d=c;
        c=b;
        b=a;
        a=temp1+temp2;

        // Taking Modulo with 2^32
        e%=modulo;
        a%=modulo;
    }

    // Update Current Hash Values
    H[i][0]=H[i-1][0]+a;
    H[i][1]=H[i-1][1]+b;
    H[i][2]=H[i-1][2]+c;
    H[i][3]=H[i-1][3]+d;
    H[i][4]=H[i-1][4]+e;
    H[i][5]=H[i-1][5]+f;
    H[i][6]=H[i-1][6]+g;
    H[i][7]=H[i-1][7]+h;

    // Take Modulo with 2^32, for All Current New Hash Values
    for(int j=0; j<8; j++)
    {
        H[i][j]%=modulo;
    }
}


// Function to Process the Hash Function for all Message Blocks of 512-bit and find the Final Hash Value of the Input Message
string process_hash(vector<vector<int>> &M, vector<array<int,8>> &H, vector<int> &k)
{
    for(int i=1; i<=int(M.size()); i++) // For Each 512-bit Message Block, Process the Hash Function
    {
        process_hash_function(i,M[i-1],H,k);
    }
    string ret="";
    for(int i=0; i<8; i++)
    {
        ret+=int_to_hex(H[int(M.size())][i]);
    }
    return ret;
}



std::string get_hash(std::string s){
    // Convert the Input String to Bits
    string input_str_in_bits=convert_string_to_bits(s);

    // Do Pre-Processing on (input_str_in_bits), in the following manner:
    // 1. Append one '1' bit, to (input_str_in_bits)
    // 2. Append 'k'(>=0) '0' bits to (input_str_in_bits), such that length(input_str_in_bits) becomes
       // exactly divisible by 512 (after completion of each pre-processing sub-step)
    // 3. Append l(length of original message, in terms of bits), as a 64-bit String
    pre_process(input_str_in_bits);

    // Break the Message(input_str_in_bits) into Chunks of 512 Bits
    vector<string> chunks_of_512_bits=break_into_chunks(input_str_in_bits);

    // Convert Each 512-Bits Message Chunk into '16' 32-bit integers
    vector<vector<int>> M;
    for(auto x:chunks_of_512_bits)
    {
        M.push_back(convert_512bits_to_16integers(x));
    }

    int number_of_512bit_chunks=int(M.size());

    // Vector to Store 8 Hash Values after each iteration of every 512-bit Block
    vector<array<int,8>> H(number_of_512bit_chunks+1);

    // Assigning Initial Hash Values
    // Actually, these are:
    // First 32 bits of the fractional parts of the square roots of the first 8 primes (from 2 to 19).
    H[0][0]=0x6a09e667;
    H[0][1]=0xbb67ae85;
    H[0][2]=0x3c6ef372;
    H[0][3]=0xa54ff53a;
    H[0][4]=0x510e527f;
    H[0][5]=0x9b05688c;
    H[0][6]=0x1f83d9ab;
    H[0][7]=0x5be0cd19;

    // 'Array of Round' Constants
    // Actually, these are:
    // First 32 bits of the fractional parts of the cube roots of the first 64 primes (from 2 to 311).
    vector<int> k=
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Process the Hash Function of SHA-256 Algorithm, on each 512-bit block of the message successively
    string res=process_hash(M,H,k);

    return res;
}


void sha256_hash_256(bm::Data & a, bm::Data & b) {
	std::string str;
	std::string result = "";

	str = b.get_string();

	result = get_hash(str);

	a.set(result);
}

void sha256_hash_512(bm::Data & a, bm::Data & b, bm::Data & c) {
    std::string str;
    std::string result = "";

	str = b.get_string();
	str = str + c.get_string();

	result = get_hash(str);

    a.set(result);
}

void sha256_hash_1024(bm::Data & a, bm::Data & b, bm::Data & c, bm::Data & d, bm::Data & e, bm::Data & len) {
    std::string str;
    std::string result = "";

    string input = e.get_string();
    long totalLength = len.get_uint64();

    char payload[totalLength+1];

    long initialPadding = totalLength - input.length();

    for (int i = 0; i < initialPadding; i++) {
        payload[i] = 0x00;
    }

    for (int i = initialPadding; i < totalLength; i++) {
        payload[i] = input[i-initialPadding];
    }
    payload[totalLength] = '\0';

	str = b.get_string();
	str = str + c.get_string();
    str = str + d.get_string();
//	str = str + payload;


	for (int i = 0; i < totalLength; i++) {
        char s[9];
        sprintf(s, "%02x", payload[i]);
        str += s;
    }

    unsigned char calculatedSha[32+1];

	result = get_hash(str);

    a.set(result);
}

std::string sha256_hash_1024_internal(bm::Data & b, bm::Data & c, bm::Data & d, std::string e) {
    std::string str;
    std::string result = "";

	str = b.get_string();
	str = str + c.get_string();
    str = str + d.get_string();
	str = str + e;

	return get_hash(str);
}


BM_REGISTER_EXTERN_FUNCTION(sha256_hash_256, bm::Data &, bm::Data &);
BM_REGISTER_EXTERN_FUNCTION(sha256_hash_512, bm::Data &, bm::Data &, bm::Data &);
BM_REGISTER_EXTERN_FUNCTION(sha256_hash_1024, bm::Data &, bm::Data &, bm::Data &, bm::Data &, bm::Data &, bm::Data &);
BM_REGISTER_EXTERN_FUNCTION(verify_hash_equals, bm::Data &, bm::Data &, bm::Data &);



BM_REGISTER_EXTERN_FUNCTION(Encrypt, bm::Data &, bm::Data &,
    bm::Data &, bm::Data &, bm::Data &, bm::Data &,
    bm::Data &, bm::Data &, bm::Data &, bm::Data &,
    bm::Data &);
BM_REGISTER_EXTERN_FUNCTION(Decrypt, bm::Data &, bm::Data &,
    bm::Data &, bm::Data &, bm::Data &, bm::Data &,
    bm::Data &, bm::Data &, bm::Data &, bm::Data &,
    bm::Data &,
    bm::Data &, bm::Data &, bm::Data &);