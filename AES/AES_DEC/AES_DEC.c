#include<assert.h>
#include<stdio.h>
#include<stdlib.h>
#include "Aes_Dec.h"

#define MUL2(a) (a<<1)^(a&0x80?0x1b:0)
#define MUL3(a) MUL2(a)^a
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))         
#define MUL9(a) (MUL8(a))^a
#define MULB(a) (MUL8(a))^(MUL2(a))^a
#define MULD(a) (MUL8(a))^(MUL4(a))^a
#define MULE(a) (MUL8(a))^(MUL4(a))^MUL2(a)
#define RotWord(x) ((x<<8)|(x>>24))
#define SubWord(x)((u32)Sbox[(u8)(x >> 24)] << 24) \
   | ((u32)Sbox[(u8)((x >> 16) & 0xff)] << 16) \
   | ((u32)Sbox[(u8)((x >> 8) & 0xff)] << 8) \
   | ((u32)Sbox[(u8)(x & 0xff)]) \

void AddRoundKey(u8 S[16], u8 RK[16])// AddRoundKey 단계는 state와 Roundkey를 각각 xor시킨다.
{
    S[0] ^= RK[0]; S[1] ^= RK[1];  S[2] ^= RK[2]; S[3] ^= RK[3];
    S[4] ^= RK[4]; S[5] ^= RK[5];  S[6] ^= RK[6]; S[7] ^= RK[7];
    S[8] ^= RK[8]; S[9] ^= RK[9];  S[10] ^= RK[10]; S[11] ^= RK[11];
    S[12] ^= RK[12]; S[13] ^= RK[13];  S[14] ^= RK[14]; S[15] ^= RK[15];
}

//addroundkey는 복호화 연산에서 달라지는 것이 없다.

void SubBytes(u8 S[16])// Sbox를 사용해 값을 치환해준다.
{
    S[0] = Sbox[S[0]];   S[1] = Sbox[S[1]];   S[2] = Sbox[S[2]];   S[3] = Sbox[S[3]];
    S[4] = Sbox[S[4]];   S[5] = Sbox[S[5]];   S[6] = Sbox[S[6]];   S[7] = Sbox[S[7]];
    S[8] = Sbox[S[8]];   S[9] = Sbox[S[9]];   S[10] = Sbox[S[10]];   S[11] = Sbox[S[11]];
    S[12] = Sbox[S[12]];   S[13] = Sbox[S[13]];   S[14] = Sbox[S[14]];   S[15] = Sbox[S[15]];
}

void inv_SubBytes(u8 S[16])
{
    S[0] = inv_Sbox[S[0]]; S[1] = inv_Sbox[S[1]]; S[2] = inv_Sbox[S[2]]; S[3] = inv_Sbox[S[3]];
    S[4] = inv_Sbox[S[4]]; S[5] = inv_Sbox[S[5]]; S[6] = inv_Sbox[S[6]]; S[7] = inv_Sbox[S[7]];
    S[8] = inv_Sbox[S[8]]; S[9] = inv_Sbox[S[9]]; S[10] = inv_Sbox[S[10]]; S[11] = inv_Sbox[S[11]];
    S[12] = inv_Sbox[S[12]]; S[13] = inv_Sbox[S[13]]; S[14] = inv_Sbox[S[14]]; S[15] = inv_Sbox[S[15]];
}

void ShiftRows(u8 S[16])
{
    u8 temp;
    temp = S[1];   S[1] = S[5];   S[5] = S[9];   S[9] = S[13];   S[13] = temp;
    temp = S[2];   S[2] = S[10];   S[10] = temp;   temp = S[6];   S[6] = S[14];   S[14] = temp;
    temp = S[15];   S[15] = S[11];   S[11] = S[7];   S[7] = S[3];   S[3] = temp;
}

void inv_ShiftRows(u8 S[16])
{
    u8 temp;
    temp = S[13];   S[13] = S[9];   S[9] = S[5];    S[5] = S[1];    S[1] = temp;
    temp = S[2];   S[2] = S[10];   S[10] = temp;   temp = S[6];   S[6] = S[14];   S[14] = temp;
    temp = S[3];    S[3] = S[7];    S[7] = S[11];   S[11] = S[15];   S[15] = temp;
}

void MixColumns(u8 S[16])
{
    u8 temp[16];// 연산과정 state를 저장
    int i;
    for (i = 0; i < 16; i += 4)
    {
        temp[i] = MUL2(S[i]) ^ MUL3(S[i + 1]) ^ S[i + 2] ^ S[i + 3];
        temp[i + 1] = S[i] ^ MUL2(S[i + 1]) ^ MUL3(S[i + 2]) ^ S[i + 3];
        temp[i + 2] = S[i] ^ S[i + 1] ^ MUL2(S[i + 2]) ^ MUL3(S[i + 3]);
        temp[i + 3] = MUL3(S[i]) ^ S[i + 1] ^ S[i + 2] ^ MUL2(S[i + 3]);
    }
    S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
    S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
    S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
    S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];
}

void inv_MixColumns(u8 S[16])
{
    u8 temp[16];// 연산과정 state를 저장
    int i;
    for (i = 0; i < 16; i += 4)
    {
        temp[i] = MULE(S[i]) ^ MULB(S[i + 1]) ^ MULD(S[i + 2]) ^ MUL9(S[i + 3]);
        temp[i + 1] = MUL9(S[i]) ^ MULE(S[i + 1]) ^ MULB(S[i + 2]) ^ MULD(S[i + 3]);
        temp[i + 2] = MULD(S[i]) ^ MUL9(S[i + 1]) ^ MULE(S[i + 2]) ^ MULB(S[i + 3]);
        temp[i + 3] = MULB(S[i]) ^ MULD(S[i + 1]) ^ MUL9(S[i + 2]) ^ MULE(S[i + 3]);
    }
    S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
    S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
    S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
    S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];

    /*0E 0B 0D 09
    09 0E 0B 0D
    0D 09 0E 0B
    0B 0D 09 0E*/
}

AES_ENC(u8 PT[16], u8 RK[16], u8 CT[16], int keysize)//암호화
{
    int Nr = keysize / 32 + 6;//몇라운드인지 계산
    int i;
    u8 temp[16];//각라운드 평문

    for (i = 0; i < 16; i++)temp[i] = PT[i];//평문 담기
    AddRoundKey(temp, RK);//0라운드 addRoundkey 단계
    for (i = 0; i < Nr - 1; i++)// AES 라운드마다 계산
    {
        SubBytes(temp);
        ShiftRows(temp);
        MixColumns(temp);
        AddRoundKey(temp, RK + 16 * (i + 1));
    }
    SubBytes(temp);
    ShiftRows(temp);
    AddRoundKey(temp, RK + 16 * (i + 1));
    for (i = 0; i < 16; i++)CT[i] = temp[i];
}

AES_DEC(u8 CT[16], u8 RK[16], u8 DPT[16], int keysize)//복호화
{
    int Nr = keysize / 32 + 6;//몇라운드인지 계산
    int i;
    u8 temp[16];//각라운드 평문

    for (i = 0; i < 16; i++)temp[i] = CT[i];//암호문 담기
    AddRoundKey(temp, RK + 16 * Nr);//0라운드 addRoundkey 단계
    for (i = Nr - 1; i > 0; i--)// AES 라운드마다 계산
    {
        inv_ShiftRows(temp);
        inv_SubBytes(temp);
        AddRoundKey(temp, RK + 16 * i);
        inv_MixColumns(temp);
    }
    inv_ShiftRows(temp);
    inv_SubBytes(temp);
    AddRoundKey(temp, RK);
    for (i = 0; i < 16; i++)DPT[i] = temp[i];
}

u32 u4byte_in(u8* x)// 마스터키를  4바이트씩 워드로 묶어준다
{
    return ((x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]);
}
void u4byte_out(u8* x, u32 y)
{
    x[0] = (y >> 24) & 0xff;
    x[1] = (y >> 16) & 0xff;
    x[2] = (y >> 8) & 0xff;
    x[3] = y & 0xff;
}
void AES_KeyWordToByte(u32 W[], u8 RK[]) { //4 바이트씩 묶인 wordfm
    int i;
    for (i = 0; i < 44; i++)
    {
        u4byte_out(RK + 4 * i, W[i]);
    }
}

u32 Rcons[20] = { 0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000 };

void RoundkeyGeneration128(u8 MK[], u8 RK[])
{
    u32 W[44];// 마스터키의 4바이트를 word로 저장
    int i;
    u32 T;

    W[0] = u4byte_in(MK);
    W[1] = u4byte_in(MK + 4);
    W[2] = u4byte_in(MK + 8);
    W[3] = u4byte_in(MK + 12);

    for (i = 0; i < 10; i++)
    {
        T = W[4 * i + 3];
        T = RotWord(T);
        T = SubWord(T);
        T ^= Rcons[i];

        W[4 * i + 4] = W[4 * i] ^ T;
        W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
        W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
        W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
    }

    AES_KeyWordToByte(W, RK);
}
void AES_keySchedule(u8 MK[], u8 RK[], int keysize)
{
    if (keysize == 128)RoundkeyGeneration128(MK, RK);
}


int main()
{
    u8 PT[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };//평문
    u8 MK[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c }; //마스터키
    u8 CT[16] = { 0x00 };//암호문
    u8 RK[240] = { 0x00 };//라운드키
    u8 DPT[16] = { 0x00 }; //복호화한 평문
    int keysize = 128;//키사이즈
    AES_keySchedule(MK, RK, keysize);//키스케줄   
    AES_ENC(PT, RK, CT, keysize);//암호화
    for (int i = 0; i < 16; i++)printf("%02x ", PT[i]);
    printf("\n");
    for (int i = 0; i < 16; i++)printf("%02x ", CT[i]);

    /*
    AES_DEC(CT, RK, DPT, keysize);//복호화
    for (int i = 0; i < 16; i++)printf("%02x ", DPT[i]);
    printf("\n");

    */
}