#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<time.h>
#include "dec_optim.h"

#define MUL2(a) (a << 1) ^ (a & 0x80 ? 0x1b : 0)
#define MUL3(a) MUL2(a)^a
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a) 
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

u32 u4byte_in(u8* x) {
    return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3];
} // x[0]||x[1]||x[2]||x[3]

void u4byte_out(u8* x, u32 y) {
    x[0] = (y >> 24) & 0xff;
    x[1] = (y >> 16) & 0xff;
    x[2] = (y >> 8) & 0xff;
    x[3] = y & 0xff;
}

void AddRoundKey(u8 S[16], u8 RK[16])// AddRoundKey 단계는 state와 Roundkey를 각각 xor시킨다.
{
    S[0] ^= RK[0]; S[1] ^= RK[1];  S[2] ^= RK[2]; S[3] ^= RK[3];
    S[4] ^= RK[4]; S[5] ^= RK[5];  S[6] ^= RK[6]; S[7] ^= RK[7];
    S[8] ^= RK[8]; S[9] ^= RK[9];  S[10] ^= RK[10]; S[11] ^= RK[11];
    S[12] ^= RK[12]; S[13] ^= RK[13];  S[14] ^= RK[14]; S[15] ^= RK[15];
}//addroundkey는 복호화 연산에서 달라지는 것이 없다.

void inv_SubBytes(u8 S[16])
{
    S[0] = inv_Sbox[S[0]]; S[1] = inv_Sbox[S[1]]; S[2] = inv_Sbox[S[2]]; S[3] = inv_Sbox[S[3]];
    S[4] = inv_Sbox[S[4]]; S[5] = inv_Sbox[S[5]]; S[6] = inv_Sbox[S[6]]; S[7] = inv_Sbox[S[7]];
    S[8] = inv_Sbox[S[8]]; S[9] = inv_Sbox[S[9]]; S[10] = inv_Sbox[S[10]]; S[11] = inv_Sbox[S[11]];
    S[12] = inv_Sbox[S[12]]; S[13] = inv_Sbox[S[13]]; S[14] = inv_Sbox[S[14]]; S[15] = inv_Sbox[S[15]];
}

void inv_ShiftRows(u8 S[16])
{
    u8 temp;
    temp = S[13];   S[13] = S[9];   S[9] = S[5];    S[5] = S[1];    S[1] = temp;
    temp = S[2];   S[2] = S[10];   S[10] = temp;   temp = S[6];   S[6] = S[14];   S[14] = temp;
    temp = S[3];    S[3] = S[7];    S[7] = S[11];   S[11] = S[15];   S[15] = temp;
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

    //  0E 0B 0D 09
    //  09 0E 0B 0D
    //  0D 09 0E 0B
    //  0B 0D 09 0E
}

AES_DEC(u8 CT[16], u8 RK[16], u8 DPT[16], int keysize)//복호화
{
    int Nr = keysize / 32 + 6;//몇라운드인지 계산
    u8 temp[16];//각라운드 평문

    for (int i = 0; i < 16; i++)
        temp[i] = CT[i];//암호문 담기
    AddRoundKey(temp, RK + 16 * Nr);//0라운드 addRoundkey 단계
    for (int i = Nr - 1; i > 0; i--)// AES 라운드마다 계산
    {
        inv_ShiftRows(temp);
        inv_SubBytes(temp);
        AddRoundKey(temp, RK + 16 * i);
        inv_MixColumns(temp);
    }
    inv_ShiftRows(temp);
    inv_SubBytes(temp);
    AddRoundKey(temp, RK);
    for (int i = 0; i < 16; i++)DPT[i] = temp[i];
}


void AES_DEC_Opt(u8 PT[16], u32 W[], u8 CT[16], int keysize) {
    int Nr = keysize / 32 + 6; //라운드 수
    u32 s0, s1, s2, s3, t0, t1, t2, t3;

    s0 = u4byte_in(CT) ^ W[40];
    s1 = u4byte_in(CT + 4) ^ W[41];
    s2 = u4byte_in(CT + 8) ^ W[42];
    s3 = u4byte_in(CT + 12) ^ W[43]; 

    t0 = inv_Te0[s0 >> 24] ^ inv_Te3[s1 & 0xff] ^ inv_Te2[(s2 >> 8) & 0xff] ^ inv_Te1[(s3 >> 16) & 0xff] ^ W[36];
    t1 = inv_Te0[s1 >> 24] ^ inv_Te3[s2 & 0xff] ^ inv_Te2[(s3 >> 8) & 0xff] ^ inv_Te1[(s0 >> 16) & 0xff] ^ W[37];
    t2 = inv_Te0[s2 >> 24] ^ inv_Te3[s3 & 0xff] ^ inv_Te2[(s0 >> 8) & 0xff] ^ inv_Te1[(s1 >> 16) & 0xff] ^ W[38];
    t3 = inv_Te0[s3 >> 24] ^ inv_Te3[s0 & 0xff] ^ inv_Te2[(s1 >> 8) & 0xff] ^ inv_Te1[(s2 >> 16) & 0xff] ^ W[39];

    s0 = inv_Te0[t0 >> 24] ^ inv_Te3[t1 & 0xff] ^ inv_Te2[(t2 >> 8) & 0xff] ^ inv_Te1[(t3 >> 16) & 0xff] ^ W[32];
    s1 = inv_Te0[t1 >> 24] ^ inv_Te3[t2 & 0xff] ^ inv_Te2[(t3 >> 8) & 0xff] ^ inv_Te1[(t0 >> 16) & 0xff] ^ W[33];
    s2 = inv_Te0[t2 >> 24] ^ inv_Te3[t3 & 0xff] ^ inv_Te2[(t0 >> 8) & 0xff] ^ inv_Te1[(t1 >> 16) & 0xff] ^ W[34];
    s3 = inv_Te0[t3 >> 24] ^ inv_Te3[t0 & 0xff] ^ inv_Te2[(t1 >> 8) & 0xff] ^ inv_Te1[(t2 >> 16) & 0xff] ^ W[35];

    t0 = inv_Te0[s0 >> 24] ^ inv_Te3[s1 & 0xff] ^ inv_Te2[(s2 >> 8) & 0xff] ^ inv_Te1[(s3 >> 16) & 0xff] ^ W[28];
    t1 = inv_Te0[s1 >> 24] ^ inv_Te3[s2 & 0xff] ^ inv_Te2[(s3 >> 8) & 0xff] ^ inv_Te1[(s0 >> 16) & 0xff] ^ W[29];
    t2 = inv_Te0[s2 >> 24] ^ inv_Te3[s3 & 0xff] ^ inv_Te2[(s0 >> 8) & 0xff] ^ inv_Te1[(s1 >> 16) & 0xff] ^ W[30];
    t3 = inv_Te0[s3 >> 24] ^ inv_Te3[s0 & 0xff] ^ inv_Te2[(s1 >> 8) & 0xff] ^ inv_Te1[(s2 >> 16) & 0xff] ^ W[31];

    s0 = inv_Te0[t0 >> 24] ^ inv_Te3[t1 & 0xff] ^ inv_Te2[(t2 >> 8) & 0xff] ^ inv_Te1[(t3 >> 16) & 0xff] ^ W[24];
    s1 = inv_Te0[t1 >> 24] ^ inv_Te3[t2 & 0xff] ^ inv_Te2[(t3 >> 8) & 0xff] ^ inv_Te1[(t0 >> 16) & 0xff] ^ W[25];
    s2 = inv_Te0[t2 >> 24] ^ inv_Te3[t3 & 0xff] ^ inv_Te2[(t0 >> 8) & 0xff] ^ inv_Te1[(t1 >> 16) & 0xff] ^ W[26];
    s3 = inv_Te0[t3 >> 24] ^ inv_Te3[t0 & 0xff] ^ inv_Te2[(t1 >> 8) & 0xff] ^ inv_Te1[(t2 >> 16) & 0xff] ^ W[27];

    t0 = inv_Te0[s0 >> 24] ^ inv_Te3[s1 & 0xff] ^ inv_Te2[(s2 >> 8) & 0xff] ^ inv_Te1[(s3 >> 16) & 0xff] ^ W[20];
    t1 = inv_Te0[s1 >> 24] ^ inv_Te3[s2 & 0xff] ^ inv_Te2[(s3 >> 8) & 0xff] ^ inv_Te1[(s0 >> 16) & 0xff] ^ W[21];
    t2 = inv_Te0[s2 >> 24] ^ inv_Te3[s3 & 0xff] ^ inv_Te2[(s0 >> 8) & 0xff] ^ inv_Te1[(s1 >> 16) & 0xff] ^ W[22];
    t3 = inv_Te0[s3 >> 24] ^ inv_Te3[s0 & 0xff] ^ inv_Te2[(s1 >> 8) & 0xff] ^ inv_Te1[(s2 >> 16) & 0xff] ^ W[23];

    s0 = inv_Te0[t0 >> 24] ^ inv_Te3[t1 & 0xff] ^ inv_Te2[(t2 >> 8) & 0xff] ^ inv_Te1[(t3 >> 16) & 0xff] ^ W[16];
    s1 = inv_Te0[t1 >> 24] ^ inv_Te3[t2 & 0xff] ^ inv_Te2[(t3 >> 8) & 0xff] ^ inv_Te1[(t0 >> 16) & 0xff] ^ W[17];
    s2 = inv_Te0[t2 >> 24] ^ inv_Te3[t3 & 0xff] ^ inv_Te2[(t0 >> 8) & 0xff] ^ inv_Te1[(t1 >> 16) & 0xff] ^ W[18];
    s3 = inv_Te0[t3 >> 24] ^ inv_Te3[t0 & 0xff] ^ inv_Te2[(t1 >> 8) & 0xff] ^ inv_Te1[(t2 >> 16) & 0xff] ^ W[19];

    t0 = inv_Te0[s0 >> 24] ^ inv_Te3[s1 & 0xff] ^ inv_Te2[(s2 >> 8) & 0xff] ^ inv_Te1[(s3 >> 16) & 0xff] ^ W[12];
    t1 = inv_Te0[s1 >> 24] ^ inv_Te3[s2 & 0xff] ^ inv_Te2[(s3 >> 8) & 0xff] ^ inv_Te1[(s0 >> 16) & 0xff] ^ W[13];
    t2 = inv_Te0[s2 >> 24] ^ inv_Te3[s3 & 0xff] ^ inv_Te2[(s0 >> 8) & 0xff] ^ inv_Te1[(s1 >> 16) & 0xff] ^ W[14];
    t3 = inv_Te0[s3 >> 24] ^ inv_Te3[s0 & 0xff] ^ inv_Te2[(s1 >> 8) & 0xff] ^ inv_Te1[(s2 >> 16) & 0xff] ^ W[15];

    s0 = inv_Te0[t0 >> 24] ^ inv_Te3[t1 & 0xff] ^ inv_Te2[(t2 >> 8) & 0xff] ^ inv_Te1[(t3 >> 16) & 0xff] ^ W[8];
    s1 = inv_Te0[t1 >> 24] ^ inv_Te3[t2 & 0xff] ^ inv_Te2[(t3 >> 8) & 0xff] ^ inv_Te1[(t0 >> 16) & 0xff] ^ W[9];
    s2 = inv_Te0[t2 >> 24] ^ inv_Te3[t3 & 0xff] ^ inv_Te2[(t0 >> 8) & 0xff] ^ inv_Te1[(t1 >> 16) & 0xff] ^ W[10];
    s3 = inv_Te0[t3 >> 24] ^ inv_Te3[t0 & 0xff] ^ inv_Te2[(t1 >> 8) & 0xff] ^ inv_Te1[(t2 >> 16) & 0xff] ^ W[11];

    t0 = inv_Te0[s0 >> 24] ^ inv_Te3[s1 & 0xff] ^ inv_Te2[(s2 >> 8) & 0xff] ^ inv_Te1[(s3 >> 16) & 0xff] ^ W[4];
    t1 = inv_Te0[s1 >> 24] ^ inv_Te3[s2 & 0xff] ^ inv_Te2[(s3 >> 8) & 0xff] ^ inv_Te1[(s0 >> 16) & 0xff] ^ W[5];
    t2 = inv_Te0[s2 >> 24] ^ inv_Te3[s3 & 0xff] ^ inv_Te2[(s0 >> 8) & 0xff] ^ inv_Te1[(s1 >> 16) & 0xff] ^ W[6];
    t3 = inv_Te0[s3 >> 24] ^ inv_Te3[s0 & 0xff] ^ inv_Te2[(s1 >> 8) & 0xff] ^ inv_Te1[(s2 >> 16) & 0xff] ^ W[7];


    s0 = ((u32)inv_Sbox[t0 >> 24] << 24) ^ ((u32)inv_Sbox[t1 & 0xff]) ^ ((u32)inv_Sbox[(t2 >> 8) & 0xff] << 8) ^ ((u32)inv_Sbox[(t3 >> 16) & 0xff] << 16) ^ W[0];
    s1 = ((u32)inv_Sbox[t1 >> 24] << 24) ^ ((u32)inv_Sbox[t2 & 0xff]) ^ ((u32)inv_Sbox[(t3 >> 8) & 0xff] << 8) ^ ((u32)inv_Sbox[(t0 >> 16) & 0xff] << 16) ^ W[1];
    s2 = ((u32)inv_Sbox[t2 >> 24] << 24) ^ ((u32)inv_Sbox[t3 & 0xff]) ^ ((u32)inv_Sbox[(t0 >> 8) & 0xff] << 8) ^ ((u32)inv_Sbox[(t1 >> 16) & 0xff] << 16) ^ W[2];
    s3 = ((u32)inv_Sbox[t3 >> 24] << 24) ^ ((u32)inv_Sbox[t0 & 0xff]) ^ ((u32)inv_Sbox[(t1 >> 8) & 0xff] << 8) ^ ((u32)inv_Sbox[(t2 >> 16) & 0xff] << 16) ^ W[3];

    u4byte_out(PT, s0);
    u4byte_out(PT + 4, s1);
    u4byte_out(PT + 8, s2);
    u4byte_out(PT + 12, s3);
}

void AES_KeyWordToByte(u32 W[], u8 RK[]) {
    for (int i = 0; i < 44; i++) {
        u4byte_out(RK + 4 * i, W[i]);
        // RK[4i]|RK[4i+1]|RK[4i+2]|RK[4i+3] <-- W[i]
    }
}

void W_inv_MixColumns(u32 W[]) {

    u8 RK[176]; //44 * 4
    u8 temp[16];

    AES_KeyWordToByte(W, RK);

    for (int i = 1; i < 10; i++) { // 1~9 RoundKey까지만 MixColumns
        for (int j = 0; j < 16; j += 4) {
            temp[j] = MULE(RK[16 * i + j]) ^ MULB(RK[16 * i + j + 1]) ^ MULD(RK[16 * i + j + 2]) ^ MUL9(RK[16 * i + j + 3]);
            temp[j + 1] = MUL9(RK[16 * i + j]) ^ MULE(RK[16 * i + j + 1]) ^ MULB(RK[16 * i + j + 2]) ^ MULD(RK[16 * i + j + 3]);
            temp[j + 2] = MULD(RK[16 * i + j]) ^ MUL9(RK[16 * i + j + 1]) ^ MULE(RK[16 * i + j + 2]) ^ MULB(RK[16 * i + j + 3]);
            temp[j + 3] = MULB(RK[16 * i + j]) ^ MULD(RK[16 * i + j + 1]) ^ MUL9(RK[16 * i + j + 2]) ^ MULE(RK[16 * i + j + 3]);
        }
        RK[0 + i * 16] = temp[0]; RK[1 + i * 16] = temp[1]; RK[2 + i * 16] = temp[2]; RK[3 + i * 16] = temp[3];
        RK[4 + i * 16] = temp[4]; RK[5 + i * 16] = temp[5]; RK[6 + i * 16] = temp[6]; RK[7 + i * 16] = temp[7];
        RK[8 + i * 16] = temp[8]; RK[9 + i * 16] = temp[9]; RK[10 + i * 16] = temp[10]; RK[11 + i * 16] = temp[11];
        RK[12 + i * 16] = temp[12]; RK[13 + i * 16] = temp[13]; RK[14 + i * 16] = temp[14]; RK[15 + i * 16] = temp[15];
    }

    for (int i = 0; i < 44; i++) {
        W[i] = u4byte_in(RK + i * 4);
    }
}

u32 Rcons[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

#define RotWord(x) ((x<<8) | (x>>24)) //G_func안에 있는 RotWord, abcd를 bcda순으로 바꿔줌

#define SubWord(x)\
   ((u32)Sbox[(u8)(x >> 24)] << 24)\
   | ((u32)Sbox[(u8)((x >> 16) & 0xff)] << 16)\
   | ((u32)Sbox[(u8)((x >> 8) & 0xff)] << 8)\
   | ((u32)Sbox[(u8)(x & 0xff)])\

void Rk_Generation128(u8 MK[], u8 RK[])
{
    u32 W[44];// 마스터키의 4바이트를 word로 저장
    u32 T;

    W[0] = u4byte_in(MK);
    W[1] = u4byte_in(MK + 4);
    W[2] = u4byte_in(MK + 8);
    W[3] = u4byte_in(MK + 12);

    for (int i = 0; i < 10; i++)
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
    if (keysize == 128)Rk_Generation128(MK, RK);
}


void Rk_Generation128_Opt(u8 MK[], u32 W[]) {
    u32 temp;//Gfunction

    //MK로 RoundKey생성에 쓰일 W만들기
    W[0] = u4byte_in(MK); //W[0] = MK[0] || MK[1] || MK[2] || MK[3] ,MK를 word로 만드는 함수
    W[1] = u4byte_in(MK + 4);
    W[2] = u4byte_in(MK + 8);
    W[3] = u4byte_in(MK + 12);

    for (int i = 0; i < 10; i++) {
        //temp = G_func(W[4 * i + 3]);//행의 마지막 배열만 Gfunction에 넣기
        temp = W[4 * i + 3];

        //G_function; G(W4i-1) = Subword(RotWord(W4i-1)) xor RCons
        temp = RotWord(temp);
        temp = SubWord(temp);
        temp ^= Rcons[i];

        W[4 * i + 4] = W[4 * i] ^ temp;
        W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
        W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
        W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
    }

    W_inv_MixColumns(W);
}

void AES_KeySchedule_Opt(u8 MK[], u32 W[], int keysize) {
    if (keysize == 128)
        Rk_Generation128_Opt(MK, W);
}

int main() {

    u8 CT[16] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    u8 MK[32] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    u8 PT[16] = { 0, };
    u32 W[44] = { 0, };
    u8 RK[240] = { 0, };//라운드키
    clock_t start, finish;
    int keysize = 128;

    AES_keySchedule(MK, RK, keysize);//키스케줄  
    start = clock();
    for (int i = 0; i < 100000; i++) {
        AES_DEC(CT, RK, PT, keysize);//복호화
    }
    finish = clock();

    printf("Decryption \n");
    printf("Ciphertext : ");
    for (int i = 0; i < 16; i++)printf("%02x ", CT[i]);
    printf("\n");
    printf("Plaintext :  ");
    for (int i = 0; i < 16; i++)printf("%02x ", PT[i]);
    printf("\nComputation time : %f second\n\n\n", (double)(finish - start) / CLOCKS_PER_SEC);



    AES_KeySchedule_Opt(MK, W, keysize);
    start = clock();
    for (int i = 0; i < 100000; i++) {
        AES_DEC_Opt(PT, W, CT, keysize);
    }
    finish = clock();

    printf("Decryption_Optimization \n");
    printf("Ciphertext : ");
    for (int i = 0; i < 16; i++)printf("%02x ", CT[i]);
    printf("\n");
    printf("Plaintext :  ");
    for (int i = 0; i < 16; i++)printf("%02x ", PT[i]);
    printf("\nComputation time : %f second\n\n\n", (double)(finish - start) / CLOCKS_PER_SEC);

    return 0;
}