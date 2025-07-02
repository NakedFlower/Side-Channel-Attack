#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include<time.h>
#include "aes.h"


#define MUL2(a) (a << 1) ^ (a & 0x80 ? 0x1b : 0)
#define MUL3(a) MUL2(a)^a
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a) 
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

u8 MUL(u8 a, u8 b) {
    u8 r = 0;
    u8 tmp = b;
    u32 i;
    for (i = 0; i < 8; i++) {
        if (a & 1)r ^= tmp;
        tmp = MUL2(tmp);
        a >>= 1; //(a=a>>1)
    }
    return r;
}

void AddRoundKey(u8 S[16], u8 RK[16]) {// (u8 temp[16]) ^= (u8 RK[16])
    S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
    S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
    S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
    S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
}


void SubBytes(u8 S[16]) { // Sbox(u8 S[16])
    S[0] = Sbox[S[0]]; S[1] = Sbox[S[1]]; S[2] = Sbox[S[2]]; S[3] = Sbox[S[3]];
    S[4] = Sbox[S[4]]; S[5] = Sbox[S[5]]; S[6] = Sbox[S[6]]; S[7] = Sbox[S[7]];
    S[8] = Sbox[S[8]]; S[9] = Sbox[S[9]]; S[10] = Sbox[S[10]]; S[11] = Sbox[S[11]];
    S[12] = Sbox[S[12]]; S[13] = Sbox[S[13]]; S[14] = Sbox[S[14]]; S[15] = Sbox[S[15]];
}
void ShiftRow(u8 S[16]) { //S = ShiftRow(S[16])
    u8 temp;
    temp = S[1]; S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = temp;

    temp = S[2]; S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp;

    temp = S[15]; S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = temp;
}

void MixColumns(u8 S[16]) { // S = Mixcolumns(S)
    u8 temp[16];
    int i;
    for (i = 0; i < 16; i += 4) { //for문으로 연산
        temp[i] = MUL2(S[i]) ^ MUL3(S[i + 1]) ^ S[i + 2] ^ S[i + 3];
        temp[i + 1] = S[i] ^ MUL2(S[i + 1]) ^ MUL3(S[i + 2]) ^ S[i + 3];
        temp[i + 2] = S[i] ^ S[i + 1] ^ MUL2(S[i + 2]) ^ MUL3(S[i + 3]);
        temp[i + 3] = MUL3(S[i]) ^ S[i + 1] ^ S[i + 2] ^ MUL2(S[i + 3]);
    }
    S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
    S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
    S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
    S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15]; //S배열에 temp값 넣기
}

void AES_ENC(u8 PT[16], u8 RK[16], u8 CT[16], int keysize) {
    int Nr = keysize / 32 + 6;//라운드 수 
    int i;
    u8 temp[16];

    for (i = 0; i < 16; i++) { temp[i] = PT[i]; }

    /*암호화 시작*/
    AddRoundKey(temp, RK);//temp(평문)의 16byte와 RK의 첫 16byte를 xor하여 temp에 결과를 담는 함수

    for (i = 0; i < Nr - 1; i++) {
        SubBytes(temp);
        ShiftRow(temp);
        MixColumns(temp);
        AddRoundKey(temp, RK + 16 * (i + 1));
    }
    /*마지막 라운드*/
    SubBytes(temp);
    ShiftRow(temp);
    AddRoundKey(temp, RK + 16 * (i + 1));

    for (i = 0; i < 16; i++) { CT[i] = temp[i]; }
}

u32 u4byte_in(u8* x) {
    return ((x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]);
}//x[0]||x[1]||x[2]||x[3], 마스터키 연접시키기

void u4byte_out(u8* x, u32 y) {
    x[0] = (y >> 24) & 0xff;
    x[1] = (y >> 16) & 0xff;
    x[2] = (y >> 8) & 0xff;
    x[3] = y & 0xff;
}

void AES_ENC_Optimization(u8 PT[16], u32 W[], u8 CT[16], int keysize) {
    int Nr = keysize / 32 + 6;//라운드 수 
    u32 s0, s1, s2, s3, t0, t1, t2, t3;

    //0round
    s0 = u4byte_in(PT) ^ W[0];
    s1 = u4byte_in(PT + 4) ^ W[1];
    s2 = u4byte_in(PT + 8) ^ W[2];
    s3 = u4byte_in(PT + 12) ^ W[3];

    //1round
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[4];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[5];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[6];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[7];

    //2round
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[8];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[9];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[10];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[11];

    //3round
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[12];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[13];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[14];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[15];

    //4round
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[16];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[17];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[18];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[19];

    //5round
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[20];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[21];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[22];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[23];

    //6round
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[24];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[25];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[26];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[27];

    //7round
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[28];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[29];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[30];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[31];

    //8round
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[32];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[33];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[34];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[35];

    if (Nr == 10) {
        //9round
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

        //10round
        s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[40];
        s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[41];
        s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[42];
        s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[43];
    }

    else if (Nr == 12) {
        //9round
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

        //10round
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];

        //11round
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

        //11round
        s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[48];
        s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[49];
        s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[50];
        s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[51];

    }

    else if (Nr == 14) {
        //9round
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

        //10round
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];

        //e11round
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

        //12round
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[48];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[49];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[50];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[51];

        //13round
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[52];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[53];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[54];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[55];

        //14round
        s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[56];
        s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[57];
        s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[58];
        s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[59];

    }
    u4byte_out(CT, s0);
    u4byte_out(CT + 4, s1);
    u4byte_out(CT + 8, s2);
    u4byte_out(CT + 12, s3);
}

void AES_KeyWordToByte(u32 W[], u8 RK[]) {
    int i;
    for (i = 0; i < 44; i++) {
        u4byte_out(RK + 4 * i, W[i]);
        //RK[4i]||RK[4i+1]||RK[4i+2]||R[4i+3] <--W[i]
    }
}

u32 Rcons[10] = { 0x01000000,0x02000000,0x04000000,0x08000000,0x10000000\
,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000 };

u8 Rcons_op[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

#define RotWord(x) ((x<<8)|(x>>24)) //G_func안에 있는 RotWord, abcd를 bcda순으로 버꿔줌

#define SubWord(x)\
    ((u32)Sbox[(u8)(x>>24)]<<24)\
   | ((u32)Sbox[(u8)((x>>16)&0xff)]<<16)\
   | ((u32)Sbox[(u8)((x>>8)&0xff)]<<8)\
   | ((u32)Sbox[(u8)(x&0xff)])\

/*u32 SubWord(u32 x) {
   u8 a, b, c, d;
   a = Sbox[(u8)(x >> 24)];
   b = Sbox[(u8)((x >> 16) & 0xff)];
   c = Sbox[(u8)((x >> 8) & 0xff)];
   d = Sbox[(u8)(x & 0xff)];

   return ((u32)Sbox[(u8)(x >> 24)] << 24) | ((u32)Sbox[(u8)((x >> 16) & 0xff)] << 16) | ((u32)Sbox[(u8)((x >> 8) & 0xff)] << 8) | (u32)Sbox[(u8)(x & 0xff)];
}*/

void RoundkeyGeneration128(u8 MK[], u8 RK[]) {//AddRoundKey 쓰일 라운드키 생성
    u32 W[44];//RoundKey
    int i;
    u32 T;//Gfunction 

    //MK로 RoundKey생성에 쓰일 W만들기
    W[0] = u4byte_in(MK);//W[0] = MK[0] || MK[1] || MK[2] || MK[3] ,마스터키를 word로 만드는 함수
    W[1] = u4byte_in(MK + 4);
    W[2] = u4byte_in(MK + 8);
    W[3] = u4byte_in(MK + 12);

    for (i = 0; i < 10; i++) {
        //T = G_func(W[4 * i + 3]);//행의 마지막 배열만 Gfunction에 넣기

        T = W[4 * i + 3];

        //G_function; G(W4i-1) = Subword(RotWord(W4i-1)) xor RCons
        T = RotWord(T);//로테이션해서 T에 다시 넣기
        T = SubWord(T);//subword해서 T에 다시 넣기
        T ^= Rcons[i];

        W[4 * i + 4] = W[4 * i] ^ T;
        W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
        W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
        W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
    }
    AES_KeyWordToByte(W, RK);//W로 라운드키 만드는 함수
}
void RoundkeyGeneration128_Optimization(u8 MK[], u32 W[]) {//AddRoundKey 쓰일 라운드키 생성
    int i;
    u32 T;//Gfunction 


    //MK로 RoundKey생성에 쓰일 W만들기
    W[0] = u4byte_in(MK);//W[0] = MK[0] || MK[1] || MK[2] || MK[3] ,마스터키를 word로 만드는 함수
    W[1] = u4byte_in(MK + 4);
    W[2] = u4byte_in(MK + 8);
    W[3] = u4byte_in(MK + 12);

    for (i = 0; i < 10; i++) {
        //T = G_func(W[4 * i + 3]);//행의 마지막 배열만 Gfunction에 넣기

        T = W[4 * i + 3];

        //G_function; G(W4i-1) = Subword(RotWord(W4i-1)) xor RCons
        T = RotWord(T);//로테이션해서 T에 다시 넣기
        T = SubWord(T);//subword해서 T에 다시 넣기
        T ^= Rcons[i];

        W[4 * i + 4] = W[4 * i] ^ T;
        W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
        W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
        W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
    }

}


void AES_Keyschedule(u8 MK[], u8 RK[], int keysize) {
    if (keysize == 128) { RoundkeyGeneration128(MK, RK); }

}

void AES_Keyschedule_Optimization(u8 MK[], u32 W[], int keysize) {
    if (keysize == 128) { RoundkeyGeneration128_Optimization(MK, W); }
}


int main() {
    int i;
    u8 PT[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    u8 MK[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    u8 CT[16] = { 0x00 };
    u8 RK[240] = { 0x00 };
    u32 W[60] = { 0x00 };
    int keysize = 128;
    clock_t start, finish;

    AES_Keyschedule(MK, RK, keysize);//1Round: Rk 0~15, 2Round 16~31...
    start = clock();
    for (i = 0; i < 1000000; i++)
        AES_ENC(PT, RK, CT, keysize);
    finish = clock();
    printf("AES:");
    for (i = 0; i < 16; i++)printf("%02x ", CT[i]);
    printf("\n");
    printf("Computation time : %f second\n\n\n", (double)(finish - start) / CLOCKS_PER_SEC);


    AES_Keyschedule_Optimization(MK, W, keysize);//1Round: Rk 0~15, 2Round 16~31...
    start = clock();
    for (i = 0; i < 1000000; i++)AES_ENC_Optimization(PT, W, CT, keysize);
    finish = clock();
    for (i = 0; i < 16; i++)printf("%02x ", CT[i]);
    printf("\n");
    printf("Computation time : %f second\n\n\n", (double)(finish - start) / CLOCKS_PER_SEC);
}