#include <string.h>
#include <inttypes.h>
#include "api.h"
#include "asconp.h"
#include "config.h"

#define MESSAGE_LENGTH			32
#define ASSOCIATED_DATA_LENGTH	32

void ABSORB_LANES(state_t* s, const uint8_t* src, uint64_t len)
{
    while (len >= 8)
    {
        // Absorb full lanes
        lane_t t0 = U64TOWORD(*(lane_t*)(src + 0));
        s->x[0] ^= t0.x;
        len -= ISAP_rH / 8;
        src += ISAP_rH / 8;
        P_sH;
    }

    if (len > 0)
    {
        // Absorb partial lane and padding
        size_t i;
        lane_t t0 = { 0 };
        for (i = 0; i < len; i++)
        {
            t0.b[7 - i] ^= *src;
            src++;
        }
        t0.b[7 - i] ^= 0x80;
        t0 = TOBI(t0);
        s->x[0] ^= t0.x;
        P_sH;
    }
    else
    {
        // Absorb padded empty lane
        s->b[0][7] ^= 0x80;
        P_sH;
    }
}

void isap_rk(
    const uint8_t* k,
    const uint8_t* iv,
    const uint8_t* y,
    state_t* out,
    const size_t outlen)
{
    state_t state;
    state_t* s = &state;

    // Initialize
    s->l[0] = U64TOWORD(*(lane_t*)(k + 0));
    s->l[1] = U64TOWORD(*(lane_t*)(k + 8));
    s->l[2] = U64TOWORD(*(lane_t*)(iv + 0));
    s->x[3] = 0;
    s->x[4] = 0;
    P_sK;

    // Absorb Y, bit by bit
    for (size_t i = 0; i < 16; i++)
    {
        uint8_t y_byte = *y;
        s->b[0][7] ^= (y_byte & 0x80) << 0;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x40) << 1;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x20) << 2;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x10) << 3;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x08) << 4;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x04) << 5;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x02) << 6;
        P_sB;
        s->b[0][7] ^= (y_byte & 0x01) << 7;
        if (i != 15)
        {
            P_sB;
            y += 1;
        }
    }

    // Squeeze K*
    P_sK;
    out->x[0] = s->x[0];
    out->x[1] = s->x[1];
    if (outlen > 16)
    {
        out->x[2] = s->x[2];
    }
}

void isap_mac(
    const uint8_t* k,
    const uint8_t* npub,
    const uint8_t* ad, uint64_t adlen,
    const uint8_t* c, uint64_t clen,
    uint8_t* tag)
{
    state_t state;
    state_t* s = &state;

    // Initialize
    s->l[0] = U64TOWORD(*(lane_t*)(npub + 0));
    s->l[1] = U64TOWORD(*(lane_t*)(npub + 8));
    s->l[2] = U64TOWORD(*(lane_t*)(ISAP_IV_A + 0));
    s->x[3] = 0;
    s->x[4] = 0;
    P_sH;

    // Absorb associated data
    ABSORB_LANES(s, ad, adlen);

    // Domain seperation
    s->w[4][0] ^= 0x1UL;

    // Absorb ciphertext
    ABSORB_LANES(s, c, clen);

    // Derive KA*
    s->l[0] = WORDTOU64(s->l[0]);
    s->l[1] = WORDTOU64(s->l[1]);
    isap_rk(k, ISAP_IV_KA, (const uint8_t*)(s->b), s, CRYPTO_KEYBYTES);

    // Squeeze tag
    P_sH;
    lane_t t0 = WORDTOU64(s->l[0]);
    memcpy(tag + 0, t0.b, 8);
    t0 = WORDTOU64(s->l[1]);
    memcpy(tag + 8, t0.b, 8);

}

int main() {

    unsigned char   key[CRYPTO_KEYBYTES] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    unsigned char   nonce[CRYPTO_NPUBBYTES] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
    unsigned char   ad[ASSOCIATED_DATA_LENGTH] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                                        17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
    unsigned char   ct[MESSAGE_LENGTH + CRYPTO_ABYTES] = { 0x2C,0xDE,0x28,0xDB,0xBB,0xD9,0x13,0x1E,0xBC,
                                                                0x56,0x8D,0x77,0x72,0x5B,0x25,0x93,0x7C,0xF8,0xED,0xB8,
                                                                    0xA8,0xF5,0x0A,0x2A,0xCE,0xDA,0x35,0x6C,0x3C,0xA3,0xD4,0x6B,
                                                                        0xAF,0x83,0xB9,0x60,0x92,0x8F,0x1E,0x4C,0xC9,0x75,0xEA,0x24,0xF4,0x88,0x20,0x2C };
    unsigned char mac_tag[ISAP_TAG_SZ] = { 0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc };

    unsigned long long mlen = MESSAGE_LENGTH;
    unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
    unsigned long long clen = 0x20;

    unsigned char* tag = &mac_tag;

    isap_mac(key, nonce, ad, adlen, ct, clen, tag);

    //printf(tag);
}