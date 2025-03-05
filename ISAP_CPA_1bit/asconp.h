#ifndef ASCONP_H_
#define ASCONP_H_

#include <inttypes.h>
#include "config.h"

typedef union
{
    uint64_t x;
    uint32_t w[2];
    uint8_t b[8];
} lane_t;

typedef union
{
    lane_t l[5];
    uint64_t x[5];
    uint32_t w[5][2];
    uint8_t b[5][8];
} state_t;

/* ---------------------------------------------------------------- */

#define P_sH P12ROUNDS(s)
#define P_sB P1ROUNDS(s)
#define P_sE P6ROUNDS(s)
#define P_sK P12ROUNDS(s)

/* ---------------------------------------------------------------- */

#define U64TOWORD(x) U64BIG(x)
#define WORDTOU64(x) U64BIG(x)

/* ---------------------------------------------------------------- */

#define TOBI(x) (x)
#define FROMBI(x) (x)

/* ---------------------------------------------------------------- */

lane_t U64BIG(lane_t x)
{
    x.x = ((((x.x) & 0x00000000000000FFULL) << 56) | (((x.x) & 0x000000000000FF00ULL) << 40) |
        (((x.x) & 0x0000000000FF0000ULL) << 24) | (((x.x) & 0x00000000FF000000ULL) << 8) |
        (((x.x) & 0x000000FF00000000ULL) >> 8) | (((x.x) & 0x0000FF0000000000ULL) >> 24) |
        (((x.x) & 0x00FF000000000000ULL) >> 40) | (((x.x) & 0xFF00000000000000ULL) >> 56));
    return x;
}

/* ---------------------------------------------------------------- */

void ROUND(state_t* s, uint8_t C)
{
    uint64_t xtemp;
    /* round constant */
    s->x[2] ^= C;
    /* s-box layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    xtemp = s->x[0] & ~s->x[4];
    s->x[0] ^= s->x[2] & ~s->x[1];
    s->x[2] ^= s->x[4] & ~s->x[3];
    s->x[4] ^= s->x[1] & ~s->x[0];
    s->x[1] ^= s->x[3] & ~s->x[2];
    s->x[3] ^= xtemp;
    s->x[1] ^= s->x[0];
    s->x[3] ^= s->x[2];
    s->x[0] ^= s->x[4];
    s->x[2] = ~s->x[2];
    /* linear layer */
    s->x[0] ^=
        (s->x[0] >> 19) ^ (s->x[0] << 45) ^ (s->x[0] >> 28) ^ (s->x[0] << 36);
    s->x[1] ^=
        (s->x[1] >> 61) ^ (s->x[1] << 3) ^ (s->x[1] >> 39) ^ (s->x[1] << 25);
    s->x[2] ^=
        (s->x[2] >> 1) ^ (s->x[2] << 63) ^ (s->x[2] >> 6) ^ (s->x[2] << 58);
    s->x[3] ^=
        (s->x[3] >> 10) ^ (s->x[3] << 54) ^ (s->x[3] >> 17) ^ (s->x[3] << 47);
    s->x[4] ^=
        (s->x[4] >> 7) ^ (s->x[4] << 57) ^ (s->x[4] >> 41) ^ (s->x[4] << 23);
}

/* ---------------------------------------------------------------- */

void P12ROUNDS(state_t* s)
{
    ROUND(s, 0xf0);
    ROUND(s, 0xe1);
    ROUND(s, 0xd2);
    ROUND(s, 0xc3);
    ROUND(s, 0xb4);
    ROUND(s, 0xa5);
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

/* ---------------------------------------------------------------- */

void P6ROUNDS(state_t* s)
{
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

/* ---------------------------------------------------------------- */

void P1ROUNDS(state_t* s)
{
    ROUND(s, 0x4b);
}

/* ---------------------------------------------------------------- */

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

#endif // ASCONP_H_