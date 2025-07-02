#ifndef CONFIG_H
#define CONFIG_H

#define ENABLE_HASH 0

#include <inttypes.h>

// Rate in bits
#define ISAP_rH 64
#define ISAP_rB 1

// Number of rounds
#define ISAP_sH 12
#define ISAP_sB 1
#define ISAP_sE 6
#define ISAP_sK 12

// State size in bytes
#define ISAP_STATE_SZ 40

// Size of rate in bytes
#define ISAP_rH_SZ ((ISAP_rH + 7) / 8)

// Size of zero truncated IV in bytes
#define ISAP_IV_SZ 8

// Size of tag in bytes
#define ISAP_TAG_SZ 16

// Security level
#define ISAP_K 128

// ISAP-A-128a
const uint8_t ISAP_IV_A[] = { 0x01, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK };
const uint8_t ISAP_IV_KA[] = { 0x02, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK };
const uint8_t ISAP_IV_KE[] = { 0x03, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK };

// Ascon-Hash
const uint8_t ASCON_HASH_IV[] = { 0x00, 0x40, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00 };

#endif // CONFIG_H