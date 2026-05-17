/**
 * @file  generate_host_app_signed_header.h
 * @brief Host Application Signed Header Generator
 *
 * Constants, macros, enums and function prototypes.
 * SBIT offset constants are chosen to reproduce exactly the pointer
 * arithmetic used in the reference firmware getappheader():
 *
 *   uint32_t *ModuleIdOffset = SBIT_ADDRESS + FIRST_MODULE_OFFSET;
 *
 * where SBIT_ADDRESS is declared as uint32_t *, so +N advances N*4 bytes.
 *
 * Crypto mapping (STRICT – do not deviate):
 *   SHA-256  → WolfSSL  <wolfssl/wolfcrypt/sha256.h>
 *   Ed25519  → WolfSSL  <wolfssl/wolfcrypt/ed25519.h>
 *   RSA      → PolarSSL <polarssl/rsa.h>
 */

#ifndef GENERATE_HOST_APP_SIGNED_HEADER_H
#define GENERATE_HOST_APP_SIGNED_HEADER_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================================================================
 * PRIMITIVE TYPES
 * =========================================================================*/

typedef uint8_t  boolean;

#ifndef TRUE
#define TRUE  (1U)
#endif
#ifndef FALSE
#define FALSE (0U)
#endif

/* ===========================================================================
 * ERROR CODES
 * =========================================================================*/

typedef int32_t ErrCodeT;

#define ERC_NO_ERROR         ( 0)
#define ERC_INVALID_CMD      (-1)
#define MODULE_NOT_FOUND     (-2)
#define ERC_NULL_PTR         (-3)
#define ERC_CRYPTO_FAIL      (-4)
#define ERC_BUFFER_TOO_SMALL (-5)

/* ===========================================================================
 * SBIT BASE ADDRESS
 *
 * In the reference firmware SBIT_ADDRESS is a uint32_t * pointing to CRS SRAM.
 * We store it as a bare integer and cast as needed.
 * =========================================================================*/

#define SBIT_BASE_ADDRESS    (0x25EFE7CDU)

/* ---------------------------------------------------------------------------
 * SBIT VERSION IDENTIFIERS
 * (read from offset 0 as uint16_t, big-endian storage → compare directly
 *  because the firmware does: uint16_t Version = (uint16_t)*TableVersion;
 *  with TableVersion = (uint16_t *)SBIT_ADDRESS, i.e. no byte-swap.)
 * -------------------------------------------------------------------------*/

#define SBIT_V1           (0x5501U)   /* standard, no MGAL          */
#define SBIT_WITH_MGAL    (0x5502U)   /* extended, MGAL active       */

/* ---------------------------------------------------------------------------
 * SBIT UINT32-WORD OFFSETS
 *
 * The reference firmware declares:
 *   uint32_t *ModuleIdOffset    = SBIT_ADDRESS + FIRST_MODULE_OFFSET;
 *   uint32_t *RegionalInfoOffset= SBIT_ADDRESS + REGION_INFO_OFFSET;
 *   uint16_t *numberofmodules   = SBIT_ADDRESS + NUMBER_OF_SBIT_MODULE_OFFSET;
 *
 * All three pointers are offset from a uint32_t * base, so each +1 is +4 bytes.
 *
 * From the SBIT engineering spec (V1 header = 66 bytes = 0x42):
 *   Byte 0x40 (word 16)  → numberOfModules  (uint16 BE)
 *   Byte 0x42 (word 16, upper half) → Module table entry 0:
 *       [0..1] moduleId  (uint16 BE)
 *       [2..3] regionOffset (uint16 BE)
 *
 * The reference code reads the module table with two parallel uint32_t*
 * pointers that both step by +1 (4 bytes):
 *   ModuleIdOffset    → points at the 4-byte word whose upper 2 bytes hold moduleId
 *   RegionalInfoOffset→ points at the SAME 4-byte word (lower 2 bytes = regionOffset)
 *
 * Because both read from the same 32-bit word but cast differently
 * (ModuleIdOffset as uint16_t, RegionalInfoOffset as uint16_t at +2),
 * and both advance together, the simplest faithful reproduction is:
 *
 *   ModuleIdOffset    starts at byte 0x42  → word offset 0x42/4 = 16 (rounded)
 *   RegionalInfoOffset starts at byte 0x44 → word offset 0x44/4 = 17
 *
 * However the reference uses *separate* uint32_t* pointers initialised from
 * SBIT_ADDRESS.  The casting to uint16_t at the point of the read is what
 * selects the correct half-word.  We replicate this exactly in the .c file.
 *
 * WORD OFFSET VALUES (uint32_t units from SBIT_ADDRESS):
 *   numberOfModules:  byte 0x40 → word 16 = 0x10
 *   first moduleId:   byte 0x42 → word 16 = 0x10  (upper 16 bits of word 16)
 *   first regionOff:  byte 0x44 → word 17 = 0x11  (upper 16 bits of word 17)
 *
 * MGAL offsets are the same structure shifted by 4 bytes (one extra word).
 * -------------------------------------------------------------------------*/

/*
 * All offsets are BYTE offsets from SBIT_BASE_PTR (uint8_t *).
 * Values derived from the SBIT V1 header engineering specification:
 *
 *   Byte 0x00 (uint16 BE)  tableType / version
 *   Byte 0x40 (uint16 BE)  numberOfModules
 *   Byte 0x42              Module Location Table entry 0:
 *     [0..1] moduleId       (uint16 BE)
 *     [2..3] regionOffset   (uint16 BE)
 *   Each module table entry is SBIT_MODULE_TABLE_ENTRY_STRIDE (4) bytes wide.
 *   regionOffset (little-endian value after read_be16) is a byte offset from
 *   SBIT base to the module info block.
 *
 * MGAL (V2) layout shifts by 4 bytes relative to V1.
 */

/* Standard SBIT (V1) */
#define NUMBER_OF_SBIT_MODULE_OFFSET         (0x40U) /* byte 0x40: numberOfModules (uint16 BE) */
#define FIRST_MODULE_OFFSET                  (0x42U) /* byte 0x42: first moduleId  (uint16 BE) */
#define REGION_INFO_OFFSET                   (0x44U) /* byte 0x44: first regionOffset (uint16 BE) */

/* MGAL SBIT (V2) */
#define NUMBER_OF_MGAL_SBIT_MODULE_OFFSET    (0x44U) /* byte 0x44 */
#define FIRST_MODULE_OFFSET_WITH_MGAL        (0x46U) /* byte 0x46 */
#define REGION_INFO_OFFSET_WITH_MGAL         (0x48U) /* byte 0x48 */

/* ---------------------------------------------------------------------------
 * SBIT MODULE INFO BLOCK – BYTE OFFSETS FROM regionOffsetLB
 *
 * In the reference firmware the region loop does:
 *   uint32_t *Address = SBIT_ADDRESS + (uint32_t)RegionoffsetLB + (3 + 9*i);
 *   uint32_t *Length  = SBIT_ADDRESS + (uint32_t)RegionoffsetLB + (7 + 9*i);
 *
 * Here SBIT_ADDRESS is cast to uint8_t * for the addition, making 3 and 7
 * byte offsets from RegionoffsetLB inside the module-info block.
 * (CCID=2B, numRegions=1B → first startAddr at +3; length 4B later → +7.)
 * -------------------------------------------------------------------------*/

#define SBIT_MOD_NUM_REGIONS_BYTE_OFF   (2U)   /* sizeof(uint16_t) = CCID size */
#define SBIT_MOD_REGION_ADDR_BYTE_BASE  (3U)   /* first startAddr byte offset  */
#define SBIT_MOD_REGION_LEN_BYTE_BASE   (7U)   /* first length byte offset      */
#define SBIT_MOD_REGION_ENTRY_BYTES     (9U)   /* bytes per region entry        */
#define SBIT_MAX_REGIONS                (100U)

/* ===========================================================================
 * ENDIANNESS MACROS  (identical to reference firmware)
 * =========================================================================*/

#define CHANGE_ENDIANNESS_16BIT(val)  \
    ((uint16_t)(((uint16_t)(val) >> 8U) | ((uint16_t)(val) << 8U)))

#define CHANGE_ENDIANNESS_32BIT(val)  \
    ((uint32_t)(                      \
        (((uint32_t)(val) & 0xFF000000U) >> 24U) | \
        (((uint32_t)(val) & 0x00FF0000U) >>  8U) | \
        (((uint32_t)(val) & 0x0000FF00U) <<  8U) | \
        (((uint32_t)(val) & 0x000000FFU) << 24U)   \
    ))

/* ===========================================================================
 * SHA-256 STAGING BUFFER
 *
 * getAppSignedHeaderAddress() returns a module-level static buffer into which
 * all region data is memcpy'd before hashing.  This mirrors the reference
 * firmware's identically-named function.
 * =========================================================================*/

/** Maximum size of the concatenated region data fed to SHA-256 (1 MB) */
#define APP_SIGNED_HDR_STAGING_SIZE     (0x100000U)

/* ===========================================================================
 * SIGNED HEADER FIELD SIZES
 * =========================================================================*/

#define HAP_MODULE_ID_SIZE            (2U)
#define HAP_BCID_SIZE                 (2U)
#define HAP_ECU_NAME_SIZE             (8U)
#define HAP_ECU_ID_SIZE               (16U)
#define HAP_ECU_ID_EXT_SIZE           (16U)
#define HAP_APP_NBID_SIZE             (2U)
#define HAP_NUM_SW_REGIONS_SIZE       (2U)
#define HAP_REGION_START_ADDR_SIZE    (4U)
#define HAP_REGION_LENGTH_SIZE        (4U)
#define HAP_MSG_DIGEST_SIZE           (32U)
#define HAP_SUBJECT_NAME_SIZE         (16U)
#define HAP_CERTIFICATE_ID_SIZE       (8U)
#define HAP_KEY_NBID_SIZE             (2U)
#define HAP_SUBJECT_PUB_KEY_SIZE      (256U)
#define HAP_ROOT_SIGNATURE_SIZE       (256U)
#define HAP_HEADER_SIGNATURE_SIZE     (256U)
#define HAP_SIGNER_INFO_SIZE          (538U)  /* 16+8+2+256+256 */

#define NORMAL_HEADER_SIZE            (882U)
#define BITDIFF_HEADER_SIZE           (914U)

/** Bytes covered by the header signature (all fields except the sig itself) */
#define NORMAL_SIGNED_LEN   (NORMAL_HEADER_SIZE  - HAP_HEADER_SIGNATURE_SIZE)
#define BITDIFF_SIGNED_LEN  (BITDIFF_HEADER_SIZE - HAP_HEADER_SIGNATURE_SIZE)

/* ===========================================================================
 * KEY TYPE CONSTANTS  (keySize parameter values)
 * =========================================================================*/

#define ED25519_KEY_SIZE      (32U)    /* seed / public-key length            */
#define RSA_KEY_SIZE          (256U)   /* RSA-2048 modulus size               */
#define ED25519_PRIV_FULL     (64U)    /* WolfSSL export: seed || public key  */
#define ED25519_SIG_SIZE      (64U)    /* Ed25519 raw signature               */
#define RSA_KEY_BITS          (2048U)
#define RSA_PUB_EXPONENT      (65537)

/* ===========================================================================
 * HARDCODED FIELD DEFAULTS
 * =========================================================================*/

/* ECU Name: "TEST_ECU" */
#define VALID_ECU_NAME \
    { 0x54U,0x45U,0x53U,0x54U,0x5FU,0x45U,0x43U,0x55U }

/* ECU ID */
#define VALID_ECU_ID \
    { 0x11U,0x23U,0x45U,0xFFU,0x00U,0x11U,0x26U,0xFFU, \
      0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xF0U,0xFFU }

/* ECU ID Extension: all 0xFF */
#define VALID_ECU_ID_EXT \
    { 0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xFFU, \
      0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xFFU,0xFFU }

/* App NBID: 0x0000 */
#define VALID_APP_NBID      { 0x00U, 0x00U }

/* BCID: 0x0000 */
#define VALID_BCID          { 0x00U, 0x00U }

/* Subject Name: "SUBJECT_NAME_V10" */
#define VALID_SUBJECT_NAME \
    { 0x53U,0x55U,0x42U,0x4AU,0x45U,0x43U,0x54U,0x5FU, \
      0x4EU,0x41U,0x4DU,0x45U,0x5FU,0x56U,0x31U,0x30U }

/* Certificate ID */
#define VALID_CERT_ID \
    { 0x00U,0x03U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U }

/* Key NBID: 0x0000 */
#define VALID_KEY_NBID      { 0x00U, 0x00U }

/* ===========================================================================
 * INVALID VALUES FOR NEGATIVE TEST CASES
 * =========================================================================*/

#define INVALID_MODULE_ID_VALUE  (0xDEADU)

/*
 * FALLBACK_ADDR / FALLBACK_LEN
 *
 * Used exclusively when NegativeCase == INVALID_MODULE_ID.
 * SBIT is NOT accessed in this path.  Instead, this known-good fixed region
 * (MOD_ID_C41A memory range) is used directly so that region data copy and
 * SHA-256 computation always succeed.  After the header is fully built, only
 * the moduleId field is overwritten with INVALID_MODULE_ID_VALUE.
 */
#define FALLBACK_ADDR  (0x25C05000U)
#define FALLBACK_LEN   (0x00000178U)

#define INVALID_ECU_NAME \
    { 0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U }

#define INVALID_ECU_ID \
    { 0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U, \
      0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U }

#define INVALID_APP_NBID    { 0xFFU, 0xFFU }

/* ===========================================================================
 * HARDCODED ROOT KEYS
 * =========================================================================*/

/* Ed25519 root public key  (32 bytes) */
#define ROOT_EDDSA_PUB_BYTES \
  { 0xF6U,0x7BU,0x00U,0xD4U,0xD9U,0x88U,0x0DU,0x00U, \
    0xE6U,0x64U,0x52U,0x5AU,0xB0U,0xD7U,0xA5U,0xC6U, \
    0x2DU,0x20U,0x3DU,0xBAU,0x4FU,0xA1U,0x71U,0x1EU, \
    0x1FU,0x08U,0x41U,0x29U,0xF9U,0xC3U,0xD9U,0x78U }

/* Ed25519 root private key / seed  (32 bytes) */
#define ROOT_EDDSA_PRIV_BYTES \
  { 0x02U,0xFDU,0x18U,0x39U,0xBFU,0xFEU,0x58U,0x0BU, \
    0x48U,0xFAU,0x7AU,0x79U,0xA9U,0x9FU,0x24U,0x95U, \
    0x08U,0x9AU,0x96U,0xC6U,0x3CU,0x81U,0xA3U,0x07U, \
    0x07U,0x33U,0x16U,0x0CU,0x44U,0x9CU,0xF8U,0x19U }

/* RSA root public modulus  (256 bytes) */
#define ROOT_RSA_PUB_BYTES \
  { 0xB7U,0x08U,0x6EU,0x1DU,0x34U,0x28U,0x78U,0x7DU, \
    0x44U,0xB4U,0x0BU,0x76U,0x71U,0x81U,0xD0U,0x7CU, \
    0x8FU,0x4EU,0x88U,0x60U,0xEFU,0x2EU,0x4BU,0xDEU, \
    0x3FU,0x45U,0xABU,0xDBU,0x6DU,0x85U,0xB2U,0xA5U, \
    0xE5U,0xB2U,0x8FU,0x7BU,0x77U,0x16U,0x4CU,0xD9U, \
    0x9AU,0x64U,0x59U,0x02U,0x18U,0x79U,0x10U,0x41U, \
    0x07U,0xAAU,0x5FU,0xC3U,0x5AU,0x96U,0x8FU,0xF9U, \
    0xFBU,0x67U,0x90U,0x96U,0x97U,0x74U,0x94U,0x7EU, \
    0xDBU,0xDBU,0xBAU,0x77U,0xF7U,0x02U,0x48U,0x41U, \
    0x5FU,0x80U,0xA1U,0x2BU,0xA0U,0x83U,0xBAU,0xBEU, \
    0xD4U,0x45U,0xF7U,0x59U,0xE9U,0x5DU,0x97U,0x16U, \
    0x71U,0x19U,0x02U,0x59U,0xF1U,0xA1U,0x99U,0x24U, \
    0x21U,0x59U,0x9AU,0x01U,0x3FU,0xBDU,0x56U,0x14U, \
    0x49U,0xBAU,0x5AU,0xF6U,0x32U,0xADU,0xAEU,0x95U, \
    0x3AU,0x99U,0xE4U,0x75U,0x95U,0xBFU,0xA2U,0xACU, \
    0x6DU,0x1FU,0x67U,0xFEU,0x5BU,0x0CU,0x6EU,0xB2U, \
    0x53U,0x60U,0x01U,0x0BU,0x4CU,0x8CU,0xAAU,0x54U, \
    0x97U,0xD8U,0xC9U,0xA9U,0xE8U,0x44U,0x97U,0xD6U, \
    0xF2U,0xCFU,0xE9U,0xF5U,0x2AU,0x80U,0x8EU,0x2EU, \
    0x6FU,0xD2U,0x0FU,0x59U,0xDAU,0x04U,0x76U,0xCCU, \
    0x3BU,0x27U,0x1BU,0xD6U,0x82U,0x20U,0x77U,0xF1U, \
    0x99U,0xF9U,0x17U,0xC3U,0xC7U,0x76U,0x9CU,0x98U, \
    0x5FU,0xB6U,0x8FU,0x33U,0x91U,0x76U,0x25U,0x7BU, \
    0x2CU,0x38U,0x76U,0x76U,0xEBU,0x00U,0x33U,0xD7U, \
    0x17U,0xD9U,0xB4U,0x70U,0x47U,0xA9U,0x5AU,0xBEU, \
    0xDBU,0x2CU,0x22U,0x73U,0x79U,0x75U,0x4DU,0x89U, \
    0x83U,0xBFU,0xA7U,0x14U,0x20U,0xCCU,0x58U,0xFEU, \
    0x0FU,0x69U,0x61U,0x87U,0xC4U,0x36U,0x97U,0xF4U, \
    0x7FU,0x0EU,0xCBU,0x10U,0x13U,0x59U,0xA6U,0x87U, \
    0x1BU,0x5CU,0x3CU,0xB6U,0xDAU,0x5CU,0xD5U,0x76U, \
    0x91U,0xB9U,0x86U,0x56U,0x76U,0x69U,0x09U,0x0CU, \
    0x11U,0x48U,0x84U,0x98U,0xFEU,0x5AU,0x0BU,0x7BU }

/* RSA root private exponent  (256 bytes) */
#define ROOT_RSA_PRIV_BYTES \
  { 0x47U,0xC1U,0x81U,0x51U,0xE7U,0xA9U,0xDAU,0x1AU, \
    0xDAU,0x3DU,0x6FU,0xA4U,0xFEU,0xB8U,0xF2U,0xE0U, \
    0x72U,0x5AU,0x4AU,0x73U,0x1EU,0x31U,0xDBU,0x42U, \
    0x85U,0x31U,0xAEU,0x3FU,0x77U,0x3FU,0x8CU,0x1BU, \
    0x27U,0xE3U,0x0AU,0x07U,0x50U,0x57U,0xA8U,0xC7U, \
    0x42U,0x95U,0x06U,0xA4U,0x20U,0xAEU,0x0DU,0xA6U, \
    0x40U,0xF8U,0x15U,0x55U,0x04U,0x05U,0xB4U,0xEAU, \
    0x3FU,0x1AU,0x89U,0xFFU,0xCFU,0xDEU,0xBFU,0x7CU, \
    0xC0U,0x7AU,0xF3U,0x2EU,0xA6U,0xE2U,0xF9U,0x2AU, \
    0xCFU,0xE3U,0x20U,0xCCU,0x76U,0xC0U,0x4EU,0x0DU, \
    0x14U,0x31U,0x5DU,0xD8U,0x9CU,0xF9U,0xB9U,0x0AU, \
    0xEEU,0x49U,0xECU,0xB7U,0x10U,0x58U,0xD7U,0x2DU, \
    0xE7U,0xF9U,0x35U,0xBCU,0x39U,0x9DU,0xE3U,0xCAU, \
    0x4EU,0x61U,0x45U,0xD9U,0xF1U,0x62U,0x4FU,0xE8U, \
    0x67U,0x31U,0xFFU,0xF3U,0xEDU,0x42U,0x54U,0xE7U, \
    0x1EU,0x5CU,0xCAU,0xABU,0x58U,0x4CU,0x96U,0x74U, \
    0x9EU,0x8DU,0xF6U,0x80U,0x31U,0x37U,0x15U,0x5BU, \
    0xA3U,0x81U,0x92U,0x73U,0x39U,0xB7U,0x34U,0xDBU, \
    0x8FU,0xD1U,0x8AU,0xFAU,0xBAU,0x92U,0xE7U,0x21U, \
    0xAAU,0x5FU,0xC1U,0xC4U,0x07U,0xC2U,0x54U,0x4EU, \
    0xA1U,0xBEU,0x33U,0x01U,0xAEU,0x92U,0x89U,0xF5U, \
    0x5BU,0x54U,0xA0U,0xEFU,0x12U,0x6AU,0x9DU,0x7AU, \
    0x02U,0xFFU,0x48U,0x85U,0xC2U,0x44U,0x54U,0x79U, \
    0xF3U,0x36U,0x4BU,0x41U,0x86U,0x7CU,0x4AU,0x07U, \
    0xD3U,0xC6U,0xCEU,0xDBU,0x4FU,0xFEU,0xFDU,0x02U, \
    0xA4U,0x4CU,0x8BU,0xFEU,0x3BU,0xCDU,0x81U,0x19U, \
    0x4EU,0x4EU,0x81U,0x3BU,0xB2U,0x5FU,0x7DU,0xCDU, \
    0xC3U,0x02U,0x2BU,0x32U,0x1CU,0x8FU,0xB1U,0x46U, \
    0x79U,0x7CU,0x51U,0x22U,0x0EU,0x39U,0x7DU,0xD8U, \
    0x03U,0x0FU,0x53U,0x21U,0x67U,0xBCU,0x75U,0xEEU, \
    0x60U,0x60U,0x2CU,0x54U,0x96U,0x37U,0xEDU,0xEFU, \
    0xACU,0xC6U,0x16U,0x91U,0x53U,0xE7U,0x96U,0xD9U }

/* ===========================================================================
 * NEGATIVE TEST CASE ENUM
 * =========================================================================*/

typedef enum
{
    NEGATIVE_NONE          = 0,
    INVALID_MODULE_ID      = 1,
    INVALID_ECU_ID_CASE    = 2,
    INVALID_ECU_NAME_CASE  = 3,
    INVALID_APP_NBID_CASE  = 4,
    INVALID_MESSAGE_DIGEST = 5,
    INVALID_SIGNER_INFO    = 6,
    INVALID_REGION_INFO    = 7,
    INVALID_SW_LOCATION    = 8
} NegativeTestCase_e;

/* ===========================================================================
 * HEADER TYPE ENUM
 * =========================================================================*/

typedef enum
{
    HEADER_TYPE_NORMAL  = 0,
    HEADER_TYPE_BITDIFF = 1
} HeaderType_e;

/* ===========================================================================
 * PUBLIC API
 * =========================================================================*/

/**
 * Return a pointer to the module-level SHA-256 staging buffer.
 * Mirrors getAppSignedHeaderAddress() in the reference firmware.
 */
uint8_t *getAppSignedHeaderAddress(void);

/**
 * Generate a Normal (non-bit-diff) App Signed Header (882 bytes).
 *
 * @param moduleId      Module to locate in the SBIT.
 * @param headerBuffer  Caller buffer >= NORMAL_HEADER_SIZE bytes.
 * @param keySize       ED25519_KEY_SIZE or RSA_KEY_SIZE.
 * @param negativeCase  Negative test selector; NEGATIVE_NONE for valid output.
 * @return ERC_NO_ERROR on success.
 */
ErrCodeT generateAppSignedHeader(uint16_t           moduleId,
                                 uint8_t           *headerBuffer,
                                 uint16_t           keySize,
                                 NegativeTestCase_e negativeCase);

/**
 * Generate a Bit-Difference App Signed Header (914 bytes).
 *
 * @param moduleId      Module to locate in the SBIT.
 * @param headerBuffer  Caller buffer >= BITDIFF_HEADER_SIZE bytes.
 * @param keySize       ED25519_KEY_SIZE or RSA_KEY_SIZE.
 * @param negativeCase  Negative test selector.
 * @return ERC_NO_ERROR on success.
 */
ErrCodeT generateAppSignedHeaderBitDiff(uint16_t           moduleId,
                                        uint8_t           *headerBuffer,
                                        uint16_t           keySize,
                                        NegativeTestCase_e negativeCase);

/**
 * Wrapper – dispatches based on headerType (LAST meaningful param is negativeCase).
 *
 * @param moduleId      Module to locate in the SBIT.
 * @param headerBuffer  Caller-allocated output buffer.
 * @param keySize       ED25519_KEY_SIZE or RSA_KEY_SIZE.
 * @param headerType    HEADER_TYPE_NORMAL or HEADER_TYPE_BITDIFF.
 * @param negativeCase  Negative test selector (LAST parameter).
 * @return ERC_NO_ERROR on success.
 */
ErrCodeT getAppSignedHeader(uint16_t           moduleId,
                            uint8_t           *headerBuffer,
                            uint16_t           keySize,
                            HeaderType_e       headerType,
                            NegativeTestCase_e negativeCase);

#ifdef __cplusplus
}
#endif

#endif /* GENERATE_HOST_APP_SIGNED_HEADER_H */
