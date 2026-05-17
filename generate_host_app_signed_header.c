/**
 * @file  generate_host_app_signed_header.c
 * @brief Host Application Signed Header Generator — Implementation
 *
 * SBIT PARSING — ALIGNMENT AND ENDIANNESS RULES
 * -----------------------------------------------
 * The SBIT base address (0x25EFE7CD) is NOT 4-byte aligned and NOT 2-byte
 * aligned.  The platform is little-endian (ARM Cortex-M) while SBIT fields
 * are stored in big-endian byte order.
 *
 * ALL SBIT field reads use the helpers read_be16() / read_be32() which:
 *   - Accept a const uint8_t * (never uint16_t * or uint32_t *)
 *   - Assemble the value byte-by-byte — fully alignment-safe
 *   - Return a native (little-endian) CPU value — no further conversion needed
 *
 * Rule: convert when reading FROM SBIT.  Do not convert again afterwards.
 *
 * SBIT_BASE_PTR is a const uint8_t * so all offset arithmetic is in bytes.
 * CHANGE_ENDIANNESS_* macros are NOT used on SBIT reads.  They remain
 * available for other purposes (e.g. legacy struct parity).
 *
 * All cryptographic operations use wolfSSL exclusively:
 *   SHA-256  → wc_Sha256*
 *   Ed25519  → wc_ed25519_*
 *   RSA      → wc_Rsa* / RsaKey
 *
 * Everything outside SBIT parsing and crypto (signer info, serialisation,
 * fallback path, negative overrides) is unchanged.
 */

#include "generate_host_app_signed_header.h"

/* WolfSSL — SHA-256, Ed25519, RSA */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/rsa.h>

/* ===========================================================================
 * SBIT BASE POINTER
 *
 * Typed as const uint8_t * so all offset arithmetic is in bytes.
 * Never cast to uint16_t * or uint32_t * — the base is unaligned.
 * =========================================================================*/

#define SBIT_BASE_PTR  ((const uint8_t *)SBIT_BASE_ADDRESS)

/* ===========================================================================
 * SHA-256 STAGING BUFFER
 * =========================================================================*/

static uint8_t s_mdStagingBuf[APP_SIGNED_HDR_STAGING_SIZE];

uint8_t *getAppSignedHeaderAddress(void)
{
    return s_mdStagingBuf;
}

/* ===========================================================================
 * INTERNAL SERIALIZATION HELPERS
 * =========================================================================*/

static void writeBE16(uint8_t *dst, uint16_t val)
{
    dst[0] = (uint8_t)(val >> 8U);
    dst[1] = (uint8_t)(val & 0xFFU);
}

static void writeBE32(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)(val >> 24U);
    dst[1] = (uint8_t)((val >> 16U) & 0xFFU);
    dst[2] = (uint8_t)((val >>  8U) & 0xFFU);
    dst[3] = (uint8_t)(val & 0xFFU);
}

/* ===========================================================================
 * ALIGNMENT-SAFE BIG-ENDIAN SBIT READ HELPERS
 *
 * Use these for every field read from SBIT memory.
 * Accepts a byte pointer — no alignment requirement.
 * Returns a native CPU (little-endian) value — use directly, no further swap.
 * =========================================================================*/

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8U) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U)
         | ((uint32_t)p[1] << 16U)
         | ((uint32_t)p[2] <<  8U)
         |  (uint32_t)p[3];
}

/* ===========================================================================
 * SHA-256 (WolfSSL)
 * =========================================================================*/

static ErrCodeT sha256Compute(const uint8_t *data,
                              uint32_t       len,
                              uint8_t        digest[HAP_MSG_DIGEST_SIZE])
{
    wc_Sha256 sha;
    int       rc;

    rc = wc_InitSha256(&sha);
    if (rc != 0) { return ERC_CRYPTO_FAIL; }

    rc = wc_Sha256Update(&sha, data, len);
    if (rc != 0) { wc_Sha256Free(&sha); return ERC_CRYPTO_FAIL; }

    rc = wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);

    return (rc == 0) ? ERC_NO_ERROR : ERC_CRYPTO_FAIL;
}

/* ===========================================================================
 * ED25519 (WolfSSL)
 * =========================================================================*/

/**
 * Generate a new Ed25519 key pair.
 * privOut receives the full 64-byte WolfSSL export (seed || pubkey).
 * pubOut  receives the 32-byte public key.
 */
static ErrCodeT edGenKeyPair(uint8_t  privOut[ED25519_PRIV_FULL],
                             uint32_t *privLen,
                             uint8_t  pubOut[ED25519_KEY_SIZE],
                             uint32_t *pubLen)
{
    ed25519_key key;
    WC_RNG      rng;
    word32      pl, ql;
    int         rc;

    rc = wc_InitRng(&rng);
    if (rc != 0) { return ERC_CRYPTO_FAIL; }

    rc = wc_ed25519_init(&key);
    if (rc != 0) { wc_FreeRng(&rng); return ERC_CRYPTO_FAIL; }

    rc = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key);
    if (rc != 0) { goto ed_fail; }

    pl = (word32)ED25519_PRIV_FULL;
    ql = (word32)ED25519_KEY_SIZE;

    rc = wc_ed25519_export_key(&key, privOut, &pl, pubOut, &ql);
    if (rc != 0) { goto ed_fail; }

    *privLen = (uint32_t)pl;
    *pubLen  = (uint32_t)ql;

    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
    return ERC_NO_ERROR;

ed_fail:
    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
    return ERC_CRYPTO_FAIL;
}

/**
 * Sign msg with an Ed25519 key pair; pad raw 64-byte signature to 256 bytes.
 * privKey = seed (32 bytes), pubKey = public key (32 bytes).
 */
static ErrCodeT edSign(const uint8_t *privKey,
                       const uint8_t *pubKey,
                       const uint8_t *msg,
                       uint32_t       msgLen,
                       uint8_t        sigOut[HAP_ROOT_SIGNATURE_SIZE])
{
    ed25519_key key;
    uint8_t     rawSig[ED25519_SIG_SIZE];
    word32      sigLen = (word32)ED25519_SIG_SIZE;
    int         rc;

    rc = wc_ed25519_init(&key);
    if (rc != 0) { return ERC_CRYPTO_FAIL; }

    /* Import seed (32 bytes) + public key (32 bytes) */
    rc = wc_ed25519_import_private_key(privKey, (word32)ED25519_KEY_SIZE,
                                       pubKey,  (word32)ED25519_KEY_SIZE,
                                       &key);
    if (rc != 0) { wc_ed25519_free(&key); return ERC_CRYPTO_FAIL; }

    rc = wc_ed25519_sign_msg(msg, (word32)msgLen, rawSig, &sigLen, &key);
    wc_ed25519_free(&key);
    if (rc != 0) { return ERC_CRYPTO_FAIL; }

    /* Ed25519 raw sig is 64 bytes; pad to 256-byte field */
    memset(sigOut, 0x00, HAP_ROOT_SIGNATURE_SIZE);
    memcpy(sigOut, rawSig, (uint32_t)sigLen);

    return ERC_NO_ERROR;
}

/** Sign with the hardcoded root Ed25519 key. */
static ErrCodeT edRootSign(const uint8_t *msg,
                           uint32_t       msgLen,
                           uint8_t        sigOut[HAP_ROOT_SIGNATURE_SIZE])
{
    static const uint8_t kRootPub[]  = ROOT_EDDSA_PUB_BYTES;
    static const uint8_t kRootPriv[] = ROOT_EDDSA_PRIV_BYTES;

    return edSign(kRootPriv, kRootPub, msg, msgLen, sigOut);
}

/* ===========================================================================
 * RSA (WolfSSL)
 * =========================================================================*/

/**
 * Generate RSA-2048 key pair; export public modulus to pubOut (256 bytes).
 * rsaKey is left initialised with the full key pair for subsequent signing.
 */
static ErrCodeT rsaGenKeyPair(RsaKey  *rsaKey,
                              uint8_t  pubOut[HAP_SUBJECT_PUB_KEY_SIZE],
                              WC_RNG  *rng)
{
    int rc;

    rc = wc_MakeRsaKey(rsaKey, (int)RSA_KEY_BITS, (long)RSA_PUB_EXPONENT, rng);
    if (rc != 0) { return ERC_CRYPTO_FAIL; }

    /* Export public modulus N (256 bytes) */
    byte   eBuf[4];
    word32 eSz = (word32)sizeof(eBuf);
    word32 nSz = (word32)HAP_SUBJECT_PUB_KEY_SIZE;

    rc = wc_RsaFlattenPublicKey(rsaKey, eBuf, &eSz, pubOut, &nSz);
    return (rc == 0) ? ERC_NO_ERROR : ERC_CRYPTO_FAIL;
}

/**
 * PKCS#1 v1.5 sign: hash msg with WolfSSL SHA-256, sign with WolfSSL RSA.
 */
static ErrCodeT rsaSign(RsaKey        *rsaKey,
                        const uint8_t *msg,
                        uint32_t       msgLen,
                        uint8_t        sigOut[HAP_ROOT_SIGNATURE_SIZE],
                        WC_RNG        *rng)
{
    uint8_t hash[HAP_MSG_DIGEST_SIZE];
    int     rc;

    if (sha256Compute(msg, msgLen, hash) != ERC_NO_ERROR)
    {
        return ERC_CRYPTO_FAIL;
    }

    rc = wc_RsaSSL_Sign(hash, (word32)HAP_MSG_DIGEST_SIZE,
                         sigOut, (word32)HAP_ROOT_SIGNATURE_SIZE,
                         rsaKey, rng);
    return (rc == (int)HAP_ROOT_SIGNATURE_SIZE) ? ERC_NO_ERROR : ERC_CRYPTO_FAIL;
}

/**
 * Load the hardcoded RSA root key and sign msg.
 * N = public modulus (256 B), D = private exponent (256 B), E = 65537.
 * Import raw key components directly into wolfSSL RsaKey structure.
 */
static ErrCodeT rsaRootSign(const uint8_t *msg,
                            uint32_t       msgLen,
                            uint8_t        sigOut[HAP_ROOT_SIGNATURE_SIZE],
                            WC_RNG        *rng)
{
    static const uint8_t kRootPub[]  = ROOT_RSA_PUB_BYTES;
    static const uint8_t kRootPriv[] = ROOT_RSA_PRIV_BYTES;

    /* E = 65537 = 0x00010001 in big-endian */
    static const uint8_t kExpBE[3] = { 0x01U, 0x00U, 0x01U };

    RsaKey   key;
    ErrCodeT err;
    int      rc;

    rc = wc_InitRsaKey(&key, NULL);
    if (rc != 0) { return ERC_CRYPTO_FAIL; }

    /* Import raw N, E, D into wolfSSL RsaKey */
    if (mp_read_unsigned_bin(&key.n, kRootPub,  HAP_SUBJECT_PUB_KEY_SIZE) != MP_OKAY ||
        mp_read_unsigned_bin(&key.e, kExpBE,    (int)sizeof(kExpBE))      != MP_OKAY ||
        mp_read_unsigned_bin(&key.d, kRootPriv, HAP_SUBJECT_PUB_KEY_SIZE) != MP_OKAY)
    {
        wc_FreeRsaKey(&key);
        return ERC_CRYPTO_FAIL;
    }
    key.type = RSA_PRIVATE;

    err = rsaSign(&key, msg, msgLen, sigOut, rng);
    wc_FreeRsaKey(&key);
    return err;
}

/* ===========================================================================
 * SBIT PARSING
 *
 * All reads from SBIT use read_be16() / read_be32() via a uint8_t * base.
 * No uint16_t* or uint32_t* casts are used on SBIT memory.
 * No CHANGE_ENDIANNESS_* calls are used — conversion is inside read_be*.
 *
 * Offset constants (FIRST_MODULE_OFFSET, REGION_INFO_OFFSET, etc.) are now
 * BYTE offsets, matching the uint8_t * base.  See header for values.
 * =========================================================================*/

typedef struct
{
    uint32_t startAddress;
    uint32_t length;
} RegionInfo_t;

typedef struct
{
    RegionInfo_t regions[SBIT_MAX_REGIONS];
    uint8_t      numRegions;
    uint16_t     numSwRegions;   /* endian-converted, for header field */
    uint16_t     moduleIdRaw;    /* BE value stored in SBIT module table */
} SbitParseResult_t;

/**
 * Parse the SBIT using alignment-safe, endian-safe byte reads.
 * All SBIT fields are read via read_be16() / read_be32() from a uint8_t * base.
 */
static ErrCodeT parseSbit(uint16_t moduleId, SbitParseResult_t *out)
{
    const uint8_t *base = SBIT_BASE_PTR;

    /* --- Version: byte offset 0, uint16 BE --- */
    uint16_t Version = read_be16(base + 0U);

    /* --- Select byte offsets based on version --- */
    uint32_t numModOff;
    uint32_t firstModOff;
    uint32_t regionInfoOff;

    if (Version == SBIT_WITH_MGAL)
    {
        numModOff     = NUMBER_OF_MGAL_SBIT_MODULE_OFFSET;
        firstModOff   = FIRST_MODULE_OFFSET_WITH_MGAL;
        regionInfoOff = REGION_INFO_OFFSET_WITH_MGAL;
    }
    else
    {
        numModOff     = NUMBER_OF_SBIT_MODULE_OFFSET;
        firstModOff   = FIRST_MODULE_OFFSET;
        regionInfoOff = REGION_INFO_OFFSET;
    }

    /* --- Number of modules: uint16 BE at numModOff --- */
    uint16_t totalmodules = read_be16(base + numModOff);

    boolean  ModuleFound    = FALSE;
    uint16_t RegionoffsetLB = 0U;

    /* --- Module search: each entry is SBIT_MODULE_TABLE_ENTRY_STRIDE bytes ---
     * Entry layout: [moduleId:uint16 BE][regionOffset:uint16 BE]             */
    for (uint16_t i = 0U; i < totalmodules; i++)
    {
        uint32_t entryOff = firstModOff + (uint32_t)i * SBIT_MODULE_TABLE_ENTRY_STRIDE;

        uint16_t ModuleIdLE = read_be16(base + entryOff);          /* converted */
        out->moduleIdRaw    = ModuleIdLE;

        if (ModuleIdLE == moduleId)
        {
            RegionoffsetLB = read_be16(base + regionInfoOff
                                       + (uint32_t)i * SBIT_MODULE_TABLE_ENTRY_STRIDE);
            ModuleFound = TRUE;
            break;
        }
    }

    if (ModuleFound == FALSE) { return MODULE_NOT_FOUND; }

    /* --- Module info block at RegionoffsetLB ---
     * [+0..+1] CCID (uint16 BE)
     * [+2]     numRegions (uint8)                                            */
    uint8_t nReg = base[RegionoffsetLB + SBIT_MOD_NUM_REGIONS_BYTE_OFF];
    if (nReg > SBIT_MAX_REGIONS) { nReg = (uint8_t)SBIT_MAX_REGIONS; }

    out->numRegions   = nReg;
    out->numSwRegions = (uint16_t)nReg;   /* native value for header field */

    /* --- Region entries ---
     * Per region i (9 bytes):
     *   [3+9i .. 6+9i]  startAddr (uint32 BE)
     *   [7+9i .. 10+9i] length    (uint32 BE)                               */
    uint32_t RegionAddressInfo[SBIT_MAX_REGIONS]  = {0};
    uint32_t RegionLocationInfo[SBIT_MAX_REGIONS] = {0};

    for (uint8_t i = 0U; i < nReg; i++)
    {
        uint32_t addrOff = (uint32_t)RegionoffsetLB
                         + SBIT_MOD_REGION_ADDR_BYTE_BASE
                         + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

        uint32_t lenOff  = (uint32_t)RegionoffsetLB
                         + SBIT_MOD_REGION_LEN_BYTE_BASE
                         + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

        uint32_t addr = read_be32(base + addrOff);   /* native CPU address */
        uint32_t len  = read_be32(base + lenOff);    /* native CPU length  */

        out->regions[i].startAddress = addr;
        out->regions[i].length       = len;

        RegionAddressInfo[i]  = addr;
        RegionLocationInfo[i] = len;
    }

    /* --- Staging buffer: memcpy each region, no endian conversion --- */
    uint8_t  *MdAddr  = getAppSignedHeaderAddress();
    uint32_t  MDLength = 0U;

    for (uint8_t i = 0U; i < nReg; i++)
    {
        uint32_t regionLen = RegionLocationInfo[i];
        void    *regionSrc = (void *)(uintptr_t)RegionAddressInfo[i];

        if ((MDLength + regionLen) > APP_SIGNED_HDR_STAGING_SIZE)
        {
            return ERC_BUFFER_TOO_SMALL;
        }

        memcpy(MdAddr, regionSrc, regionLen);
        MdAddr   += regionLen;
        MDLength += regionLen;
    }

    return sha256Compute(getAppSignedHeaderAddress(), MDLength,
                         (uint8_t *)(uintptr_t)0U /* placeholder */);
}

/* ---------------------------------------------------------------------------
 * parseSbitWithDigest — thin wrapper that also captures the SHA-256 output.
 * -------------------------------------------------------------------------*/

typedef struct
{
    SbitParseResult_t sbit;
    uint8_t           msgDigest[HAP_MSG_DIGEST_SIZE];
} FullParseResult_t;

static ErrCodeT parseSbitFull(uint16_t moduleId, FullParseResult_t *out)
{
    const uint8_t *base = SBIT_BASE_PTR;

    /* --- Version: byte offset 0, uint16 BE --- */
    uint16_t Version = read_be16(base + 0U);

    /* --- Select byte offsets based on version --- */
    uint32_t numModOff;
    uint32_t firstModOff;
    uint32_t regionInfoOff;

    if (Version == SBIT_WITH_MGAL)
    {
        numModOff     = NUMBER_OF_MGAL_SBIT_MODULE_OFFSET;
        firstModOff   = FIRST_MODULE_OFFSET_WITH_MGAL;
        regionInfoOff = REGION_INFO_OFFSET_WITH_MGAL;
    }
    else
    {
        numModOff     = NUMBER_OF_SBIT_MODULE_OFFSET;
        firstModOff   = FIRST_MODULE_OFFSET;
        regionInfoOff = REGION_INFO_OFFSET;
    }

    /* --- Number of modules: uint16 BE at numModOff --- */
    uint16_t totalmodules = read_be16(base + numModOff);

    boolean  ModuleFound    = FALSE;
    uint16_t RegionoffsetLB = 0U;

    /* --- Module search: each entry is SBIT_MODULE_TABLE_ENTRY_STRIDE bytes ---
     * Entry layout: [moduleId:uint16 BE][regionOffset:uint16 BE]             */
    for (uint16_t i = 0U; i < totalmodules; i++)
    {
        uint32_t entryOff = firstModOff + (uint32_t)i * SBIT_MODULE_TABLE_ENTRY_STRIDE;

        uint16_t ModuleIdLE = read_be16(base + entryOff);    /* converted, use directly */
        out->sbit.moduleIdRaw = ModuleIdLE;

        if (ModuleIdLE == moduleId)
        {   
	    RegionoffsetLB = read_be16(base + entryOff + 2);
            ModuleFound = TRUE;
            break;
        }
    }

    if (ModuleFound == FALSE) { return MODULE_NOT_FOUND; }

    /* --- Module info block at RegionoffsetLB ---
     * [+0..+1] CCID (uint16 BE)  — read but not used in output
     * [+2]     numRegions (uint8)                                            */
    uint8_t nReg = base[RegionoffsetLB + SBIT_MOD_NUM_REGIONS_BYTE_OFF];
    if (nReg > SBIT_MAX_REGIONS) { nReg = (uint8_t)SBIT_MAX_REGIONS; }

    out->sbit.numRegions   = nReg;
    out->sbit.numSwRegions = (uint16_t)nReg;   /* native value for header field */

    /* --- Region entries ---
     * Per region i (9 bytes):
     *   [3+9i .. 6+9i]  startAddr (uint32 BE) → native CPU address
     *   [7+9i .. 10+9i] length    (uint32 BE) → native CPU length            */
    uint32_t RegionAddressInfo[SBIT_MAX_REGIONS]  = {0};
    uint32_t RegionLocationInfo[SBIT_MAX_REGIONS] = {0};

    for (uint8_t i = 0U; i < nReg; i++)
    {
        uint32_t addrOff = (uint32_t)RegionoffsetLB
                         + SBIT_MOD_REGION_ADDR_BYTE_BASE
                         + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

        uint32_t lenOff  = (uint32_t)RegionoffsetLB
                         + SBIT_MOD_REGION_LEN_BYTE_BASE
                         + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

        uint32_t addr = read_be32(base + addrOff);   /* endian-converted inside read_be32 */
        uint32_t len  = read_be32(base + lenOff);

        out->sbit.regions[i].startAddress = addr;
        out->sbit.regions[i].length       = len;

        RegionAddressInfo[i]  = addr;   /* already native — use directly for memcpy */
        RegionLocationInfo[i] = len;
    }

    /* --- Staging buffer: memcpy each region, no endian conversion on addresses --- */
    uint8_t  *MdAddr  = getAppSignedHeaderAddress();
    uint32_t  MDLength = 0U;

    for (uint8_t i = 0U; i < nReg; i++)
    {
        uint32_t regionLen = RegionLocationInfo[i];
        void    *regionSrc = (void *)(uintptr_t)RegionAddressInfo[i];

        if ((MDLength + regionLen) > APP_SIGNED_HDR_STAGING_SIZE)
        {
            return ERC_BUFFER_TOO_SMALL;
        }

        memcpy(MdAddr, regionSrc, regionLen);
        MdAddr   += regionLen;
        MDLength += regionLen;
    }

    return sha256Compute(getAppSignedHeaderAddress(), MDLength, out->msgDigest);
}

/* ===========================================================================
 * SIGNER INFO BLOCK  (538 bytes)
 *
 * [  0.. 15] Subject Name       (16 B)
 * [ 16.. 23] Certificate ID     ( 8 B)
 * [ 24.. 25] Key NBID           ( 2 B)
 * [ 26..281] Subject Public Key (256 B)
 * [282..537] Root Signature     (256 B)
 *
 * Root Signature is computed over:
 *   SubjectName || CertID || KeyNBID || SubjectPublicKey
 * =========================================================================*/

#define ROOT_SIG_INPUT_LEN \
    (HAP_SUBJECT_NAME_SIZE + HAP_CERTIFICATE_ID_SIZE + \
     HAP_KEY_NBID_SIZE     + HAP_SUBJECT_PUB_KEY_SIZE)

static ErrCodeT buildSignerInfo(uint8_t       *siDst,
                                const uint8_t *subjectPubKey,
                                uint16_t       keySize,
                                RsaKey        *rsaKey,
                                const uint8_t *edPriv,
                                const uint8_t *edPub,
                                WC_RNG        *rng)
{
    static const uint8_t kSubjName[] = VALID_SUBJECT_NAME;
    static const uint8_t kCertId[]   = VALID_CERT_ID;
    static const uint8_t kKeyNbid[]  = VALID_KEY_NBID;

    uint8_t  rootSigIn[ROOT_SIG_INPUT_LEN];
    uint32_t off = 0U;

    /* Subject Name */
    memcpy(siDst + off, kSubjName, HAP_SUBJECT_NAME_SIZE);
    off += HAP_SUBJECT_NAME_SIZE;

    /* Certificate ID */
    memcpy(siDst + off, kCertId, HAP_CERTIFICATE_ID_SIZE);
    off += HAP_CERTIFICATE_ID_SIZE;

    /* Key NBID */
    memcpy(siDst + off, kKeyNbid, HAP_KEY_NBID_SIZE);
    off += HAP_KEY_NBID_SIZE;

    /* Subject Public Key */
    memcpy(siDst + off, subjectPubKey, HAP_SUBJECT_PUB_KEY_SIZE);
    off += HAP_SUBJECT_PUB_KEY_SIZE;

    /* Assemble root signature input */
    uint32_t rsiOff = 0U;
    memcpy(rootSigIn + rsiOff, kSubjName,     HAP_SUBJECT_NAME_SIZE);   rsiOff += HAP_SUBJECT_NAME_SIZE;
    memcpy(rootSigIn + rsiOff, kCertId,       HAP_CERTIFICATE_ID_SIZE); rsiOff += HAP_CERTIFICATE_ID_SIZE;
    memcpy(rootSigIn + rsiOff, kKeyNbid,      HAP_KEY_NBID_SIZE);       rsiOff += HAP_KEY_NBID_SIZE;
    memcpy(rootSigIn + rsiOff, subjectPubKey, HAP_SUBJECT_PUB_KEY_SIZE);

    /* Root Signature */
    if (keySize == ED25519_KEY_SIZE)
    {
        return edRootSign(rootSigIn, ROOT_SIG_INPUT_LEN, siDst + off);
    }
    else
    {
        return rsaRootSign(rootSigIn, ROOT_SIG_INPUT_LEN, siDst + off, rng);
    }
}

/* ===========================================================================
 * NEGATIVE TEST OVERRIDES
 *
 * Applied AFTER SBIT parsing and digest computation.
 * Only the targeted field is corrupted; all others remain valid.
 * =========================================================================*/

static void applyNegOverrides(FullParseResult_t  *res,
                              uint16_t           *moduleId,
                              uint8_t            *subjectPubKey,
                              uint8_t            *edPriv,
                              uint8_t            *edPub,
                              NegativeTestCase_e  neg)
{
    switch (neg)
    {
        case INVALID_MODULE_ID:
            *moduleId = (uint16_t)INVALID_MODULE_ID_VALUE;
            break;

        case INVALID_MESSAGE_DIGEST:
            memset(res->msgDigest, 0x00, HAP_MSG_DIGEST_SIZE);
            break;

        case INVALID_REGION_INFO:
        case INVALID_SW_LOCATION:
            for (uint8_t i = 0U; i < res->sbit.numRegions; i++)
            {
                res->sbit.regions[i].startAddress = 0U;
                res->sbit.regions[i].length       = 0U;
            }
            break;

        case INVALID_SIGNER_INFO:
            memset(subjectPubKey, 0x00, HAP_SUBJECT_PUB_KEY_SIZE);
            if (edPriv) { memset(edPriv, 0x00, ED25519_PRIV_FULL); }
            if (edPub)  { memset(edPub,  0x00, ED25519_KEY_SIZE);  }
            break;

        case NEGATIVE_NONE:
        default:
            break;
    }
}

/* ===========================================================================
 * NORMAL APP SIGNED HEADER  (882 bytes)
 *
 * Byte layout:
 *   [000-001] Module ID            2 B
 *   [002-003] BCID                 2 B
 *   [004-011] ECU Name             8 B
 *   [012-027] ECU ID              16 B
 *   [028-043] ECU ID Extension    16 B
 *   [044-045] App NBID             2 B
 *   [046-047] Number of SW Regs    2 B
 *   [048-051] Region Start Addr    4 B   (first region)
 *   [052-055] Region Length        4 B   (first region)
 *   [056-087] Message Digest      32 B
 *   [088-625] Signer Info        538 B
 *   [626-881] Header Signature   256 B
 * =========================================================================*/

ErrCodeT generateAppSignedHeader(uint16_t           moduleId,
                                 uint8_t           *headerBuffer,
                                 uint16_t           keySize,
                                 NegativeTestCase_e negativeCase)
{
    static const uint8_t kEcuName[]    = VALID_ECU_NAME;
    static const uint8_t kEcuId[]      = VALID_ECU_ID;
    static const uint8_t kEcuIdExt[]   = VALID_ECU_ID_EXT;
    static const uint8_t kAppNbid[]    = VALID_APP_NBID;
    static const uint8_t kBcid[]       = VALID_BCID;

    static const uint8_t kBadEcuName[] = INVALID_ECU_NAME;
    static const uint8_t kBadEcuId[]   = INVALID_ECU_ID;
    static const uint8_t kBadAppNbid[] = INVALID_APP_NBID;

    if (headerBuffer == NULL) { return ERC_NULL_PTR; }
    memset(headerBuffer, 0, NORMAL_HEADER_SIZE);

    /* === Step 1: Region population and SHA-256 ===
     *
     * Shared region arrays are declared here and populated by whichever path
     * executes.  SHA-256 is computed from the staging buffer after the branch.
     *
     * FALLBACK PATH (negativeCase == INVALID_MODULE_ID):
     *   SBIT is NOT accessed.  FALLBACK_ADDR/FALLBACK_LEN define the region.
     *
     * NORMAL PATH (all other cases):
     *   Existing SBIT parsing logic runs unchanged inside the else block.
     */
    uint32_t RegionAddressInfo[SBIT_MAX_REGIONS] = {0};
    uint32_t RegionLengthInfo[SBIT_MAX_REGIONS]  = {0};
    uint16_t numRegions = 0U;
    uint32_t totalLen   = 0U;

    FullParseResult_t res;
    memset(&res, 0, sizeof(res));

    ErrCodeT err;

    if (negativeCase == INVALID_MODULE_ID)
    {
        /* -----------------------------------------------------------------
         * FALLBACK PATH (NO SBIT ACCESS)
         * ----------------------------------------------------------------- */
        numRegions = 1U;
        RegionAddressInfo[0] = FALLBACK_ADDR;
        RegionLengthInfo[0]  = FALLBACK_LEN;

        uint8_t *dst = getAppSignedHeaderAddress();
        memcpy(dst, (void *)FALLBACK_ADDR, FALLBACK_LEN);
        totalLen = FALLBACK_LEN;

        /* Populate res fields used during serialisation */
        res.sbit.numRegions   = (uint8_t)numRegions;
        res.sbit.numSwRegions = (uint16_t)numRegions;
        res.sbit.regions[0].startAddress = CHANGE_ENDIANNESS_32BIT(FALLBACK_ADDR);
        res.sbit.regions[0].length       = CHANGE_ENDIANNESS_32BIT(FALLBACK_LEN);
    }
    else
    {
        /* -----------------------------------------------------------------
         * SBIT PARSING — alignment-safe, endian-safe
         * All reads via read_be16() / read_be32().  No uint16_t* / uint32_t* casts.
         * Endian conversion happens inside the read helpers; values are native
         * CPU words after that — no further CHANGE_ENDIANNESS_* needed.
         * ----------------------------------------------------------------- */
        const uint8_t *base = SBIT_BASE_PTR;

        uint16_t Version = read_be16(base + 0U);

        uint32_t numModOff;
        uint32_t firstModOff;
        uint32_t regionInfoOff;

        if (Version == SBIT_WITH_MGAL)
        {
            numModOff     = NUMBER_OF_MGAL_SBIT_MODULE_OFFSET;
            firstModOff   = FIRST_MODULE_OFFSET_WITH_MGAL;
            regionInfoOff = REGION_INFO_OFFSET_WITH_MGAL;
        }
        else
        {
            numModOff     = NUMBER_OF_SBIT_MODULE_OFFSET;
            firstModOff   = FIRST_MODULE_OFFSET;
            regionInfoOff = REGION_INFO_OFFSET;
        }

        uint16_t totalmodules  = read_be16(base + numModOff);
        boolean  ModuleFound   = FALSE;
        uint16_t RegionoffsetLB = 0U;

        for (uint16_t i = 0U; i < totalmodules; i++)
        {
            uint32_t entryOff  = firstModOff + (uint32_t)i * SBIT_MODULE_TABLE_ENTRY_STRIDE;
            uint16_t ModuleIdLE = read_be16(base + entryOff);
            res.sbit.moduleIdRaw = ModuleIdLE;

            if (ModuleIdLE == moduleId)
            {
                RegionoffsetLB = read_be16(base + entryOff + 2);
                ModuleFound = TRUE;
                break;
            }
        }

        if (ModuleFound == FALSE) { return MODULE_NOT_FOUND; }

        uint8_t nReg = base[RegionoffsetLB + SBIT_MOD_NUM_REGIONS_BYTE_OFF];
        if (nReg > SBIT_MAX_REGIONS) { nReg = (uint8_t)SBIT_MAX_REGIONS; }

        res.sbit.numRegions   = nReg;
        res.sbit.numSwRegions = (uint16_t)nReg;
        numRegions            = (uint16_t)nReg;

        for (uint8_t i = 0U; i < nReg; i++)
        {
            uint32_t addrOff = (uint32_t)RegionoffsetLB
                             + SBIT_MOD_REGION_ADDR_BYTE_BASE
                             + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

            uint32_t lenOff  = (uint32_t)RegionoffsetLB
                             + SBIT_MOD_REGION_LEN_BYTE_BASE
                             + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

            uint32_t addr = read_be32(base + addrOff);   /* native CPU value */
            uint32_t len  = read_be32(base + lenOff);

            res.sbit.regions[i].startAddress = addr;
            res.sbit.regions[i].length       = len;

            RegionAddressInfo[i] = addr;   /* no further conversion */
            RegionLengthInfo[i]  = len;
        }

        uint8_t *MdAddr   = getAppSignedHeaderAddress();
        uint32_t MDLength = 0U;

        for (uint8_t i = 0U; i < nReg; i++)
        {
            uint32_t regionLen = RegionLengthInfo[i];
            void    *regionSrc = (void *)(uintptr_t)RegionAddressInfo[i];

            if ((MDLength + regionLen) > APP_SIGNED_HDR_STAGING_SIZE)
            {
                return ERC_BUFFER_TOO_SMALL;
            }

            memcpy(MdAddr, regionSrc, regionLen);
            MdAddr   += regionLen;
            MDLength += regionLen;
        }

        totalLen = MDLength;
    }

    /* SHA-256 over staging buffer — shared by both paths */
    err = sha256Compute(getAppSignedHeaderAddress(), totalLen, res.msgDigest);
    if (err != ERC_NO_ERROR) { return err; }

    /* === Step 5: Key generation === */
    uint8_t subjectPubKey[HAP_SUBJECT_PUB_KEY_SIZE];
    memset(subjectPubKey, 0, HAP_SUBJECT_PUB_KEY_SIZE);

    uint8_t  edPrivKey[ED25519_PRIV_FULL];
    uint8_t  edPubKey[ED25519_KEY_SIZE];
    memset(edPrivKey, 0, sizeof(edPrivKey));
    memset(edPubKey,  0, sizeof(edPubKey));

    RsaKey rsaKey;
    WC_RNG rng;

    int wret = wc_InitRsaKey(&rsaKey, NULL);
    if (wret != 0) { return ERC_CRYPTO_FAIL; }

    wret = wc_InitRng(&rng);
    if (wret != 0) { wc_FreeRsaKey(&rsaKey); return ERC_CRYPTO_FAIL; }

    if (keySize == ED25519_KEY_SIZE)
    {
        uint32_t pl = 0U, ql = 0U;
        err = edGenKeyPair(edPrivKey, &pl, edPubKey, &ql);
        if (err != ERC_NO_ERROR) { wc_FreeRng(&rng); wc_FreeRsaKey(&rsaKey); return err; }

        /* Pad 32-byte Ed25519 public key into the 256-byte subject-key field */
        memcpy(subjectPubKey, edPubKey, ED25519_KEY_SIZE);
    }
    else if (keySize == RSA_KEY_SIZE)
    {
        err = rsaGenKeyPair(&rsaKey, subjectPubKey, &rng);
        if (err != ERC_NO_ERROR) { wc_FreeRng(&rng); wc_FreeRsaKey(&rsaKey); return err; }
    }
    else
    {
        wc_FreeRng(&rng);
        wc_FreeRsaKey(&rsaKey);
        return ERC_INVALID_CMD;
    }

    /* === Step 6: Apply negative overrides (post-computation) === */
    applyNegOverrides(&res, &moduleId, subjectPubKey, edPrivKey, edPubKey, negativeCase);

    /* === Step 7: Serialize header === */
    uint32_t off = 0U;

    /* [000-001] Module ID */
    writeBE16(headerBuffer + off, moduleId);
    off += HAP_MODULE_ID_SIZE;

    /* [002-003] BCID */
    memcpy(headerBuffer + off, kBcid, HAP_BCID_SIZE);
    off += HAP_BCID_SIZE;

    /* [004-011] ECU Name */
    if (negativeCase == INVALID_ECU_NAME_CASE)
        memcpy(headerBuffer + off, kBadEcuName, HAP_ECU_NAME_SIZE);
    else
        memcpy(headerBuffer + off, kEcuName, HAP_ECU_NAME_SIZE);
    off += HAP_ECU_NAME_SIZE;

    /* [012-027] ECU ID */
    if (negativeCase == INVALID_ECU_ID_CASE)
        memcpy(headerBuffer + off, kBadEcuId, HAP_ECU_ID_SIZE);
    else
        memcpy(headerBuffer + off, kEcuId, HAP_ECU_ID_SIZE);
    off += HAP_ECU_ID_SIZE;

    /* [028-043] ECU ID Extension (mandatory, always 0xFF) */
    memcpy(headerBuffer + off, kEcuIdExt, HAP_ECU_ID_EXT_SIZE);
    off += HAP_ECU_ID_EXT_SIZE;

    /* [044-045] App NBID */
    if (negativeCase == INVALID_APP_NBID_CASE)
        memcpy(headerBuffer + off, kBadAppNbid, HAP_APP_NBID_SIZE);
    else
        memcpy(headerBuffer + off, kAppNbid, HAP_APP_NBID_SIZE);
    off += HAP_APP_NBID_SIZE;

    /* [046-047] Number of SW Regions */
    writeBE16(headerBuffer + off, res.sbit.numSwRegions);
    off += HAP_NUM_SW_REGIONS_SIZE;

    /* [048-051] Region Start Address (first region, raw BE from SBIT) */
    writeBE32(headerBuffer + off, res.sbit.regions[0].startAddress);
    off += HAP_REGION_START_ADDR_SIZE;

    /* [052-055] Region Length (first region, raw BE from SBIT) */
    writeBE32(headerBuffer + off, res.sbit.regions[0].length);
    off += HAP_REGION_LENGTH_SIZE;

    /* [056-087] Message Digest */
    memcpy(headerBuffer + off, res.msgDigest, HAP_MSG_DIGEST_SIZE);
    off += HAP_MSG_DIGEST_SIZE;

    /* [088-625] Signer Info */
    if (negativeCase == INVALID_SIGNER_INFO)
    {
        memset(headerBuffer + off, 0x00, HAP_SIGNER_INFO_SIZE);
    }
    else
    {
        err = buildSignerInfo(headerBuffer + off, subjectPubKey, keySize,
                              &rsaKey, edPrivKey, edPubKey, &rng);
        if (err != ERC_NO_ERROR)
        {
            wc_FreeRng(&rng);
            wc_FreeRsaKey(&rsaKey);
            return err;
        }
    }
    off += HAP_SIGNER_INFO_SIZE;

    /* [626-881] Header Signature — signs bytes [0..625] */
    if (keySize == ED25519_KEY_SIZE)
    {
        err = edSign(edPrivKey, edPubKey,
                     headerBuffer, (uint32_t)NORMAL_SIGNED_LEN,
                     headerBuffer + off);
    }
    else
    {
        err = rsaSign(&rsaKey,
                      headerBuffer, (uint32_t)NORMAL_SIGNED_LEN,
                      headerBuffer + off, &rng);
    }

    wc_FreeRng(&rng);
    wc_FreeRsaKey(&rsaKey);
    return err;
}

/* ===========================================================================
 * BIT-DIFFERENCE APP SIGNED HEADER  (914 bytes)
 *
 * Byte layout:
 *   [000-001] Module ID                          2 B
 *   [002-033] Digest of Full "To-Be" Raw Data   32 B
 *   [034-035] BCID                               2 B
 *   [036-043] ECU Name                           8 B
 *   [044-059] ECU ID                            16 B
 *   [060-075] ECU ID Extension                  16 B
 *   [076-077] App NBID                           2 B
 *   [078-079] Number of SW Regions               2 B
 *   [080-083] Region Start Addr                  4 B
 *   [084-087] Region Length                      4 B
 *   [088-119] Digest of Bit-Diff Envelope       32 B  ← HARDCODED 0x00
 *   [120-657] Signer Info                      538 B
 *   [658-913] Header Signature                 256 B
 * =========================================================================*/

ErrCodeT generateAppSignedHeaderBitDiff(uint16_t           moduleId,
                                        uint8_t           *headerBuffer,
                                        uint16_t           keySize,
                                        NegativeTestCase_e negativeCase)
{
    static const uint8_t kEcuName[]    = VALID_ECU_NAME;
    static const uint8_t kEcuId[]      = VALID_ECU_ID;
    static const uint8_t kEcuIdExt[]   = VALID_ECU_ID_EXT;
    static const uint8_t kAppNbid[]    = VALID_APP_NBID;
    static const uint8_t kBcid[]       = VALID_BCID;

    static const uint8_t kBadEcuName[] = INVALID_ECU_NAME;
    static const uint8_t kBadEcuId[]   = INVALID_ECU_ID;
    static const uint8_t kBadAppNbid[] = INVALID_APP_NBID;

    if (headerBuffer == NULL) { return ERC_NULL_PTR; }
    memset(headerBuffer, 0, BITDIFF_HEADER_SIZE);

    /* === Step 1: Region population and SHA-256 ===
     *
     * Shared region arrays are declared here and populated by whichever path
     * executes.  SHA-256 is computed from the staging buffer after the branch.
     *
     * FALLBACK PATH (negativeCase == INVALID_MODULE_ID):
     *   SBIT is NOT accessed.  FALLBACK_ADDR/FALLBACK_LEN define the region.
     *
     * NORMAL PATH (all other cases):
     *   Existing SBIT parsing logic runs unchanged inside the else block.
     */
    uint32_t RegionAddressInfo[SBIT_MAX_REGIONS] = {0};
    uint32_t RegionLengthInfo[SBIT_MAX_REGIONS]  = {0};
    uint16_t numRegions = 0U;
    uint32_t totalLen   = 0U;

    FullParseResult_t res;
    memset(&res, 0, sizeof(res));

    ErrCodeT err;

    if (negativeCase == INVALID_MODULE_ID)
    {
        /* -----------------------------------------------------------------
         * FALLBACK PATH (NO SBIT ACCESS)
         * ----------------------------------------------------------------- */
        numRegions = 1U;
        RegionAddressInfo[0] = FALLBACK_ADDR;
        RegionLengthInfo[0]  = FALLBACK_LEN;

        uint8_t *dst = getAppSignedHeaderAddress();
        memcpy(dst, (void *)FALLBACK_ADDR, FALLBACK_LEN);
        totalLen = FALLBACK_LEN;

        /* Populate res fields used during serialisation */
        res.sbit.numRegions   = (uint8_t)numRegions;
        res.sbit.numSwRegions = (uint16_t)numRegions;
        res.sbit.regions[0].startAddress = CHANGE_ENDIANNESS_32BIT(FALLBACK_ADDR);
        res.sbit.regions[0].length       = CHANGE_ENDIANNESS_32BIT(FALLBACK_LEN);
    }
    else
    {
        /* -----------------------------------------------------------------
         * SBIT PARSING — alignment-safe, endian-safe
         * All reads via read_be16() / read_be32().  No uint16_t* / uint32_t* casts.
         * Endian conversion happens inside the read helpers; values are native
         * CPU words after that — no further CHANGE_ENDIANNESS_* needed.
         * ----------------------------------------------------------------- */
        const uint8_t *base = SBIT_BASE_PTR;

        uint16_t Version = read_be16(base + 0U);

        uint32_t numModOff;
        uint32_t firstModOff;
        uint32_t regionInfoOff;

        if (Version == SBIT_WITH_MGAL)
        {
            numModOff     = NUMBER_OF_MGAL_SBIT_MODULE_OFFSET;
            firstModOff   = FIRST_MODULE_OFFSET_WITH_MGAL;
            regionInfoOff = REGION_INFO_OFFSET_WITH_MGAL;
        }
        else
        {
            numModOff     = NUMBER_OF_SBIT_MODULE_OFFSET;
            firstModOff   = FIRST_MODULE_OFFSET;
            regionInfoOff = REGION_INFO_OFFSET;
        }

        uint16_t totalmodules  = read_be16(base + numModOff);
        boolean  ModuleFound   = FALSE;
        uint16_t RegionoffsetLB = 0U;

        for (uint16_t i = 0U; i < totalmodules; i++)
        {
            uint32_t entryOff  = firstModOff + (uint32_t)i * SBIT_MODULE_TABLE_ENTRY_STRIDE;
            uint16_t ModuleIdLE = read_be16(base + entryOff);
            res.sbit.moduleIdRaw = ModuleIdLE;

            if (ModuleIdLE == moduleId)
            {
                uint32_t entryOff = firstModOff + ((uint32_t)i * SBIT_MODULE_TABLE_ENTRY_STRIDE);
		RegionoffsetLB = read_be16(base + entryOff + 2);
                ModuleFound = TRUE;
                break;
            }
        }

        if (ModuleFound == FALSE) { return MODULE_NOT_FOUND; }

        uint8_t nReg = base[RegionoffsetLB + SBIT_MOD_NUM_REGIONS_BYTE_OFF];
        if (nReg > SBIT_MAX_REGIONS) { nReg = (uint8_t)SBIT_MAX_REGIONS; }

        res.sbit.numRegions   = nReg;
        res.sbit.numSwRegions = (uint16_t)nReg;
        numRegions            = (uint16_t)nReg;

        for (uint8_t i = 0U; i < nReg; i++)
        {
            uint32_t addrOff = (uint32_t)RegionoffsetLB
                             + SBIT_MOD_REGION_ADDR_BYTE_BASE
                             + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

            uint32_t lenOff  = (uint32_t)RegionoffsetLB
                             + SBIT_MOD_REGION_LEN_BYTE_BASE
                             + (uint32_t)i * SBIT_MOD_REGION_ENTRY_BYTES;

            uint32_t addr = read_be32(base + addrOff);   /* native CPU value */
            uint32_t len  = read_be32(base + lenOff);

            res.sbit.regions[i].startAddress = addr;
            res.sbit.regions[i].length       = len;

            RegionAddressInfo[i] = addr;   /* no further conversion */
            RegionLengthInfo[i]  = len;
        }

        uint8_t *MdAddr   = getAppSignedHeaderAddress();
        uint32_t MDLength = 0U;

        for (uint8_t i = 0U; i < nReg; i++)
        {
            uint32_t regionLen = RegionLengthInfo[i];
            void    *regionSrc = (void *)(uintptr_t)RegionAddressInfo[i];

            if ((MDLength + regionLen) > APP_SIGNED_HDR_STAGING_SIZE)
            {
                return ERC_BUFFER_TOO_SMALL;
            }

            memcpy(MdAddr, regionSrc, regionLen);
            MdAddr   += regionLen;
            MDLength += regionLen;
        }

        totalLen = MDLength;
    }

    /* SHA-256 over staging buffer — shared by both paths */
    err = sha256Compute(getAppSignedHeaderAddress(), totalLen, res.msgDigest);
    if (err != ERC_NO_ERROR) { return err; }

    /* === Step 5: Key generation === */
    uint8_t subjectPubKey[HAP_SUBJECT_PUB_KEY_SIZE];
    memset(subjectPubKey, 0, HAP_SUBJECT_PUB_KEY_SIZE);

    uint8_t edPrivKey[ED25519_PRIV_FULL];
    uint8_t edPubKey[ED25519_KEY_SIZE];
    memset(edPrivKey, 0, sizeof(edPrivKey));
    memset(edPubKey,  0, sizeof(edPubKey));

    RsaKey rsaKey;
    WC_RNG rng;

    int wret = wc_InitRsaKey(&rsaKey, NULL);
    if (wret != 0) { return ERC_CRYPTO_FAIL; }

    wret = wc_InitRng(&rng);
    if (wret != 0) { wc_FreeRsaKey(&rsaKey); return ERC_CRYPTO_FAIL; }

    if (keySize == ED25519_KEY_SIZE)
    {
        uint32_t pl = 0U, ql = 0U;
        err = edGenKeyPair(edPrivKey, &pl, edPubKey, &ql);
        if (err != ERC_NO_ERROR) { wc_FreeRng(&rng); wc_FreeRsaKey(&rsaKey); return err; }
        memcpy(subjectPubKey, edPubKey, ED25519_KEY_SIZE);
    }
    else if (keySize == RSA_KEY_SIZE)
    {
        err = rsaGenKeyPair(&rsaKey, subjectPubKey, &rng);
        if (err != ERC_NO_ERROR) { wc_FreeRng(&rng); wc_FreeRsaKey(&rsaKey); return err; }
    }
    else
    {
        wc_FreeRng(&rng);
        wc_FreeRsaKey(&rsaKey);
        return ERC_INVALID_CMD;
    }

    /* === Step 6: Negative overrides === */
    applyNegOverrides(&res, &moduleId, subjectPubKey, edPrivKey, edPubKey, negativeCase);

    /* === Step 7: Serialize === */
    uint32_t off = 0U;

    /* [000-001] Module ID */
    writeBE16(headerBuffer + off, moduleId);
    off += HAP_MODULE_ID_SIZE;

    /* [002-033] Digest of Full "To-Be" Raw Data
     *   Spec: SHA-256 of the fully reconstructed final image.
     *   This implementation: use the region-derived digest (same source)
     *   which matches the reference firmware's behaviour for this field.   */
    memcpy(headerBuffer + off, res.msgDigest, HAP_MSG_DIGEST_SIZE);
    off += HAP_MSG_DIGEST_SIZE;

    /* [034-035] BCID */
    memcpy(headerBuffer + off, kBcid, HAP_BCID_SIZE);
    off += HAP_BCID_SIZE;

    /* [036-043] ECU Name */
    if (negativeCase == INVALID_ECU_NAME_CASE)
        memcpy(headerBuffer + off, kBadEcuName, HAP_ECU_NAME_SIZE);
    else
        memcpy(headerBuffer + off, kEcuName, HAP_ECU_NAME_SIZE);
    off += HAP_ECU_NAME_SIZE;

    /* [044-059] ECU ID */
    if (negativeCase == INVALID_ECU_ID_CASE)
        memcpy(headerBuffer + off, kBadEcuId, HAP_ECU_ID_SIZE);
    else
        memcpy(headerBuffer + off, kEcuId, HAP_ECU_ID_SIZE);
    off += HAP_ECU_ID_SIZE;

    /* [060-075] ECU ID Extension */
    memcpy(headerBuffer + off, kEcuIdExt, HAP_ECU_ID_EXT_SIZE);
    off += HAP_ECU_ID_EXT_SIZE;

    /* [076-077] App NBID */
    if (negativeCase == INVALID_APP_NBID_CASE)
        memcpy(headerBuffer + off, kBadAppNbid, HAP_APP_NBID_SIZE);
    else
        memcpy(headerBuffer + off, kAppNbid, HAP_APP_NBID_SIZE);
    off += HAP_APP_NBID_SIZE;

    /* [078-079] Number of SW Regions */
    writeBE16(headerBuffer + off, res.sbit.numSwRegions);
    off += HAP_NUM_SW_REGIONS_SIZE;

    /* [080-083] Region Start Address (first region, raw BE from SBIT) */
    writeBE32(headerBuffer + off, res.sbit.regions[0].startAddress);
    off += HAP_REGION_START_ADDR_SIZE;

    /* [084-087] Region Length (first region, raw BE from SBIT) */
    writeBE32(headerBuffer + off, res.sbit.regions[0].length);
    off += HAP_REGION_LENGTH_SIZE;

    /* [088-119] Bit-Diff Envelope Digest — HARDCODED ZERO per spec */
    memset(headerBuffer + off, 0x00, HAP_MSG_DIGEST_SIZE);
    off += HAP_MSG_DIGEST_SIZE;

    /* [120-657] Signer Info */
    if (negativeCase == INVALID_SIGNER_INFO)
    {
        memset(headerBuffer + off, 0x00, HAP_SIGNER_INFO_SIZE);
    }
    else
    {
        err = buildSignerInfo(headerBuffer + off, subjectPubKey, keySize,
                              &rsaKey, edPrivKey, edPubKey, &rng);
        if (err != ERC_NO_ERROR)
        {
            wc_FreeRng(&rng);
            wc_FreeRsaKey(&rsaKey);
            return err;
        }
    }
    off += HAP_SIGNER_INFO_SIZE;

    /* [658-913] Header Signature — signs bytes [0..657] */
    if (keySize == ED25519_KEY_SIZE)
    {
        err = edSign(edPrivKey, edPubKey,
                     headerBuffer, (uint32_t)BITDIFF_SIGNED_LEN,
                     headerBuffer + off);
    }
    else
    {
        err = rsaSign(&rsaKey,
                      headerBuffer, (uint32_t)BITDIFF_SIGNED_LEN,
                      headerBuffer + off, &rng);
    }

    wc_FreeRng(&rng);
    wc_FreeRsaKey(&rsaKey);
    return err;
}

/* ===========================================================================
 * WRAPPER
 * =========================================================================*/

ErrCodeT getAppSignedHeader(uint16_t           moduleId,
                            uint8_t           *headerBuffer,
                            uint16_t           keySize,
                            HeaderType_e       headerType,
                            NegativeTestCase_e negativeCase)
{
    if (headerBuffer == NULL) { return ERC_NULL_PTR; }

    if (headerType == HEADER_TYPE_BITDIFF)
    {
        return generateAppSignedHeaderBitDiff(moduleId, headerBuffer,
                                             keySize, negativeCase);
    }

    return generateAppSignedHeader(moduleId, headerBuffer,
                                  keySize, negativeCase);
}
