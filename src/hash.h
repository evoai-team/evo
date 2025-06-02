// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include <crypto/common.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <crypto/heavyhash.h>
#include "crypto/sph_blake.h"
#include "crypto/sph_bmw.h"
#include "crypto/sph_groestl.h"
#include "crypto/sph_jh.h"
#include "crypto/sph_keccak.h"
#include "crypto/sph_skein.h"
#include "crypto/sph_luffa.h"
#include "crypto/sph_cubehash.h"
#include "crypto/sph_shavite.h"
#include "crypto/sph_simd.h"
#include "crypto/sph_echo.h"
#include "crypto/sph_hamsi.h"
#include "crypto/sph_fugue.h"
#include "crypto/sph_shabal.h"
#include "crypto/sph_whirlpool.h"
extern "C" {
#include "crypto/sph_sha2.h"
}
#include "crypto/sph_haval.h"
#include "crypto/sph_streebog.h"
#include "crypto/sph_radiogatun.h"
#include "crypto/sph_panama.h"
#include "crypto/lyra2/Lyra2.h"

#include <prevector.h>
#include <serialize.h>
#include <uint256.h>
#include <version.h>
#include <memory>
#include <vector>

typedef uint256 ChainCode;

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash256& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash160& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash160& Reset() {
        sha.Reset();
        return *this;
    }
};

/** Compute the 256-bit hash of an object. */
template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(pbegin == pend ? pblank : (const unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
            .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
            .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
            .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 160-bit hash an object. */
template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    uint160 result;
    CHash160().Write(pbegin == pend ? pblank : (const unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
            .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 160-bit hash of a vector. */
inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

/** Compute the 160-bit hash of a vector. */
template<unsigned int N>
inline uint160 Hash160(const prevector<N, unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

/** A writer stream (for serialization) that computes a 256-bit hash. */
class CHashWriter
{
private:
    CHash256   ctx;

    const int nType;
    const int nVersion;
public:

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}

    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void write(const char *pch, size_t size) {
        ctx.Write((const unsigned char*)pch, size);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }

    /**
     * Returns the first 64 bits from the resulting hash.
     */
    inline uint64_t GetCheapHash() {
        unsigned char result[CHash256::OUTPUT_SIZE];
        ctx.Finalize(result);
        return ReadLE64(result);
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};

/** A writer stream (for serialization) that computes a HeavyHash. */
class CHeavyHashWriter
{
private:
    CHeavyHash ctx;

    const int nType;
    const int nVersion;
public:

    CHeavyHashWriter(uint64_t heavyhash_matrix[64*64],
                     int nTypeIn, int nVersionIn) : ctx(heavyhash_matrix), nType(nTypeIn), nVersion(nVersionIn) {};

    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void write(const char *pch, size_t size) {
        ctx.Write((const unsigned char*)pch, size);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }

    /**
     * Returns the first 64 bits from the resulting hash.
     */
    inline uint64_t GetCheapHash() {
        unsigned char result[CHeavyHash::OUTPUT_SIZE];
        ctx.Finalize(result);
        return ReadLE64(result);
    }

    template<typename T>
    CHeavyHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};

/** Reads data from an underlying stream, while hashing the read data. */
template<typename Source>
class CHashVerifier : public CHashWriter
{
private:
    Source* source;

public:
    explicit CHashVerifier(Source* source_) : CHashWriter(source_->GetType(), source_->GetVersion()), source(source_) {}

    void read(char* pch, size_t nSize)
    {
        source->read(pch, nSize);
        this->write(pch, nSize);
    }

    void ignore(size_t nSize)
    {
        char data[1024];
        while (nSize > 0) {
            size_t now = std::min<size_t>(nSize, 1024);
            read(data, now);
            nSize -= now;
        }
    }

    template<typename T>
    CHashVerifier<Source>& operator>>(T&& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }
};

/** Compute the 256-bit hash of an object's serialization. */
template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

/** Compute the 256-bit HeavyHash of an object's serialization*/
template<typename T>
uint256 SerializeHeavyHash(const T& obj, uint64_t heavyhash_matrix[64*64],
                           const int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHeavyHashWriter ss(heavyhash_matrix, nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

/** Generates deterministically a full-rank pseudorandom matrix for HeavyHash using \p matrix_seed
 * @pre matrix_seed must be non-zero
 * */

void GenerateHeavyHashMatrix(uint256 matrix_seed, uint64_t matrix[64*64]);

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);


template<typename T1>
inline uint256 heavyhashv2(const T1 pbegin, const T1 pend)
{
    sph_blake512_context     ctx_blake;
    sph_whirlpool_context    ctx_whirlpool;
    sph_sha256_context       ctx_sha256;

    static unsigned char pblank[1];

    uint512 hash[4];

    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash[0]));

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, static_cast<const void*>(&hash[0]), 64);
    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[1]));

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, static_cast<const void*>(&hash[1]), 64);
    sph_sha256_close(&ctx_sha256, static_cast<void*>(&hash[2]));

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, static_cast<const void*>(&hash[2]), 64);
    sph_sha256_close(&ctx_sha256, static_cast<void*>(&hash[3]));

    return hash[3].trim256();
}

template<typename T1>
inline uint256 t5_hash(const T1 pbegin, const T1 pend)
{
    unsigned char hash[128] = { 0 };
    unsigned char hashA[64] = { 0 };
    unsigned char hashB[64] = { 0 };
    static unsigned char pblank[1];
    uint512 output;
    int len = (pend - pbegin) * sizeof(pbegin[0]);

    sph_groestl512_context   ctx_groestl;
    sph_keccak512_context    ctx_keccak;
    sph_cubehash512_context  ctx_cubehash;
    sph_luffa512_context     ctx_luffa;
    sph_echo512_context      ctx_echo;
    sph_simd512_context      ctx_simd;
    sph_shavite512_context   ctx_shavite;
    sph_hamsi512_context     ctx_hamsi;
    sph_fugue512_context     ctx_fugue;
    sph_whirlpool_context    ctx_whirlpool;
    sph_skein512_context     ctx_skein;
    sph_shabal512_context    ctx_shabal;
    sph_bmw512_context       ctx_bmw;
    sph_jh512_context        ctx_jh;

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, pbegin, 80);
    sph_cubehash512_close(&ctx_cubehash, (void*)hash);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, (const void*) hash, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, (const void*) hashA, 64);
    sph_groestl512_close(&ctx_groestl, hash);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hash, 64);
    sph_hamsi512_close(&ctx_hamsi, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, hashA, 64);
    sph_fugue512_close(&ctx_fugue, hash);

    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, 64);
    sph_simd512_close(&ctx_simd, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashA, 64);
    sph_echo512_close(&ctx_echo, hash);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash, 64);
    sph_cubehash512_close(&ctx_cubehash, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashA, 64);
    sph_shavite512_close(&ctx_shavite, hash);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hash, 64);
    sph_luffa512_close(&ctx_luffa, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashA, 64);
    sph_shavite512_close(&ctx_shavite, hash);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hash, 64);
    sph_luffa512_close(&ctx_luffa, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool,  hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hash);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hash, 64);
    sph_shabal512_close(&ctx_shabal, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, (const void*) hashA, 64);
    sph_jh512_close(&ctx_jh, hash);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, (const void*) hash, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hash);

    for (int i=0; i<32; i++)
        hash[i] ^= hash[i+32];

    memcpy((void *) &output, hash, 32);
    return output.trim256();
}
#endif // BITCOIN_HASH_H
