// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <hash.h>
#include <tinyformat.h>
#include <stdint.h>
#include <stdio.h>

uint256 CBlockHeader::GetHash() const
{
    return GetPoWHash();
}

uint256 CBlockHeader::GetPoWHash() const
{
    if(nTime < 1749866400) {
        return evo_hash(BEGIN(nVersion), END(nNonce));
    } else { // > 2025-06-14 10:00:00
        return evo2_hash(BEGIN(nVersion), END(nNonce));
    }

}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
