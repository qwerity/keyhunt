#include "crypto_util.h"
#include "address_util.h"
#include "secp256k1.h"
#include "common.h"
#include "utils.h"

#include <cstring>
#include <string>

uint32_t crypto::checksum(const uint32_t *hash)
{
    uint32_t msg[16]{};
    uint32_t digest[8]{};

    // Insert network byte, shift everything right 1 byte
    msg[0] = 0x00; // main network
    msg[0] |= hash[0] >> 8;
    msg[1] = (hash[0] << 24) | (hash[1] >> 8);
    msg[2] = (hash[1] << 24) | (hash[2] >> 8);
    msg[3] = (hash[2] << 24) | (hash[3] >> 8);
    msg[4] = (hash[3] << 24) | (hash[4] >> 8);
    msg[5] = (hash[4] << 24) | 0x00800000;

    // Padding and length
    msg[15] = 168;

    // Hash address
    sha256Init(digest);
    sha256(msg, digest);

    // Prepare to make a hash of the digest
    memset(msg, 0, 16 * sizeof(uint32_t));
    for (int i = 0; i < 8; i++)
    {
        msg[i] = digest[i];
    }
    msg[8] = 0x80000000;
    msg[15] = 256;
    sha256Init(digest);
    sha256(msg, digest);
    return digest[0];
}

bool Address::verifyAddress(const std::string &address)
{
    // Check length
    if (address.length() > 34)
    {
        return false;
    }

    // Check encoding
    if (!Base58::isBase58(address))
    {
        return false;
    }

    const auto noPrefix = address.substr(1);
    const secp256k1::uint256 value = Base58::toBigInt(noPrefix);
    uint32_t words[6]{};
    uint32_t hash[5]{};

    value.exportWords(words, 6, secp256k1::uint256::BigEndian);
    memcpy(hash, words, sizeof(uint32_t) * 5);

    const uint32_t checksum = words[5];
    return crypto::checksum(hash) == checksum;
}

std::string Address::fromPublicKey(const secp256k1::ecpoint &p, bool compressed)
{
    uint32_t xWords[8]{};
    uint32_t yWords[8]{};
    p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
    p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

    uint32_t digest[5]{};
    if (compressed)
    {
        Hash::hashPublicKeyCompressed(xWords, yWords, digest);
    } else
    {
        Hash::hashPublicKey(xWords, yWords, digest);
    }

    const uint32_t checksum = crypto::checksum(digest);
    uint32_t addressWords[8] = {};
    for (int i = 0; i < 5; i++)
    {
        addressWords[2 + i] = digest[i];
    }
    addressWords[7] = checksum;
    secp256k1::uint256 addressBigInt(addressWords, secp256k1::uint256::BigEndian);
    return "1" + Base58::toBase58(addressBigInt);
}

void Hash::hashPublicKey(const secp256k1::ecpoint &p, uint32_t *digest)
{
    uint32_t xWords[8]{};
    uint32_t yWords[8]{};
    p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
    p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);
    hashPublicKey(xWords, yWords, digest);
}


void Hash::hashPublicKeyCompressed(const secp256k1::ecpoint &p, uint32_t *digest)
{
    uint32_t xWords[8]{};
    uint32_t yWords[8]{};
    p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
    p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);
    hashPublicKeyCompressed(xWords, yWords, digest);
}

void Hash::hashPublicKey(const uint32_t *x, const uint32_t *y, uint32_t *digest)
{
    uint32_t msg[16]{};
    uint32_t sha256Digest[8]{};
    // 0x04 || x || y
    msg[15] = (y[7] >> 8) | (y[6] << 24);
    msg[14] = (y[6] >> 8) | (y[5] << 24);
    msg[13] = (y[5] >> 8) | (y[4] << 24);
    msg[12] = (y[4] >> 8) | (y[3] << 24);
    msg[11] = (y[3] >> 8) | (y[2] << 24);
    msg[10] = (y[2] >> 8) | (y[1] << 24);
    msg[9] = (y[1] >> 8) | (y[0] << 24);
    msg[8] = (y[0] >> 8) | (x[7] << 24);
    msg[7] = (x[7] >> 8) | (x[6] << 24);
    msg[6] = (x[6] >> 8) | (x[5] << 24);
    msg[5] = (x[5] >> 8) | (x[4] << 24);
    msg[4] = (x[4] >> 8) | (x[3] << 24);
    msg[3] = (x[3] >> 8) | (x[2] << 24);
    msg[2] = (x[2] >> 8) | (x[1] << 24);
    msg[1] = (x[1] >> 8) | (x[0] << 24);
    msg[0] = (x[0] >> 8) | 0x04000000;
    crypto::sha256Init(sha256Digest);
    crypto::sha256(msg, sha256Digest);

    // Zero out the message
    std::ranges::fill(msg, 0);

    // Set first byte, padding, and length
    msg[0] = (y[7] << 24) | 0x00800000;
    msg[15] = 65 * 8;
    crypto::sha256(msg, sha256Digest);
    std::ranges::fill(msg, 0);

    // Swap to little-endian
    std::ranges::transform(sha256Digest, msg, utils::endian);

    // Message length, little endian
    msg[8] = 0x00000080;
    msg[14] = 256;
    msg[15] = 0;
    crypto::ripemd160(msg, digest);
}


void Hash::hashPublicKeyCompressed(const uint32_t *x, const uint32_t *y, uint32_t *digest)
{
    uint32_t msg[16]{};
    uint32_t sha256Digest[8]{};

    // Compressed public key format
    msg[15] = 33 * 8;  // Message length in bits (compressed key is 33 bytes)
    msg[8] = (x[7] << 24) | 0x00800000;
    msg[7] = (x[7] >> 8) | (x[6] << 24);
    msg[6] = (x[6] >> 8) | (x[5] << 24);
    msg[5] = (x[5] >> 8) | (x[4] << 24);
    msg[4] = (x[4] >> 8) | (x[3] << 24);
    msg[3] = (x[3] >> 8) | (x[2] << 24);
    msg[2] = (x[2] >> 8) | (x[1] << 24);
    msg[1] = (x[1] >> 8) | (x[0] << 24);

    if (y[7] & 0x01)
    {
        msg[0] = (x[0] >> 8) | 0x03000000;
    }
    else
    {
        msg[0] = (x[0] >> 8) | 0x02000000;
    }

    // SHA-256 hash
    crypto::sha256Init(sha256Digest);
    crypto::sha256(msg, sha256Digest);

    // Clear msg array
    std::ranges::fill(msg, 0);

    // Swap to little-endian
    std::ranges::transform(sha256Digest, msg, utils::endian);

    // Append padding for RIPEMD-160 (message length and 0x80 bit), little endian
    msg[8] = 0x00000080;  // Padding bit and message length
    msg[14] = 256;        // Length of the SHA-256 digest in bits
    msg[15] = 0;

    // RIPEMD-160 hash
    crypto::ripemd160(msg, digest);
}
