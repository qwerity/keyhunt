#include "bip32.cuh"
#include "bip39.cuh"
#include "secp256k1.cuh"
#include "ripemd160.cuh"
#include "hmac.cuh"
#include "sha.cuh"
#include "utils.cuh"

__device__ void generatePublicFromPrivateKey(const extended_private_key_t* priv, extended_public_key_t* pub)
{
    secp256k1_ec_pubkey_create(pub->key, &priv->key[0]);
}

__device__ void publicKeyToHash160(extended_public_key_t* pub, uint32_t* hash160_bytes)
{
    uint8_t serializedPublicKey[36]{};
    serialized_public_key(pub, &serializedPublicKey[0]);
    hash160(&serializedPublicKey[0], 33, hash160_bytes);
}

__device__ void bip49_publicKeyToHash160(extended_public_key_t* pub, uint32_t* hash160_bytes)
{
    uint8_t serializedPublicKey[36]{};
    serialized_public_key(pub, &serializedPublicKey[0]);

    uint8_t sha256Result[32]{};
    sha256(reinterpret_cast<const uint32_t*>(serializedPublicKey), 33, reinterpret_cast<uint32_t*>(&sha256Result));

    RIPEMD160_CTX ctx;
    ripemd160Init(&ctx);
    ripemd160Update(&ctx, sha256Result, 32);
    ripemd160Final(&ctx, reinterpret_cast<uint32_t*>(sha256Result));

    ////uint8_t hash[24];
    serializedPublicKey[0] = 0;
    serializedPublicKey[1] = 0x14;
    for (int i = 0; i < 20; i++)
    {
        serializedPublicKey[i + 2] = sha256Result[i];
    }

    serializedPublicKey[22] = 0;
    serializedPublicKey[23] = 0;

    sha256(reinterpret_cast<const uint32_t*>(serializedPublicKey), 22, reinterpret_cast<uint32_t*>(&sha256Result));

    ripemd160Init(&ctx);
    ripemd160Update(&ctx, sha256Result, 32);
    ripemd160Final(&ctx, (uint32_t*) hash160_bytes);
}

__device__ void hardenedPrivateChildFromPrivate(const extended_private_key_t* parent, extended_private_key_t* child, uint16_t hardenedChildNumber)
{
    alignas(8 * 8) uint32_t hmacSHA512Result[64 / 4]{};
    uint8_t hmacInput[40]{}; //37 bytes

    for (int x = 0; x < 32; x++)
    {
        hmacInput[x + 1] = parent->key[x];
    }
    hmacInput[33] = 0x80;
    hmacInput[34] = 0;

    hmacInput[35] = *(reinterpret_cast<uint8_t*>(&hardenedChildNumber) + 1);
    hmacInput[36] = *(reinterpret_cast<uint8_t*>(&hardenedChildNumber));
    hmacSHA512(reinterpret_cast<const uint32_t*>(&parent->chainCode[0]), reinterpret_cast<uint32_t*>(&hmacInput), reinterpret_cast<uint32_t*>(&hmacSHA512Result));

    uint8_t sk[32]{};
    cuda_memcpy(reinterpret_cast<uint8_t*>(&sk), reinterpret_cast<const uint8_t*>(&hmacSHA512Result), 32);

    secp256k1_ec_seckey_tweak_add(reinterpret_cast<uint8_t*>(&sk), reinterpret_cast<const uint8_t*>(&parent->key));

    for (int x = 0; x < 32; ++x)
    {
        child->key[x] = sk[x];
    }
    cuda_memcpy_offset(reinterpret_cast<uint8_t*>(&child->chainCode), reinterpret_cast<uint8_t*>(&hmacSHA512Result), 32, 32);
}

__device__ void normalPrivateChildFromPrivate(const extended_private_key_t* parent, extended_private_key_t* child, uint16_t normalChildNumber)
{
    alignas(8 * 8) uint32_t hmacSHA512Result[64 / 4]{};

    extended_public_key_t pub;
    generatePublicFromPrivateKey(parent, &pub);

    uint8_t hmacInput[40]{}; //37 bytes
    serialized_public_key(&pub, reinterpret_cast<uint8_t*>(&hmacInput));

    hmacInput[33] = 0;
    hmacInput[34] = 0;

    hmacInput[35] = *(reinterpret_cast<uint8_t*>(&normalChildNumber) + 1);
    hmacInput[36] = *reinterpret_cast<uint8_t*>(&normalChildNumber);

    hmacSHA512(reinterpret_cast<const uint32_t*>(&parent->chainCode[0]), reinterpret_cast<uint32_t*>(&hmacInput), reinterpret_cast<uint32_t*>(&hmacSHA512Result));

    uint8_t sk[32]{};
    cuda_memcpy(reinterpret_cast<uint8_t*>(&sk), reinterpret_cast<const uint8_t*>(&hmacSHA512Result), 32);

    secp256k1_ec_seckey_tweak_add(reinterpret_cast<uint8_t*>(&sk), reinterpret_cast<const uint8_t*>(&parent->key[0]));

    for (int x = 0; x < 32; x++)
    {
        child->key[x] = sk[x];
    }
    cuda_memcpy_offset(&child->chainCode[0], reinterpret_cast<const uint8_t*>(&hmacSHA512Result), 32, 32);
}

__global__ void mnemonicToHash160(const uint8_t* mnemonic, uint8_t* masterExKey, uint32_t* seed, uint8_t* childKey, uint8_t* childChildKey, uint8_t* hardenedChildKey, uint16_t childNumber, extended_public_key_t* childPublicKey, uint32_t* hash160_bytes)
{
    mnemonicToExtendedMasterKey(mnemonic, seed, masterExKey);
    hardenedPrivateChildFromPrivate(reinterpret_cast<const extended_private_key_t*>(masterExKey), reinterpret_cast<extended_private_key_t*>(hardenedChildKey), childNumber);
    normalPrivateChildFromPrivate(reinterpret_cast<const extended_private_key_t*>(masterExKey), reinterpret_cast<extended_private_key_t*>(childKey), childNumber);
    normalPrivateChildFromPrivate(reinterpret_cast<const extended_private_key_t*>(childKey), reinterpret_cast<extended_private_key_t*>(childChildKey), childNumber);
    generatePublicFromPrivateKey(reinterpret_cast<const extended_private_key_t*>(childKey), childPublicKey);
    publicKeyToHash160(childPublicKey, hash160_bytes);
}

__constant__ uint32_t dev_num_bytes_find[1];
__constant__ uint32_t dev_generate_path[10];
__constant__ uint32_t dev_num_paths[1];
__constant__ uint32_t dev_num_childs[1];
__constant__ int16_t dev_static_words_indices[12];
__device__ void generatePublicsForMnemonicByPaths(const uint8_t* mnemonic, const extended_private_key_t* masterKey)
{
    extended_private_key_t target_key;
    extended_private_key_t target_key_fo_pub;
    extended_private_key_t master_private_fo_extint;
    extended_public_key_t target_public_key;
    
    //______________________________________________________________________________________________________________________
    if (dev_generate_path[0] != 0)
    {
        normalPrivateChildFromPrivate(masterKey, &target_key, 0);
        //m/0/x
        for (int i = 0; i < dev_num_childs[0]; i++)
        {
            normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
        }
    }

    //______________________________________________________________________________________________________________________
    if (dev_generate_path[1] != 0)
    {
        normalPrivateChildFromPrivate(masterKey, &target_key, 1);
        //m/1/x
        for (int i = 0; i < dev_num_childs[0]; i++)
        {
            normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
            generatePublicFromPrivateKey(&target_key_fo_pub, &target_public_key);
        }
    }
    //______________________________________________________________________________________________________________________
    if ((dev_generate_path[2] != 0) || (dev_generate_path[3] != 0))
    {
        //m/0
        normalPrivateChildFromPrivate(masterKey, &master_private_fo_extint, 0);

        if (dev_generate_path[2] != 0)
        {
            //m/0/0
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 0);
            //m/0/0/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
                generatePublicFromPrivateKey(&target_key_fo_pub, &target_public_key);
            }
        }
        if (dev_generate_path[3] != 0)
        {
            //m/0/1
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 1);
            //m/0/1/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
                generatePublicFromPrivateKey(&target_key_fo_pub, &target_public_key);
            }
        }
    }
    //______________________________________________________________________________________________________________________
    if ((dev_generate_path[4] != 0) || (dev_generate_path[5] != 0))
    {
        hardenedPrivateChildFromPrivate(masterKey, &target_key, 44);
        hardenedPrivateChildFromPrivate(&target_key, &target_key, 0);
        hardenedPrivateChildFromPrivate(&target_key, &master_private_fo_extint, 0);
        //______________________________________________________________________________________________________________________
        if (dev_generate_path[4] != 0)
        {
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 0);
            //m/44'/0'/0'/0/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
            }
        }
        //______________________________________________________________________________________________________________________
        if (dev_generate_path[5] != 0)
        {
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 1);
            //m/44'/0'/0'/1/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
            }
        }
    }
    //______________________________________________________________________________________________________________________
    if ((dev_generate_path[6] != 0) || (dev_generate_path[7] != 0))
    {
        hardenedPrivateChildFromPrivate(masterKey, &target_key, 49);
        hardenedPrivateChildFromPrivate(&target_key, &target_key, 0);
        hardenedPrivateChildFromPrivate(&target_key, &master_private_fo_extint, 0);
        //______________________________________________________________________________________________________________________
        if (dev_generate_path[6] != 0)
        {
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 0);
            //m/49'/0'/0'/0/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
            }
        }
        //______________________________________________________________________________________________________________________
        if (dev_generate_path[7] != 0)
        {
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 1);
            //m/49'/0'/0'/1/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
            }
        }
    }
    //______________________________________________________________________________________________________________________
    if ((dev_generate_path[8] != 0) || (dev_generate_path[9] != 0))
    {
        hardenedPrivateChildFromPrivate(masterKey, &target_key, 84);
        hardenedPrivateChildFromPrivate(&target_key, &target_key, 0);
        hardenedPrivateChildFromPrivate(&target_key, &master_private_fo_extint, 0);
        //______________________________________________________________________________________________________________________
        if (dev_generate_path[8] != 0)
        {
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 0);
            //m/84'/0'/0'/0/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
            }
        }
        //______________________________________________________________________________________________________________________
        if (dev_generate_path[9] != 0)
        {
            normalPrivateChildFromPrivate(&master_private_fo_extint, &target_key, 1);
            //m/84'/0'/0'/1/x
            for (int i = 0; i < dev_num_childs[0]; i++)
            {
                normalPrivateChildFromPrivate(&target_key, &target_key_fo_pub, i);
            }
        }
    }
}
