#include "cuda/secp256k1_v2/bip32.cuh"
#include "cuda/secp256k1_v2/sha.cuh"

#include "util/utils.h"

#include <iostream>

#include <thrust/host_vector.h>
#include <thrust/device_vector.h>

using namespace std;
int main()
{
    const char mnemonic_[] = "tennis hero student waste adapt where fall call amused mandate hat panel";

    thrust::host_vector<uint8_t> mnemonic(SIZE_MNEMONIC_FRAME, 0);
    thrust::copy(mnemonic_, mnemonic_ + sizeof(mnemonic_), mnemonic.begin());

    thrust::device_vector<uint32_t> d_seed(64 / 4);
    thrust::device_vector<uint8_t> d_masterExKey(sizeof(extended_private_key_t));
    thrust::device_vector<uint8_t> d_mnemonic = mnemonic;

    thrust::device_vector<uint8_t> d_m0_child(sizeof(extended_private_key_t));
    thrust::device_vector<extended_public_key_t> d_m0_child_pub(1);

    thrust::device_vector<uint32_t> d_hash160_bytes(5);

    mnemonicToHash160<<<1, 1>>>(thrust::raw_pointer_cast(d_mnemonic.data()), thrust::raw_pointer_cast(d_masterExKey.data()), thrust::raw_pointer_cast(d_seed.data()),
                                    thrust::raw_pointer_cast(d_m0_child.data()), 0,
                                    thrust::raw_pointer_cast(d_m0_child_pub.data()), thrust::raw_pointer_cast(d_hash160_bytes.data()));

    cout << "mnemonic: " << mnemonic_ << endl;

    thrust::host_vector<uint32_t> seed = d_seed;
    auto* seedPtr = reinterpret_cast<uint64_t*>(seed.data());
    for (uint32_t i = 0; i < seed.size() / 2; ++i)
    {
        seedPtr[i] = utils::endian64(seedPtr[i]);
    }
    const auto seedStr = utils::toHex(seed.data(), seed.size());
    cout << "seed:" << seedStr << endl;
    if ("48a9daa56a2ebd1bcf9d0524fb96ea49217ecbad1fd12a065ad1996b103965826e3f9617dade34c48b927be05e3f5fae8009ac3576bcb7510d4c198b523cc646" != seedStr)
    {
        cout << "Seed is wrong\n";
    }

    thrust::host_vector<uint8_t> masterExKey = d_masterExKey;
    const auto masterPrivateKeyStr = utils::toHex(masterExKey.data(), 32);
    cout << "Master Private Key:" << masterPrivateKeyStr << endl;
    if ("98ca9c9345c45dbb69adaea3d52f1eedeb7b82ec6dc6ec178ece47d15f737c3a" != masterPrivateKeyStr)
    {
        cout << "Master private key is wrong\n";
    }
    const auto masterChainCodeStr = utils::toHex(masterExKey.data() + 32, 32);
    cout << "Master Chain Code:" << masterChainCodeStr << endl;
    if ("8459d6d7804b3afacec9929c35b1328f3ee0e7acfce0f7d268f03737480cbb96" != masterChainCodeStr)
    {
        cout << "Master chain code is wrong\n";
    }

    thrust::host_vector<uint8_t> m0_child = d_m0_child;
    const auto m0PrivKeyStr = utils::toHex(m0_child.data(), 32);
    cout << "m0 priv key: " << m0PrivKeyStr << endl;
    if ("c25ec8d53730cf453fa516cfe9ee4995c39318e0595dbcb15e4d877bde1a8630" != m0PrivKeyStr)
    {
        cout << "m0 priv key is wrong\n";
    }

    const auto m0ChainCodeStr = utils::toHex(m0_child.data() + 32, 32);
    cout << "m0 chain code: " << m0ChainCodeStr << endl;
    if ("afa3778cd632b207d5e17ba7f6eb409f326d6fe5d82d7c727c9ae77a89aee1ac" != m0ChainCodeStr)
    {
        cout << "m0 chain code: is wrong\n";
    }

    thrust::host_vector<extended_public_key_t> h_m0_child_pub = d_m0_child_pub;
    const auto h_m0_child_pubStr = utils::toHex(h_m0_child_pub.data()->key, 64);
    cout << "m0 pub: " << h_m0_child_pubStr << endl;
    if ("250897e9364b8a41376ec13b2a38f2102e03616c725bdc9a5628b0bf00b0db99d1acd3d1e8297c4bae55aea7ccf603cf721b1fc00252bb7988d80c3658d4dafb" != h_m0_child_pubStr)
    {
        cout << "m0 pub is wrong\n";
    }

    thrust::host_vector<uint32_t> hash160_bytes = d_hash160_bytes;
    const auto m0_hash160_bytesStr = utils::toHex(hash160_bytes.data(), 5);
    cout << "m0 hash160_bytes: " << m0_hash160_bytesStr << endl;
    if ("2487e5b2c039c635a819b05a01cdf3e92d266293" != utils::toHex(hash160_bytes.data(), 5))
    {
        cout << "m0 hash160_bytes is wrong\n";
    }

    return 0;
}