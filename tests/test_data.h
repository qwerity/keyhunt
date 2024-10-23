#pragma once

#include <string>
#include <vector>

struct MnemonicKeysTestData
{
    std::string path;
    std::string privateKey;
    std::string hash160;
    std::string btcAddress;
};

struct MnemonicTestData
{
    const std::string mnemonic = "actress fuel dumb ship obey cream online choose bulb mango neglect speed";
    const std::string seed = "3d457035d6d59c36b229561a7becb807516861bb51c97b83944c8e1d55b1c4ab20161ccbe7a9b315f9890964eaff85cd04ab7638edf6d19e40494c13e7bb7211";
    const std::vector<MnemonicKeysTestData> keysTestData;
};

const static MnemonicTestData mnemonicTestData =
{
    .mnemonic = "actress fuel dumb ship obey cream online choose bulb mango neglect speed",
    .seed = "3d457035d6d59c36b229561a7becb807516861bb51c97b83944c8e1d55b1c4ab20161ccbe7a9b315f9890964eaff85cd04ab7638edf6d19e40494c13e7bb7211",
    .keysTestData =
    {
        {"m/0",                 "edbdba19fb7f7923b33428fe32601d8aa9ed1b92ad784b175fa65c4d20ccd78a", "1a1ad9759f5a30c242bd819d9ef641d2b4c8a51c", "13P2jXAo8jokkQ19f8pFtLjRmUrfuSaiDv"},
        {"m/0/0",               "318ce972bf726b8510c4e3039c0f5c617c6cb86320621aeaf84764f59c121429", "e6e40c43903ff298f15fb4de93410d5adf6b3de1", "1N3qcAhjz7TmarrNGZDpZkhiQ1Avep1eTU"},
        {"m/0/0/0",             "554614710a92ed7532f0ea263c0e9bb76f8d7a0485c6ff6591e112f69f80adf7", "138e7c83eab9ea190e7d94998cd63005aa6d0a69", "12nQXmovbzVd4B4V3X5chMdFbDQyvGuFof"},
        {"m/0'/0",              "3780d3fef77de109bc626ecce0e9c65364b7af659af3b756e12822694d98694e", "0557cf0ad6715b9017ccb2a118dedaa3becd6ca6", "1VFa25tX9M8GzF2HSNCQNM8WXEbJB84W1"},
        {"m/0'/0/0",            "cb0470d227dec4082169517d64554250ccdf1a7c9d07ae284950dde5f13e9411", "542ebc0355d5e754a9a8bd82ed5e0d422fdcdf75", "18g7kHABpJqJfgthG8s7EUnqFhpjdytNEJ"},
        {"m/44'/0'/0/0",        "72ba1fe21b26c672a2f8420bea808b9fb7987454488fec8c5f805824278f6b37", "10fe24f0ec34943b6708505ea9e10e972c716209", "12YrGKqyXq45X2L7fbUjQ3Js1W15GWQb8U"},
        {"m/44'/0'/0'/0/0",     "f1e2b55db98f4d0863881335fff5146c03da2a4a92a6f96b67d845b529642d7b", "f36a74a7eda1a876854a5a40543224cb7b692e89", "1PC4jHZqbN3r67uCNUvVFN5hKd5j3NhtsS"},
        {"m/49'/0'/0'/0/0",     "dd33f2662e17b557f05b9ffbd4023cf558387fa07af9919dfbff8a1f7779e6f8", "ff1988775703dfe882446d479be3684ddeaae783", "35zBH75ypB427rnWemeVwDGaARMd9SaJNv"},
    }
};