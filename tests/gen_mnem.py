from mnemonic import Mnemonic
from bip32 import BIP32
from bitcoin import privkey_to_pubkey, privkey_to_address, hash160, pubkey_to_address, compress
from base58 import b58encode
import hashlib

def sha256(inputs: bytes) -> bytes:
    """ Computes sha256 """
    sha = hashlib.sha256()
    sha.update(inputs)
    return sha.digest()

def ripemd160(inputs: bytes) -> bytes:
    """ Computes ripemd160 """
    rip = hashlib.new('ripemd160')
    rip.update(inputs)
    return rip.digest()


def base58_cksum(inputs: bytes) -> bytes:
    """ Computes base 58 four bytes check sum """
    s1 = sha256(inputs)
    s2 = sha256(s1)
    checksum = s2[0:4]
    return checksum

def pubkey_to_p2sh_p2wpkh_addr(pubkey_compressed: bytes, version: bytes = b'\x05') -> str:
    """ Derives p2sh-segwit (p2sh p2wpkh) address from pubkey """
    pubkey_hash = sha256(pubkey_compressed)
    rip = ripemd160(pubkey_hash)
    redeem_script = b'\x00\x14' + rip
    redeem_hash = sha256(redeem_script)
    redeem_rip = ripemd160(redeem_hash)
    checksum = base58_cksum(version + redeem_rip)
    address_bytes = version + redeem_rip + checksum
    return b58encode(address_bytes).decode()

paths = [
    "m/addr", "m/acc/addr", "m/acc/0/addr", "m/acc'/addr", "m/acc'/0/addr",
    "m/44'/acc'/0/addr", "m/44'/0'/acc'/0/addr", "m/49'/0'/acc'/0/addr"
]
acc = 0
addr = 0
mnemo = Mnemonic("english")
words = 'actress fuel dumb ship obey cream online choose bulb mango neglect speed' # mnemo.generate(strength=128)
seed = mnemo.to_seed(words, passphrase="")

bip32 = BIP32.from_seed(seed)
print('---------------------------------------------------------------------')
print('Mnemonic', words)
print('SEED', seed.hex())

for path in paths:
    if "acc" in path:
        path = path.replace("acc", str(acc))
    if "addr" in path:
        path = path.replace("addr", str(addr))
    print(f'---------------------------- {path} -----------------------------------------')
    
    pvk = bip32.get_privkey_from_path(path)
    print('Приватный ключ', pvk.hex())
            
    pub_uncompress = privkey_to_pubkey(pvk)
    pub_compress = compress(pub_uncompress)
    # print('Несжатый публичный ключ', pub_uncompress.hex())
    # print('Сжатый публичный ключ', pub_compress.hex())

    h160_uncompress = hash160(pub_uncompress)
    h160_compress = hash160(pub_compress)
    # print('HASH160 из Несжатого публичного ключа', h160_uncompress)
    print('HASH160 из Сжатого публичного ключа', h160_compress)

    if not "49" in path and not "44" in path:
        addr_uncompress = pubkey_to_address(pub_uncompress,'00')
        addr_compress = pubkey_to_address(pub_compress,'00')
        # print('Адрес type legacy p2pkh из Несжатого публичного ключа ', addr_uncompress)
        print('Адрес type legacy p2pkh из сжатого публичного ключа',addr_compress)
        continue

    if "44" in path:
        addr_compress = pubkey_to_address(pub_compress,'00')
        print('Адрес type legacy p2pkh из сжатого публичного ключа',addr_compress)

    if "49" in path:
        addr_p2sh_segwit = pubkey_to_p2sh_p2wpkh_addr(pub_compress)
        print('Адрес SegWit Base58 (p2sh) из сжатого публичного ключа', addr_p2sh_segwit)
    
