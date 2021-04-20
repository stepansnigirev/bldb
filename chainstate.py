import plyvel
from embit import compact, ec
from embit.transaction import TransactionOutput
from embit.script import Script
from embit.networks import NETWORKS
from io import BytesIO
import math
import os

class DB_PREFIX:
    COIN = b"C"
    COINS = b"c"
    BLOCK_FILES = b"f"
    TXINDEX = b"t"
    BLOCK_INDEX = b"b"
    BEST_BLOCK = b"B"
    HEAD_BLOCKS = b"H"
    FLAG = b"F"
    REINDEX_FLAG = b"R"
    LAST_BLOCK = b"l"
    OBFUSCATION_KEY = b"\x0e\x00obfuscate_key"

def deobfuscate(utxo, obfuscation_key=None):
    # no obfuscation key
    if obfuscation_key is None:
        return utxo
    # extend the obfuscation key
    mul = int(math.ceil(len(utxo)/len(obfuscation_key)))
    k = (obfuscation_key*mul)[:len(utxo)]
    return bytes([a^b for a, b in zip(utxo, k)])

def read_b128(s):
    res = 0
    while True:
        chunk = s.read(1)
        if len(chunk) == 0:
            raise ValueError("Missing b128 final byte")
        res = (res << 7) | (chunk[0] & 0x7F)
        # last byte doesn't have 0x80 bit set
        if chunk[0] & 0x80:
            res += 1
        else:
            return res

def value_decompress(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x = x // 10
    if e < 9:
        d = (x % 9) + 1
        x = x // 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n

# special scripts
def read_script(s):
    script_type = read_b128(s)
    # p2pkh
    if script_type == 0:
        data = s.read(20)
        assert len(data) == 20
        return b"\x76\xa9\x14" + data + b"\x88\xac"
    # p2sh
    elif script_type == 1:
        data = s.read(20)
        assert len(data) == 20
        return b"\xa9\x14" + data + b"\x87"
    # p2pk-compressed
    elif script_type in [2, 3]:
        data = s.read(32)
        assert len(data) == 32
        return bytes([0x33, script_type]) + data + b"\xac"
    # p2pk-uncompressed
    elif script_type in [4, 5]:
        data = s.read(32)
        sec = bytes([script_type - 2])+data
        pub = ec.PublicKey.parse(sec)
        pub.compressed = False
        return bytes([0x65]) + pub.sec() + b"\xac"
    # other script type
    l = script_type-6
    data = s.read(l)
    assert len(data) == l
    return data

def parse_utxo(key, value, obfuscation_key=None, network=NETWORKS['main']):
    # DB key is prefix | txid | vout
    s = BytesIO(key)
    prefix = s.read(len(DB_PREFIX.COIN))
    # unknown prefix
    if prefix != DB_PREFIX.COIN:
        raise RuntimeError("Invalid prefix")

    txid = s.read(32)[::-1]
    vout = read_b128(s)
    assert len(s.read()) == 0

    # DB value is (2*height + coinbase) | value | script
    utxo = deobfuscate(value, obfuscation_key)
    s = BytesIO(utxo)

    # first b128 value is (height << 1) + coinbase
    code = read_b128(s)
    height = code >> 1
    coinbase = bool(code & 0x01)

    v = read_b128(s)
    value = value_decompress(v)

    script = read_script(s)
    assert len(s.read()) == 0

    address=None
    sc = Script(script)
    try:
        address = sc.address(network)
    except:
        pass

    return {
        "txid": txid,
        "vout": vout,
        "height": height,
        "coinbase": coinbase,
        "value": value,
        "script": script,
        "address": address,
    }

if __name__ == '__main__':
    # path to chainstate leveldb
    chainstate_path = os.path.expanduser("~/.bitcoin/chainstate")

    db = plyvel.DB(chainstate_path, compression=None)
    # load obfuscation key from the DB
    obfuscation_key = db.get(DB_PREFIX.OBFUSCATION_KEY)
    if obfuscation_key is not None:
        obfuscation_key = obfuscation_key[1:]

    # first 10 utxos
    i = 0
    for key, value in db.iterator(prefix=DB_PREFIX.COIN):
        utxo = parse_utxo(key, value, obfuscation_key)
        print(utxo)
        i += 1
        if i > 10:
            break

    db.close()