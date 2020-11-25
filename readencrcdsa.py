"""
Script for decrypting encrypted apple disk images.

(c) 2019 Willem Hengeveld <itsme@xs4all.nl>
"""
from __future__ import print_function, division
import struct
from binascii import b2a_hex, a2b_hex

import Crypto.Protocol.KDF
import Crypto.Hash.HMAC
try:
    import Crypto.Hash.SHA1 as SHA1
except ImportError:
    import Crypto.Hash.SHA as SHA1

from Crypto.Cipher import DES3, AES

import Crypto.Cipher.PKCS1_v1_5
import Crypto.PublicKey.RSA

import io

def debugprint(msg):
    #print(msg)
    pass

def hexdump(data):
    """
    Prints a hexdump of 'data' to stdout, 16 bytes per line.
    """
    for o in range(0, len(data), 16):
        line = "%04x:" % o
        for i in range(16):
            if o+i < len(data):
                line += " %02x" % data[o+i]
            else:
                line += "   "
        line += "  "
        for i in range(16):
            if o+i < len(data):
                line += "%c" % data[o+i] if 32 <= data[o+i] <= 126 else "."
            else:
                line += " "
        print(line)

def hmacsha1(key, data):
    """
    calculates a sha1-hmac. ( see rfc2104 )
    """
    hm = Crypto.Hash.HMAC.new(key, digestmod=SHA1)
    hm.update(data)
    return hm.digest()

def pbkdf2(data, nonce, itercount):
    """
    Password Based Key Derivation Function # 2 - see rfc2898
    """
    return Crypto.Protocol.KDF.PBKDF2(data, nonce, 32, itercount, prf=hmacsha1)

def remove_pkcs7_padding(data, blocksize):
    """
    PKCS7 - Symmetric cipher padding
    """
    padlen = ord(data[-1:])
    if padlen==0 or padlen>blocksize:
        #print("WARNING: invalid padlen: %02x" % padlen)
        raise Exception("invalid padding")

    for i in range(padlen):
        if data[-1-i]!=data[-1]:
            print("WARNING: invalid padding: %s" % b2a_hex(data[-padlen:]))
            raise Exception("invalid padding")
    return data[:-padlen]


class Struct:
    def __init__(self, *args):
        if len(args)==1 and type(args[0])==bytes:
            self.parse(args[0])
    def dumplist(self, o, k, v):
        if not v:
            print("%04x: %-40s []" % (o, k))
        elif type(v[0]) == int:
            print("%04x: %-40s [%s]" % (o, k, ", ".join("0x%08x" % _ for _ in v)))
        elif isinstance(v[0], Struct):
            for item in v:
                item.dump()
        else:
            print("%04x: %-40s %s" % (o, k, v))

    def dumpval(self, o, k, v):                       
        if isinstance(v, Struct):
            v.dump()                               
        elif type(v) == bytes:
            print("%04x: %-40s %s" % (o, k, b2a_hex(v)))
        elif type(v) == int:
            print("%04x: %-40s 0x%08x" % (o, k, v))
        elif type(v) == list:
            self.dumplist(o, k, v)
        else:
            print("%04x: %-40s: %s" % (o, k, v))

    def dump(self):
        if hasattr(self, "header"):
            self.header.dump()
        print("====== %s ====== <<" % self.__class__.__name__)
        for o, aname, atype in self.fieldinfo:
            val = getattr(self, aname)
            self.dumpval(o, aname, val)
        print(">>")



CSSM_ALGID_PKCS5_PBKDF2 = 0x67
CSSM_ALGID_3DES_3KEY_EDE  = 0x11
CSSM_PADDING_PKCS7 = 7
CSSM_ALGMODE_CBCPadIV8 = 6


CSSM_APPLE_UNLOCK_TYPE_KEY_DIRECT               = 1 # master secret key stored directly
CSSM_APPLE_UNLOCK_TYPE_WRAPPED_PRIVATE          = 2 # master key wrapped by public key
CSSM_APPLE_UNLOCK_TYPE_KEYBAG                   = 3 # master key wrapped via keybag

class PassphraseWrappedKey(Struct):
    """
    A encrcdsa v2 password wrapped key.
    """
    fieldinfo = [
( 0x0000, "kdfAlgorithm",         "L"),   # 0x67  CSSM_ALGID_PKCS5_PBKDF2
( 0x0004, "kdfIterationCount",    "Q"),   # between 0x10000 and 0x50000
( 0x000c, "kdfSaltLen",           "L"),   # in bytes - 20
( 0x0010, "kdfSalt",              "32s"), 
( 0x0030, "blobEncIvLen",         "L"),   # in bytes - 8
( 0x0034, "blobEncIv",            "32s"), 
( 0x0054, "blobEncKeyBits",       "L"),   # in bits - 192
( 0x0058, "blobEncAlgorithm",     "L"),   # 0x11 CSSM_ALGID_3DES_3KEY_EDE 
( 0x005c, "blobEncPadding",       "L"),   # 0x07 CSSM_PADDING_PKCS7
( 0x0060, "blobEncMode",          "L"),   # 0x06 CSSM_ALGMODE_CBCPadIV8
( 0x0064, "encryptedKeyblobLen",  "L"),   # in bytes 48 or 64
( 0x0068, "encryptedKeyblob",     "64s"), 
    ]
    def parse(self, data):
        (
        self.kdfAlgorithm,     # CSSM_ALGID_PKCS5_PBKDF2 
        self.kdfIterationCount, 
        self.kdfSaltLen,       # 0x14
        self.kdfSalt,          # ...
        self.blobEncIvLen,     # 8
        self.blobEncIv,        # ...
        self.blobEncKeyBits,   # 0xc0 (bits)  = 24 bytes
        self.blobEncAlgorithm, #  CSSM_ALGID_3DES_3KEY_EDE 
        self.blobEncPadding,   #  CSSM_PADDING_PKCS7
        self.blobEncMode,      #  CSSM_ALGMODE_CBCPadIV8
        self.encryptedKeyblobLen,  # 0x30, or 0x40   in bytes
        ) = struct.unpack(">LQL32sL32s5L", data[:0x68])
        self.encryptedKeyblob = data[0x68:]

    def isvalid(self):
        """
        Check if we can decode this wrapped key.
        """
        if self.kdfAlgorithm != CSSM_ALGID_PKCS5_PBKDF2:
            print("unsupported kdf algorithm: %d" % self.kdfAlgorithm)
        elif self.blobEncAlgorithm != CSSM_ALGID_3DES_3KEY_EDE:
            print("unsupported wrap algorithm: %d" % self.blobEncAlgorithm)
        elif self.blobEncPadding != CSSM_PADDING_PKCS7:
            print("unsupported wrap padding : %d" % self.blobEncPadding)
        elif self.blobEncMode != CSSM_ALGMODE_CBCPadIV8 :
            print("unsupported wrap encmode : %d" % self.blobEncMode)
        else:
            return True

    def unwrapkey(self, passphrase, **kwargs):
        """
        decrypt the key using a passphrase.
        """
        if not kwargs.get('skipkdf'):
            hashedpw = pbkdf2(passphrase, self.kdfSalt[:self.kdfSaltLen], self.kdfIterationCount)
            debugprint("hashedpw = %s" % b2a_hex(hashedpw))
            deskey = hashedpw[:self.blobEncKeyBits//8]
            iv = self.blobEncIv[:self.blobEncIvLen]
        else:
            deskey = passphrase[:self.blobEncKeyBits//8]
            iv = passphrase[self.blobEncKeyBits//8:]

        des = DES3.new(deskey, mode=DES3.MODE_CBC, IV=iv)
        unwrappeddata = des.decrypt(self.encryptedKeyblob[:self.encryptedKeyblobLen])
        debugprint("deskey = %s" % b2a_hex(deskey))
        debugprint("iv = %s" % b2a_hex(iv))
        debugprint("unwrappeddata = %s" % b2a_hex(unwrappeddata))
        keydata = remove_pkcs7_padding(unwrappeddata, self.blobEncIvLen)
        debugprint("keydata = %s" % b2a_hex(keydata))

        if keydata[-5:] != b'CKIE\x00':
            print("v2 unwrap: missing CKIE suffix: %s" % b2a_hex(keydata[-5:]))

        return keydata[:-5]

class CertificateWrappedKey(Struct):
    """
    A encrcdsa v2 cert wrapped key.
    """
    fieldinfo = [
( 0x0000, "pubkeyHashLength",     "L"),   # 0x14 
( 0x0004, "pubkeyHash",           "20s"),
( 0x0018, "unk1",                 "L"),   # 0
( 0x001c, "unk2",                 "L"),   # 0
( 0x0020, "unk3",                 "L"),   # 0
( 0x0024, "alg1",                 "L"),   # 42 == RSA
( 0x0028, "unk4",                 "L"),   # 10
( 0x002c, "unk5",                 "L"),   # 0
( 0x0030, "unk6",                 "L"),   # 0x100
( 0x0068, "wrappedKey",           "256s"), 
    ]
    def parse(self, data):
        (
        self.pubkeyHashLength,# 0x14
        self.pubkeyHash,
        self.unk1, 
        self.unk2, 
        self.unk3, 
        self.alg1, 
        self.unk4, 
        self.unk5, 
        self.unk6, 
        self.wrappedKey,       
        ) = struct.unpack(">L20s7L256s", data[:0x134])

    def isvalid(self):
        """
        Check if we can decode this wrapped key.
        """
        if self.pubkeyHashLength != 20:
            print("unsupported cert hash size: %d" % self.pubkeyHashLength)
        elif self.alg1!= 42:
            print("unsupported wrap algorithm: %d" % self.alg1)
        else:
            return True

    def unwrapkey(self, privkey, **kwargs):
        """
        decrypt the key using a private key
        """
        cipher = Crypto.Cipher.PKCS1_v1_5.new(privkey)
        keydata = cipher.decrypt(self.wrappedKey, b'xxxxx')

        if keydata[-5:] != b'CKIE\x00':
            print("v2 unwrap: missing CKIE suffix: %s" % b2a_hex(keydata[-5:]))

        return keydata[:-5]


class BaggedKey(Struct):
    """
    A encrcdsa v2 key-bag

    TODO - figure out how this works
    """
    fieldinfo = [
( 0x0000, "keybag",     "128s"),
    ]
    def __init__(self, data):
        self.keybag = data

    def isvalid(self):
        """
        Check if we can decode this wrapped key.
        """
        return True

    def unwrapkey(self, privkey, **kwargs):
        """
        decrypt the key using a private key
        """
        return None


CSSM_ALGMODE_CBC_IV8  = 5
CSSM_ALGID_AES = 0x80000001
CSSM_ALGID_SHA1HMAC = 0x5b

class EncrCdsaFile(Struct):
    """
    Interface to a encrcdsa v2 file.
    """
    fieldinfo = [
( 0x0000, "signature",           "8s"),
( 0x0008, "version",             "L"),   # 2
( 0x000c, "blockIvLen",          "L"),   # 16
( 0x0010, "blockMode",           "L"),   # 5  CSSM_ALGMODE_CBC_IV8
( 0x0014, "blockAlgorithm",      "L"),   # 0x80000001  CSSM_ALGID_AES
( 0x0018, "keyBits",             "L"),   # in bits - 128 or 256
( 0x001c, "ivkeyAlgorithm",      "L"),   # 0x5b CSSM_ALGID_SHA1HMAC
( 0x0020, "ivkeyBits",           "L"),   # 160
( 0x0024, "unknownGuid",         "16s"),
( 0x0034, "bytesPerBlock",       "L"),   # 0x200
( 0x0038, "dataLen",             "Q"),   # ... a little less than the total nr of bytes
( 0x0040, "offsetToDataStart",   "Q"),   # 0x01de00
( 0x0048, "nritems",             "L"),   # 1
( 0x004C, "keyitems",            "*"),   # list of 20 byte records
( 0xFFFF, "wrappedkeys",         "*"),   # decoded key items
]
    @staticmethod
    def hasmagic(fh):
        fh.seek(0, io.SEEK_SET)
        cdsatag = fh.read(12)
        if not cdsatag:
            return False
        signature, version, = struct.unpack(">8sL", cdsatag)

        return signature == b'encrcdsa' and version == 2

    def nrblocks(self):
        return (self.dataLen-1) // self.bytesPerBlock + 1

    def parse(self, hdr):
        (
        self.signature,        # "encrcdsa"
        self.version,          #  2
        self.blockIvLen,       # 16
        self.blockMode,        #  5   CSSM_ALGMODE_CBC_IV8 
        self.blockAlgorithm,   # 0x80000001  CSSM_ALGID_AES
        self.keyBits,          # in bits   128  = 16 bytes
        self.ivkeyAlgorithm,  # CSSM_ALGID_SHA1HMAC
        self.ivkeyBits,       # in bits   160  = 20 bytes
        self.unknownGuid,      
        self.bytesPerBlock,    # in bytes  0x200
        self.dataLen,          # in bytes
        self.offsetToDataStart,# in bytes  0x01de00
        self.nritems,          # 1
        )  = struct.unpack(">8s7L16sLQQL", hdr[:0x4c])

        if self.signature != b'encrcdsa':
            raise Exception("not a encrcdsa header")

        o = 0x4c

        self.keyitems = []
        for i in range(self.nritems):
            itemtype, itemoffset, itemsize = struct.unpack(">LQQ", hdr[o:o+0x14])
            o += 0x14

            self.keyitems.append( (itemtype, itemoffset, itemsize) )

        self.wrappedkeys = []

        for tp, of, sz in self.keyitems:
            if tp == CSSM_APPLE_UNLOCK_TYPE_KEY_DIRECT:
                self.wrappedkeys.append(PassphraseWrappedKey(hdr[of:of+sz]))
            elif tp == CSSM_APPLE_UNLOCK_TYPE_WRAPPED_PRIVATE:
                self.wrappedkeys.append(CertificateWrappedKey(hdr[of:of+sz]))
            elif tp == CSSM_APPLE_UNLOCK_TYPE_KEYBAG:
                self.wrappedkeys.append(BaggedKey(hdr[of:of+sz]))

    def load(self, fh):
        fh.seek(0, io.SEEK_SET)
        hdr = fh.read(0x10000)
        self.parse(hdr)

    def isvalid(self):
        """
        Checks if we can decrypt this file.
        """
        if self.blockMode != CSSM_ALGMODE_CBC_IV8:
            print("unsupported block mode: %d" % self.blockMode)
        elif self.blockAlgorithm != CSSM_ALGID_AES:
            print("unsupported block algorithm: %d" % self.blockAlgorithm)
        elif self.ivkeyAlgorithm != CSSM_ALGID_SHA1HMAC:
            print("unsupported ivkey algorithm: %d" % self.ivkeyAlgorithm)
        else:
            return True

    def login(self, passphrase, **kwargs):
        """
        Authenticate v2
        """
        for i, wp in enumerate(self.wrappedkeys):
            if not wp.isvalid():
                print("key#%d - %s is not valid" % (i, type(wp)))
                continue
            try:
                keydata = wp.unwrapkey(passphrase, **kwargs)
                if keydata:
                    debugprint("keydata = %s" % b2a_hex(keydata))
                    self.setkey(keydata)
                    print("FOUND: passphrase decodes wrappedkey # %d" % i)
                    return True
            except Exception as e:
                pass

    def setkey(self, keydata):
        self.aeskey = keydata[:self.keyBits//8]
        self.hmackey = keydata[self.keyBits//8:]


    def readblock(self, fh, blocknum):
        """
        Read and decrypt a single block
        """
        fh.seek(self.offsetToDataStart + blocknum * self.bytesPerBlock)
        data = fh.read(self.bytesPerBlock)

        # because: self.ivkeyAlgorithm == CSSM_ALGID_SHA1HMAC
        # sha1 implying: self.ivkeyBits == 160
        iv = hmacsha1(self.hmackey, struct.pack(">L", blocknum))

        # because: self.blockAlgorithm == CSSM_ALGID_AES
        # because: self.blockMode == CSSM_ALGMODE_CBC_IV8 
        debugprint("blk ofs: %x, iv=%s" % (self.offsetToDataStart + blocknum * self.bytesPerBlock, b2a_hex(iv)))
        aes = AES.new(self.aeskey, mode=AES.MODE_CBC, IV=iv[:self.blockIvLen])

        data = aes.decrypt(data)
        if blocknum == self.nrblocks() - 1:
            trunk = self.dataLen % self.bytesPerBlock
            return data[:trunk]
        return data


class CdsaEncrFile(Struct):
    """
    Interface to a cdsaencr v1 file.
    """
    fieldinfo = [
( 0x0000, "unknownGuid",         "16s" ),  # 
( 0x0010, "bytesPerBlock",       "L"   ),  # 
( 0x0014, "blobEncAlgorithm",    "L"   ),  # CSSM_ALGID_3DES_3KEY_EDE
( 0x0018, "blobEncPadding",      "L"   ),  # CSSM_PADDING_PKCS7
( 0x001c, "blobEncMode",         "L"   ),  # CSSM_ALGMODE_CBCPadIV8
( 0x0020, "blobEncKeyBits",      "L"   ),  # 
( 0x0024, "blobEncIvLen",        "L"   ),  # 
( 0x0028, "kdfAlgorithm",        "L"   ),  # CSSM_ALGID_PKCS5_PBKDF2
( 0x002c, "kdfIterationCount",   "Q"   ),  #   .. todo: should be L
( 0x0034, "kdfSaltLen",          "L"   ),  # 
( 0x0038, "kdfSalt",             "32s" ),  # 
( 0x0058, "blockIvLen",          "L"   ),  # 
( 0x005c, "blockMode",           "L"   ),  # CSSM_ALGMODE_CBC_IV8

( 0x0060, "blockAlgorithm",      "L"   ),  # CSSM_ALGID_AES
( 0x0064, "keyBits",             "L"   ),  # 
( 0x0068, "keyIv",               "32s" ),  # 
( 0x0088, "wrappedAesKeyLen",         "L"   ),  # 
( 0x008c, "wrappedAesKey",            "256s"),  # 

( 0x018c, "hmacAlgorithm",     "L"   ),  # CSSM_ALGID_SHA1HMAC
( 0x0190, "hmacBits",          "L"   ),  # 
( 0x0194, "hmacIv",            "32s" ),  # 
( 0x01b4, "wrappedHmacKeyLen",         "L"   ),  # 
( 0x01b8, "wrappedHmacKey",            "256s"),  # 

( 0x02b8, "integrityAlgorithm",     "L"   ),  # CSSM_ALGID_SHA1HMAC
( 0x02bc, "integrityBits",          "L"   ),  # 
( 0x02c0, "integrityIv",            "32s" ),  # 
( 0x02e0, "wrappedIntegrityKeyLen",         "L"   ),  # 
( 0x02e4, "wrappedIntegrityKey",            "256s"),  # 

( 0x03e4, "unkLen",              "L"   ),  # 
( 0x03e8, "unkData",             "256s"),  # 

( 0x04e8, "offsetToHeader",      "Q"   ),  # 
( 0x04f0, "version",             "L"   ),  # 
( 0x04f4, "signature",           "8s"  ),  # 
            ]
    @staticmethod
    def hasmagic(fh):
        fh.seek(-12, io.SEEK_END)
        cdsatag = fh.read(12)
        if not cdsatag:
            return False
        version, signature = struct.unpack(">L8s", cdsatag)

        return signature == b'cdsaencr' and version == 1

    def nrblocks(self):
        return (self.offsetToHeader-1) // self.bytesPerBlock + 1

    def load(self, fh):
        self.offsetToDataStart = 0

        fh.seek(-20, io.SEEK_END)
        cdsatag = fh.read(20)
        if not cdsatag:
            raise Exception("no cdsatag")
        self.offsetToHeader, self.version, self.signature = struct.unpack(">QL8s", cdsatag)

        if self.signature != b'cdsaencr':
            raise Exception("no cdsatag")

        fh.seek(self.offsetToHeader, io.SEEK_SET)
        infohdr = fh.read(0x4e8)
        if not infohdr:
            raise Exception("no infohdr")
        self.parse(infohdr)

    def parse(self, infohdr):
        (
            self.unknownGuid,
            self.bytesPerBlock,
            self.blobEncAlgorithm,
            self.blobEncPadding,
            self.blobEncMode,
            self.blobEncKeyBits,
            self.blobEncIvLen,
            self.kdfAlgorithm,
            self.kdfIterationCount,
            self.kdfSaltLen,
            self.kdfSalt,
            self.blockIvLen,
            self.blockMode,
        ) = struct.unpack(">16s L L L L L L L Q L 32s L L", infohdr[:0x60])

        o = 0x60

        (
            self.blockAlgorithm,
            self.keyBits,
            self.keyIv,
            self.wrappedAesKeyLen,
            self.wrappedAesKey,
        ) = struct.unpack(">L L 32s L 256s", infohdr[o:o+0x12C])

        o += 0x12C

        (
            self.hmacAlgorithm,
            self.hmacBits,
            self.hmacIv,
            self.wrappedHmacKeyLen,
            self.wrappedHmacKey,
        ) = struct.unpack(">L L 32s L 256s", infohdr[o:o+0x12C])

        o += 0x12C

        (
            self.integrityAlgorithm,
            self.integrityBits,
            self.integrityIv,
            self.wrappedIntegrityKeyLen,
            self.wrappedIntegrityKey,
        ) = struct.unpack(">L L 32s L 256s", infohdr[o:o+0x12C])

        o += 0x12C

        (
            self.unkLen,
            self.unkData,
        ) = struct.unpack(">L 256s", infohdr[o:o+0x104])

        o += 0x104

    def isvalid(self):
        """
        Check if this v1 header uses our supported algorithms.
        """
        if self.blobEncAlgorithm != CSSM_ALGID_3DES_3KEY_EDE:
            print("unsupported blobEncAlgorithm: %d" % self.blobEncAlgorithm)
        elif self.blobEncPadding != CSSM_PADDING_PKCS7:
            print("unsupported blobEncPadding : %d" % self.blobEncPadding)
        elif self.blobEncMode != CSSM_ALGMODE_CBCPadIV8:
            print("unsupported blobEncMode : %d" % self.blobEncMode)
        elif self.kdfAlgorithm != CSSM_ALGID_PKCS5_PBKDF2:
            print("unsupported kdfAlgorithm : %d" % self.kdfAlgorithm)
        elif self.blockMode != CSSM_ALGMODE_CBC_IV8:
            print("unsupported blockMode : %d" % self.blockMode)
        elif self.blockAlgorithm != CSSM_ALGID_AES:
            print("unsupported blockAlgorithm : %d" % self.blockAlgorithm)
        elif self.hmacAlgorithm != CSSM_ALGID_SHA1HMAC:
            print("unsupported hmacAlgorithm : %d" % self.hmacAlgorithm)
        else:
            return True

    def getHmacKey(self, passphrase, **kwargs):
        """
        decodes the hmac key
        """
        return self.unwrapkey(passphrase, self.wrappedHmacKey[:self.wrappedHmacKeyLen], **kwargs)

    def getIntegrityKey(self, passphrase, **kwargs):
        """
        decodes the integrity key
        """
        return self.unwrapkey(passphrase, self.wrappedIntegrityKey[:self.wrappedIntegrityKeyLen], **kwargs)

    def getAesKey(self, passphrase, **kwargs):
        """
        decodes the aes key
        """
        return self.unwrapkey(passphrase, self.wrappedAesKey[:self.wrappedAesKeyLen], **kwargs)

    def unwrapkey(self, passphrase, blob, **kwargs):
        """
        Unwraps the keys using the algorithm specified in rfc3217 or rfc3537 
        """
        if not kwargs.get('skipkdf'):
            hashedpw = pbkdf2(passphrase, self.kdfSalt[:self.kdfSaltLen], self.kdfIterationCount)
            deskey = hashedpw[:self.blobEncKeyBits//8]
        else:
            deskey = passphrase[:self.blobEncKeyBits//8]

        tdesIv = b'\x4A\xDD\xA2\x2C\x79\xE8\x21\x05'
        des1 = DES3.new(deskey, mode=DES3.MODE_CBC, IV=tdesIv)
        key1 = remove_pkcs7_padding(des1.decrypt(blob), self.blobEncIvLen)

        # note: standard says: use first block for iv,
        # this is equivalent to using a zero IV, and ignoring the first
        # plaintext block
        des2 = DES3.new(deskey, mode=DES3.MODE_CBC, IV=b'\x00'*8)
        keydata = remove_pkcs7_padding(des2.decrypt(key1[::-1]), self.blobEncIvLen)

        if keydata[8:12] != b'\x00' * 4:
            print("note: tdes key unwrap has non zero prefix: %s" % b2a_hex(keydata[8:12]))

        return keydata[12:]

    def login(self, passphrase, **kwargs):
        """
        Authenticate v1
        """
        self.aeskey = self.getAesKey(passphrase, **kwargs)
        self.hmackey = self.getHmacKey(passphrase, **kwargs)
        self.ikey = self.getIntegrityKey(passphrase, **kwargs)

        debugprint("login -> aes=%s, hmac=%s" % (b2a_hex(self.aeskey), b2a_hex(self.hmackey)))

        return True

    def setkey(self, keydata):
        self.aeskey = keydata[:self.keyBits//8]
        self.hmackey = keydata[self.keyBits//8:]
        self.ikey = b''

    def readblock(self, fh, blocknum):
        """
        Read and decrypt a single block
        """
        fh.seek(self.offsetToDataStart + blocknum * self.bytesPerBlock)
        data = fh.read(self.bytesPerBlock)
        iv = hmacsha1(self.hmackey, struct.pack(">L", blocknum))
        aes = AES.new(self.aeskey, mode=AES.MODE_CBC, IV=iv[:self.blockIvLen])
        return aes.decrypt(data)


def unlockfile(args, enc):
    """
    unlock the encrypted diskimage in `enc`, 
    """

    # output all the header values
    enc.dump()

    # determine the passphrase, either specified in ascii, or hex.
    if args.password:
        passphrase = args.password.encode('utf-8')
    elif args.hexpassword:
        passphrase = a2b_hex(args.hexpassword.replace(' ',''))
    else:
        passphrase = None

    # load the private key if any was specified on the commandline.
    if args.privatekey:
        privatekey = Crypto.PublicKey.RSA.importKey(open(args.privatekey, "rb").read())
    else:
        privatekey = None

    # now use the passphrase or private to to unlock
    # you can also directly specify the keydata, bypassing
    # the wrapped keys.
    if passphrase is not None:
        return enc.login(passphrase, skipkdf = args.skipkdf)
    elif privatekey is not None:
        return enc.login(privatekey)
    elif args.keydata:
        enc.setkey(a2b_hex(args.keydata))
        return True


def savedecrypted(enc, fh, filename):
    """
    Write all decrypted blocks to `filename`.
    """
    with open(filename, "wb") as ofh:
        for bnum in range(enc.nrblocks()):
            data = enc.readblock(fh, bnum)
            ofh.write(data)


def dumpblocks(enc, fh):
    """
    print all decrypted blocks as hexdump to stdout.
    """
    for bnum in range(enc.nrblocks()):
        print("-- blk %d" % bnum)
        data = enc.readblock(fh, bnum)
        hexdump(data)


def createdecryptedfilename(filename):
    """
    Determine a filename to save the decrypted diskimage to.
    """
    i = filename.rfind(".")
    if i<0:
        return filename + "-decrypted"
    return filename[:i] + "-decrypted" + filename[i:]


def processfile(args, filename, fh):
    """
    determines the diskimage type, unlocks it,
    then performs action requested from the commandline.
    """
    enc = None
    for cls in (EncrCdsaFile, CdsaEncrFile):
        try:
            if cls.hasmagic(fh):
                enc = cls()

                enc.load(fh)

        except Exception as e:
            print("ERR %s" % e)
            if args.debug:
                raise
    if not enc:
        print("Did not find an encrypted disk image")
        return
    if not unlockfile(args, enc):
        print("unlock failed")
        return
    if args.save:
        savedecrypted(enc, fh, createdecryptedfilename(filename))
    elif args.dump:
        dumpblocks(enc, fh)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='A tool for decrypting Apple encrypted disk images.')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--debug', action='store_true', help='abort on exceptions.')
    parser.add_argument('--password', '-p', type=str)
    parser.add_argument('--privatekey', '-k', type=str)
    parser.add_argument('--hexpassword', '-P', type=str)
    parser.add_argument('--keydata', '-K', type=str)
    parser.add_argument('--skipkdf', '-n', action='store_true', help='skip passphrase hashing - useful for ipsw decryption')
    parser.add_argument('--save', '-s', action='store_true', help='save decrypted image')
    parser.add_argument('--dump', '-d', action='store_true', help='hexdump decrypted image')
    parser.add_argument('files', nargs='*', type=str)

    args = parser.parse_args()

    for filename in args.files:
        try:
            print("==>", filename, "<==")
            with open(filename, "rb") as fh:
                processfile(args, filename, fh)
        except Exception as e:
            print("EXCEPTION %s" % e)
            if args.debug:
                raise


if __name__ == '__main__':
    main()
