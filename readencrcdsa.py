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
import io

def hexdump(data):
    """
    Prints a hexdump of 'data' to stdout, 16 bytes per line.
    """
    for o in range(0, len(data), 16):
        line = "%04x:" % o
        for i in range(16):
            line += " %02x" % data[o+i]
        line += "  "
        for i in range(16):
            line += "%c" % data[o+i] if 32 <= data[o+i] <= 126 else "."
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

CSSM_ALGID_PKCS5_PBKDF2 = 0x67
CSSM_ALGID_3DES_3KEY_EDE  = 0x11
CSSM_PADDING_PKCS7 = 7
CSSM_ALGMODE_CBCPadIV8 = 6

class WrappedKey:
    """
    A encrcdsa v2 wrapped key.
    """
    wrappedkeyinfo = [
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
    def __init__(self, data):
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

    def dump(self):
        print("------ WrappedKey ------")
        for o, aname, atype in self.wrappedkeyinfo:
            val = getattr(self, aname)
            if type(val) == bytes:
                print("%04x: %-40s %s" % (o, aname, b2a_hex(val)))
            else:
                print("%04x: %-40s 0x%08x" % (o, aname, val))

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

    def unwrapkey(self, passphrase, bypasskdf = False):
        """
        decrypt the key using a passphrase.
        """
        if not bypasskdf:
            hashedpw = pbkdf2(passphrase, self.kdfSalt[:self.kdfSaltLen], self.kdfIterationCount)
            deskey = hashedpw[:self.blobEncKeyBits//8]
            iv = self.blobEncIv[:self.blobEncIvLen]
        else:
            deskey = passphrase[:self.blobEncKeyBits//8]
            iv = passphrase[self.blobEncKeyBits//8:]

        des = DES3.new(deskey, mode=DES3.MODE_CBC, IV=iv)
        unwrappeddata = des.decrypt(self.encryptedKeyblob[:self.encryptedKeyblobLen])
        keydata = remove_pkcs7_padding(unwrappeddata, self.blobEncIvLen)

        if keydata[-5:] != b'CKIE\x00':
            print("v2 unwrap: missing CKIE suffix: %s" % b2a_hex(keydata[-5:]))

        return keydata[:-5]



CSSM_ALGMODE_CBC_IV8  = 5
CSSM_ALGID_AES = 0x80000001
CSSM_ALGID_SHA1HMAC = 0x5b

class EncrCdsaFile:
    """
    Interface to a encrcdsa v2 file.
    """
    headerinfo = [
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
]

    def __init__(self, fh):
        hdr = fh.read(0x10000)
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
        self.pubkeys = []
        self.filesigs = []

        for tp, of, sz in self.keyitems:
            if tp == 1:
                self.wrappedkeys.append(WrappedKey(hdr[of:of+sz]))
            elif tp == 2:
                self.pubkeys.append(hdr[of:of+sz])
            elif tp == 3:
                self.filesigs.append(hdr[of:of+sz])


    def dump(self):
        """
        Prints all info found in the header.
        """
        print("------ EncrCdsaFile ------")
        for o, aname, atype in self.headerinfo:
            val = getattr(self, aname)
            if type(val) == bytes:
                print("%04x: %-40s %s" % (o, aname, b2a_hex(val)))
            else:
                print("%04x: %-40s 0x%08x" % (o, aname, val))
        for wp in self.wrappedkeys:
            wp.dump()
        for pk in self.pubkeys:
            print("--pubkey  %s" % b2a_hex(pk))
        for fs in self.filesigs:
            print("--filesig  %s" % b2a_hex(fs))

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

    def login(self, passphrase, bypasskdf = False):
        """
        Authenticate
        """
        for i, wp in enumerate(self.wrappedkeys):
            if not isinstance(wp, WrappedKey):
                print("not a wrapped key: %s" % wp)
                continue
            if not wp.isvalid():
                continue

            try:
                keydata = wp.unwrapkey(passphrase, bypasskdf)
                self.setkey(keydata)

                print("FOUND: passphrase decodes wrappedkey # %d" % i)
                break
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
        iv = hmacsha1(self.hmackey, struct.pack(">L", blocknum))
        aes = AES.new(self.aeskey, mode=AES.MODE_CBC, IV=iv[:16])
        return aes.decrypt(data)


class CdsaEncrFile:
    """
    Interface to a cdsaencr v1 file.
    """
    headerinfo = [
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
    def __init__(self, fh):
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

    def dump(self):
        """
        Prints all info found in the header.
        """
        print("------ CdsaEncrFile ------")
        for o, aname, atype in self.headerinfo:
            val = getattr(self, aname)
            if type(val) == bytes:
                print("%04x: %-40s %s" % (o, aname, b2a_hex(val)))
            else:
                print("%04x: %-40s 0x%08x" % (o, aname, val))

    def getHmacKey(self, passphrase, bypasskdf = False):
        """
        decodes the hmac key
        """
        return self.unwrapkey(passphrase, self.wrappedHmacKey[:self.wrappedHmacKeyLen], bypasskdf)

    def getIntegrityKey(self, passphrase, bypasskdf = False):
        """
        decodes the integrity key
        """
        return self.unwrapkey(passphrase, self.wrappedIntegrityKey[:self.wrappedIntegrityKeyLen], bypasskdf)

    def getAesKey(self, passphrase, bypasskdf = False):
        """
        decodes the aes key
        """
        return self.unwrapkey(passphrase, self.wrappedAesKey[:self.wrappedAesKeyLen], bypasskdf)

    def unwrapkey(self, passphrase, blob, bypasskdf = False):
        """
        Unwraps the keys using the algorithm specified in rfc3217 or rfc3537 
        """
        if not bypasskdf:
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

    def login(self, passphrase, bypasskdf = False):
        """
        Authenticate
        """
        self.aeskey = self.getAesKey(passphrase, bypasskdf)
        self.hmackey = self.getHmacKey(passphrase, bypasskdf)
        self.ikey = self.getIntegrityKey(passphrase, bypasskdf)

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
        aes = AES.new(self.aeskey, mode=AES.MODE_CBC, IV=iv[:16])
        return aes.decrypt(data)


def dumpblocks(args, enc, fh):
    enc.dump()

    if args.password:
        passphrase = args.password.encode('utf-8')
    elif args.hexpassword:
        passphrase = a2b_hex(args.hexpassword)
    else:
        passphrase = None

    if passphrase is not None:
        enc.login(passphrase, bypasskdf = args.bypasskdf)
    elif args.keydata:
        enc.setkey(a2b_hex(args.keydata))

    for bnum in range(0x10):
        print("-- blk %d" % bnum)
        data = enc.readblock(fh, bnum)
        hexdump(data)


def processfile(args, fh):
    for cls in (EncrCdsaFile, CdsaEncrFile):
        try:
            enc = cls(fh)
            try:
                dumpblocks(args, enc, fh)
            except Exception as e:
                print("ERR %s" % e)
                if args.debug:
                    raise
        except Exception as e:
            print("ERR %s" % e)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='efidump')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--debug', action='store_true', help='abort on exceptions.')
    parser.add_argument('--password', '-p', type=str)
    parser.add_argument('--hexpassword', '-P', type=str)
    parser.add_argument('--keydata', '-K', type=str)
    parser.add_argument('--bypasskdf', '-n', action='store_true', help='bypass passphrase hashing - useful for ipsw decryption')
    parser.add_argument('files', nargs='*', type=str)

    args = parser.parse_args()

    for filename in args.files:
        try:
            print("==>", filename, "<==")
            with open(filename, "rb") as fh:
                processfile(args, fh)
        except Exception as e:
            print("EXCEPTION %s" % e)
            if args.debug:
                raise


if __name__ == '__main__':
    main()
