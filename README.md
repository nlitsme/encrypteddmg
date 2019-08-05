readencrcdsa
============

A tool for decrypting Apple encrypted disk images.
Both old 'v1' and current 'v2' images are supported.
This tool can also decrypt iphone rootfilesystem diskimages.


iphone images
=============

Iphone images are downloaded as `.ipsw` files.

    http://appldnld.apple.com.edgesuite.net/content.info.apple.com/iPhone/061-6582.20090617.LlI87/iPhone2,1_3.0_7A341_Restore.ipsw

The `ipsw` file is a PKZIP file, this file contains several diskimages:
 * 018-5302-002.dmg, the root filesystem
 * 018-5304-002.dmg, 018-5306-002.dmg, the encrypted update and restore ramdisk images.

Decrypting iphone ramdisk images is done using a different tool, named `img3tool`.

The rootfilesystem is encrypted with a hash of either of the decrypted ramdisk images. To use this hash to decrypt the 
root filesystem, you have to pass the `-n` option disabiing the normal password hashing code.

    python3 readencrcdsa.py -n -P a597f200228fb4766e4c8a2a03bcb54d83c75f538fb75a981229f0c09d7ac85f ipsw/018-5302-002.dmg

Alternatively, when you know the master key, you can specify this directly using `-K`

    python3 readencrcdsa.py -K 7d779fed28961506ca9443de210224f211790192b2a2308b8bc0e7d4a2ca61a68e26200e ipsw/018-5302-002.dmg


OSXSDK
======

The relevant headers from the MacOSX sdk:

    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Security.framework/Versions/A/Headers/cssmtype.h
    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Security.framework/Versions/A/Headers/cssmapple.h


AUTHOR
======

(C) 2019 Willem Hengeveld <itsme@xs4all.nl>

