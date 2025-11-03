# ryde-native-dump
A messy python script that dumps encryption keys &amp; secrets from Ryde´s native lib.

## Libraries used
1. elftools
2. capstone

# Example dump
``Version: 4.4.0``
> [!CAUTION]
> getThirdKey (1, 2) is invalid since it doesn't function the same as the other functions and I am simply in a rush and don't have time to rewrite the code.
```py
{
    'Java_com_yulai_keylib_NativeLib_getCryptAlgorithm': {
        0: 'AES'
    },
    'Java_com_yulai_keylib_NativeLib_getThirdKey': {
        0: 'AIzaSyBNFtjnuBTZu5qHMg0fJlRR8abt7iN_x0k',
        1: '¤7@ùß\x02\x01ë¢',
        2: ''
    },
    'Java_com_yulai_keylib_NativeLib_getCryptAlgorithm2': {
        0: 'MD5'
    },
    'Java_com_yulai_keylib_NativeLib_getSchoolPoint': {
        0: 'UnlkZS4yMDIzMDExMS5jaGFuZ3pob3Vnb29k'
    },
    'Java_com_yulai_keylib_NativeLib_getCryptTransformation2': {
        0: 'AES/CBC/PKCS5Padding'
    },
    'Java_com_yulai_keylib_NativeLib_getKeySecret1': {
        0: b'8070605040392010IALUYBAD9B39A8D84907A'
    },
    'Java_com_yulai_keylib_NativeLib_getKeySecret2': {
        0: b'8070705040332010EDYRBAD913968D87607A'
    },
    'Java_com_yulai_keylib_NativeLib_getKeySecret': {
        0: b'8E74C26OA0NB3F10EDYROMC9B3KB8DZ410AB'
    },
    'Java_com_yulai_keylib_NativeLib_getCryptTransformation': {
        0: 'AES/ECB/NoPadding'
    },
    'Java_com_yulai_keylib_NativeLib_getTimeVerify': {
        0: 'Ryde.200220411.changzhouchangfa'
    },
    'Java_com_yulai_keylib_NativeLib_getBLEKey': {
        0: [
            '0x61', '0x73', '0x64', '0x66', '0x67', '0x68', 
            '0x31', '0x32', '0x33', '0x34', '0x35', '0x36', 
            '0x7a', '0x78', '0x63', '0x76'
        ]
    }
}

```
