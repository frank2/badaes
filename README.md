# badaes
This is my repository for learning AES, so it is bad and you should not use it.
# why are you posting this on github then?
I dunno maybe you'll find it useful. 😇
# how do you use it?
So if you're familiar with AES, this library contains all the basic components you need: polynomial field objects, word objects and their mathematical equivalents based on FIPS-197: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

* Field objects
  * Field(0x57) == {x^6 + x^4 + x^2 + x + 1}
  * Field(0x57) * Field(0x83) == {x^13 + x^11 + x^9 + x^8 + x^6 + x^5 + x^4 + x^3 + 1} == Field(0x2b79)
  * Field::AESMul(Field(0x57), Field(0x83)) ==
    * Field(0x57) * Field(0x83) % Field(0x11b) == Field(0x2b79) % Field(0x11b)
    * {x^13 + x^11 + x^9 + x^8 + x^6 + x^5 + x^4 + x^3 + 1} % {x^8 + x^4 + x^3 + x + 1} == {x^7 + x^6 + 1} == Field(0xc1)
* Word objects
  * Word({0x02, 0x01, 0x01, 0x03}) == {03}x^3 + {01}x^2 + {01}x + {02}
  * Word({0x02, 0x01, 0x01, 0x03}) * Word({0x10, 0x20, 0x30, 0x40}) ==
    * Word[0] = AESMul({02}, {10}) ^ AESMul({03}, {20}) ^ AESMul({01}, {30}) ^ AESMul({01}, {40})
    * Word[1] = AESMul({01}, {10}) ^ AESMul({02}, {20}) ^ AESMul({03}, {30}) ^ AESMul({01}, {40})
    * Word[2] = AESMul({01}, {10}) ^ AESMul({01}, {20}) ^ AESMul({02}, {30}) ^ AESMul({03}, {40})
    * Word[3] = AESMul({03}, {10}) ^ AESMul({01}, {20}) ^ AESMul({01}, {30}) ^ AESMul({02}, {40})
    * == Word({0x30, 0x40, 0x90, 0xa0})
* SBox objects are straightforward-- all your favorite subWord and subByte functionality is there.
* State objects contain the core AES functionality: addRoundKey, sub/invSubBytes, shift/invShiftRows and mix/invMixColumns
* Key objects perform their own expansion based on access, e.g. (taken from Appendix 1 of FIPS-197):
  * key = AESKey({0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}, 16)
  * key[8] == Word({0xf2, 0xc2, 0x95, 0xf2})
* Key objects can be forked. What this means is that after a key has fully expanded, using Key::fork, the key will create a new key based on the last N rounds of the expansion, where N is the size of the key in words.
* Cipher objects allow you to modify the means by which the AES algorithm is driven.
* The following AES cipher modes are available:
  * Electronic codebook: AESCipherECB (please don't ever use this unless you're doing so intentionally)
  * Cipher block chaining: AESCipherCBC
  * Propagating cipher block chaining: AESCipherPCBC
  * Cipher feedback: AESCipherCFB
  * Output feedback: AESCipherOFB
  * If you're unsure of which mode to use, use AESCipher-- this defaults to AESCipherCBC.
* Some usage notes:
  * If you're using any mode other than ECB, encryption will generate an initialization vector-- you will need this vector for when you perform decryption.
  * **If the data you're encrypting does not land on a block boundary, the data will be padded with random data. It is your responsibility to make sure the true length of the data you encrypt is recoverable.**