#pragma once

#include <stdint.h>
#include <vector>

#include <badaes/exception.hpp>
#include <badaes/key.hpp>
#include <badaes/sbox.hpp>
#include <badaes/state.hpp>

namespace BadAES
{
   class Cipher
   {
   protected:
      Key *key;
      SBox *sBox;
      size_t blockSize;

   public:
      Cipher(Key *key, SBox *sBox, size_t blockSize);
      Cipher(const Cipher &cipher);
      Cipher();

      void setKey(Key *key);
      Key *getKey(void) const;

      void setSBox(SBox *sBox);
      SBox *getSBox(void) const;

      void setBlockSize(size_t blockSize);
      size_t getBlockSize(void) const;

      virtual size_t numberOfRounds(void);
      virtual void encryptionRound(State *state, size_t round);
      virtual void decryptionRound(State *state, size_t round);
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      
   protected:
      virtual std::vector<State> getStatesFromBuffer(uint8_t *dataBuffer, size_t dataSize);
      virtual uint8_t *dumpStatesToBuffer(std::vector<State> states, size_t *outSize);
   };

   class AESCipher : public Cipher
   {
   public:
      const static size_t BlockSize = 4;
      
   protected:
      size_t blockSize = AESCipher::BlockSize;
      
   public:
      AESCipher(Key *key, size_t blockSize);
      AESCipher(const AESCipher &cipher);
      AESCipher();
   };
}
