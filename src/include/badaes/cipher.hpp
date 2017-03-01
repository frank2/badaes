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
      std::vector<Word> initVector;

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

      void setInitVector(std::vector<Word> initVector);
      std::vector<Word> getInitVector(void) const;
      void generateVector(void);

      virtual size_t numberOfRounds(void);
      virtual void encryptionRound(State *state, size_t round);
      virtual void decryptionRound(State *state, size_t round);
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      
   protected:
      virtual std::vector<State> getStatesFromBuffer(uint8_t *dataBuffer, size_t dataSize);
      virtual uint8_t *dumpStatesToBuffer(std::vector<State> states, size_t *outSize);
   };

   /* named as such to prevent use of AESCipher being ECB
      fuck ECB */
   class AESCipherECB : public Cipher
   {
   public:
      const static size_t BlockSize = 4;
      
   protected:
      size_t blockSize = AESCipherECB::BlockSize;

   public:
      AESCipherECB(Key *key);
      AESCipherECB(const AESCipherECB &cipher);
      AESCipherECB();
   };

   class AESCipherCBC : public AESCipherECB
   {
   public:
      AESCipherCBC(Key *key);
      AESCipherCBC(const AESCipherCBC &cipher);
      AESCipherCBC();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   class AESCipherPCBC : public AESCipherECB
   {
   public:
      AESCipherPCBC(Key *key);
      AESCipherPCBC(const AESCipherPCBC &cipher);
      AESCipherPCBC();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   class AESCipherCFB : public AESCipherECB
   {
   public:
      AESCipherCFB(Key *key);
      AESCipherCFB(const AESCipherCFB &cipher);
      AESCipherCFB();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   class AESCipherOFB : public AESCipherECB
   {
   public:
      AESCipherOFB(Key *key);
      AESCipherOFB(const AESCipherOFB &cipher);
      AESCipherOFB();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   typedef AESCipherCBC AESCipher;
}
