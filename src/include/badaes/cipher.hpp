#pragma once

#include <stdint.h>
#include <vector>

#include <badaes/exception.hpp>
#include <badaes/key.hpp>
#include <badaes/sbox.hpp>
#include <badaes/state.hpp>

namespace BadAES
{
   class CipherECB
   {
   protected:
      Key *key;
      SBox *sBox;
      size_t blockSize;
      std::vector<Word> initVector;

   public:
      CipherECB(Key *key, SBox *sBox, size_t blockSize);
      CipherECB(const CipherECB &cipher);
      CipherECB();

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

   class CipherCBC : public CipherECB
   {
   public:
      CipherCBC(Key *key, SBox *sBox, size_t blockSize);
      CipherCBC(const CipherCBC &cipher);
      CipherCBC();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   class CipherPCBC : public CipherECB
   {
   public:
      CipherPCBC(Key *key, SBox *sBox, size_t blockSize);
      CipherPCBC(const CipherPCBC &cipher);
      CipherPCBC();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   class CipherCFB : public CipherECB
   {
   public:
      CipherCFB(Key *key, SBox *sBox, size_t blockSize);
      CipherCFB(const CipherCFB &cipher);
      CipherCFB();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   class CipherOFB : public CipherECB
   {
   public:
      CipherOFB(Key *key, SBox *sBox, size_t blockSize);
      CipherOFB(const CipherOFB &cipher);
      CipherOFB();
      
      virtual uint8_t *encrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
      virtual uint8_t *decrypt(uint8_t *dataBuffer, size_t dataSize, size_t *outSize);
   };

   typedef CipherCBC Cipher;

   class AESCipherECB : public CipherECB
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

   class AESCipherCBC : public CipherCBC
   {
   public:
      const static size_t BlockSize = 4;

   protected:
      size_t blockSize = AESCipherCBC::BlockSize;
      
   public:
      AESCipherCBC(Key *key);
      AESCipherCBC(const AESCipherCBC &cipher);
      AESCipherCBC();
   };

   class AESCipherPCBC : public CipherPCBC
   {
   public:
      const static size_t BlockSize = 4;

   protected:
      size_t blockSize = AESCipherPCBC::BlockSize;
      
   public:
      AESCipherPCBC(Key *key);
      AESCipherPCBC(const AESCipherPCBC &cipher);
      AESCipherPCBC();
   };
   
   class AESCipherCFB : public CipherCFB
   {
   public:
      const static size_t BlockSize = 4;

   protected:
      size_t blockSize = AESCipherCFB::BlockSize;
      
   public:
      AESCipherCFB(Key *key);
      AESCipherCFB(const AESCipherCFB &cipher);
      AESCipherCFB();
   };
   
   class AESCipherOFB : public CipherOFB
   {
   public:
      const static size_t BlockSize = 4;

   protected:
      size_t blockSize = AESCipherOFB::BlockSize;
      
   public:
      AESCipherOFB(Key *key);
      AESCipherOFB(const AESCipherOFB &cipher);
      AESCipherOFB();
   };

   typedef AESCipherCBC AESCipher;
}
