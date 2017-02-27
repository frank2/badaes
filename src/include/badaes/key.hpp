#pragma once

#include <map>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include <badaes/exception.hpp>
#include <badaes/field.hpp>
#include <badaes/sbox.hpp>
#include <badaes/word.hpp>

namespace BadAES
{
   class Key
   {
   protected:
      size_t size = 0; /* size of key in words */
      std::vector<Word> words;
      const SBox *sBox;
      std::vector<Word> expansion;
      Field roundConstant;

   public:
      Key(std::vector<Word> words, const SBox *sBox);
      Key(uint8_t *keyData, size_t bufferSize, const SBox *sBox);
      Key(size_t size, const SBox *sBox);
      Key(const Key &key);
      Key();

      static Key Generate(size_t size, const SBox *sBox);

      Word operator[](size_t index);

      void setSize(size_t size);
      size_t getSize(void) const;

      void setWords(std::vector<Word> words);
      void setWords(uint8_t *keyData, size_t bufferSize);
      std::vector<Word> getWords(void) const;

      void setSBox(const SBox *sBox);
      const SBox *getSBox(void) const;

      void setExpansion(std::vector<Word> expansion);
      std::vector<Word> getExpansion(void) const;

      void setRoundConstant(Field constant);
      Field getRoundConstant(void) const;

      Word getRound(size_t index);

      Key fork(void) const;
   };

   class AESKey : public Key
   {
   public:
      AESKey(std::vector<Word> words);
      AESKey(uint8_t *keyData, size_t bufferSize);
      AESKey(size_t size);
      AESKey(const AESKey &key);
      AESKey(const Key &key);
      AESKey();

      static AESKey Generate(size_t size);
   };

   class AESKey128 : public AESKey
   {
   public:
      const static size_t Size = 4;
      
   protected:
      size_t size = AESKey128::Size;

   public:
      AESKey128(std::vector<Word> words);
      AESKey128(uint8_t *keyData, size_t bufferSize);
      AESKey128(const AESKey128 &key);
      AESKey128(const AESKey &key);
      AESKey128(const Key &key);
      AESKey128();

      static AESKey128 Generate(void);
   };

   class AESKey192 : public AESKey
   {
   public:
      const static size_t Size = 6;
      
   protected:
      size_t size = AESKey192::Size;

   public:
      AESKey192(std::vector<Word> words);
      AESKey192(uint8_t *keyData, size_t bufferSize);
      AESKey192(const AESKey192 &key);
      AESKey192(const AESKey &key);
      AESKey192(const Key &key);
      AESKey192();
      
      static AESKey192 Generate(void);
   };

   class AESKey256 : public AESKey
   {
   public:
      const static size_t Size = 8;
      
   protected:
      size_t size = AESKey256::Size;

   public:
      AESKey256(std::vector<Word> words);
      AESKey256(uint8_t *keyData, size_t bufferSize);
      AESKey256(const AESKey256 &key);
      AESKey256(const AESKey &key);
      AESKey256(const Key &key);
      AESKey256();

      static AESKey256 Generate(void);
   };
}
