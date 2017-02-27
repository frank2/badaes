#pragma once

#include <stdint.h>
#include <vector>

#include <badaes/exception.hpp>
#include <badaes/field.hpp>
#include <badaes/key.hpp>
#include <badaes/sbox.hpp>
#include <badaes/word.hpp>

namespace BadAES
{
   class State
   {
   protected:
      size_t blockSize = 0;
      std::vector<Word> words;
      const SBox *sBox;

   public:
      State(std::vector<Word> words, const SBox *sBox);
      State(uint8_t *stateData, size_t stateSize, const SBox *sBox);
      State(size_t blockSize, const SBox *sBox);
      State(const State &state);
      State();

      Word &operator[](int index);

      void setBlockSize(size_t blockSize);
      size_t getBlockSize(void) const;

      void setWords(std::vector<Word> words);
      void setWords(uint8_t *stateData, size_t stateSize);
      std::vector<Word> getWords(void) const;

      void setSBox(const SBox *sBox);
      const SBox *getSBox(void) const;

      void addState(State *state);
      void addRoundKey(Key *key, size_t round);
      
      void subBytes(void);
      void invSubBytes(void);

      void shiftRows(void);
      void invShiftRows(void);

      void mixColumns(void);
      void invMixColumns(void);
   };

   class AESState : public State
   {
   public:
      const static size_t BlockSize = 4;
      
   protected:
      size_t blockSize = AESState::BlockSize;
      
   public:
      AESState(std::vector<Word> words);
      AESState(uint8_t *stateData, size_t stateSize);
      AESState(const AESState &state);
      AESState(const State &state);
      AESState();
   };
}
