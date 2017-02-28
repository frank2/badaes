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

   public:
      State(std::vector<Word> words);
      State(uint8_t *stateData, size_t stateSize);
      State(size_t blockSize);
      State(const State &state);
      State();

      Word &operator[](int index);

      void setBlockSize(size_t blockSize);
      size_t getBlockSize(void) const;

      void setWords(std::vector<Word> words);
      void setWords(uint8_t *stateData, size_t stateSize);
      std::vector<Word> getWords(void) const;

      void addState(State *state); /* typically an initialization vector */
      void addRoundKey(Key *key, size_t round);
      
      void subBytes(const SBox *sBox);
      void invSubBytes(const SBox *sBox);

      void shiftRows(void);
      void invShiftRows(void);

      void mixColumns(void);
      void invMixColumns(void);
   };
}
