#pragma once

#include <stdint.h>
#include <vector>

#include <badaes/exception.hpp>
#include <badaes/field.hpp>
#include <badaes/word.hpp>

namespace BadAES
{
   class SBox
   {
   protected:
      std::vector<uint8_t> sBox, invSBox;

   public:
      SBox(std::vector<uint8_t> sBox, std::vector<uint8_t> invSBox);
      SBox(uint8_t sBox[256], uint8_t invSBox[256]);
      SBox(const SBox &sBox);
      SBox();

      static SBox AESSBox(void);

      void setSBox(std::vector<uint8_t> sBox);
      void setSBox(uint8_t sBox[256]);
      std::vector<uint8_t> getSBox(void) const;

      void setInvSBox(std::vector<uint8_t> invSBox);
      void setInvSBox(uint8_t invSBox[256]);
      std::vector<uint8_t> getInvSBox(void) const;

      uint8_t subByte(uint8_t byte) const;
      uint8_t invSubByte(uint8_t byte) const;
      Word subWord(Word word) const;
      Word invSubWord(Word word) const;
   };
}
